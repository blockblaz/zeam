# Threading Refactor — Slice (a): Per-Resource Locks + Lock-Free Req/Resp

Date: 2026-04-29
Tracking issue: #803
Status: **DESIGN — REVISION 2 (review feedback applied)**
Author: zclawz bot (under direction of @ch4r10t33r, @gr3999)

Changelog vs. r1 (Partha #1–#7):
- Added §State-pointer lifetime (Partha #1) — slice (a) ships `BorrowedState` wrapper; refcount deferred but the API contract is fixed now.
- Added §Long-hold FFI paths (Partha #2) — `aggregate` and `getProposalAttestations` now snapshot-then-release explicitly.
- Added §Single-writer claim retracted (Partha #3) — `events_lock` introduced for `last_emitted_*` and `cached_finalized_state`.
- Added §Block-cache atomicity (Partha #4) — three `network` block-cache maps consolidated under one `block_cache_lock`.
- Split `caches_lock` into `pubkey_cache_lock` + `root_to_slot_lock` (Partha #5).
- Folded (a-1) into (a-2) (Partha #6); LockedMap unit tests still required.
- Reworked `processPendingBlocks` to one-at-a-time `orderedRemove(0)` (Partha #7).

Changelog vs. r2 (Partha #8–#13 + open-question responses):
- Added §Lock-dance ownership note (Partha #8) — (a-2) absorbs the cognitive load that previously lived in `external_mutex`; LOC estimate revised to ~1000+, and the slice's review burden lives here.
- Added §Cross-thread chain readers (Partha #9) — enumerates current API/metrics/event-broadcaster reads, and reserves the `/eth/v1/*` HTTP surface for an explicit follow-up section.
- Added §Lock-hierarchy semantics clarification (Partha #10) — the rule is about *simultaneous* hold order, not all-time acquire order; sequential acquire/release of any lock is fine.
- Reaffirmed metric migration plan (Partha #11) — emit both old and new metrics for one release; folded into (a-2) since it touches the same labels.
- Added §Stress test plan (Partha #12) — (a-3) gets gossip-flood + RPC concurrency, 10-node devnet under jitter, reorg + finalization stress.
- Added §`connected_peers` access pattern (Partha #13) — atomic counter for hot-path `count()`, `RwLock` for the few `iterator()` callers, mutex sized for adds/removes.
- Resolved open questions: (1) refcount required before slice (c) goes off-thread; (2) `connected_peers` → atomic count + RwLock for iterator; (3) metric migration in (a-2); (4) drop `external_mutex` outright, no null-only transitional release.
- Added §Long-term direction — single chain-mutator thread + queues vs. fine-grained locks. Slice (a) lock-hierarchy work survives either way; per-resource exclusive write locks become dead weight if mutation marshalls. Captured as a #803 question, not slice (a)'s decision.

## Why a design doc first

Slice (a) of #803 is the riskiest of the five slices: it changes how every chain-mutation entry point synchronises against shared state, and a wrong lock hierarchy here = consensus bug or deadlock on devnet. Burning a few hundred lines of design before touching code is a much cheaper failure mode than discovering the wrong shape in a 2000-line PR review.

Once this doc is reviewed and the lock hierarchy + invariants are agreed, the actual code change becomes mostly mechanical and can land in 2–3 small PRs.

## Current state (as of `main` @ commit `dacc1c2`)

Single coarse `BeamNode.mutex` (`std.Thread.Mutex`) serializes all libxev-thread vs libp2p-bridge-thread access to **everything** under `BeamNode`:

| Resource | Owner | Today’s synchronisation |
|---|---|---|
| `BeamChain.forkChoice` | chain | `RwLock` ✅ already per-resource |
| `BeamChain.states` (HashMap<Root, *BeamState>) | chain | only `BeamNode.mutex` |
| `BeamChain.pending_blocks` (ArrayList<SignedBlock>) | chain | only `BeamNode.mutex` |
| `BeamChain.public_key_cache` | chain | only `BeamNode.mutex` (documented not-thread-safe internally) |
| `BeamChain.root_to_slot_cache` | chain | only `BeamNode.mutex` |
| `BeamChain.last_emitted_justified` / `last_emitted_finalized` | chain | only `BeamNode.mutex`, single-writer (chain itself) |
| `BeamChain.cached_finalized_state` | chain | only `BeamNode.mutex` |
| `Network.pending_rpc_requests` | network | only `BeamNode.mutex` |
| `Network.pending_block_roots` | network | only `BeamNode.mutex` |
| `Network.fetched_blocks` / `fetched_block_ssz` / `fetched_block_children` | network | only `BeamNode.mutex` |
| `Network.timed_out_requests` | network | only `BeamNode.mutex` |
| `Network.connected_peers` | network | only `BeamNode.mutex` |
| `BeamNode.batch_pending_parent_roots` | node | only `BeamNode.mutex` |

Only forkchoice has its own per-resource lock today. Everything else is "BeamNode.mutex or nothing."

## Threads in play

1. **libxev main thread** — drives `onInterval` (slot tick), validator client.
2. **libp2p bridge thread** — Rust → Zig FFI delivers gossip and req/resp callbacks (`onGossip`, `onReqRespRequest`, `onReqRespResponse`). See `forkchoice_concurrency_analysis.md` for the detailed proof that these run synchronously on the bridge thread, not marshalled to the libxev loop.
3. **`ThreadPool` workers** — used today for parallel sig verify / aggregation compaction. Stay short-lived, finite scope (`spawnWg`).
4. **(Slice c, future)** — followup worker thread for `processFinalizationFollowup`.
5. **(Slice d, future)** — possibly parallel net-fetch dispatch.

## Design

### Lock-hierarchy rule (the single most important thing)

**Locks are acquired in the order below. Crossing this order = deadlock risk.**

```
1. BeamNode.finalization_lock      (slow, multi-resource, only finalization advance)
2. Network.{single-purpose maps}   (per-map, short critical sections)
2'. Network.block_cache_lock       (covers fetched_blocks + fetched_block_ssz + fetched_block_children atomically — see #4)
3. BeamChain.states_lock           (read-mostly during gossip; write during STF commit + prune)
4. BeamChain.pending_blocks_lock   (short critical sections)
5a. BeamChain.pubkey_cache_lock    (XMSS FFI miss latency lives here — separate from 5b)
5b. BeamChain.root_to_slot_lock    (per-attestation hot path — separate from 5a)
5c. BeamChain.events_lock          (last_emitted_justified/finalized + cached_finalized_state)
6. BeamChain.forkChoice            (its own RwLock — innermost)
```

Rules (clarified per Partha #10):
- **Scope:** the rule applies to locks held *simultaneously*. A code path that does `lock(forkChoice) ... unlock(forkChoice); lock(states) ... unlock(states)` sequentially is fine even though it appears to acquire 6 before 3 — they are never co-held.
- A holder of lock N can additionally take lock M (i.e. nest M inside N's critical section) only if M > N. Never the reverse.
- The 5a/5b/5c locks are siblings: they sit at the same tier but **must not be held simultaneously** (they protect independent resources). Treat them as mutually exclusive within a single nesting depth to avoid deadlock-via-different-orderings.
- The vast majority of code paths take **at most one** of these. The hierarchy exists for the few paths that legitimately span multiple resources.
- Finalization advancement is the only known multi-resource path that may legitimately need (1).
- (`onBlock` legitimately touches multiple locks sequentially — forkchoice read for parent lookup, then states for STF commit, then forkchoice write for head update. This is sequential, not nested, and stays legal.)

### Resource-by-resource design

#### `BeamChain.forkChoice` — already done ✅
Already has its own `Thread.RwLock`. No change in slice (a). Make sure new code paths use shared (read) lock for snapshot reads where possible.

#### `BeamChain.states` (state map) — incl. state-pointer lifetime
Add `states_lock: std.Thread.RwLock`.
- Reads (`states.get(parent_root)`): shared lock.
- Writes (`states.put`, `states.fetchRemove`, prune iteration): exclusive lock.

**State-pointer lifetime — `BorrowedState` is the API contract (addresses Partha #1).**
The r1 design relied on every caller doing the right thing ("take a `sszClone` first if you need the state across an unlock"). That's an unenforced invariant: one missed callsite → consensus-invariant UAF. Fine today with ~9 sites, will not stay fine as slice (c)/(d) workers appear.

Slice (a) introduces a typed wrapper:

```zig
pub const BorrowedState = struct {
    state: *const types.BeamState,
    // tied to states_lock.shared — released by deinit().
    states_lock: *std.Thread.RwLock,
    pub fn deinit(self: *BorrowedState) void { self.states_lock.unlockShared(); }
    /// Materialise an owned copy and drop the borrow.
    pub fn sszClone(self: *BorrowedState, allocator: Allocator) !*types.BeamState { ... self.deinit(); ... }
};
```

- Every `states.get` returns a `?BorrowedState`, not a raw `*const BeamState`.
- The lock is held for the borrow's lifetime → readers cannot observe a freed pointer.
- If a caller needs the state across a long-running operation (FFI, STF, await), it calls `sszClone` to materialise an owned copy and drop the borrow.
- `deinit` is `defer`-style; in debug builds we assert exactly one release per borrow.

This keeps slice (a) **simple** (no atomic refcount, no Arc) while fixing the API contract. Refcount/Arc is still an option for slice (b) or (c) if a later workload needs reader-outlives-prune semantics, but slice (a) does not need it.

**Inventory of `states.get` call sites today (the floor we must migrate in (a-2)):**

| File:line | Function | Lifetime today |
|---|---|---|
| `chain.zig:458` | `produceBlock` | reads then immediately calls `forkChoice.getProposalAttestations(pre_state, ...)` (FFI, ~700ms) — **needs `sszClone` per Partha #2** |
| `chain.zig:919` | `onBlock` | reads then runs STF; today guarded by global mutex; needs lock-dance with `sszClone` |
| `chain.zig:1575` | `onGossipAttestation` | short read; borrow-only is fine |
| `chain.zig:1626` | `onGossipAggregatedAttestation` | short read; borrow-only is fine |
| `chain.zig:1654` | `aggregate` (chain wrapper) | hands state to `forkChoice.aggregate` (~700ms FFI) — **needs `sszClone` per Partha #2** |
| `chain.zig:1716` | `getFinalizedState` | returns pointer outward — **callers must take borrow or sszClone**; today this is an unsafe escape hatch |
| `chain.zig:1921` (test) | test only | n/a |
| `chain.zig:2697` (test) | test only | n/a |
| `node.zig:1477` | `publishBlock`'s `.postState = self.chain.states.get(block_root)` | passes raw pointer to API response builder — needs to take a borrow until the response is serialised, OR sszClone |

(a-2) migrates each row. Each test-only site stays raw with a `// SAFETY: test-only, single-threaded` comment.

#### `BeamChain.pending_blocks`
Add `pending_blocks_lock: std.Thread.Mutex`.
- Append (gossip future-slot path): exclusive.
- Drain (`processPendingBlocks` in `onInterval`): exclusive for the **iteration**, but the inner `chain.onBlock` per replayed block must release this lock during its verify+STF window so gossip-thread appends aren’t blocked.
- Implementation (revised per Partha #7): **one-at-a-time, no index snapshot.** Each iteration takes the lock, scans for the first ready block, `orderedRemove(0)` (or removes the matched index — but always re-finds it after re-acquiring), releases, replays, repeats. Indices are never assumed stable across an unlock. No snapshot array of indices.
  ```zig
  while (true) {
      var ready: ?types.SignedBlock = null;
      {
          self.pending_blocks_lock.lock();
          defer self.pending_blocks_lock.unlock();
          for (self.pending_blocks.items, 0..) |b, i| {
              if (b.message.slot <= current_slot) {
                  ready = self.pending_blocks.orderedRemove(i);
                  break;
              }
          }
      }
      if (ready) |b| {
          self.onBlock(b, ...) catch |e| { ... };
      } else break;
  }
  ```
  This avoids the index-drift bug class entirely: between the unlock and the next lock, the gossip thread is free to append (which only adds at the tail) and the next iteration re-scans from index 0.

#### `BeamChain.public_key_cache` (XMSS) — separate lock
Add `pubkey_cache_lock: std.Thread.Mutex` (own lock, lock 5a). On a miss, `getOrPut` does a Rust FFI deserialize that can take ~ms. Holding this lock over `root_to_slot_cache` lookups (which fire on every gossip-attestation validation) would be a contention trap (Partha #5).

The XMSS pubkey cache documents itself as not-thread-safe. The current parallel verify path keeps cache access in a serial pre-phase (see `BeamChain.thread_pool` doc comment). Slice (a) does NOT change that — slice (b) is where parallel cache access is reconsidered.

#### `BeamChain.root_to_slot_cache` — separate lock
Add `root_to_slot_lock: std.Thread.Mutex` (own lock, lock 5b). Hit on every gossip-attestation validation; critical sections are O(1) hashmap ops.

Kept separate from `pubkey_cache_lock` so an FFI miss in pubkey-cache cannot stall attestation validation.

#### `BeamChain.last_emitted_*` + `cached_finalized_state` — `events_lock` (Partha #3)
The r1 doc claimed these were single-writer. **That claim was wrong.** `chain.onBlockFollowup` is the writer, and it is reachable from at least:
- libp2p bridge thread — via `chain.onBlock` → `onBlockFollowup` (gossip block import path, `chain.zig:771`).
- libxev main thread — via `processPendingBlocks` → `onBlockFollowup` (`chain.zig:322`) and via `node.onInterval` → `node.zig:583` / `1496` / `854`.

Different threads, currently serialised by `BeamNode.mutex`. After slice (a) without explicit synchronisation here → torn writes / lost events / wrong checkpoint emitted to API consumers.

Fix: add `events_lock: std.Thread.Mutex` (lock 5c) covering `last_emitted_justified`, `last_emitted_finalized`, and `cached_finalized_state`. Acquired exclusively by `emitChainEvents` and `processFinalizationFollowup` for the read-modify-write of these three fields. Critical section is short (a few comparisons + assignments + an event publish that itself doesn't block on chain state).

Alternative considered: route all event emission through a single-writer queue drained by a dedicated thread. Rejected for slice (a) — adds a thread before we need one. Revisit in slice (c) when the followup worker lands.

#### Cross-thread chain readers (Partha #9)

Existing and forward-looking surfaces that read chain/network state from a thread other than libxev/libp2p-bridge:

| Surface | File | What it reads | Status today | After slice (a) |
|---|---|---|---|---|
| Prometheus `/metrics` writer | `pkgs/api/src/lib.zig` (HTTP worker thread when wired up) | metric values only — metric registry has its own internal sync | already lock-free | unchanged |
| `event_broadcaster.zig` (SSE consumers) | `pkgs/api/src/event_broadcaster.zig` | broadcaster.subscribers + queued events | own `Mutex` | unchanged; receives events via `events_lock` writer pushing into the broadcaster |
| `lean_connected_peers` metric set | `pkgs/node/src/node.zig:1174,1215` | called from `onPeerConnected` / `onPeerDisconnected` callbacks (libp2p bridge thread) | inside `BeamNode.mutex` | uses `connected_peers` lock only |
| Peer broadcast iterator | `pkgs/node/src/node.zig:1389` | iterates `connected_peers` for outgoing req/resp | inside `BeamNode.mutex` | takes `connected_peers_lock.shared` (RwLock — see Partha #13) |

**Reserved for a separate follow-up section before code:** the upcoming `/eth/v1/beacon/states/*`, `/eth/v1/beacon/headers`, `/eth/v1/beacon/blocks/{block_id}` HTTP endpoints. Those run on an HTTP worker thread independent of libxev/libp2p, and they read `chain.forkChoice`, `chain.states`, `chain.last_emitted_*`, and `db.loadBlock`. After slice (a) they MUST take per-resource locks (forkchoice shared / `BorrowedState` / `events_lock` / db handles its own sync). Today they don't exist; the doc reserves the contract here so it isn't discovered at runtime when they land.

If any prototype HTTP route lives on a feature branch I'm not aware of, please flag it before (a-2) merges so the route migration lands together.

#### `Network` maps
Wrap independent maps in a small `LockedMap(K, V)` helper that bundles `std.Thread.Mutex` + the underlying map and exposes the few methods we actually use (`get`, `put`, `remove`, `count`, `iterator-while-locked`). This keeps callsite changes mechanical: `self.network.pending_rpc_requests.get(...)` becomes thread-safe by construction.

The maps that get **independent** locks (separate code paths, no shared invariants):
- `pending_rpc_requests`
- `pending_block_roots`
- `timed_out_requests`
- `connected_peers` — see special handling below (Partha #13)

**`block_cache_lock` — bundled (Partha #4).** `fetched_blocks`, `fetched_block_ssz`, and `fetched_block_children` share a lifecycle: when a block arrives from req/resp we cache the parsed block, the raw ssz bytes, and link its children atomically. With three independent locks a reader can observe an inconsistent slice (block present, ssz absent) — today this triple-update is atomic under `BeamNode.mutex` and code relies on it.

Fix: a single `block_cache_lock: std.Thread.Mutex` guards all three maps together, exposed via a small `BlockCache` helper (`insert(block, ssz, parent)`, `get(root) -> ?CachedBlock`, `removeChildrenOf(root)`, etc.). The three underlying `HashMap`s are private; callers can only mutate via the helper, so the invariant is structural, not aspirational.

**`connected_peers` access pattern (Partha #13).** `connected_peers.count()` is read from logger config on most gossip paths — frequent, hot. `connected_peers.iterator()` is read from peer broadcast (`node.zig:1389`) — less frequent, longer hold. Adds/removes happen on libp2p bridge callbacks. Plan:
- Replace the `count`-only hot path with an `std.atomic.Value(usize)` (`connected_peer_count`) that is incremented/decremented atomically under the lock when entries are added/removed. Logger reads this atomic, never touches the lock.
- Use `std.Thread.RwLock` for the map itself: `iterator()` callers take `lockShared`; `add` / `remove` take `lockExclusive` and update the atomic count alongside the map mutation.
- Net: logger pays one atomic load instead of a mutex acquire per gossip log line; iterator readers run concurrently.

#### `BeamNode.batch_pending_parent_roots`
Same `LockedMap` helper. Single-resource lock.

#### `BeamNode.mutex` itself

Renamed → `BeamNode.finalization_lock`. Held by:
- `processFinalizationFollowup` (and its dispatcher when slice c lands).
- Anywhere we need a multi-resource view (today only finalization).

#### Lock-dance ownership in `chain.zig` (Partha #8)

The r1 doc described `external_mutex` removal as "mechanical." It isn't. Each of `onBlock`, `onGossipAttestation`, `onGossipAggregatedAttestation`, `produceBlock`, `processPendingBlocks` currently has a lock-dance shape that today is owned by `BeamNode` via `external_mutex`. After slice (a) that shape moves *into* `chain.zig`:

- `states_lock.shared` is taken at the top to fetch the parent state via `BorrowedState`.
- The borrow is converted to an owned snapshot (`sszClone`) for any work that crosses an unlock — verify, FFI, STF.
- For STF commit, `states_lock.exclusive` is re-acquired at the *end* of the path to publish the new state and forkchoice update.

The cognitive load ("release shared → do work → re-acquire exclusive → commit") is preserved, just owned by `chain.zig` instead of `BeamNode.zig`. Callers no longer have to know about it. That is the win — not less code, less spreading.

**LOC reality check:** ~1000+ for (a-2), not the ~600 I estimated in r1. Most of it is per-callsite migration + tests. (a-2) carries the slice's whole review burden — plan reviewer time accordingly.

NOT held by:
- `onGossip` — uses per-resource locks now.
- `onInterval` — uses per-resource locks now.
- `onReqRespRequest` — see below; **lock-free** for the common path.
- `onReqRespResponse` — uses per-resource locks now.

### Long-hold FFI paths — snapshot then release (Partha #2)

Two paths hold a `*const BeamState` for ~700ms while a Rust FFI runs:
- `BeamChain.aggregate` (`chain.zig:1654`) → forwards to `forkChoice.aggregate(pre_state)` which reads `state.validators` for the entire FFI window.
- `BeamChain.produceBlock` (`chain.zig:458`) → `forkChoice.getProposalAttestations(pre_state, ...)`, same shape.

In r1 the implicit assumption was "`states_lock.shared` covers the whole call." That just shifts the contention from `BeamNode.mutex` to `states_lock`: every gossip block commit waits for `states_lock.exclusive`, which waits for the aggregator FFI to finish. **Net win is near zero on aggregator-heavy nodes.**

Fix: snapshot-then-release.

```zig
// chain.aggregate — revised
var borrow = self.states.get(head_root) orelse return error.MissingState;
const snapshot = try borrow.sszClone(self.allocator); // releases states_lock.shared
defer snapshot.deinitAndDestroy(self.allocator);
return self.forkChoice.aggregate(snapshot);  // FFI runs against owned copy
```

If full `sszClone` is too expensive in the hot path (the validator list dominates the state), the alternative is to copy only the fields the aggregator actually reads (`validators` slice + the small handful of integers it touches) into a stack-allocated `AggregatorView` struct. We measure first; ssz-clone is the simple correct default.

Same pattern in `produceBlock`. Both sites must release `states_lock` before entering the FFI.

### Lock-free req/resp (`onReqRespRequest`)

This is the headline of slice (a) per G's points 1+2.

`onReqRespRequest` handles two cases today:

- `.status` — reads `chain.getStatus()`, which reads forkchoice fields. Already lock-free if forkchoice is read under its own RwLock (shared).
- `.blocks_by_root` — for each requested root, calls `db.loadBlock(...)`. The DB has its own internal synchronisation (rocksdb / lmdb backends are thread-safe for concurrent reads).

Neither case mutates `chain` or `network` state. Slice (a) drops the `BeamNode.mutex` acquisition entirely from this path:

```zig
// before
var guard = self.acquireMutex("onReqRespRequest.blocks_by_root");
defer guard.unlock();

// after
// LOCK-FREE: reads only chain.db (own synchronisation) and forkchoice via
// snapshot read (its own RwLock). Confirmed in design doc / slice (a).
```

The status path becomes:
```zig
const status = self.chain.getStatus();   // reads forkchoice under shared lock internally
```

`chain.getStatus()` will be audited to ensure it only reads forkchoice via its `RwLock` shared path; no other state is touched.

#### What about `onReqRespResponse`?

Different shape — this path **does** mutate `chain` (it calls `chain.onBlock` for fetched blocks). It still needs synchronisation, but with per-resource locks, not the global one. After slice (a):
- `network.{pending_rpc_requests, pending_block_roots, fetched_blocks, fetched_block_children}` access goes through the per-map locks.
- `chain.onBlock` takes the relevant resource locks itself (states, fc, caches), no caller-supplied mutex required.
- The `external_mutex` parameter introduced by #798–#801 goes away. Lock-dancing was a workaround for the global lock; per-resource locks make it unnecessary because `onBlock` releases short-lived resource locks naturally.

### What slice (a) does NOT do

Listed explicitly to keep PR scope tight:

- ❌ Move the followup off-thread (slice c).
- ❌ Parallelise sig-verify with state-clone (slice b).
- ❌ Parallel net-fetch + missed-root prune (slice d).
- ❌ Centralise hash-root cache on gossip envelopes (slice e).
- ❌ Switch state map to refcounted `Arc<BeamState>` shape — only consider if slice (b) or (c) actually needs it.

## PR breakdown for slice (a)

Revised to **two PRs** per Partha #6 — folding (a-1) into (a-2) so reviewers can evaluate the new primitives against real callsites in one pass instead of trying to spot init/deinit ordering bugs in isolation. The cost (a slightly bigger (a-2)) is offset by mandatory unit tests on the new primitives.

1. **`(a-2) chain + primitives`** — adds the `LockedMap` and `BlockCache` helpers, adds `BorrowedState`, adds `states_lock`, `pending_blocks_lock`, `pubkey_cache_lock`, `root_to_slot_lock`, `events_lock`. Migrates every `chain.zig` callsite (states.get → BorrowedState, pending_blocks → new lock, caches → split locks, events → events_lock). Updates `chain.onBlock` / `chain.onGossip` / `chain.processPendingBlocks` to no longer require an `external_mutex` parameter. Drops the `external_mutex` parameter (was added by #798–#801, now obsolete — dropped outright, no null-only transitional release). Implements the snapshot-then-release pattern in `chain.aggregate` and `produceBlock` so `forkChoice.aggregate` / `getProposalAttestations` see an owned snapshot, not a borrow. Adds the per-lock metric histograms (`zeam_lock_wait_seconds{lock="...", site="..."}`) and keeps the old `zeam_node_mutex_*` series alive as a derived sum for one release (compat shim) so dashboards don't go dark (Partha #11).
   - **Mandatory unit tests** (per Partha #6): `LockedMap` (constructor, get/put/remove, iterator-while-locked, deinit-when-empty, deinit-when-non-empty), `BlockCache` (atomic triple-insert, partial-state invariants), `BorrowedState` (one-release assertion, sszClone-then-deinit). These are the only standalone tests in this slice; everything else is covered by chain integration tests.
   - **Realistic LOC: ~1000+** (revised up from r1's 600 per Partha #8 — the lock-dance moves into chain.zig, not away). This PR carries the slice's full review burden.

2. **`(a-3) node + req/resp`** — migrate `Network` map accesses to the new locks (`block_cache_lock` plus the four independent ones, with `connected_peers` getting the atomic count + RwLock pattern). Drop `BeamNode.mutex` from `onGossip`, `onInterval`, `onReqRespResponse`. Make `onReqRespRequest` fully lock-free. Rename `BeamNode.mutex` → `finalization_lock` for the few remaining multi-resource paths. ~400 LOC.
   - **Stress test plan** (per Partha #12) — devnet smoke alone catches obvious deadlocks but misses UAFs and concurrency races. (a-3) ships at minimum:
     1. **Single-node ingestion stress.** Synthetic gossip-block flood + concurrent `blocks_by_root` RPC against the same node. Run 30+ minutes; assert no `state-map-key-not-found` panics, no assertion failures, no `MissingPreState`.
     2. **10-node devnet under jitter.** Existing devnet runner + tc-netem packet loss/delay for ≥1h. Watch for divergence, deadlock, or growing pending_blocks queue.
     3. **Reorg + finalization stress.** Constructed scenario where two competing chain branches force a reorg right around a finalization advance — exercises the `events_lock` / `finalization_lock` boundary. (Partha right that this is rare on current devnet; need a synthetic harness.)
   - At least one of these gates merge; ideally all three are wired into nightly so the slice keeps paying off in regression catches.

Each PR builds + tests cleanly on its own; (a-2) and (a-3) get devnet smoke runs against the existing instrumentation from #786 to confirm no contention regression.

## Resolved open questions (Partha r2 responses)

1. **`states` map prune coordination.** Slice (a) handles this by keeping followup inline. **However:** if slice (c) moves the followup off-thread without first adding refcounted state pointers, it will tear. **Hard requirement: slice (c) MUST land an `Arc<BeamState>` (or equivalent refcount) before going off-thread.** Captured as a slice-(c) blocker in #803.

2. **`connected_peers` lock granularity.** Resolved — atomic counter for the hot `count()` path + `RwLock` for the iterator path. See §Network maps above.

3. **Lock metric coverage.** Resolved — fold into (a-2) since the metric label set changes anyway. Emit both old (`zeam_node_mutex_*`) and new (`zeam_lock_wait_seconds{lock=...}`) for one release; old metric becomes the sum across new lock labels via a recording rule / derived shim. Drop the old series in the release after.

4. **`external_mutex` removal vs. backward-compat.** Resolved — drop outright in (a-2). No `null`-only transitional release. (No external embedders today; the param was internal-only plumbing from #798–#801.)

## Long-term direction note (Partha post-script)

This refactor preserves the shape "every chain mutator can be called from any thread, synchronised via per-resource locks." An alternative long-term shape is "all chain mutation marshalled to a single chain-mutator thread with a queue, readers read snapshots." Slice (a)'s lock-hierarchy work survives the marshalling refactor (still useful for *read* paths and for any per-resource cache the mutator thread owns), but per-resource *exclusive write* locks become dead weight under marshalling.

Which direction is #803's long-term target should be a #803-level decision before slice (b)/(c) commits to a specific shape; flagging here so each slice converges in the same direction. My read of the original 8-point plan: the marshalling shape is the cleaner end state, and slice (a) is a strict prerequisite either way (read snapshots need lock-hierarchy regardless). Worth a one-paragraph statement of intent on #803.

## Ask for reviewers (r3)

Most of r1/r2's open questions are now closed. Remaining decisions before I cut code:

- **Long-term direction in #803.** Marshalled chain-mutator vs fine-grained per-resource locks. Slice (a) is compatible with either, but slice (b)+(c) need this pinned. Looking for a one-paragraph statement of intent in #803.
- **`AggregatorView` partial-copy vs full `sszClone`** in `aggregate` / `produceBlock`. Default is full clone; only worth the partial copy if benchmarks show ssz-clone time dominates the FFI. Defer to (a-2) profiling unless someone has data already.
- **HTTP `/eth/v1/*` surface.** If a prototype branch already exists, please flag before (a-2) merges so the route migration lands together rather than as a follow-up.
- **Stress test prioritisation.** All three scenarios in (a-3) are useful but only one is required as a merge gate. My pick: **single-node ingestion stress** (cheapest to wire up, catches the largest UAF surface). Open to a different pick.

Once these are resolved (or explicitly punted), I’ll cut PR (a-2) with the LockedMap/BlockCache/BorrowedState primitives + chain migration in one go.
