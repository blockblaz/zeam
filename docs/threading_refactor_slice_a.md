# Threading Refactor — Slice (a): Per-Resource Locks + Lock-Free Req/Resp

Date: 2026-04-29
Tracking issue: #803
Status: **DESIGN — REVISION 2 (review feedback applied)**
Author: zclawz bot (under direction of @ch4r10t33r, @gr3999)

Changelog vs. r1:
- Added §State-pointer lifetime (Partha #1) — slice (a) ships `BorrowedState` wrapper; refcount deferred but the API contract is fixed now.
- Added §Long-hold FFI paths (Partha #2) — `aggregate` and `getProposalAttestations` now snapshot-then-release explicitly.
- Added §Single-writer claim retracted (Partha #3) — `events_lock` introduced for `last_emitted_*` and `cached_finalized_state`.
- Added §Block-cache atomicity (Partha #4) — three `network` block-cache maps consolidated under one `block_cache_lock`.
- Split `caches_lock` into `pubkey_cache_lock` + `root_to_slot_lock` (Partha #5).
- Folded (a-1) into (a-2) (Partha #6); LockedMap unit tests still required.
- Reworked `processPendingBlocks` to one-at-a-time `orderedRemove(0)` (Partha #7).

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

Rules:
- Higher number = inner lock. Acquire 1 → 2 → 3 → 4 → 5* → 6 only. Never reverse.
- A holder of lock N can take lock M only if M > N.
- The 5a/5b/5c locks are siblings: they sit at the same tier but **must not be held simultaneously** (they protect independent resources). Treat them as mutually exclusive within a single critical section to avoid deadlock-via-different-orderings.
- The vast majority of code paths take **at most one** of these. The hierarchy exists for the few paths that legitimately span multiple resources.
- Finalization advancement is the only known multi-resource path that may legitimately need (1).

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

#### `Network` maps
Wrap independent maps in a small `LockedMap(K, V)` helper that bundles `std.Thread.Mutex` + the underlying map and exposes the few methods we actually use (`get`, `put`, `remove`, `count`, `iterator-while-locked`). This keeps callsite changes mechanical: `self.network.pending_rpc_requests.get(...)` becomes thread-safe by construction.

The maps that get **independent** locks (separate code paths, no shared invariants):
- `pending_rpc_requests`
- `pending_block_roots`
- `timed_out_requests`
- `connected_peers`

**`block_cache_lock` — bundled (Partha #4).** `fetched_blocks`, `fetched_block_ssz`, and `fetched_block_children` share a lifecycle: when a block arrives from req/resp we cache the parsed block, the raw ssz bytes, and link its children atomically. With three independent locks a reader can observe an inconsistent slice (block present, ssz absent) — today this triple-update is atomic under `BeamNode.mutex` and code relies on it.

Fix: a single `block_cache_lock: std.Thread.Mutex` guards all three maps together, exposed via a small `BlockCache` helper (`insert(block, ssz, parent)`, `get(root) -> ?CachedBlock`, `removeChildrenOf(root)`, etc.). The three underlying `HashMap`s are private; callers can only mutate via the helper, so the invariant is structural, not aspirational.

#### `BeamNode.batch_pending_parent_roots`
Same `LockedMap` helper. Single-resource lock.

#### `BeamNode.mutex` itself

Renamed → `BeamNode.finalization_lock`. Held by:
- `processFinalizationFollowup` (and its dispatcher when slice c lands).
- Anywhere we need a multi-resource view (today only finalization).

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

1. **`(a-2) chain + primitives`** — adds the `LockedMap` and `BlockCache` helpers, adds `BorrowedState`, adds `states_lock`, `pending_blocks_lock`, `pubkey_cache_lock`, `root_to_slot_lock`, `events_lock`. Migrates every `chain.zig` callsite (states.get → BorrowedState, pending_blocks → new lock, caches → split locks, events → events_lock). Updates `chain.onBlock` / `chain.onGossip` / `chain.processPendingBlocks` to no longer require an `external_mutex` parameter. Drops the `external_mutex` parameter (was added by #798–#801, now obsolete). Implements the snapshot-then-release pattern in `chain.aggregate` and `produceBlock` so `forkChoice.aggregate` / `getProposalAttestations` see an owned snapshot, not a borrow.
   - **Mandatory unit tests** (per Partha #6): `LockedMap` (constructor, get/put/remove, iterator-while-locked, deinit-when-empty, deinit-when-non-empty), `BlockCache` (atomic triple-insert, partial-state invariants), `BorrowedState` (one-release assertion, sszClone-then-deinit). These are the only standalone tests in this slice; everything else is covered by chain integration tests.
   - ~800 LOC. Real semantic change; this is the one to review carefully.

2. **`(a-3) node + req/resp`** — migrate `Network` map accesses to the new locks (`block_cache_lock` plus the four independent ones). Drop `BeamNode.mutex` from `onGossip`, `onInterval`, `onReqRespResponse`. Make `onReqRespRequest` fully lock-free. Rename `BeamNode.mutex` → `finalization_lock` for the few remaining multi-resource paths. ~400 LOC.

Each PR builds + tests cleanly on its own; (a-2) and (a-3) get devnet smoke runs against the existing instrumentation from #786 to confirm no contention regression.

## Open questions for review

1. **`states` map prune coordination.** Today prune runs under the global mutex, so no reader can hold a stale `*BeamState`. After slice (a), prune runs under `states_lock` exclusive — fine — but the followup-dispatch path (slice c) might want to read a state from a worker thread that started before prune ran. Slice (a) handles this by keeping followup inline (slice c hasn't landed yet); revisit when slice c lands.

2. **`connected_peers` lock granularity.** It's read on every gossip block (logger), so a coarse mutex on it could become a contention point itself. Consider `RwLock` here? The reads are pure and short, so probably fine with `Mutex`, but worth measuring.

3. **Lock metric coverage.** The current `zeam_node_mutex_{wait,hold}_time_seconds` instrumentation is keyed by site label and assumes a single mutex. Slice (a) should replace this with per-lock histograms (`zeam_lock_wait_seconds{lock="states", site="..."}`). Lean toward folding into (a-2) since the metric label set changes anyway.

4. **`external_mutex` removal vs. backward-compat.** Once (a-2) lands, the `external_mutex: ?*std.Thread.Mutex` parameter on `onBlock`/`processPendingBlocks` is dead weight. Drop in (a-2), or keep as `null`-only for one release in case external embedders depend on it? (No known external embedders today, so probably just drop.)

## Ask for reviewers (r2)

Please weigh in on:

- The revised lock hierarchy with sibling 5a/5b/5c — anyone see a path that legitimately needs two of those at once?
- `BorrowedState` API shape — do we want the typed wrapper now or skip straight to refcounted `Arc<BeamState>`? (My read: wrapper now, refcount only if slice c forces the issue.)
- `BlockCache` helper — is bundling the three maps the right call, or is it cleaner to keep them as separate `LockedMap`s and document the readers-may-see-partial invariant?
- The snapshot-then-release pattern in `aggregate` / `produceBlock` — OK with full `sszClone`, or do we need an `AggregatorView` partial-copy from day one for cost reasons?
- The 2-PR breakdown after folding (a-1) into (a-2) — still tractable for review, or should I split (a-2) along chain-vs-primitives lines instead?

Once we agree, I’ll cut PR (a-2) with the LockedMap/BlockCache/BorrowedState primitives + chain migration in one go.
