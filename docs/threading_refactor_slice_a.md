# Threading Refactor — Slice (a): Per-Resource Locks + Lock-Free Req/Resp

Date: 2026-04-29
Tracking issue: #803
Status: **DESIGN — REVIEW BEFORE CODE**
Author: zclawz bot (under direction of @ch4r10t33r, @gr3999)

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
1. BeamNode.finalization_lock     (slow, multi-resource, only finalization advance)
2. Network.{maps}_lock             (per-map, short critical sections)
3. BeamChain.states_lock          (read-mostly during gossip; write during STF commit + prune)
4. BeamChain.pending_blocks_lock  (short critical sections)
5. BeamChain.caches_lock          (xmss pubkey cache + root_to_slot cache; short)
6. BeamChain.forkChoice           (its own RwLock — innermost)
```

Rules:
- Higher number = inner lock. Acquire 1 → 2 → 3 → 4 → 5 → 6 only. Never reverse.
- A holder of lock N can take lock M only if M > N.
- The vast majority of code paths take **at most one** of these. The hierarchy exists for the few paths that legitimately span multiple resources.
- Finalization advancement is the only known multi-resource path that may legitimately need (1).

### Resource-by-resource design

#### `BeamChain.forkChoice` — already done ✅
Already has its own `Thread.RwLock`. No change in slice (a). Make sure new code paths use shared (read) lock for snapshot reads where possible.

#### `BeamChain.states` (state map)
Add `states_lock: std.Thread.RwLock`.
- Reads (`states.get(parent_root)`): shared lock.
- Writes (`states.put`, `states.fetchRemove`, prune iteration): exclusive lock.

State pointers themselves: once a `*BeamState` is in the map, only the writer who called `fetchRemove` is allowed to `deinit`/`destroy` it. Readers borrow the pointer for the duration of their work; the prune path coordinates with the finalization-advance lock to make sure no reader still holds a freed pointer.

Open question: should we replace the `*BeamState` with `Arc`-style refcounting (`std.atomic.Value(u32)` + manual decRef / deinit-when-zero) so readers can outlive the prune-write? In slice (a) we **avoid this** by ensuring all reads of a given state pointer are confined to the critical section that took the read lock. Anything that needs the state across an unlock (e.g. `chain.onBlock` lock-dance for STF) takes a `sszClone` first — which the existing code already does.

#### `BeamChain.pending_blocks`
Add `pending_blocks_lock: std.Thread.Mutex`.
- Append (gossip future-slot path): exclusive.
- Drain (`processPendingBlocks` in `onInterval`): exclusive for the **iteration**, but the inner `chain.onBlock` per replayed block must release this lock during its verify+STF window so gossip-thread appends aren’t blocked.
- Implementation: `processPendingBlocks` snapshots the indices it will replay, releases the lock, processes one block, re-acquires to advance. (Mirrors the lock-dance pattern from #798–#801 but scoped to the resource lock instead of the whole `BeamNode.mutex`.)

#### `BeamChain.public_key_cache` + `root_to_slot_cache`
Add a single `caches_lock: std.Thread.Mutex` covering both. They’re hit together on every block import and aren’t large enough to deserve separate locks.

The XMSS pubkey cache documents itself as not-thread-safe. The current parallel verify path keeps cache access in a serial pre-phase (see `BeamChain.thread_pool` doc comment). Slice (a) does NOT change that — slice (b) is where parallel cache access is reconsidered.

#### `BeamChain.last_emitted_*` + `cached_finalized_state`
Single-writer (chain itself, on the followup path). Slice (a) marks this explicitly with a `// SAFETY: single-writer, written only from {emitChainEvents, processFinalizationFollowup}` comment + asserts; no lock added. Slice (c) (followup worker) will revisit if writes move off the gossip thread.

#### `Network` maps
Wrap each in a small `LockedMap(K, V)` helper that bundles `std.Thread.Mutex` + the underlying map and exposes the few methods we actually use (`get`, `put`, `remove`, `count`, `iterator-while-locked`). This keeps callsite changes mechanical: `self.network.fetched_blocks.get(root)` becomes thread-safe by construction.

The seven maps (`pending_rpc_requests`, `pending_block_roots`, `fetched_blocks`, `fetched_block_ssz`, `fetched_block_children`, `timed_out_requests`, `connected_peers`) get separate locks. They are accessed from independent code paths and contention between them is rare; keeping them separate also reduces the blast radius of any single critical section.

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

Three small PRs, each independently mergeable, each with its own devnet-style test:

1. **`(a-1) infra`** — add the `LockedMap` helper, add per-resource lock fields to `BeamChain` and `Network` (init/deinit only, not yet used). No callsite changes. ~200 LOC. Pure mechanical.

2. **`(a-2) chain`** — migrate `BeamChain.{states, pending_blocks, public_key_cache, root_to_slot_cache}` accesses to the new locks. Update `chain.onBlock` / `chain.onGossip` / `chain.processPendingBlocks` to no longer require an `external_mutex` parameter. Drop the `external_mutex` parameter (was added by #798–#801, now obsolete). ~600 LOC. Real semantic change; this is the one to review carefully.

3. **`(a-3) node + req/resp`** — migrate `Network` map accesses to the new locks. Drop `BeamNode.mutex` from `onGossip`, `onInterval`, `onReqRespResponse`. Make `onReqRespRequest` fully lock-free. Rename `BeamNode.mutex` → `finalization_lock` for the few remaining multi-resource paths. ~400 LOC.

Each PR builds + tests cleanly on its own; (a-2) and (a-3) get devnet smoke runs against the existing instrumentation from #786 to confirm no contention regression.

## Open questions for review

1. **`states` map prune coordination.** Today prune runs under the global mutex, so no reader can hold a stale `*BeamState`. After slice (a), prune runs under `states_lock` exclusive — fine — but the followup-dispatch path (slice c) might want to read a state from a worker thread that started before prune ran. Slice (a) handles this by keeping followup inline (slice c hasn't landed yet); revisit when slice c lands.

2. **`connected_peers` lock granularity.** It's read on every gossip block (logger), so a coarse mutex on it could become a contention point itself. Consider `RwLock` here? The reads are pure and short, so probably fine with `Mutex`, but worth measuring.

3. **Lock metric coverage.** The current `zeam_node_mutex_{wait,hold}_time_seconds` instrumentation is keyed by site label and assumes a single mutex. Slice (a) should replace this with per-lock histograms (`zeam_lock_wait_seconds{lock="states", site="..."}`). Is this worth doing as part of (a-1) or in a separate observability PR?

4. **`external_mutex` removal vs. backward-compat.** Once (a-2) lands, the `external_mutex: ?*std.Thread.Mutex` parameter on `onBlock`/`processPendingBlocks` is dead weight. Drop in (a-2), or keep as `null`-only for one release in case external embedders depend on it? (No known external embedders today, so probably just drop.)

## Ask for reviewers

Please weigh in on:

- The lock hierarchy ordering — anyone see a path that violates it?
- Whether `LockedMap` is the right primitive vs hand-rolling per-map locks.
- The lock-free req/resp claim — anyone aware of state I'm missing that gets touched on the request path?
- The PR breakdown — is 3 PRs the right granularity, or should (a-2) and (a-3) be combined / split further?

Once we agree on the design, I’ll cut PR (a-1) and we go from there.
