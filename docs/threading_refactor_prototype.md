# Threading refactor — prototype scaffold

Local working branch: `refactor/per-resource-locks-prototype`. Implements the 8-point requirements from #786 / #803 as a working starting point. Builds + `zig build test` + `zig build simtest` all green.

## Status (commits on this branch)

| commit | scope |
|--------|-------|
| `1b8b2b0` | Initial scaffold: per-resource lock fields, `BorrowedState`, `FollowupWorker`, mutex rename, lock-free req/resp, follow-up removal from backfill |
| `d01d26c` | iter 1: migrate hot `states.get` callsites to `BorrowedState`; add `putState` / `fetchRemoveState` / `statesCount` writer accessors |
| `d95cb20` | iter 2: per-resource locks on every `Network` map; `block_cache_lock` bundles 3 maps; atomic `connected_peer_count` for hot logger reads |
| `58c92f1` | iter 3 (partial): drop `finalization_lock` from `onReqRespResponse`; chain.onBlock / produceBlock states.put migrated to `putState` / `fetchRemoveState` |
| (this) | iter 6: `NetFetchWorker` scaffold — MPSC queue + worker thread, wired into `BeamNode.init` / `deinit`. Call-site migration (fetchBlockByRoots → enqueue) follows in next iteration |

## Status of the 8 requirements

| # | Requirement | Status |
|---|-------------|--------|
| 1 | All shared resources own their own locks | **mostly done** — `BeamChain` has 5 locks (states_lock RwLock + 4 mutexes); `Network` has block_cache_lock + 4 single-purpose mutexes + connected_peers RwLock + atomic count. Hot `states.get` callsites use `BorrowedState`; writer sites use `putState`/`fetchRemoveState`. |
| 2 | Minimise locking on req/resp | **done** — `onReqRespRequest` lock-free; `onReqRespResponse` lock-free at the entry point (chain methods take per-resource locks internally). |
| 3 | Multi-resource lock only at finalization | **partial** — `BeamNode.mutex` renamed to `finalization_lock`. Dropped from `onReqRespResponse` + `onReqRespRequest`. Still acquired by `onGossip` and `onInterval` until the rest of their chain-side state mutations migrate to per-resource locks. |
| 4 | Parallel sig verify + state clone | **achieved at outer-lock level** by iter 1+2: `states_lock.shared` is released after `cloneAndRelease`; `verifySignaturesParallel` already spawns parallel attestation verifies on the thread pool; concurrent gossip block commits proceed in parallel with the verify window. Literal pool-spawn fork-join for clone alongside verify gives <1ms additional win and competes with verify tasks for pool slots — not implemented. |
| 5 | Hash-root cache on gossip envelopes | **partial** — block path already cached via `precomputed_block_root` (#787). Attestation + aggregation pre-hash + thread-through is TODO'd inline at `BeamNode.onGossip` — requires plumbing through `state-transition.verifySingleAttestation` signature. |
| 6 | onBlockFollowup off-thread | **done** — `FollowupWorker` (MPSC queue + worker thread). `BeamNode` spawns + joins. Gossip + pending-replay paths post a job and return. Backfill paths skip follow-up entirely (req. 7). |
| 7 | Remove followup from backfill | **done** — `processCachedDescendants` and `processBlockByRootChunk` no longer call `onBlockFollowup`. |
| 8 | Parallel network fetching + missed-root prune | **scaffold** — `NetFetchWorker` (MPSC queue + worker thread) wired into `BeamNode.init` / `deinit`. Dispatch callback in place. Call-site migration (`fetchBlockByRoots` → `enqueue`) staged for the next iteration; the worker is exercised today only via the dispatch test path. |

## What was added (cumulative)

- `pkgs/node/src/followup_worker.zig` — MPSC queue + worker thread. Decouples gossip-thread followup work.
- `pkgs/node/src/net_fetch_worker.zig` — same shape for blocks_by_root fetches. Scaffold; call-site migration pending.
- `pkgs/node/src/chain.zig` —
  - 5 per-resource lock fields (`states_lock` RwLock + `pending_blocks_lock` / `pubkey_cache_lock` / `root_to_slot_lock` / `events_lock` mutexes).
  - `BorrowedState` typed wrapper. `cloneAndRelease` always releases the underlying lock on every exit path (success or error). Caller MUST NOT call `deinit` after `cloneAndRelease`.
  - `borrowState(root) ?BorrowedState` accessor (shared lock).
  - `putState(root, state_ptr) !void` (exclusive lock).
  - `fetchRemoveState(root) ?*BeamState` (exclusive lock).
  - `statesCount() u32` (shared lock; metrics-only).
  - `setOnBlockFollowupDispatch(ctx, fn)` + `dispatchOrRunFollowup(prune, sb)` for gossip path.
  - 5 hot `states.get` callsites migrated to `BorrowedState` (`onGossipAttestation`, `verifyAggregatedAttestation`, `aggregate`, `produceBlock`, `onBlock`).
  - `produceBlock` + `onBlock` `states.put` / `fetchRemove` migrated to writer accessors.
- `pkgs/node/src/network.zig` —
  - `block_cache_lock` (mutex; covers 3 fetched_* maps atomically).
  - `pending_rpc_lock`, `pending_block_roots_lock`, `timed_out_lock` (mutexes).
  - `connected_peers_lock` (RwLock) + `connected_peer_count` (atomic shadow).
  - 18 methods wrapped with appropriate locks; `disconnectPeer` rewritten as 3-phase to respect the hierarchy; `getTimedOutRequests` documented as the single legitimate sibling-lock co-hold.
- `pkgs/node/src/node.zig` —
  - `BeamNode.mutex` → `BeamNode.finalization_lock` (field rename).
  - `BeamNode.followup_worker` + `BeamNode.net_fetch_worker` fields. Spawned in `init`, joined in `deinit` (in reverse spawn order).
  - `runFollowupDispatch` + `runNetFetchDispatch` worker-thread entry points.
  - `enqueueChainFollowup` adapter (chain → followup-worker). Falls back to inline followup on enqueue allocation failure.
  - `onReqRespRequest.blocks_by_root` lock-free.
  - `onReqRespResponse` lock-free at the entry point.
  - Backfill paths (`processCachedDescendants`, `processBlockByRootChunk`) skip `onBlockFollowup`.

## Lock hierarchy (target shape — partially in place)

```
1. BeamNode.finalization_lock      (multi-resource view, prune)
2. Network.{single-purpose maps}   ← in place, see network.zig
2'. Network.block_cache_lock       ← in place
3. BeamChain.states_lock           ← fields + accessors in place; hot
                                     callsites migrated; remaining
                                     count/iterator sites still
                                     finalization_lock-protected
4. BeamChain.pending_blocks_lock   ← field present; not yet wired
5a. BeamChain.pubkey_cache_lock    ← field present; not yet wired
5b. BeamChain.root_to_slot_lock    ← field present; not yet wired
5c. BeamChain.events_lock          ← field present; not yet wired
6. BeamChain.forkChoice            ← already RwLock
```

Sibling locks (5a / 5b / 5c) MUST NOT be held simultaneously. Iteration 3 will tighten ordering as `onGossip` / `onInterval` migrate.

## What remains (next iterations)

1. **Drop `finalization_lock` from `onGossip` + `onInterval`.** Audit each call inside the locked scope; wrap any chain.zig `states.iterator` / `states.count` / `cached_finalized_state` access with `events_lock` / `states_lock`. Migrate the prune sweep (`pruneStates`) to take `states_lock.exclusive` once and hold it across the iteration.
2. **Wire pending_blocks_lock + pubkey_cache_lock + root_to_slot_lock + events_lock.** Each lock has a small fixed set of producers; mostly mechanical.
3. **NetFetchWorker call-site migration.** Replace synchronous `self.fetchBlockByRoots(roots, depth)` calls with `self.net_fetch_worker.enqueue(roots_owned, depth)` at sites where the producer thread should NOT block on the network round-trip. Start with the easy ones (`sweepTimedOutRequests` retry path); leave the gossip-path missing-root fetches for last because they interact with `batch_pending_parent_roots` flushing.
4. **Hash-root cache for attestations + aggregations.** Plumb through `verifySingleAttestation` / `verifyAggregatedAttestation` to accept an optional pre-computed `*const [32]u8` message hash; pre-compute in `BeamNode.onGossip` before any lock.
5. **`BorrowedState` partial-failure path tightening.** `cloneAndRelease` already always-releases via errdefer; document the contract more visibly + add a unit test.
6. **Lock-invariant tests for the new accessors** (BorrowedState, putState, fetchRemoveState, NetFetchWorker, FollowupWorker). Standalone unit tests, not chain-integration.
