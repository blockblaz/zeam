# Threading refactor — prototype scaffold

Local working branch: `refactor/per-resource-locks-prototype`. Implements the 8-point requirements from #786 / #803 as a working starting point. Builds + `zig build test` + `zig build simtest` all green.

## Status of the 8 requirements

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | All shared resources own their own locks (forkchoice already does) | **partial** | `BeamChain` gains `states_lock` (RwLock), `pending_blocks_lock`, `pubkey_cache_lock`, `root_to_slot_lock`, `events_lock`. Fields + lifecycle wired. **Per-callsite migration to `BorrowedState` is the work that remains** — chain methods still use `BeamNode.finalization_lock` via the existing `acquireMutex` shape so the build is unbroken during migration. |
| 2 | Minimise locking on req/resp | **done** | `onReqRespRequest.blocks_by_root` is fully lock-free — reads `chain.db` (own sync) and emits responses. `onReqRespRequest.status` was already lock-free. |
| 3 | Multi-resource lock only at finalization | **done (rename)** | `BeamNode.mutex` renamed to `BeamNode.finalization_lock`. Existing call sites still acquire it via `acquireMutex(...)` for back-compat during migration; once chain methods migrate to per-resource locks, the only real users of `finalization_lock` will be the prune sweep at finalization advance. |
| 4 | Parallel sig verify + state clone | **deferred** | The `ThreadPool` is already wired into chain via `verifySignaturesParallel`. The next step is to spawn the sig-verify pool fork in parallel with `sszClone`, joining at STF apply. Tracked as a follow-up. |
| 5 | Compute hash roots once for gossip objects | **partial** | `BeamNode.onGossip` already hoists `hashTreeRoot(BeamBlock)` before any lock (precomputed_block_root, from #787). Attestation + aggregation gossip envelopes still re-hash inside the chain layer. Tracked as a follow-up to extend the `precomputed_*_root` pattern to all three message types. |
| 6 | onBlockFollowup on a separate thread | **done** | New `pkgs/node/src/followup_worker.zig` (`FollowupWorker`): MPSC queue + worker thread. Spawned in `BeamNode.init`, joined in `BeamNode.deinit`. `BeamChain` gets `setOnBlockFollowupDispatch(ctx, fn)`; gossip and pending-replay paths post a job and return. Inline path remains as a fallback when no dispatcher is wired (tests). |
| 7 | Remove onBlockFollowup from backfill ops | **done** | `processCachedDescendants` (`node.zig:599`) and `processBlockByRootChunk` (`node.zig:876`) no longer call `chain.onBlockFollowup`. Comments explain why: events / finalization advance still fire from the gossip path that imports the canonical chain. |
| 8 | Parallel network fetching + missed-root prune | **deferred** | Bigger change — needs its own worker (similar shape to `FollowupWorker`). Tracked as a follow-up. |

## What was added

- `pkgs/node/src/followup_worker.zig` — new module. `FollowupWorker { queue, mutex, cond, thread, dispatch_fn }`. Public API: `init`, `start(dispatch_ctx, dispatch_fn)`, `enqueue(job)`, `deinit`. Worker thread drains and invokes the dispatch callback outside the queue lock so chain-side locks (events_lock, finalization_lock) can be taken without nesting under it.
- `pkgs/node/src/chain.zig` —
  - Per-resource lock fields (5 locks) on `BeamChain` (init/deinit by default).
  - `BorrowedState` typed wrapper. `deinit` releases the shared lock; debug-build assertion on double-release. `cloneAndRelease(allocator)` materialises an owned snapshot and drops the borrow.
  - `borrowState(root) ?BorrowedState` accessor.
  - `setOnBlockFollowupDispatch(ctx, fn)` + `dispatchOrRunFollowup(prune, sb)` helper. Used by gossip-path + pending-replay so follow-ups fire off-thread when wired.
- `pkgs/node/src/node.zig` —
  - `BeamNode.mutex` → `BeamNode.finalization_lock` (field rename only; `acquireMutex` continues to use it).
  - `BeamNode.followup_worker` field. `init` spawns it, `deinit` joins. `enqueueChainFollowup` adapter bridges `chain.OnBlockFollowupDispatchFn` → `FollowupWorker.enqueue`. Falls back to inline followup on enqueue allocation failure.
  - `onReqRespRequest.blocks_by_root` is lock-free.
  - `processCachedDescendants` and `processBlockByRootChunk` no longer call `chain.onBlockFollowup`.

## Lock hierarchy (target shape — partially in place)

```
1. BeamNode.finalization_lock      (multi-resource view, prune)
2. Network.{maps}_lock             (TODO — per-map; #803 slice (a-3))
3. BeamChain.states_lock           (added; not yet wired into call sites)
4. BeamChain.pending_blocks_lock   (added; not yet wired)
5a. BeamChain.pubkey_cache_lock    (added; not yet wired)
5b. BeamChain.root_to_slot_lock    (added; not yet wired)
5c. BeamChain.events_lock          (added; not yet wired)
6. BeamChain.forkChoice            (already RwLock — innermost)
```

Sibling locks (5a / 5b / 5c) MUST NOT be held simultaneously. Document in code as call sites migrate.

## What remains (next iterations)

1. **`BorrowedState` migration of every `chain.states.get` call site.** ~9 callers. Each pre-existing `const pre_state = self.states.get(root) orelse ...` becomes `var borrow = self.chain.borrowState(root) orelse ...; defer borrow.deinit();` — or `cloneAndRelease` for paths that span FFI / STF / pool spawn.
2. **Network per-map locks.** Currently `Network.fetched_blocks` / `_ssz` / `_children` / `pending_block_roots` / `pending_rpc_requests` / `timed_out_requests` / `connected_peers` are protected only by `BeamNode.finalization_lock`. Wrap `fetched_blocks + _ssz + _children` in a `BlockCache` helper (atomic triple-update); rest get individual `LockedMap` wrappers. `connected_peers` gets atomic `count` for hot-path logger reads + RwLock for iterator.
3. **Drop `BeamNode.finalization_lock` from `onGossip` / `onInterval` / `onReqRespResponse`.** Once steps 1+2 land, the only legitimate holder is the prune sweep inside `processFinalizationFollowup`.
4. **Parallel sig verify with state clone.** In `chain.onBlock`, fire `verifySignaturesParallel` on the thread pool while `sszClone(parent_state, post_state)` runs concurrently. Join at STF apply.
5. **Hash-root cache on gossip envelopes.** Extend `precomputed_block_root` (from #787) to attestations + aggregations: hash before any lock, pass through to chain layer to skip rehashing under lock.
6. **Parallel network fetch + missed-root prune.** New worker similar in shape to `FollowupWorker` for missing-root fetches and stale-pending-root prune.

## Testing posture

- `zig build all` — clean rebuild, EXIT=0.
- `zig build test` — all 144 unit tests pass.
- `zig build simtest` — devnet SSE + node-3 sync integration test passes.
- The `FollowupWorker` is exercised end-to-end on every gossip block import in `simtest`. The worker thread drains, and `BeamNode.deinit` joins cleanly at shutdown.
- Lock-invariant regression tests for `BorrowedState` are NOT added yet — should land with the per-callsite migration so they exercise the actual contract on real call sites.

## Risks + open questions

- **`BorrowedState.cloneAndRelease` allocator failure.** Current impl: allocator failure inside `sszClone` propagates the error; the borrow's lock is NOT released because `self.deinit()` is called only after `sszClone` succeeds. Errdefer should release the lock on failure paths. Will fix in the migration PR.
- **`FollowupWorker` queue is unbounded.** No backpressure. If the worker stalls (e.g. event broadcaster slow), the queue grows without bound. Consider bounded queue + drop-on-full policy.
- **Single-writer `last_emitted_*` claim.** Currently the gossip path is single-writer for these fields, but once the followup worker is the writer, gossip thread might attempt a same-slot read (e.g. for emitChainEvents inline fallback). Audit needed before promoting `events_lock` from declared to enforced.
- **`finalization_lock` is still acquired by `onGossip` / `onInterval` / `onReqRespResponse`** today — the rename is mechanical. Remove these acquisitions once per-resource locks are wired into chain methods.
