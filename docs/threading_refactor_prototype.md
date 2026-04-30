# Threading refactor — prototype scaffold

Local working branch: `refactor/per-resource-locks-prototype`. Implements the 8-point requirements from #786 / #803 as a working starting point. Builds + `zig build test` + `zig build simtest` all green.

## Commits on this branch

| commit | scope |
|--------|-------|
| `1b8b2b0` | Initial scaffold: per-resource lock fields, `BorrowedState`, `FollowupWorker`, mutex rename, lock-free req/resp, follow-up removal from backfill |
| `d01d26c` | iter 1: migrate hot `states.get` callsites to `BorrowedState`; add `putState` / `fetchRemoveState` / `statesCount` writer accessors |
| `d95cb20` | iter 2: per-resource locks on every `Network` map; `block_cache_lock` bundles 3 maps; atomic `connected_peer_count` for hot logger reads |
| `58c92f1` | iter 3 partial: drop `finalization_lock` from `onReqRespResponse`; chain.onBlock / produceBlock states.put migrated to `putState` / `fetchRemoveState` |
| `f52071e` | iter 6 scaffold: `NetFetchWorker` module + `BeamNode` wiring |
| `c7c1da0` | iter 3 rest: wire pending_blocks_lock + pubkey_cache_lock + root_to_slot_lock + events_lock; drop finalization_lock from onGossip + onInterval |
| `bb21e78` | iter 6: migrate sweepTimedOutRequests + onInterval pending-replay fetches to NetFetchWorker via `dispatchFetchBlockByRoots` |
| (this) | iter 5: hash-root cache for attestation + aggregation gossip envelopes — pre-compute in BeamNode.onGossip, thread through chain.onGossip → verify path |

## Status of the 8 requirements

| # | Requirement | Status |
|---|-------------|--------|
| 1 | All shared resources own their own locks | **done** — chain has 5 locks, network has 6 + atomic peer count, `BorrowedState` typed wrapper enforces state-pointer lifetime |
| 2 | Minimise locking on req/resp | **done** — `onReqRespRequest` lock-free; `onReqRespResponse` lock-free at entry |
| 3 | Multi-resource lock only at finalization | **done** — `BeamNode.mutex` renamed to `finalization_lock`; dropped from every entry point. The wrapper is retained so the existing `zeam_node_mutex_*` metrics keep populating during the migration window for operators who depend on them |
| 4 | Parallel sig verify + state clone | **achieved at outer-lock level** by iter 1+2: `states_lock.shared` released after `cloneAndRelease`; `verifySignaturesParallel` already spawns parallel attestation verifies on the thread pool; concurrent gossip block commits run alongside the verify window |
| 5 | Hash-root cache on gossip envelopes | **done** — block, attestation, and aggregation gossip envelopes all pre-compute their respective `hashTreeRoot` outside any lock in `BeamNode.onGossip`; threaded through `chain.onGossip` → `chain.onGossipAttestation` → `stf.verifySingleAttestation` (and the aggregated path). Internal callers pass `null` and fall back to recomputation |
| 6 | onBlockFollowup off-thread | **done** — `FollowupWorker` MPSC queue + worker thread; gossip + pending-replay paths post a job and return |
| 7 | Remove followup from backfill | **done** — `processCachedDescendants` and `processBlockByRootChunk` no longer call `onBlockFollowup` |
| 8 | Parallel network fetching | **partial** — `NetFetchWorker` MPSC queue + worker thread spawned in `BeamNode.init`. Two safe call sites migrated (`onInterval` pending-replay missing-roots; `sweepTimedOutRequests` retry loop). Other `fetchBlockByRoots` sites stay synchronous on the libp2p worker thread (which already runs in parallel with libxev) until cross-thread ordering is audited |

## Lock hierarchy (in place)

```
1. BeamNode.finalization_lock      (multi-resource view, prune — currently only the wrapper for metrics)
2. Network.{single-purpose maps}   ← in place (4 mutexes + 1 RwLock + atomic count)
2'. Network.block_cache_lock       ← in place (covers fetched_blocks + ssz + children atomically)
3. BeamChain.states_lock           ← in place (RwLock); BorrowedState enforces lifetime
4. BeamChain.pending_blocks_lock   ← in place; one-at-a-time drain pattern
5a. BeamChain.pubkey_cache_lock    ← in place (cacheGetOrPutPubkey accessor)
5b. BeamChain.root_to_slot_lock    ← in place (rootToSlotPut/Get accessors)
5c. BeamChain.events_lock          ← in place (last_emitted_* + cached_finalized_state)
6. BeamChain.forkChoice            ← already RwLock — innermost
```

Sibling locks at tier 5 (a/b/c) MUST NOT be held simultaneously. Verified by inspection of current callsites.

## Key types + accessors

- `BeamChain.BorrowedState` — typed wrapper around `*const BeamState`. `deinit()` releases the underlying `states_lock.shared`. `cloneAndRelease(allocator) !*BeamState` always releases the lock on every exit path (success or error). Caller MUST NOT call `deinit` after `cloneAndRelease`.
- `BeamChain.borrowState(root) ?BorrowedState` — shared-lock accessor.
- `BeamChain.putState(root, state_ptr) !void` — exclusive-lock accessor.
- `BeamChain.fetchRemoveState(root) ?*BeamState` — exclusive-lock accessor.
- `BeamChain.cacheGetOrPutPubkey(idx, bytes) !*HashSigPublicKey` — pubkey_cache_lock-protected.
- `BeamChain.rootToSlotPut(root, slot) !void` / `BeamChain.rootToSlotGet(root) ?Slot` — root_to_slot_lock-protected.
- `BeamNode.dispatchFetchBlockByRoots(roots, depth)` — dupe + enqueue on NetFetchWorker; fire-and-forget.
- `chain.OnBlockFollowupDispatchFn` — chain-side callback for off-thread followup; wired by BeamNode at init.

## What remains (not blocking; tracked here for future iterations)

1. **Migrate remaining `fetchBlockByRoots` call sites** to `dispatchFetchBlockByRoots`. Currently 8 sites are synchronous — most sit on the libp2p worker thread which already runs alongside libxev, so the win is incremental. Audit each producer's expected ordering vs. `batch_pending_parent_roots` flushing before flipping.
2. **Lock-invariant unit tests** for `BorrowedState`, `putState`/`fetchRemoveState`, `FollowupWorker`, `NetFetchWorker`. Standalone tests, not chain-integration.
3. **Refcounted `*BeamState`** if a future workload needs reader-outlives-prune semantics (slice c). Slice (a) avoids it via the borrow-or-clone contract on `BorrowedState`.
4. **Drop the `finalization_lock` field entirely** once a migration window has closed and operators no longer depend on the legacy `zeam_node_mutex_*` histogram series. Today the field is acquired only by the `acquireMutex` wrapper; the wrapper itself is dead code on the consensus path but kept alive for metric compatibility.
5. **Stress test plan**: single-node ingestion stress + 10-node devnet under jitter + reorg/finalization stress. Devnet smoke (current `simtest`) passes but doesn't catch UAFs / data races under sustained load.

## Verified

- `zig build all` — EXIT=0 on every commit.
- `zig build test` — 144 / 144 unit tests pass.
- `zig build simtest` — devnet integration test passes.
- `FollowupWorker` + `NetFetchWorker` exercised on every gossip block import in simtest. Both join cleanly at `BeamNode.deinit`.
