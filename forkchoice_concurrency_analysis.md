# Forkchoice Concurrency + Stale Snapshot Analysis

Date: 2026-01-22
Branch: forkchoice-graph (local)

## Executive summary
- Forkchoice can be mutated concurrently with chain processing in the current production path because gossip callbacks may run on the Rust bridge thread while `onInterval` runs on the xev loop thread.
- The specific “canonical view + analysis mismatch” issue existed on `main` and has now been fixed locally by combining view + analysis under a single shared lock.
- A broader “analysis result can become stale before it is used” risk remains anywhere analysis results are computed and then used later while forkchoice can still mutate concurrently.
- These concurrency/staleness risks were **not introduced** by the forkchoice visualization PR; they already exist on `main`.

## Evidence of concurrent mutation
### Rust bridge thread calls gossip handlers directly
- `pkgs/network/src/ethlibp2p.zig` spawns a Rust bridge thread (`Thread.spawn`) and uses it to deliver gossip.
- In `handleGossipFromRustBridge`, gossip is dispatched via `gossipHandler.onGossip(..., scheduleOnLoop=false)`. That path invokes handlers immediately on the Rust thread.

### gossip handler does not schedule on xev loop
- `pkgs/network/src/interface.zig:GenericGossipHandler.onGossip` only schedules via xev when `scheduleOnLoop=true`. The ethlibp2p path passes `false`, so handlers run synchronously on the Rust thread.

### chain mutation from gossip vs onInterval
- `pkgs/node/src/node.zig:onGossip` -> `pkgs/node/src/chain.zig:onGossip` -> `forkChoice.onBlock/onAttestation` can run on the Rust bridge thread.
- `pkgs/node/src/node.zig:onInterval` -> `pkgs/node/src/chain.zig:onInterval` -> `forkChoice.onInterval` runs on the xev loop.

Net: forkchoice (and chain state) can be mutated concurrently.

## Stale analysis: what it is
A “stale analysis” happens when:
1) canonical analysis is computed from snapshot S
2) forkchoice mutates to snapshot S'
3) the results from S are used later (pruning, DB updates, rebase)

This can lead to misclassification or pruning of blocks that are now canonical.

## Where stale analysis can occur
### 1) Finalization processing
File: `pkgs/node/src/chain.zig` in `processFinalizationAdvancement`
- Local change (this branch) now uses `getCanonicalViewAndAnalysis(...)` to build view + analysis under one shared lock (fixing the *view/analysis mismatch*).
- **Remaining risk:** analysis results can still be stale before DB updates/pruning if forkchoice mutates concurrently after analysis.

### 2) Periodic pruning
File: `pkgs/node/src/chain.zig` near line ~210
- Uses `getCanonicalityAnalysis(..., null)`, which is internally consistent (view built inside analysis call).
- **Remaining risk:** analysis results can become stale before pruning if forkchoice mutates concurrently.

### 3) Observability (lower severity)
- `pkgs/node/src/chain.zig:printSlot` reads multiple forkchoice values in separate calls. These can be inconsistent under concurrency, but this is observability only.

## Specific bug fixed in this branch
### View + analysis mismatch in finalization
On `main`, `processFinalizationAdvancement` did:
1) `getCanonicalView` (shared lock)
2) `getCanonicalityAnalysis` (shared lock)

If forkchoice mutated in between, analysis could be computed against a stale view. This was present on `main` before the PR.

Local fix:
- Added `getCanonicalViewAndAnalysis(...)` in `forkchoice.zig` to compute both under one shared lock.
- Updated `processFinalizationAdvancement` to call the combined API.

## Other forkchoice lock issue fixed
- `computeDeltas(...)` previously used a shared lock while mutating `self.deltas` and `self.attestations`.
- Updated to use exclusive lock in this branch.

## Were these issues introduced by the forkchoice visualization PR?
No.
- The Rust bridge concurrency path exists on `main`.
- The view/analysis split in finalization existed on `main`.
- These are pre-existing issues; current branch fixes a subset of them.

## Options to fully address concurrency/staleness
### Option A — Single-threaded chain (recommended)
- Route all gossip callbacks onto the xev loop thread (set `scheduleOnLoop=true` and fix the scheduling bug).
- This makes chain + forkchoice effectively single-threaded and removes the stale-analysis hazard.

### Option B — Chain-level mutex
- Add a `Chain` mutex and lock at entry of `onGossip`, `onInterval`, `onBlock`, finalization pruning, etc.
- Ensures serialized access without reworking network callbacks.

### Option C — Full concurrent correctness
- Introduce explicit locking around all shared chain state and make all analysis/pruning operate on snapshots.
- Higher effort, higher complexity.

## Recommendation
Keep the forkchoice visualization PR scoped:
- Accept the local fixes (combined view+analysis, computeDeltas lock).
- Track the broader concurrency model decision separately (Option A or B).

