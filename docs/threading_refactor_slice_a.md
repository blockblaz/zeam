# Threading Refactor — Slice (a): Per-Resource Locks + Lock-Free Req/Resp

Date: 2026-04-29 (last revision: 2026-05-04)
Tracking issue: #803
Status: **DESIGN — REVISION 5 (chain-worker-thread target absorbed per @GrapeBaBa)**
Author: zclawz bot (under direction of @ch4r10t33r, @gr3999, @GrapeBaBa)

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

Changelog vs. r4 (@GrapeBaBa actor-model + lighthouse hackmd, 2026-05-02):
- **Recognised both event-loop threads as IO-only targets.** §Threads in play now distinguishes the libxev main thread's *current* role (slot tick + pending-block drain — mixes IO and CPU) from its *target* role (event router only — enqueue-and-return). Same recognition applied to the libp2p bridge thread, with a stronger framing per @GrapeBaBa: holding either event loop for XMSS verify + STF is a correctness bug (mesh maintenance / peer scoring stalls, slot-tick jitter), not a perf nuance.
- **Added §IO-thread non-blocking invariant.** New first-class invariant: neither libxev main nor the libp2p bridge thread may run XMSS verify, STF, or any FFI work whose worst case exceeds a slot's per-interval budget. Crossing the invariant = peers dropped, intervals missed, downstream consensus impact.
- **Added §Chain-worker thread (target architecture).** New section describing the end state: `libxev main → event router only`, dedicated `chain worker thread → owns forkchoice + STF + pending_blocks + states (single owner, zero contention)`, `ThreadPool → parallel crypto only (XMSS verify, BLS aggr, signature batches)`. FFI callbacks become enqueue-and-return work-queue producers. Mirrors what PR #670 already did Rust-side for the `Swarm` (FFI → `SwarmCommand` enqueue → tokio task drains the queue), and mirrors lighthouse's three-tier model documented in https://hackmd.io/@JVtpwRK3SwmkRIFfF0Bmyg/rylVP_WY-g (router → BeaconProcessor manager → workers, where Tier 1 is the only tier that can trigger other tiers).
- **Slice repositioning.** Slice (a) is the *prerequisite* for the chain-worker target, not the target itself. With per-resource locks + `BorrowedState` in place, FFI handlers can `cloneAndRelease` and hand owned snapshots to the worker queue without contending against the libxev thread. Lock-hierarchy work survives — it still describes how the chain worker thread's owned resources interact with the few legitimate cross-thread readers (HTTP API, metrics scrape, event broadcaster).
- **Renamed slice (c).** Was "followup off-thread." Now: **"off-IO-thread chain mutation"** — introduces the chain-worker thread, marshalls `onBlock` / `onGossip` / `onAttestation` / `processPendingBlocks` to it via a bounded work queue, leaves only event routing on libxev main and the libp2p bridge. `processFinalizationFollowup` rides along (was the original (c) goal, now subsumed).
- **Refcount requirement promoted.** The slice-(c) blocker on `Arc<BeamState>` (or equivalent refcount) is now a structural requirement of the chain-worker design, not just a prune-coordination corner case: every cross-thread reader (HTTP API handlers, metrics refreshers, event broadcaster consumers) needs to outlive the worker's `states_lock` window.
- **Updated §Long-term direction** to be concrete instead of suggestive. The actor / chain-worker shape is the explicit target, with lighthouse cited as the proof-of-shape reference. The fine-grained-lock alternative is now described as the failure mode if we never get to slice (c).

Changelog vs. r3 polish (Partha r3 verification feedback):
- Renamed `BorrowedState.sszClone` → `cloneAndRelease` — the old name read like a non-mutating snapshot helper, but the call consumes the borrow and releases the lock. Honest naming prevents double-release bugs.
- Spelled out `BorrowedState` `errdefer` for OOM-mid-clone — lock always released, success or failure.
- Added `released: bool` sentinel + `debug.assert(borrow.released)` in deinit — mirrors `MutexGuard.released` from #787.
- Added debug-build TLS depth counter for tier-5 sibling locks (5a/5b/5c) — "never co-held" enforced at runtime in tests, not just by convention.
- Metric compat shim clarified to **code-side derived double-emit**, not a Prometheus recording rule. Operators do not redeploy.
- Added `getFinalizedState` migration scope note — (a-2) PR description must enumerate every caller; grepping `states.get` won't find them.
- Documented O(n²) worst case for `processPendingBlocks` re-scan; ships a histogram so we measure before optimising; cap-or-cursor mitigations on the shelf.
- Documented `removeChildrenOf` ceiling (`MAX_CACHED_BLOCKS = 1024`) as the longest critical section under `block_cache_lock`.
- Resolved final r3 asks: long-term direction does NOT gate (a-2); single-node ingestion stress is the merge gate; full `sszClone` default; no `/eth/v1/*` prototype branch.

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

Current zeam thread inventory and the role each thread *should* play under the chain-worker target architecture (see §Chain-worker thread below).

| # | Thread | Today (mixes IO + CPU) | Target role |
|---|--------|------------------------|-------------|
| 1 | **libxev main thread** | Drives `onInterval` (slot tick + every-interval bookkeeping), validator client, `processPendingBlocks` drain (which calls `onBlock` → STF inline). | Event router only. Slot ticks, validator-client API timers, peer/connection bookkeeping. **No STF, no XMSS verify, no FFI calls beyond the chain-worker enqueue.** |
| 2 | **libp2p bridge thread** | Single-threaded Tokio runtime (`Builder::new_current_thread()`). Runs all of TCP/QUIC IO, GossipSub mesh, peer scoring **and** the Zig FFI callbacks (`onGossip`, `onReqRespRequest`, `onReqRespResponse`). Holds the loop for the full XMSS verify + STF window. See `forkchoice_concurrency_analysis.md`. | Same as today *minus* the FFI body. The FFI entry point synchronously enqueues a `ChainCommand` (or snapshot+enqueue for paths that need pre-state) and returns immediately. |
| 3 | **`ThreadPool` workers** | Parallel sig-verify and aggregation compaction (`spawnWg` short-lived). | Same — but additionally the natural home for any other parallel-friendly crypto work (BLS aggregate verify, batched XMSS verify) that the chain worker dispatches. |
| 4 | **Chain worker thread** | *(does not exist today — slice (c))* | Owns `BeamChain.{forkChoice, states, pending_blocks, public_key_cache, root_to_slot_cache, last_emitted_*, cached_finalized_state}` exclusively. Drains a bounded MPSC queue produced by libxev / libp2p bridge / HTTP API / sync. Runs all STF, all forkchoice mutation, all state-prune. |
| 5 | **(Slice d, future)** | — | Possibly parallel net-fetch dispatch — out of scope for this design. |

Rationale for the libxev/bridge separation: both are event-loop threads, so business logic on them stalls *every other connection / timer* on the same loop until the work returns. The bridge thread's case is well-known (lighthouse, libp2p docs). The libxev case is symmetric: a 700ms STF blocks the next slot tick, the validator client API timer, and the pending-block drain's own re-entry — which is exactly the source of the slot-jitter @GrapeBaBa called out.

## IO-thread non-blocking invariant

Added as a first-class invariant per @GrapeBaBa:

> Neither the libxev main thread nor the libp2p bridge thread may run any work whose worst case exceeds a per-interval budget (currently 4s slot / 5 intervals = 800ms, and we want headroom inside that). In particular, no XMSS verify, no STF, no `forkChoice.aggregate`/`getProposalAttestations`, no `cloneAndRelease` on a hot state. FFI work that touches `states_lock` for longer than the snapshot window must be marshalled to the chain worker thread (or, for parallel-friendly crypto, the `ThreadPool`).

Violating this invariant is a correctness bug, not just throughput: the libp2p side starts dropping peers (mesh scoring penalises slow handlers), and the libxev side starts missing slot ticks. Both have downstream consensus impact (missed attestation slots, lost head broadcasts).

Slice (a) does not satisfy this invariant on its own — it only shrinks the FFI critical sections enough that the marshalling step in slice (c) can be a snapshot-then-enqueue rather than a stop-the-world. The invariant is satisfied end-to-end after slice (c).

## Chain-worker thread (target architecture)

Reference: lighthouse's threading model documented in https://hackmd.io/@JVtpwRK3SwmkRIFfF0Bmyg/rylVP_WY-g.

Lighthouse uses a three-tier model:
- **Tier 1 (Tokio async executor):** event loops, routers, the `BeaconProcessor` manager, short-lived async workers per work item. Nothing in Tier 1 may block.
- **Tier 2 (Tokio blocking pool):** synchronous CPU-bound work the BeaconProcessor manager dispatches via `spawn_blocking` — BLS verification, gossip-attestation processing, RPC serving, etc.
- **Tier 3 (named Rayon pools):** data-parallel work (backfill segments, PeerDAS column reconstruction).

Key property: **Tier 1 is the only tier that can trigger other tiers.** Tier 2 and Tier 3 only signal back to Tier 1 (`idle_tx`, `oneshot`) when work is done. Routes are a strict pipeline: `network` task → `router` task → `BeaconProcessor` manager → spawned worker → DB / EL / fork-choice update.

For zeam, the equivalent shape is:

```
┌──────────────────┐    enqueue          ┌────────────────────────────┐
│  libxev main     │ ─────────────────▶  │                            │
│  (event router,  │                     │   Chain worker thread      │
│   slot tick,     │                     │   (single owner of chain)  │
│   timers)        │                     │                            │
└──────────────────┘                     │   - drains MPSC queue       │
                                          │   - runs STF / forkchoice  │
┌──────────────────┐    enqueue          │   - emits chain events     │
│  libp2p bridge   │ ─────────────────▶  │   - prunes states           │
│  (Tokio reactor, │                     │                            │
│   FFI entry pt)  │                     └────────────┬───────────────┘
└──────────────────┘                                  │ dispatch to
                                                       ▼
┌──────────────────┐                     ┌────────────────────────────┐
│  HTTP API task   │ ─── snapshot read ──▶  ThreadPool workers        │
│  /eth/v1/*       │     via BorrowedState   (XMSS verify, BLS aggr,  │
└──────────────────┘                     │    sig batches)             │
                                          └────────────────────────────┘
```

The chain worker thread is the **single owner** of the resources slice (a) gives per-resource locks today. Inside the worker thread, those locks become near-no-ops (uncontended) — but they remain useful as the read-side serialisation for the few cross-thread readers that legitimately bypass the queue:

- HTTP API request handlers serving `/eth/v1/beacon/states/*`, `/eth/v1/beacon/headers`, `/eth/v1/beacon/blocks/{block_id}` (snapshot read of `states` / forkchoice — `BorrowedState` is exactly the right shape).
- Prometheus `/metrics` writer (lock-free atomics where possible, `BorrowedState` for anything else).
- Event broadcaster SSE consumers (read `last_emitted_*` under `events_lock`).
- The peer-broadcast iterator in `node.zig:1389` (already moving to atomic count + RwLock).

Mutation-side, only the chain worker touches state. That collapses every deadlock class slice (a) carefully sequences (the lock hierarchy is enforced by program structure, not by careful ordering at every callsite), and zeros locking overhead on the hot mutation path.

### Refcounted state pointers are mandatory under this shape

The HTTP API / metrics / event-broadcaster reads can outlive the chain worker's current view of `states` (e.g. the worker prunes a finalized state while an HTTP request is mid-serialisation). Slice (a)'s `BorrowedState` keeps `states_lock.shared` for the borrow's lifetime — which means **any cross-thread reader that holds a `BorrowedState` will block the chain worker's next state mutation** until that reader completes.

For short reads (status, head block fetch) this is fine. For long reads (full beacon-state JSON serialise of an old slot), it isn't — the chain worker would stall on every old-state read.

The slice (c) chain-worker PR therefore must land refcounted state pointers (`Arc<BeamState>` or a hand-rolled equivalent) before it goes live. Cross-thread readers `cloneAndRelease` *or* take a refcounted pointer that survives independently. Either way, slice (a)'s `BorrowedState` API stays correct — it just acquires a refcount instead of holding a shared lock for long-lived borrows.

This is now a hard prerequisite of slice (c), not an open question.

### Bounded queue, backpressure, and starvation

The chain worker queue is bounded (size TBD, but ~MAX_PENDING_BLOCKS-class). Producers (libxev / bridge / HTTP) `try_send`; full queue means:

- libp2p bridge: drop the message and bump a `lean_chain_queue_drops_total{source="gossip"}` counter — same shape as the swarm-command-channel drop introduced in #808.
- libxev main `processPendingBlocks` drain: stop draining for this interval; resume next interval. Already tolerant of partial drains.
- HTTP API: 503 Retry-After.

Lighthouse's BeaconProcessor uses LIFO for attestations/aggregates (freshness > order) and FIFO for slashings/exits/blocks (ordering matters for safety). Same split applies here: gossip blocks FIFO, gossip attestations LIFO, slashings FIFO. To be specified in slice (c).

Backlog visibility: every queue gets a `lean_chain_queue_depth{queue="..."}` gauge so devnet stress tests catch unbounded growth.

### Slice (c) scope (revised)

With the chain-worker target promoted from "long-term direction footnote" to "named slice," slice (c) now covers:

1. Spawn the chain worker thread + bounded MPSC queue.
2. Migrate `onBlock` / `onGossip` / `onAttestation` / `processPendingBlocks` from synchronous FFI / libxev calls into queue producers.
3. Refcounted state pointers (`Arc<BeamState>` or equivalent) so cross-thread readers don't block worker mutations.
4. `processFinalizationFollowup` rides along (the original (c) goal, now subsumed).
5. Drop fine-grained exclusive *write* locks on chain-worker-owned resources (states_lock, pending_blocks_lock, pubkey_cache_lock, root_to_slot_lock, events_lock) — keep their *read* sides for cross-thread consumers; the worker doesn't need them for mutation since it's the sole writer.
6. Pre-merge stress: same scenarios as slice (a-3) plus a queue-depth saturation test (synthetic gossip flood faster than STF can drain).

LOC estimate: slice (c) becomes a ~1500–2000 LOC PR. Likely needs to split into (c-1) chain-worker scaffold + queue + Arc-state, and (c-2) per-handler migration.

## Threads in play (legacy view, kept for slice (a-2) review)

1. **libxev main thread** — drives `onInterval` (slot tick), validator client.
2. **libp2p bridge thread** — Rust → Zig FFI delivers gossip and req/resp callbacks (`onGossip`, `onReqRespRequest`, `onReqRespResponse`). See `forkchoice_concurrency_analysis.md` for the detailed proof that these run synchronously on the bridge thread, not marshalled to the libxev loop.
3. **`ThreadPool` workers** — used today for parallel sig verify / aggregation compaction. Stay short-lived, finite scope (`spawnWg`).
4. **(Slice c, future)** — chain worker thread + `processFinalizationFollowup` riding along (see §Chain-worker thread above for the revised scope).
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

**Debug-build runtime enforcement (Partha r3 #4).** The 5a/5b/5c "never co-held" rule is a design constraint, not a property: a future contributor can violate it accidentally. (a-2) ships a thread-local depth counter for tier 5 that increments on entry to any 5* lock and decrements on exit, with `debug.assert(depth_tier5 == 0)` at the top of every 5* lock-acquire. A violation fails loudly in tests, not silently in production. Same shape as the lock-hierarchy assertions Folly / Abseil ship in debug builds.

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
    states_lock: *std.Thread.RwLock,  // tied to states_lock.shared
    released: bool = false,            // sentinel — mirrors MutexGuard.released from #787

    /// Idempotent-on-release; debug builds catch double-release / drop-without-release.
    pub fn deinit(self: *BorrowedState) void {
        if (self.released) return;
        self.states_lock.unlockShared();
        self.released = true;
    }

    /// Consume this borrow: materialise an owned copy AND release the lock atomically.
    /// Caller does NOT call deinit() afterwards — ownership of the lock has moved out.
    /// On allocator failure the lock is still released (errdefer below).
    pub fn cloneAndRelease(self: *BorrowedState, allocator: Allocator) !*types.BeamState {
        // errdefer covers the OOM-mid-clone path: the lock must always be released
        // before this function returns, success or failure.
        errdefer self.deinit();
        const owned = try self.state.sszClone(allocator);
        self.deinit();
        return owned;
    }
};

// In deinit-of-parent / drop sites:
//   debug.assert(borrow.released)   // "BorrowedState dropped without release"
```

- Every `states.get` returns a `?BorrowedState`, not a raw `*const BeamState`.
- The lock is held for the borrow's lifetime → readers cannot observe a freed pointer.
- If a caller needs the state across a long-running operation (FFI, STF, await), it calls **`cloneAndRelease`** to materialise an owned copy and drop the borrow in one shot. (Renamed from r2's `sszClone` per Partha r3 — the old name read like a non-mutating snapshot helper, but the semantics consume the borrow. The new name is honest about ownership transfer.)
- `deinit` is `defer`-style and idempotent; in debug builds we assert exactly one release per borrow via the `released: bool` sentinel.
- Allocator failure inside `cloneAndRelease` still releases the lock (`errdefer self.deinit()` before the clone, then explicit `deinit()` after success). No path leaks the lock.

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

**Note on `getFinalizedState` (chain.zig:1716, Partha r3 #6).** This function returns a `*const types.BeamState` *outward* by a different code path than `states.get` — grepping `states.get` will not catch its callers. Before (a-2) merges, the PR description must list every `getFinalizedState` caller (HTTP/RPC layer, validator, tests). One forgotten caller = production UAF after the lock-borrow contract lands. The migration is straightforward (return `?BorrowedState` instead, callers `cloneAndRelease` if they cross an unlock) but the call-site enumeration is non-negotiable.

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

**Worst-case complexity note (Partha r3 #7).** The re-scan-from-front pattern is O(n) per iteration; draining n blocks is O(n²). For typical n<10 (current devnet) this is irrelevant. For pathological n (devnet partitioned for hours, large catch-up) it could become a measurable hot-path cost. Two mitigations available if needed:
  1. **Bound the queue:** introduce `MAX_PENDING_BLOCKS` cap, drop oldest-by-slot on overflow with a metric. Today there is no cap.
  2. **Track a "first ready" cursor:** maintain a hint index that the gossip-append path doesn't invalidate (it only appends at the tail, so the leftmost-ready index never moves left).
  Slice (a) ships the simple O(n) form and adds a `lean_pending_blocks_drain_iters` histogram so we can measure before optimising. Documented assumption: n stays small in normal operation.

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

**Critical-section ceiling (Partha r3 #8).** `removeChildrenOf(root)` worst-case iterates `MAX_CACHED_BLOCKS = 1024` entries while holding `block_cache_lock`. Bounded but ms-scale on the gossip thread. This is the longest critical section under that lock; documenting so the next perf review knows where to look.

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

1. **`(a-2) chain + primitives`** — adds the `LockedMap` and `BlockCache` helpers, adds `BorrowedState`, adds `states_lock`, `pending_blocks_lock`, `pubkey_cache_lock`, `root_to_slot_lock`, `events_lock`. Migrates every `chain.zig` callsite (states.get → BorrowedState, pending_blocks → new lock, caches → split locks, events → events_lock). Updates `chain.onBlock` / `chain.onGossip` / `chain.processPendingBlocks` to no longer require an `external_mutex` parameter. Drops the `external_mutex` parameter (was added by #798–#801, now obsolete — dropped outright, no null-only transitional release). Implements the snapshot-then-release pattern in `chain.aggregate` and `produceBlock` so `forkChoice.aggregate` / `getProposalAttestations` see an owned snapshot, not a borrow. Adds per-lock metric histograms (`zeam_lock_wait_seconds{lock="...", site="..."}`) plus a **code-side derived shim** that double-emits the legacy `zeam_node_mutex_{wait,hold}_time_seconds` from the new lock observations, summed across `lock∈{states,pending_blocks,pubkey_cache,root_to_slot,events,block_cache,...}` (Partha #11, r3 polish #5). Operators do NOT have to redeploy Prometheus or change recording rules — the legacy metric stays alive automatically for one release, then is removed in the release after.
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

## Long-term direction (resolved per @GrapeBaBa, 2026-05-02)

**Target architecture: chain worker thread, per the §Chain-worker thread section above.** Lighthouse uses the same shape (network task → router task → BeaconProcessor manager → workers, with the rule that event loops never run business logic) — see https://hackmd.io/@JVtpwRK3SwmkRIFfF0Bmyg/rylVP_WY-g for the full breakdown.

Why this is the right target rather than fine-grained per-resource locks as the end state:

1. **Forkchoice + STF have almost no useful parallelism between them.** They are inherently sequential — each block builds on the previous head. Per-resource locks pay ongoing complexity and deadlock risk to enable concurrency that doesn't materially exist on the mutation hot path.
2. **IO threads cannot run STF.** Both libxev main and the libp2p bridge are event loops. Holding either one for ~700ms (XMSS verify + STF) breaks slot ticks, GossipSub mesh maintenance, peer scoring, and downstream consensus participation. The fix is to *not run STF on those threads at all*, which means a separate worker.
3. **Single owner = zero locking on the hot path.** Inside the worker thread, the per-resource locks become uncontended (effectively no-ops). Mutation cost drops; deadlock classes collapse to "can the worker self-deadlock," which is structurally easier to verify.
4. **Read paths still need the lock-hierarchy work.** Cross-thread readers (HTTP API, metrics, event broadcaster) still need a safe protocol to read worker-owned state. `BorrowedState` + `events_lock` + the lock hierarchy is exactly that protocol. Slice (a) is a strict prerequisite either way.

What that means for the slice plan:

- **Slice (a)** ships the lock-hierarchy + `BorrowedState` infrastructure. Useful in its own right (devnet runs better, the legacy global mutex is unblocked), and structurally required for slice (c).
- **Slice (b)** (parallel sig-verify + state-clone) is independent of the chain-worker direction and lands either way.
- **Slice (c)** introduces the chain worker thread, marshalls every `chain.onBlock`/`onGossip`/`onAttestation`/`processPendingBlocks` to it, and lands refcounted state pointers so cross-thread readers don't block worker mutations.
- **Slice (d)** (parallel net-fetch) and **slice (e)** (gossip envelope cache) are tangentially related and stay separate.

The alternative end state ("keep chain mutators callable from any thread, just keep adding finer locks") is not the target. It works for slice (a) as an interim because it's a strict subset of what the worker thread needs anyway, but it does not satisfy the §IO-thread non-blocking invariant on its own.

## Status (r5 — chain-worker target absorbed; (a-2) lands as prerequisite)

All r1/r2/r3/r4 review items closed:
- Long-term direction is now **explicit**, not deferred: the chain worker thread + lighthouse-style router model is the target. Slice (a-2) lands as a prerequisite, not as the end state.
- §IO-thread non-blocking invariant added as the correctness rule that drives the chain-worker requirement.
- Slice (c) repositioned and rescoped to deliver the chain worker thread, with refcounted state pointers as a hard prerequisite (see §Chain-worker thread).
- Stress merge gate for (a-3): **single-node ingestion stress**; the other two scenarios run in nightly post-merge.
- `AggregatorView` deferred — default to full `cloneAndRelease`; profile in (a-2), cut over only if `lean_block_building_time_seconds` flags clone time as dominant.
- No prototype `/eth/v1/*` HTTP surface to fold in; the reservation in §Cross-thread chain readers is sufficient.

What this revision changes for slice (a-2) implementation: nothing on the wire. The PR (#805) ships exactly the primitives + migrations described in r3/r4. The redesign is forward-looking — it reframes what slice (a-2) is *for* (chain-worker prerequisite, not standalone solution to the libxev/bridge blocking problem) and locks in slice (c)'s scope so it can be a single PR rather than a series of follow-ups.

Next step: review and merge PR #805 (slice a-2) as the prerequisite it now is, then open the slice (c) tracker with the chain-worker scope above so the team can pre-agree on queue shape, refcount choice, and migration order before the implementation PR lands.
