//! Refcounted `*BeamState` wrapper (slice c-2a of #803).
//!
//! Background: `BeamChain.states` is a hashmap of `Root → *BeamState`.
//! Slice (a-2) wrapped reads in `BorrowedState` so callers couldn't
//! deref-after-free. That works for a single-writer model but creates
//! contention under the c-2 chain-worker design: a long-lived
//! cross-thread reader (HTTP API, metrics scrape, event broadcaster)
//! holds `states_lock.shared` for the entire duration of its read,
//! blocking the chain worker's next state mutation.
//!
//! `RcBeamState` decouples the lifetime of a `*BeamState` from the
//! lock that guards the map. Readers `acquire` a refcount, can drop
//! the map lock immediately, and call `release` when done. The chain
//! worker can `fetchRemove` from the map while a reader still holds
//! a refcount; the state is freed only when refcount reaches zero.
//!
//! Slice (c-2a) ships the type and rewires `BeamChain.states` storage.
//! No behaviour change at call sites: `statesGet` still hands out a
//! `BorrowedState` whose drop releases the rwlock — the lock is still
//! the source of truth for "has this entry been pruned." c-2b drops
//! the lock from the borrow path and switches to refcount-only
//! release; that's where the cross-thread-reader wins land.
//!
//! ## Storage layout (option (a) per the c-2 plan)
//!
//! Single allocation: `RcBeamState` embeds `BeamState` inline and
//! holds the refcount alongside. Pros:
//!   * one allocation per state (vs split `RcHeader` + `*BeamState`)
//!   * one `release` frees the whole header + state
//!   * no double-pointer chase on the read path
//! Cons:
//!   * cannot share a refcount across multiple distinct `BeamState`
//!     pointers (e.g. shadowing). c-2a has no caller that needs this;
//!     option (b) split layout can be added later if a use case appears.
//!
//! ## Refcount semantics
//!
//! `init` returns a refcount of 1 (the creator's reference). Every
//! `acquire` bumps; every `release` decrements. The thread that brings
//! refcount to 0 frees the state and the wrapper. Acquire/release are
//! Memory ordering follows the standard refcount pattern (Rust
//! `Arc`, C++ `shared_ptr`):
//!
//!   * `acquire`: `.monotonic` fetchAdd. The caller already holds
//!     a valid acquire (that's the contract); incrementing the
//!     count cannot race with a free because no thread can free
//!     until refcount reaches 0, which can't happen while we hold
//!     a reference. No fence needed on this side.
//!   * `release`: `.acq_rel` fetchSub. The freeing thread (the one
//!     that observes `prev == 1`) needs `.acquire` to synchronise
//!     with all prior `.release` decrements from other threads, so
//!     it observes every prior write to the state before calling
//!     `state.deinit()`. The `.release` half ensures non-freeing
//!     decrements publish their writes before the count drop is
//!     visible. `.acq_rel` is the union.
//!
//! Double-release is a debug-build panic (the refcount underflows).
//! Release after a refcount has already been freed is undefined; the
//! map's invariant must guarantee callers hold a valid acquire before
//! calling release. Slice (a-2)'s `BorrowedState` already enforces
//! this for the lock path; under c-2b it will enforce it for the
//! refcount path too.

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");

/// Refcounted wrapper over `BeamState` (option (a) inline layout).
///
/// Lifecycle:
///
///     // Creator path: `create` takes ownership of `state`
///     // unconditionally. On success, the heap allocation embeds
///     // `state` and the matching `release` frees it; on OOM,
///     // `state.deinit()` runs before the error returns. Either
///     // way the caller does NOT call `state.deinit()` after.
///     const rc = try RcBeamState.create(allocator, state);
///     defer rc.release();              // initial reference
///
///     // Cross-thread reader path (HTTP, metrics, broadcaster):
///     // use acquireConst() so the type system enforces that
///     // the holder cannot mutate state.<field>. release()
///     // accepts *const Self, no cast needed at the call site.
///     const reader_rc = rc.acquireConst();
///     defer reader_rc.release();       // independent of creator
///
///     // Chain-worker (writer) path: use acquireWriter() to get
///     // *Self when the follow-up handler may mutate state.
///     const writer_rc = rc.acquireWriter();
///     defer writer_rc.release();
///
/// Concurrent acquire/release is safe; the underlying refcount is an
/// atomic and the freeing thread wins exactly one cmpxchg.
pub const RcBeamState = struct {
    /// Owning allocator. Final release frees `self` via this allocator.
    allocator: Allocator,
    /// Refcount. See the file header for the memory-ordering rules:
    /// `.monotonic` on bump (caller holds a valid acquire so there
    /// is nothing to synchronise against), `.acq_rel` on decrement
    /// (the freeing thread synchronises with every prior
    /// non-freeing decrement via the `.acquire` half).
    refcount: std.atomic.Value(u32),
    /// The wrapped state. Heap-owned; `release` calls `state.deinit()`
    /// when refcount hits 0.
    state: types.BeamState,

    const Self = @This();

    /// Create a new refcounted state wrapping `state` (transferred
    /// by value into the heap allocation; caller must not retain a
    /// pointer to the old `state` location). Initial refcount is 1
    /// — the creator is responsible for the matching `release`.
    ///
    /// **Always-consume contract.** This function takes ownership of
    /// `state` unconditionally. On the success path, `state` is
    /// embedded into the heap allocation and the matching `release`
    /// frees it. On `error.OutOfMemory`, `state.deinit()` is called
    /// before the error is returned, so the caller never has to
    /// remember an `errdefer state.deinit()` between
    /// `buildState(...)` and `RcBeamState.create(...)`.
    ///
    /// Earlier versions of this function returned without consuming
    /// `state` on the OOM path. That asymmetry forced every caller
    /// to write a fragile cleanup pattern; symmetric ownership is
    /// the lower-footgun shape for an API used at every chain.zig
    /// state-write site.
    pub fn create(allocator: Allocator, state: types.BeamState) !*Self {
        const self = allocator.create(Self) catch |err| {
            // OOM on the wrapper allocation — we still consumed
            // `state` per the always-consume contract, so drop its
            // owned interior allocations before returning.
            var consumed = state;
            consumed.deinit();
            return err;
        };
        self.* = .{
            .allocator = allocator,
            .refcount = std.atomic.Value(u32).init(1),
            .state = state,
        };
        return self;
    }

    /// Bump refcount, returning a mutable pointer. Used by the
    /// chain worker (the sole writer under c-2b) when handing a
    /// reference to a follow-up handler that may itself mutate the
    /// state. Safe to call from any thread that holds a valid
    /// acquire.
    ///
    /// Convention, NOT compile-time enforcement: the type system
    /// does not gate `acquireWriter` to a particular thread —
    /// anyone can call it and get `*Self`. What the type system
    /// DOES enforce is the consequence: a holder of `*const Self`
    /// (from `acquireConst`) cannot mutate `state`. The asymmetric
    /// names (`acquireWriter` vs `acquireConst`) make the
    /// convention loud at every call site, and code review (not
    /// the compiler) keeps non-worker code paths off this entry
    /// point. If convention proves leaky in c-2b, the next step
    /// is two distinct types (`RcBeamStateWriter` /
    /// `RcBeamStateReader`).
    ///
    /// Memory ordering: `.monotonic` on the increment per the
    /// standard refcount pattern. The caller already holds a valid
    /// acquire so there is no race against a free; incrementing
    /// requires no fence. (Rust `Arc::clone`, C++
    /// `shared_ptr::shared_ptr(const &)` use the same ordering.)
    pub fn acquireWriter(self: *Self) *Self {
        const prev = self.refcount.fetchAdd(1, .monotonic);
        // Overflow check: u32 max is 4 billion; we should never get
        // anywhere near this in practice, but a wraparound would be
        // a silent UAF. Debug-build assert.
        std.debug.assert(prev < std.math.maxInt(u32));
        return self;
    }

    /// Bump refcount, returning a const pointer. Use this for every
    /// call site that does NOT need to mutate the state — i.e. all
    /// cross-thread readers (HTTP API, metrics scrape, event
    /// broadcaster). The c-2b design has the chain worker as the
    /// sole writer; what `acquireConst` actually provides is a
    /// compile-checked guarantee that the holder cannot mutate
    /// `state.<field>` through this reference. The choice of which
    /// entry point to call (`acquireWriter` vs `acquireConst`)
    /// remains a convention enforced by code review.
    ///
    /// ## Lifetime contract (READ THIS BEFORE c-2b)
    ///
    /// The `*const Self` you hold keeps the underlying `state`
    /// alive ONLY until you call `release()` on it. The freeing
    /// thread is whichever thread brings refcount to 0 — it could
    /// be a *different* thread (e.g. the chain worker dropping its
    /// last reference while you still hold yours), and that thread
    /// will call `state.deinit()` the moment YOUR `release()`
    /// returns if you happen to be the last reference holder.
    ///
    /// Implications:
    ///
    ///   * Drop the borrow as soon as the read is done. Acquire,
    ///     read what you need (snapshot fields, copy slices), call
    ///     release. Treat it like a Rust scoped borrow, not a
    ///     cached handle.
    ///
    ///   * Do NOT cache the `*const Self` in a long-lived struct
    ///     field. That is the obvious footgun; it pins the state
    ///     across STF advances and blocks the freeing path on
    ///     stale heads. Each consumer takes a fresh acquire per
    ///     unit of work.
    ///
    ///   * Do NOT hold the borrow across an STF FFI window or any
    ///     long-running call. The chain worker (sole writer) may
    ///     be ready to retire that state; pinning it serialises
    ///     the worker against the slowest reader.
    ///
    ///   * The borrow does NOT pin `state.<field>` against in-place
    ///     mutation. The chain-worker's `acquireWriter` view of
    ///     the same `RcBeamState` can mutate `state.<field>`
    ///     concurrently. Today this is fine because the c-2b
    ///     design promotes-then-releases (writer never mutates
    ///     a state that has live readers), but the type system
    ///     does NOT enforce that — see the `acquireWriter`
    ///     docstring on the convention vs enforcement point.
    ///
    /// Refcount semantics are identical to `acquireWriter`:
    /// matched by a `release()` call on the same pointer.
    /// `release` takes `*const Self` so the reader path doesn't
    /// need a cast at the call site.
    pub fn acquireConst(self: *Self) *const Self {
        return self.acquireWriter();
    }

    /// Decrement refcount. When refcount reaches 0, calls
    /// `state.deinit()` and frees `self`. After `release`, the
    /// caller MUST NOT use `self` again.
    ///
    /// Takes `*const Self` so a reader that holds a `*const Self`
    /// (from `acquireConst`) can release directly without casting
    /// at the call site. The function itself uses `@constCast`
    /// internally because release IS a destructive operation —
    /// const-ness on the reader's view is about preventing
    /// `state.<field>` mutation, not about the refcount itself.
    ///
    /// MUST NOT be called on a `*const Self` derived from a true
    /// const value (a global `const RcBeamState`, or a stack-local
    /// declared `const`). The `@constCast` is only safe because
    /// every `RcBeamState` is heap-allocated by `create()` — the
    /// underlying memory is mutable, the `*const` qualifier is
    /// purely a view restriction. Mutating through a pointer
    /// derived from a true-const value is undefined behaviour in
    /// optimised builds (the compiler is allowed to assume the
    /// memory does not change). Future contributors writing test
    /// fixtures or examples MUST go through `create()`; do not
    /// fabricate an `RcBeamState` value as a `const` decl and
    /// release it.
    ///
    /// Memory ordering: `.acq_rel` on the decrement. The freeing
    /// thread (`prev == 1`) needs the `.acquire` half to
    /// synchronise with every prior non-freeing decrement so it
    /// observes all prior writes to the state before calling
    /// `state.deinit()`. The `.release` half ensures non-freeing
    /// decrements publish their writes before the count drop is
    /// visible. (Cf. Rust `Arc::drop`, C++ `~shared_ptr`.)
    ///
    /// Underflow (double-release without a matching acquire) is a
    /// debug-build panic when caught — but only when the freed
    /// memory's first 4 bytes happen to read 0 by the time the
    /// stale release runs. The assert is best-effort, NOT a
    /// guaranteed safety net; it catches some double-releases but
    /// release-build / racy-stale-pointer behaviour is silent UB.
    /// Slice c-2b will need the `tryAcquire` upgrade-from-weak
    /// pattern to make stale-pointer acquires safe; see the
    /// follow-up note in #803.
    pub fn release(self: *const Self) void {
        // Cast: refcount is logically internal mutable state even
        // on a const view, and the freeing branch needs to call
        // mutating methods (state.deinit, allocator.destroy).
        const mut = @constCast(self);
        const prev = mut.refcount.fetchSub(1, .acq_rel);
        std.debug.assert(prev > 0); // catch double-release
        if (prev == 1) {
            // Last reference — we own the free.
            mut.state.deinit();
            mut.allocator.destroy(mut);
        }
    }

    /// Try to bump refcount, returning the same pointer on success
    /// or `null` if the rc is already being freed (refcount has
    /// reached 0). This is the upgrade-from-weak primitive that
    /// makes "read pointer from a shared map without holding the
    /// map lock" safe: a concurrent release-to-zero is detected
    /// and the caller backs off instead of dereferencing freed
    /// memory.
    ///
    /// CAS pattern (matches Rust `Arc::upgrade` / C++
    /// `weak_ptr::lock`):
    ///
    ///   loop:
    ///     load current
    ///     if current == 0: return null  // freeing thread won
    ///     cmpxchg(current, current+1)
    ///     if swapped: retry             // someone else won the race
    ///     else:        return self      // we won
    ///
    /// The freeing thread's claim is the `.acq_rel` `fetchSub` in
    /// `release()` that takes refcount from 1 to 0; once that
    /// publishes, every subsequent `tryAcquire` observes 0 and
    /// returns null. There is no race against the free itself
    /// because:
    ///
    ///   * `tryAcquire`'s cmpxchg from 0 to 1 is always rejected
    ///     (the load returns 0 first; the if-guard short-circuits
    ///     before cmpxchg).
    ///   * `tryAcquire`'s cmpxchg from N>0 to N+1 only succeeds
    ///     while the freeing thread has not yet committed its
    ///     `fetchSub(1)` from 1 to 0 — i.e. while the rc is still
    ///     alive.
    ///
    /// SAFETY PRECONDITION: the caller must guarantee that `self`
    /// is a valid `*Self` (not a dangling pointer to freed memory).
    /// The typical pattern is to read the pointer from a shared
    /// data structure (e.g. `BeamChain.states.get(root)`) under
    /// some membership invariant: as long as the pointer is in the
    /// map, the underlying allocation is alive, and `tryAcquire`
    /// then resolves the in-flight free race. Holding the map lock
    /// across the read AND the `tryAcquire` makes this trivially
    /// safe; dropping the lock in c-2b is what motivates this
    /// primitive in the first place. The c-2b removal-protocol
    /// requires "remove-from-map then release" so the pointer is
    /// guaranteed alive at any time it is reachable through the
    /// map.
    ///
    /// Memory ordering: `.monotonic` on both load and the cmpxchg
    /// success/failure orderings. The increment side does not need
    /// to synchronise (caller of a successful `tryAcquire` then
    /// holds a valid acquire and any subsequent reads of `state`
    /// are ordered by the producer's prior `.release` decrement
    /// when the producer eventually releases its own ref). For the
    /// freeing thread's visibility guarantee, see the `release`
    /// docstring.
    pub fn tryAcquire(self: *Self) ?*Self {
        var current = self.refcount.load(.monotonic);
        while (true) {
            if (current == 0) return null;
            if (self.refcount.cmpxchgWeak(
                current,
                current + 1,
                .monotonic,
                .monotonic,
            )) |actual| {
                current = actual;
            } else {
                // CAS succeeded; we won the race.
                std.debug.assert(current < std.math.maxInt(u32));
                return self;
            }
        }
    }

    /// Snapshot the current refcount. For tests + metrics only; do
    /// NOT branch on this value to decide whether to release. Reads
    /// are `.monotonic` because the only correct uses are
    /// observational.
    pub fn count(self: *const Self) u32 {
        return self.refcount.load(.monotonic);
    }
};

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

/// Build a minimal genesis BeamState for tests. Uses the canonical
/// `BeamState.genGenesisState` constructor with a tiny validator set
/// so the test allocator's leak detector can verify clean teardown
/// via `BeamState.deinit`.
fn makeState() !types.BeamState {
    const allocator = testing.allocator;
    const validator_count: usize = 1;
    const attestation_pubkeys = try allocator.alloc(types.Bytes52, validator_count);
    defer allocator.free(attestation_pubkeys);
    const proposal_pubkeys = try allocator.alloc(types.Bytes52, validator_count);
    defer allocator.free(proposal_pubkeys);
    for (attestation_pubkeys, proposal_pubkeys, 0..) |*apk, *ppk, i| {
        @memset(apk, @intCast(i + 1));
        @memset(ppk, @intCast(i + 1));
    }
    var state: types.BeamState = undefined;
    try state.genGenesisState(allocator, .{
        .genesis_time = 0,
        .validator_attestation_pubkeys = attestation_pubkeys,
        .validator_proposal_pubkeys = proposal_pubkeys,
    });
    return state;
}

test "RcBeamState: create + release frees the state" {
    // Most basic test: create with refcount=1, release brings it
    // to 0, the state's interior allocations are freed via
    // BeamState.deinit, the wrapper is freed via allocator.destroy.
    // Test allocator's leak detector is the implicit assertion.
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    try testing.expectEqual(@as(u32, 1), rc.count());
    rc.release();
}

test "RcBeamState: acquire + release pair is balanced" {
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    defer rc.release(); // creator's reference

    const reader = rc.acquireWriter();
    try testing.expectEqual(@as(u32, 2), rc.count());
    reader.release();
    try testing.expectEqual(@as(u32, 1), rc.count());
}

test "RcBeamState: multiple acquires and releases keep state alive until last" {
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    // creator's release happens last (at the bottom of this test)

    const r1 = rc.acquireWriter();
    const r2 = rc.acquireWriter();
    const r3 = rc.acquireWriter();
    try testing.expectEqual(@as(u32, 4), rc.count());

    r1.release();
    try testing.expectEqual(@as(u32, 3), rc.count());
    r2.release();
    try testing.expectEqual(@as(u32, 2), rc.count());
    r3.release();
    try testing.expectEqual(@as(u32, 1), rc.count());

    // Final release frees.
    rc.release();
}

test "RcBeamState: acquire returns the same pointer (cheap to chain)" {
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    defer rc.release();

    const reader = rc.acquireWriter();
    try testing.expect(reader == rc);
    reader.release();
}

test "RcBeamState: acquire/release pair accounting under producer race (40 threads × 10k iters)" {
    // Pair-accounting test: 40 threads each take an acquire, do a
    // tiny no-op load, then release. The creator's refcount stays
    // at 1 throughout (each thread's acquire/release pair is
    // balanced). At the end, refcount must be exactly 1, then the
    // creator's release frees.
    //
    // What this test does NOT prove: the freeing race. Because the
    // creator's reference is held throughout, every fetchSub call
    // observes `prev > 1` and the freeing branch is never taken
    // under contention — the acq_rel ordering on the freeing
    // thread is not exercised. The next test
    // ("freeing race — last release wins under contention") fills
    // that gap by dropping the creator's reference partway and
    // verifying that whichever thread brings refcount to 0 frees
    // cleanly under testing.allocator's leak detection.
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);

    const NUM_THREADS: usize = 40;
    const ITERS_PER_THREAD: usize = 10_000;

    const Worker = struct {
        fn run(target: *RcBeamState, n: usize) void {
            var k: usize = 0;
            while (k < n) : (k += 1) {
                const reader = target.acquireWriter();
                // Touch the state to keep the compiler honest about
                // ordering: the load must happen between acquire
                // and release, otherwise the refcount semantics are
                // not actually being exercised.
                std.mem.doNotOptimizeAway(reader.state.slot);
                reader.release();
            }
        }
    };

    var threads: [NUM_THREADS]std.Thread = undefined;
    var i: usize = 0;
    while (i < NUM_THREADS) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ rc, ITERS_PER_THREAD });
    }
    i = 0;
    while (i < NUM_THREADS) : (i += 1) {
        threads[i].join();
    }

    // Every worker's acquire matched its own release; the only
    // outstanding reference is the creator's.
    try testing.expectEqual(@as(u32, 1), rc.count());

    rc.release();
}

test "RcBeamState: freeing race — last release wins under contention" {
    // The pair-accounting test above never exercises the freeing
    // branch (creator's reference is held throughout). This test
    // does the opposite: pre-bump the refcount once per worker
    // BEFORE spawning, hand each worker its own pre-acquired
    // reference, then drop the creator's reference WHILE the
    // workers are still running. Whichever thread brings
    // refcount to 0 — worker or creator depending on
    // interleaving — must free cleanly.
    //
    // The pre-bump matters: `acquire()`'s contract is "safe to
    // call from any thread that holds a valid acquire." A worker
    // that's just been spawned does NOT yet hold one (spawn
    // doesn't bump for it). If we let the worker call acquire()
    // as its first action, the rc may already have been freed
    // by another worker that finished first — that's UAF on the
    // acquire itself. Pre-bumping on the spawning thread closes
    // that hole because the spawning thread DOES hold the
    // creator's reference at the time of the bump.
    //
    // Repeat the whole shape `OUTER_ITERS` times so we sweep the
    // interleaving space and don't depend on a single lucky
    // schedule. testing.allocator's leak/UAF detector is the
    // assertion.
    const NUM_WORKERS: usize = 16;
    const WORK_ITERS_PER_WORKER: usize = 200;
    const OUTER_ITERS: usize = 50;

    const Worker = struct {
        // Receives a pre-acquired reference. Worker is
        // responsible for releasing it exactly once.
        fn run(reader: *RcBeamState, iters: usize) void {
            defer reader.release();
            // Touch the state inside the acquire window. The
            // doNotOptimizeAway barrier ensures the load is not
            // hoisted out by the compiler — we need the
            // .acq_rel-ordered fetchSub on release to order
            // every prior load before the freeing thread's free.
            var k: usize = 0;
            while (k < iters) : (k += 1) {
                std.mem.doNotOptimizeAway(reader.state.slot);
                std.Thread.yield() catch {};
            }
        }
    };

    var outer: usize = 0;
    while (outer < OUTER_ITERS) : (outer += 1) {
        const state = try makeState();
        const rc = try RcBeamState.create(testing.allocator, state);
        // refcount = 1 (creator)

        var threads: [NUM_WORKERS]std.Thread = undefined;
        var i: usize = 0;
        while (i < NUM_WORKERS) : (i += 1) {
            // Pre-bump on the spawning thread (we still hold
            // the creator's reference here, so this is safe).
            const handed = rc.acquireWriter();
            threads[i] = std.Thread.spawn(
                .{},
                Worker.run,
                .{ handed, WORK_ITERS_PER_WORKER },
            ) catch |err| {
                // Spawn failed AFTER we bumped — release the
                // pre-acquired reference so we don't leak.
                handed.release();
                return err;
            };
        }
        // refcount = 1 + NUM_WORKERS here.

        // Drop the creator's reference while workers are still
        // alive. Now refcount is somewhere in
        // [0, NUM_WORKERS] depending on how many workers have
        // already released. When the LAST release happens (the
        // last worker, or this very call if every worker has
        // already finished), refcount reaches 0 and the freeing
        // thread — worker or creator, we don't know which —
        // calls state.deinit() + allocator.destroy(self).
        rc.release();

        i = 0;
        while (i < NUM_WORKERS) : (i += 1) {
            threads[i].join();
        }
        // After every worker has joined, refcount must have
        // reached 0 and rc must have been freed. We MUST NOT
        // read rc.count() or any rc field here — rc is freed
        // memory by now, so touching it would be UAF.
        // testing.allocator's leak detector catches both the
        // leak case (refcount never reached 0) and the
        // double-free case (refcount underflow on a fetchSub).
    }
}

test "RcBeamState: freeing race — worker takes the final release" {
    // Stronger variant of the previous test: deterministically
    // ensure the WORKER (not the creator) brings refcount to 0,
    // so we exercise the path where a non-creator thread observes
    // prev == 1 on fetchSub and frees.
    //
    // Sequence on the test thread:
    //   1. create(state)            → refcount = 1 (creator)
    //   2. handed = rc.acquireWriter()    → refcount = 2 (creator + handed)
    //   3. rc.release()             → refcount = 1 (handed only)
    //   4. spawn(worker, handed)
    //   5. join
    // The worker is now the sole reference holder; its release
    // brings refcount to 0 and frees. The .acq_rel ordering on
    // fetchSub is what makes this safe: any prior writes to
    // `state` (none in this test, but the contract covers them)
    // are observed by the worker before its free.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const state = try makeState();
        const rc = try RcBeamState.create(testing.allocator, state);
        // refcount = 1 (creator)
        const handed = rc.acquireWriter();
        // refcount = 2 (creator + handed)
        rc.release();
        // refcount = 1 (handed only)

        const Worker = struct {
            fn run(target: *RcBeamState) void {
                // We are the sole reference holder. Touch the
                // state, then release.
                std.mem.doNotOptimizeAway(target.state.slot);
                target.release();
            }
        };

        var t = try std.Thread.spawn(.{}, Worker.run, .{handed});
        t.join();
        // rc is freed by the worker; we must not touch it.
    }
}

test "RcBeamState: release order doesn't matter (acquire-then-release vs release-then-acquire)" {
    // T1 acquires then releases. T2 acquires then releases. Result
    // refcount must be the creator's 1, regardless of interleaving.
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);

    const Worker = struct {
        fn run(target: *RcBeamState) void {
            const reader = target.acquireWriter();
            std.Thread.yield() catch {};
            reader.release();
        }
    };

    var t1 = try std.Thread.spawn(.{}, Worker.run, .{rc});
    var t2 = try std.Thread.spawn(.{}, Worker.run, .{rc});
    t1.join();
    t2.join();

    try testing.expectEqual(@as(u32, 1), rc.count());
    rc.release();
}

test "RcBeamState.create: OOM path consumes state (no leak under FailingAllocator)" {
    // Locks the always-consume contract in code: when the wrapper
    // allocation fails, `create` MUST call state.deinit() before
    // returning the error so the caller never has to remember an
    // errdefer state.deinit() between buildState() and create().
    //
    // Mechanism: FailingAllocator with fail_index=0 fails the very
    // first allocator.create() call (the wrapper allocation inside
    // RcBeamState.create). The state passed in was built with
    // testing.allocator and has owned interior allocations
    // (validators list etc.). If create() returned the error
    // without consuming, the caller (this test) would not call
    // state.deinit() and testing.allocator's leak detector would
    // flag the leak. This test passes ONLY if create() consumes
    // on the OOM path.
    const state = try makeState();

    // FailingAllocator wrapping an always-failing inner allocator.
    // We give it `fail_index = 0` so the first create() fails;
    // the deinit() inside create() then runs against
    // testing.allocator (the state's interior was allocated with
    // testing.allocator, which is what makeState() uses).
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const failing_allocator = failing.allocator();

    const result = RcBeamState.create(failing_allocator, state);
    try testing.expectError(error.OutOfMemory, result);
    // The caller does NOT call state.deinit() here. If create()
    // failed to consume, testing.allocator's leak detector trips
    // when this test scope exits.
}

test "RcBeamState.acquireConst: returns *const Self that releases cleanly" {
    // Locks the c-2b sole-writer invariant in the type system: the
    // chain worker uses `acquire()` to get `*Self` (mutable);
    // every cross-thread reader uses `acquireConst()` to get
    // `*const Self`. Both are released via the same `release()`
    // entry point, which takes `*const Self` so the reader path
    // doesn't need a cast at the call site.
    //
    // This test exercises the reader path end-to-end: take a
    // const reference, dereference state.slot through the const
    // pointer, release. testing.allocator's leak detector verifies
    // clean teardown.
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    defer rc.release(); // creator's reference

    const reader: *const RcBeamState = rc.acquireConst();
    // Read-only deref through the const view. The negative case
    // — the line that would fail to compile if a contributor
    // tried to mutate — is shown explicitly below as a comment
    // (uncommenting it surfaces the type-system guarantee at
    // build time):
    //
    //     reader.state.slot = 5;
    //     // error: cannot assign to constant
    //
    // We don't actually compile-fail in this test (Zig has no
    // stable in-source @compileError fixture for negative tests),
    // but the commented line documents what the type system
    // catches. The positive case is below: a plain read.
    std.mem.doNotOptimizeAway(reader.state.slot);
    try testing.expectEqual(@as(u32, 2), rc.count());
    reader.release();
    try testing.expectEqual(@as(u32, 1), rc.count());
}

test "RcBeamState.acquireConst: concurrent readers free cleanly when creator drops" {
    // Same shape as the freeing-race test, but every reader uses
    // acquireConst() — the c-2b cross-thread reader pattern. The
    // freeing path is identical; this test exists to confirm the
    // const-pointer + release(*const Self) path is exercised at
    // least once under contention.
    const NUM_READERS: usize = 8;
    const ITERS_PER_READER: usize = 100;

    const Reader = struct {
        fn run(reader: *const RcBeamState, iters: usize) void {
            defer reader.release();
            var k: usize = 0;
            while (k < iters) : (k += 1) {
                std.mem.doNotOptimizeAway(reader.state.slot);
                std.Thread.yield() catch {};
            }
        }
    };

    var outer: usize = 0;
    while (outer < 25) : (outer += 1) {
        const state = try makeState();
        const rc = try RcBeamState.create(testing.allocator, state);

        var threads: [NUM_READERS]std.Thread = undefined;
        var i: usize = 0;
        while (i < NUM_READERS) : (i += 1) {
            const handed = rc.acquireConst();
            threads[i] = std.Thread.spawn(
                .{},
                Reader.run,
                .{ handed, ITERS_PER_READER },
            ) catch |err| {
                handed.release();
                return err;
            };
        }
        rc.release(); // creator drops; some reader will be the freer

        i = 0;
        while (i < NUM_READERS) : (i += 1) {
            threads[i].join();
        }
    }
}

test "RcBeamState.tryAcquire: succeeds when rc is alive (basic case)" {
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    defer rc.release();
    // refcount = 1
    const got = rc.tryAcquire();
    try testing.expect(got != null);
    try testing.expectEqual(rc, got.?);
    try testing.expectEqual(@as(u32, 2), rc.count());
    got.?.release();
    try testing.expectEqual(@as(u32, 1), rc.count());
}

test "RcBeamState.tryAcquire: increments refcount under producer race" {
    // Same shape as the existing pair-accounting test but using
    // tryAcquire instead of acquireWriter. Each thread does a
    // tryAcquire (which must succeed because the creator holds
    // a valid reference), reads, releases. Creator's refcount=1
    // is held throughout; tryAcquire never observes 0.
    const NUM_THREADS: usize = 32;
    const ITERS_PER_THREAD: usize = 1_000;

    const Worker = struct {
        fn run(rc: *RcBeamState, iters: usize) void {
            var i: usize = 0;
            while (i < iters) : (i += 1) {
                const got = rc.tryAcquire() orelse {
                    // Should never happen: creator holds a ref so
                    // refcount is always >= 1.
                    @panic("tryAcquire returned null while creator held ref");
                };
                std.mem.doNotOptimizeAway(got.state.slot);
                got.release();
            }
        }
    };

    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    defer rc.release();

    var threads: [NUM_THREADS]std.Thread = undefined;
    var i: usize = 0;
    while (i < NUM_THREADS) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ rc, ITERS_PER_THREAD });
    }
    i = 0;
    while (i < NUM_THREADS) : (i += 1) {
        threads[i].join();
    }
    try testing.expectEqual(@as(u32, 1), rc.count());
}

test "RcBeamState.tryAcquire: returns null after refcount reaches 0" {
    // White-box test: drop the refcount to 0 manually (simulating
    // the freeing thread's commit) BEFORE calling tryAcquire, then
    // verify tryAcquire short-circuits to null without bumping.
    //
    // We can't actually let release() free the wrapper here —
    // we'd be calling tryAcquire on freed memory, which is UAF
    // even with our short-circuit. So we use a hand-rolled fixture
    // that bypasses the destroy() so the wrapper memory stays alive
    // for the test's read. testing.allocator's leak detector ignores
    // this fixture because we destroy it manually at the end.
    const state = try makeState();
    const wrapper = try testing.allocator.create(RcBeamState);
    wrapper.* = .{
        .allocator = testing.allocator,
        .refcount = std.atomic.Value(u32).init(0), // simulate post-free state
        .state = state,
    };
    defer {
        // Manual cleanup: the wrapper's state was never released
        // through the normal path because we forced refcount to 0.
        wrapper.state.deinit();
        testing.allocator.destroy(wrapper);
    }

    const got = wrapper.tryAcquire();
    try testing.expect(got == null);
    try testing.expectEqual(@as(u32, 0), wrapper.count()); // no increment
}

test "RcBeamState.tryAcquire: succeeds while caller holds a pre-bump (no UAF under release-to-zero of separate ref)" {
    // Renamed from "race against release-to-zero — producer + freer"
    // because that title oversold what the test actually exercises
    // (PR #828 review by @ch4r10t33r):
    //
    // Each Trier thread is HANDED its own pre-bumped reference by
    // the spawning thread (`rc.acquireWriter()` before spawn). So
    // for the entire body of `Trier.run`, refcount is >= 1 — the
    // Trier itself is one of the holders. `tryAcquire` on that rc
    // MUST therefore succeed (the panic-on-null in the body proves
    // the test ASSUMES success). The freeing thread (the spawning
    // thread, after dropping the creator ref) is racing the Triers'
    // releases, but it never races a tryAcquire-vs-zero observation
    // because every tryAcquire-caller is itself a refcount holder.
    //
    // What the test DOES prove (which is still useful):
    //   * No UAF: the wrapper is freed exactly once, by whichever
    //     thread observes the last release — testing.allocator's
    //     leak detector + double-free detector are the witnesses.
    //   * Refcount accounting under contention: every successful
    //     tryAcquire is matched by exactly one release, regardless
    //     of interleaving.
    //   * The CAS loop in tryAcquire is safe under concurrent
    //     release pressure on a SEPARATE reference (the creator's
    //     ref being dropped while Triers are running).
    //
    // What the test CANNOT prove (and why no test can):
    //   tryAcquire returning null in a multi-threaded race against
    //   release-to-zero is unreachable by safe code, because
    //   tryAcquire's SAFETY PRECONDITION (lines 318–330) requires
    //   the caller to hold a reference (or otherwise know the rc
    //   wrapper is alive) at the moment of the call. Calling
    //   tryAcquire on a freed wrapper IS a UAF. The null-return
    //   path is exercised by the white-box test above
    //   (`returns null after refcount reaches 0`) which manually
    //   sets refcount=0 on a wrapper whose destroy() it skips.
    //   That is the only safe shape, and it's the right one
    //   because the docstring's safety preconditions ARE the
    //   contract surface tryAcquire offers.
    const NUM_TRIERS: usize = 16;
    const OUTER_ITERS: usize = 50;

    const Trier = struct {
        fn run(handed: *RcBeamState) void {
            // We hold one valid reference (handed). While we hold
            // it, refcount is >= 1, so any tryAcquire on this rc
            // MUST succeed. This is the safety-precondition path.
            const got = handed.tryAcquire() orelse {
                @panic("tryAcquire failed while we held a ref");
            };
            std.mem.doNotOptimizeAway(got.state.slot);
            got.release(); // drop the tryAcquire bump
            handed.release(); // drop the pre-bump
        }
    };

    var outer: usize = 0;
    while (outer < OUTER_ITERS) : (outer += 1) {
        const state = try makeState();
        const rc = try RcBeamState.create(testing.allocator, state);
        // refcount = 1 (creator)

        var threads: [NUM_TRIERS]std.Thread = undefined;
        var i: usize = 0;
        while (i < NUM_TRIERS) : (i += 1) {
            const handed = rc.acquireWriter();
            threads[i] = std.Thread.spawn(.{}, Trier.run, .{handed}) catch |err| {
                handed.release();
                return err;
            };
        }
        // Drop creator's ref while triers are still running. The
        // last release — from any thread — frees.
        rc.release();

        i = 0;
        while (i < NUM_TRIERS) : (i += 1) {
            threads[i].join();
        }
    }
}
