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
//! `acq_rel`-ordered atomic ops so the freeing thread observes all
//! prior writes to the state.
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
///     // Creator path: takes ownership of `state` (which must be
///     // a freshly-allocated, fully-initialised BeamState).
///     const rc = try RcBeamState.create(allocator, state);
///     defer rc.release();              // initial reference
///
///     // Reader path: existing rc, take a fresh acquire.
///     const reader_rc = rc.acquire();
///     defer reader_rc.release();       // independent of creator
///
/// Concurrent acquire/release is safe; the underlying refcount is an
/// atomic and the freeing thread wins exactly one cmpxchg.
pub const RcBeamState = struct {
    /// Owning allocator. Final release frees `self` via this allocator.
    allocator: Allocator,
    /// Refcount. `acq_rel` orderings on bumps and decrements ensure the
    /// thread that observes 0 also observes all prior writes to `state`
    /// (and that the freeing thread's writes are not reordered before
    /// the decrement).
    refcount: std.atomic.Value(u32),
    /// The wrapped state. Heap-owned; `release` calls `state.deinit()`
    /// when refcount hits 0.
    state: types.BeamState,

    const Self = @This();

    /// Create a new refcounted state wrapping `state` (transferred by
    /// value into the heap allocation; caller must not retain a
    /// pointer to the old `state` location). Initial refcount is 1
    /// — the creator is responsible for the matching `release`.
    ///
    /// Returns `error.OutOfMemory` if the allocation fails. On
    /// failure, `state` is NOT consumed — the caller still owns it
    /// and is responsible for its cleanup.
    pub fn create(allocator: Allocator, state: types.BeamState) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .refcount = std.atomic.Value(u32).init(1),
            .state = state,
        };
        return self;
    }

    /// Bump refcount. Returns the same pointer for chained call sites
    /// (e.g. `const reader = rc.acquire();`). Safe to call from any
    /// thread that holds a valid acquire.
    pub fn acquire(self: *Self) *Self {
        const prev = self.refcount.fetchAdd(1, .acq_rel);
        // Overflow check: u32 max is 4 billion; we should never get
        // anywhere near this in practice, but a wraparound would be a
        // silent UAF. Debug-build assert.
        std.debug.assert(prev < std.math.maxInt(u32));
        return self;
    }

    /// Decrement refcount. When refcount reaches 0, calls
    /// `state.deinit()` and frees `self`. After `release`, the caller
    /// MUST NOT use `self` again.
    ///
    /// Underflow (double-release without a matching acquire) is a
    /// debug-build panic; release-build behaviour is silent UB.
    pub fn release(self: *Self) void {
        const prev = self.refcount.fetchSub(1, .acq_rel);
        std.debug.assert(prev > 0); // catch double-release
        if (prev == 1) {
            // Last reference — we own the free.
            self.state.deinit();
            self.allocator.destroy(self);
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

    const reader = rc.acquire();
    try testing.expectEqual(@as(u32, 2), rc.count());
    reader.release();
    try testing.expectEqual(@as(u32, 1), rc.count());
}

test "RcBeamState: multiple acquires and releases keep state alive until last" {
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);
    // creator's release happens last (at the bottom of this test)

    const r1 = rc.acquire();
    const r2 = rc.acquire();
    const r3 = rc.acquire();
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

    const reader = rc.acquire();
    try testing.expect(reader == rc);
    reader.release();
}

test "RcBeamState: concurrent acquire/release stress (40 threads × 10k iters)" {
    // High-contention test: 40 threads each take an acquire, do a
    // tiny no-op load, then release. The creator's refcount stays
    // at 1 throughout (each thread's acquire/release pair is
    // balanced). At the end, refcount must be exactly 1, then the
    // creator's release frees.
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);

    const NUM_THREADS: usize = 40;
    const ITERS_PER_THREAD: usize = 10_000;

    const Worker = struct {
        fn run(target: *RcBeamState, n: usize) void {
            var k: usize = 0;
            while (k < n) : (k += 1) {
                const reader = target.acquire();
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

test "RcBeamState: release order doesn't matter (acquire-then-release vs release-then-acquire)" {
    // T1 acquires then releases. T2 acquires then releases. Result
    // refcount must be the creator's 1, regardless of interleaving.
    const state = try makeState();
    const rc = try RcBeamState.create(testing.allocator, state);

    const Worker = struct {
        fn run(target: *RcBeamState) void {
            const reader = target.acquire();
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
