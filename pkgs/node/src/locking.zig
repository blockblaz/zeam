// SPDX-License-Identifier: MIT
//
// Per-resource locking primitives for slice (a) of the BeamNode threading
// refactor. See `docs/threading_refactor_slice_a.md` (commit a76c274) for the
// design these helpers implement.
//
// This file provides three primitives:
//
//   * `LockedMap(K, V)` — `zeam_utils.SyncMutex` + `std.AutoHashMap(K, V)` bundle
//     with the small set of methods we actually use. Network-side wiring lands
//     in slice (a-3); the helper itself ships in (a-2) so its unit tests
//     anchor the API contract reviewers can rely on.
//
//   * `BlockCache` — atomic triple of `fetched_blocks`, `fetched_block_ssz`
//     and `fetched_block_children` under a single `block_cache_lock`. Same
//     shipping rationale as `LockedMap`: the helper lives here, the wiring
//     into `network.zig` lands in (a-3).
//
//   * `BorrowedState` — RAII-style wrapper around a borrowed `*const BeamState`
//     paired with the `states_lock` reader that keeps the pointer alive. The
//     wrapper centralises three correctness rules that the design doc calls
//     out: idempotent release, single-release assertion in debug builds, and
//     errdefer-on-OOM-mid-clone for `cloneAndRelease`.
//
// Plus two debug-only helpers used by `chain.zig`:
//
//   * `tier5_depth` — thread-local counter incremented when any of the
//     5a/5b/5c sibling locks are acquired and decremented on release. Tier-5
//     locks must never be co-held; an assertion at every entry point catches
//     a future contributor accidentally violating the rule in tests rather
//     than in production.
//
//   * `LockTimer` — small RAII struct that records `zeam_lock_wait_seconds`
//     and `zeam_lock_hold_seconds` for the new per-resource locks, plus
//     double-emits into the legacy `zeam_node_mutex_{wait,hold}_time_seconds`
//     histograms so existing dashboards keep working for one release.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const zeam_metrics = @import("@zeam/metrics");
const zeam_utils = @import("@zeam/utils");

/// Thread-local depth counter for tier-5 sibling locks (5a/5b/5c). The design
/// doc forbids co-holding any two of them; this counter is the runtime check
/// that fails loudly in tests instead of producing rare deadlocks in
/// production. Decrements happen on lock release.
///
/// The counter is incremented to N (any of 1..3 depending on which sibling)
/// when a tier-5 lock is taken. Re-acquiring the SAME lock recursively is
/// also a violation (none of the tier-5 locks are recursive), but the depth
/// counter rejects that case as well — debug.assert(depth_tier5 == 0) at the
/// acquire entry guarantees no co-holding regardless of which sibling.
pub threadlocal var tier5_depth: u32 = 0;

/// Helper used by chain.zig to make tier-5 lock acquisition fail loudly if
/// another sibling is already held by this thread. Compiled out in release.
pub inline fn assertNoTier5SiblingHeld(comptime site: []const u8) void {
    if (builtin.mode == .Debug) {
        if (tier5_depth != 0) {
            std.debug.panic(
                "tier-5 sibling lock violation at {s}: another tier-5 lock already held (depth={d})",
                .{ site, tier5_depth },
            );
        }
    }
}

pub inline fn enterTier5() void {
    if (builtin.mode == .Debug) tier5_depth += 1;
}

pub inline fn leaveTier5() void {
    if (builtin.mode == .Debug) {
        std.debug.assert(tier5_depth > 0);
        tier5_depth -= 1;
    }
}

/// Per-resource lock observation helper. Records wait + hold time into the
/// new `zeam_lock_{wait,hold}_seconds` histograms. To keep the legacy
/// `zeam_node_mutex_{wait,hold}_time_seconds` dashboards alive for one
/// release, the same observation is also written into the legacy histogram
/// (the "code-side derived shim" the design doc mandates instead of a
/// Prometheus recording rule).
///
/// Usage:
///   var t = LockTimer.start("states", "produceBlock");
///   t.acquired();
///   defer t.released();
///   ... critical section ...
pub const LockTimer = struct {
    lock_label: []const u8,
    site: []const u8,
    /// Monotonic-clock timestamp for the start of the wait phase, captured at
    /// `start()`. Re-used as the start of the hold phase after `acquired()`
    /// records the wait delta and resets the anchor.
    anchor_ns: i128,
    waited: bool = false,
    released_flag: bool = false,

    pub fn start(comptime lock_label: []const u8, comptime site: []const u8) LockTimer {
        return .{
            .lock_label = lock_label,
            .site = site,
            .anchor_ns = zeam_utils.monotonicTimestampNs(),
        };
    }

    /// Call after the lock has been acquired; records wait time and resets
    /// the anchor to measure hold time.
    pub fn acquired(self: *LockTimer) void {
        if (self.waited) return;
        self.waited = true;
        const now_ns = zeam_utils.monotonicTimestampNs();
        const wait_ns: i128 = if (now_ns >= self.anchor_ns) now_ns - self.anchor_ns else 0;
        self.anchor_ns = now_ns;
        const wait_s: f32 = @as(f32, @floatFromInt(wait_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
        zeam_metrics.metrics.zeam_lock_wait_seconds.observe(
            .{ .lock = self.lock_label, .site = self.site },
            wait_s,
        ) catch {};
        // Legacy compat shim: keep the old `zeam_node_mutex_*` series alive
        // for one release so existing dashboards do not go dark. The label
        // we pass through is the callsite (`site`); the lock name is dropped
        // because the legacy series only had one label.
        zeam_metrics.metrics.zeam_node_mutex_wait_time_seconds.observe(
            .{ .site = self.site },
            wait_s,
        ) catch {};
    }

    /// Call when the critical section ends. Idempotent.
    pub fn released(self: *LockTimer) void {
        if (self.released_flag) return;
        self.released_flag = true;
        const now_ns = zeam_utils.monotonicTimestampNs();
        const hold_ns: i128 = if (now_ns >= self.anchor_ns) now_ns - self.anchor_ns else 0;
        const hold_s: f32 = @as(f32, @floatFromInt(hold_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
        zeam_metrics.metrics.zeam_lock_hold_seconds.observe(
            .{ .lock = self.lock_label, .site = self.site },
            hold_s,
        ) catch {};
        zeam_metrics.metrics.zeam_node_mutex_hold_time_seconds.observe(
            .{ .site = self.site },
            hold_s,
        ) catch {};
    }
};

/// `LockedMap(K, V)` is a `zeam_utils.SyncMutex` + `std.AutoHashMap(K, V)` bundle
/// with the small set of methods we actually use. Iteration is exposed via
/// `iteratorWhileLocked` which returns the lock-holder a raw map iterator —
/// callers must finish iterating before releasing the lock. Mutation methods
/// take and release the lock internally.
pub fn LockedMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Map = std.AutoHashMap(K, V);
        pub const Iterator = Map.Iterator;

        map: Map,
        mutex: zeam_utils.SyncMutex = .{},

        pub fn init(allocator: Allocator) Self {
            return .{ .map = Map.init(allocator) };
        }

        /// Free underlying hashmap storage. Caller is responsible for any
        /// per-value cleanup (e.g. allocator.destroy on heap pointer values)
        /// before calling deinit; this helper does NOT iterate to free
        /// values, matching the existing `BeamNode` patterns.
        pub fn deinit(self: *Self) void {
            self.map.deinit();
        }

        pub fn get(self: *Self, key: K) ?V {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.get(key);
        }

        pub fn put(self: *Self, key: K, value: V) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.map.put(key, value);
        }

        pub fn remove(self: *Self, key: K) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.remove(key);
        }

        pub fn fetchRemove(self: *Self, key: K) ?Map.KV {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.fetchRemove(key);
        }

        pub fn count(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.count();
        }

        /// Locks the map and returns an iterator. Caller MUST call
        /// `endIteration` (or use the `IterationGuard` helper below) to
        /// release the lock. Holding the lock across long-running work is a
        /// design smell — prefer copying out the values you need under the
        /// lock and releasing it before doing real work.
        pub fn beginIteration(self: *Self) Iterator {
            self.mutex.lock();
            return self.map.iterator();
        }

        pub fn endIteration(self: *Self) void {
            self.mutex.unlock();
        }

        /// RAII helper for `beginIteration` / `endIteration`. Use:
        ///   var guard = lm.iterateLocked();
        ///   defer guard.deinit();
        ///   while (guard.iter.next()) |entry| { ... }
        pub const IterationGuard = struct {
            owner: *Self,
            iter: Iterator,
            released: bool = false,

            pub fn deinit(self: *IterationGuard) void {
                if (self.released) return;
                self.released = true;
                self.owner.mutex.unlock();
            }
        };

        pub fn iterateLocked(self: *Self) IterationGuard {
            self.mutex.lock();
            return .{ .owner = self, .iter = self.map.iterator() };
        }
    };
}

/// Bundle of the three block-cache maps that today live in `Network`. The
/// design doc requires them to be guarded by a single `block_cache_lock` so
/// the triple-update (block + ssz + parent link) is atomic from any reader's
/// perspective. The wiring into `network.zig` lands in (a-3); this file
/// ships the helper + unit tests so the contract is reviewed independently.
///
/// `MAX_CACHED_BLOCKS = 1024` — `removeChildrenOf` worst case iterates up to
/// this many entries while holding the lock. Documented per the design doc's
/// "longest critical section under block_cache_lock" call-out.
pub const MAX_CACHED_BLOCKS: usize = 1024;

pub const CachedBlock = struct {
    block: types.SignedBlock,
    ssz: []const u8,
    parent_root: types.Root,
};

pub const BlockCache = struct {
    const Self = @This();

    const BlockMap = std.AutoHashMap(types.Root, types.SignedBlock);
    const SszMap = std.AutoHashMap(types.Root, []const u8);
    const ChildrenMap = std.AutoHashMap(types.Root, std.ArrayListUnmanaged(types.Root));

    allocator: Allocator,
    mutex: zeam_utils.SyncMutex = .{},
    blocks: BlockMap,
    ssz_bytes: SszMap,
    children: ChildrenMap,

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .blocks = BlockMap.init(allocator),
            .ssz_bytes = SszMap.init(allocator),
            .children = ChildrenMap.init(allocator),
        };
    }

    /// Free every map's internal storage AND the per-entry heap allocations
    /// that the cache owns:
    ///   * the SignedBlock value (deinit only — caller-owned heap clones are
    ///     out of scope for the helper, the caller registers them via
    ///     `insert` so the helper owns the deinit obligation).
    ///   * the SSZ-bytes slice.
    ///   * the children ArrayLists.
    pub fn deinit(self: *Self) void {
        // No need to lock — deinit is single-threaded by contract.
        var block_it = self.blocks.iterator();
        while (block_it.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.blocks.deinit();

        var ssz_it = self.ssz_bytes.iterator();
        while (ssz_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.ssz_bytes.deinit();

        var child_it = self.children.iterator();
        while (child_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.children.deinit();
    }

    /// Atomic insert of (block, ssz, parent link). Either all three updates
    /// happen or none — partial state is invisible to readers.
    ///
    /// Ownership: `block` and `ssz` are taken by the cache (deinit/free at
    /// removal). `parent_root` is just a key copy.
    pub fn insert(
        self: *Self,
        root: types.Root,
        block: types.SignedBlock,
        ssz: []const u8,
        parent_root: types.Root,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Pre-reserve on all three so we can roll back on partial failure.
        const block_gop = try self.blocks.getOrPut(root);
        errdefer if (!block_gop.found_existing) {
            _ = self.blocks.remove(root);
        };
        if (block_gop.found_existing) {
            // Caller is overwriting; deinit the old block before clobber so
            // we don't leak.
            block_gop.value_ptr.*.deinit();
        }
        block_gop.value_ptr.* = block;

        const ssz_gop = try self.ssz_bytes.getOrPut(root);
        errdefer if (!ssz_gop.found_existing) {
            _ = self.ssz_bytes.remove(root);
        };
        if (ssz_gop.found_existing) {
            self.allocator.free(ssz_gop.value_ptr.*);
        }
        ssz_gop.value_ptr.* = ssz;

        // Append to children list under parent_root. Allocate a fresh list
        // when the parent has no entry yet.
        const child_gop = try self.children.getOrPut(parent_root);
        errdefer if (!child_gop.found_existing) {
            // We just allocated an empty list; clean it up.
            _ = self.children.remove(parent_root);
        };
        if (!child_gop.found_existing) {
            child_gop.value_ptr.* = .empty;
        }
        try child_gop.value_ptr.append(self.allocator, root);
    }

    /// Read the cached triple by root. Returns null when any of the three
    /// underlying maps is missing the entry (defensive; should be impossible
    /// once `insert` is the only mutator).
    pub fn get(self: *Self, root: types.Root) ?CachedBlock {
        self.mutex.lock();
        defer self.mutex.unlock();
        const block = self.blocks.get(root) orelse return null;
        const ssz = self.ssz_bytes.get(root) orelse return null;
        // We don't carry parent_root in the helper structurally — return a
        // synthetic CachedBlock with a zero parent root (callers that need
        // the parent must consult `children` separately).
        return .{
            .block = block,
            .ssz = ssz,
            .parent_root = std.mem.zeroes(types.Root),
        };
    }

    pub fn contains(self: *Self, root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.blocks.contains(root);
    }

    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.blocks.count();
    }

    /// Remove every cached descendant rooted at `root` (transitive children
    /// only — the entry for `root` itself is NOT removed; callers that want
    /// to drop the root pass it through `removeOne` first). Worst case
    /// iterates up to `MAX_CACHED_BLOCKS` entries; documented per the
    /// design doc's "longest critical section" call-out.
    pub fn removeChildrenOf(self: *Self, root: types.Root) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var removed: usize = 0;
        // BFS over the children map, bounded by MAX_CACHED_BLOCKS.
        var queue: std.ArrayListUnmanaged(types.Root) = .empty;
        defer queue.deinit(self.allocator);

        if (self.children.fetchRemove(root)) |entry| {
            var list = entry.value;
            defer list.deinit(self.allocator);
            queue.appendSlice(self.allocator, list.items) catch return removed;
        }

        while (queue.items.len > 0) {
            if (removed >= MAX_CACHED_BLOCKS) break;
            const child = queue.pop().?;
            removed += 1;

            if (self.blocks.fetchRemove(child)) |b| {
                var bv = b.value;
                bv.deinit();
            }
            if (self.ssz_bytes.fetchRemove(child)) |s| {
                self.allocator.free(s.value);
            }
            if (self.children.fetchRemove(child)) |entry| {
                var list = entry.value;
                defer list.deinit(self.allocator);
                queue.appendSlice(self.allocator, list.items) catch break;
            }
        }
        return removed;
    }

    /// Remove a single cached entry by root (block + ssz + the entry in the
    /// parent's children list). Returns true if the block was present.
    pub fn removeOne(self: *Self, root: types.Root, parent_root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        var removed = false;
        if (self.blocks.fetchRemove(root)) |b| {
            var bv = b.value;
            bv.deinit();
            removed = true;
        }
        if (self.ssz_bytes.fetchRemove(root)) |s| {
            self.allocator.free(s.value);
        }
        if (self.children.getPtr(parent_root)) |children| {
            for (children.items, 0..) |c, i| {
                if (std.mem.eql(u8, &c, &root)) {
                    _ = children.swapRemove(i);
                    break;
                }
            }
            if (children.items.len == 0) {
                if (self.children.fetchRemove(parent_root)) |entry| {
                    var list = entry.value;
                    list.deinit(self.allocator);
                }
            }
        }
        return removed;
    }
};

/// `BorrowedState` is the API contract for handing a `*const BeamState` out
/// of `BeamChain.states` (and, for `getFinalizedState`, out of
/// `cached_finalized_state` under `events_lock`). The wrapper owns the
/// read-side of the appropriate lock for the borrow's lifetime so a
/// concurrent prune / cache-refresh cannot free the pointer underneath the
/// holder. Two release shapes are supported:
///
///   * `deinit()` — the common case: short-lived borrow, lock released as
///     soon as the borrow goes out of scope. Idempotent.
///
///   * `cloneAndRelease(allocator)` — for callers that need to keep the
///     state around past an unlock (FFI windows, STF, anything that runs
///     hundreds of milliseconds): materialise an owned copy AND release
///     the lock atomically. On allocator failure mid-clone the lock is
///     still released via `errdefer self.deinit()`.
///
/// Debug builds enforce single-release via the `released: bool` sentinel —
/// dropping a borrow without releasing it panics in `assertReleased`, the
/// same shape as `MutexGuard.released` from #787.
///
/// Naming note: the previous draft called the consume-and-release helper
/// `sszClone`, which read like a non-mutating snapshot helper. The current
/// name `cloneAndRelease` is honest about the fact that the call consumes
/// the borrow.
///
/// Backing-lock variants:
///   * `.states_shared_rwlock` — backed by `BeamChain.states_lock` (RwLock,
///     read side). Used by every borrow returned from `BeamChain.statesGet`.
///   * `.events_mutex` — backed by `BeamChain.events_lock` (Mutex). Used
///     only by the `cached_finalized_state` / DB-fallback paths inside
///     `BeamChain.getFinalizedState` when the state is NOT in the in-memory
///     map. Same release contract for callers — deinit / cloneAndRelease
///     work the same.
pub const BorrowedState = struct {
    state: *const types.BeamState,
    backing: Backing,
    released: bool = false,

    pub const Backing = union(enum) {
        states_shared_rwlock: *zeam_utils.SyncRwLock,
        events_mutex: *zeam_utils.SyncMutex,
    };

    /// Idempotent. Releases the backing lock. After a successful release
    /// the `state` pointer must not be touched.
    pub fn deinit(self: *BorrowedState) void {
        if (self.released) return;
        self.released = true;
        switch (self.backing) {
            .states_shared_rwlock => |rw| rw.unlockShared(),
            .events_mutex => |m| m.unlock(),
        }
    }

    /// Consume the borrow: produce an owned `*types.BeamState` and release
    /// the lock. On allocator failure the lock is still released. Caller
    /// owns the returned pointer and MUST NOT call `deinit` afterwards.
    pub fn cloneAndRelease(self: *BorrowedState, allocator: Allocator) !*types.BeamState {
        // OOM-mid-clone: the lock must always be released, success or
        // failure. errdefer fires on the `try` lines below.
        errdefer self.deinit();
        const owned = try allocator.create(types.BeamState);
        errdefer allocator.destroy(owned);
        try types.sszClone(allocator, types.BeamState, self.state.*, owned);
        // Past the last `try`: success path. Drop the borrow explicitly.
        self.deinit();
        return owned;
    }

    /// Debug-only assert: panic if the borrow has not been released. Mirrors
    /// `MutexGuard.assertReleased` from #787. Compiled out in release.
    pub fn assertReleased(self: *const BorrowedState) void {
        if (builtin.mode == .Debug) {
            std.debug.assert(self.released);
        }
    }
};

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

test "LockedMap: ctor + get/put/remove + count" {
    var lm = LockedMap(u32, u32).init(testing.allocator);
    defer lm.deinit();

    try testing.expectEqual(@as(usize, 0), lm.count());
    try testing.expectEqual(@as(?u32, null), lm.get(7));

    try lm.put(7, 42);
    try testing.expectEqual(@as(usize, 1), lm.count());
    try testing.expectEqual(@as(?u32, 42), lm.get(7));

    try lm.put(7, 100);
    try testing.expectEqual(@as(?u32, 100), lm.get(7));

    try testing.expect(lm.remove(7));
    try testing.expectEqual(@as(usize, 0), lm.count());
    try testing.expect(!lm.remove(7));
}

test "LockedMap: fetchRemove returns the prior entry" {
    var lm = LockedMap(u32, u32).init(testing.allocator);
    defer lm.deinit();

    try lm.put(1, 11);
    try lm.put(2, 22);
    const got = lm.fetchRemove(1);
    try testing.expect(got != null);
    try testing.expectEqual(@as(u32, 1), got.?.key);
    try testing.expectEqual(@as(u32, 11), got.?.value);
    try testing.expectEqual(@as(usize, 1), lm.count());
    try testing.expect(lm.fetchRemove(99) == null);
}

test "LockedMap: iterator-while-locked sees every inserted entry" {
    var lm = LockedMap(u32, u32).init(testing.allocator);
    defer lm.deinit();
    try lm.put(1, 11);
    try lm.put(2, 22);
    try lm.put(3, 33);

    var seen_keys: [3]bool = .{ false, false, false };

    var guard = lm.iterateLocked();
    defer guard.deinit();
    while (guard.iter.next()) |entry| {
        const k = entry.key_ptr.*;
        try testing.expect(k >= 1 and k <= 3);
        seen_keys[k - 1] = true;
    }

    try testing.expect(seen_keys[0] and seen_keys[1] and seen_keys[2]);
}

test "LockedMap: deinit on empty map is a no-op" {
    var lm = LockedMap(u32, u32).init(testing.allocator);
    lm.deinit(); // no panic, no leak
}

test "LockedMap: deinit on non-empty map frees internal storage" {
    var lm = LockedMap(u32, u32).init(testing.allocator);
    try lm.put(1, 1);
    try lm.put(2, 2);
    try lm.put(3, 3);
    // testing.allocator will detect any leak on test exit.
    lm.deinit();
}

test "BorrowedState: deinit is idempotent and releases the lock" {
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lockShared();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_shared_rwlock = &rwl },
    };
    borrow.deinit();
    try testing.expect(borrow.released);
    // Second deinit must be a no-op (would otherwise unlock an unlocked
    // RwLock and trigger UB).
    borrow.deinit();
    try testing.expect(borrow.released);

    // Lock is now released — exclusive lock should succeed.
    rwl.lock();
    rwl.unlock();
}

test "BorrowedState: events_mutex backing also releases" {
    var m: zeam_utils.SyncMutex = .{};
    m.lock();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .events_mutex = &m },
    };
    borrow.deinit();
    try testing.expect(borrow.released);
    // Lock is released — should be reacquirable.
    m.lock();
    m.unlock();
}

test "BorrowedState: assertReleased fires only when not released" {
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lockShared();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_shared_rwlock = &rwl },
    };
    borrow.deinit();
    // Should not panic — borrow is released.
    borrow.assertReleased();
}

test "BorrowedState: cloneAndRelease releases lock on OOM-mid-clone" {
    // FailingAllocator with budget=0 causes the very first allocator.create
    // inside cloneAndRelease to fail. The errdefer must still release the
    // states_lock — the whole point of the wrapper.
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lockShared();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_shared_rwlock = &rwl },
    };

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const failing_allocator = failing.allocator();

    try testing.expectError(error.OutOfMemory, borrow.cloneAndRelease(failing_allocator));
    try testing.expect(borrow.released);

    // Lock is released — taking the exclusive side should not block.
    rwl.lock();
    rwl.unlock();
}

test "BlockCache: helper init/deinit when empty" {
    var bc = BlockCache.init(testing.allocator);
    bc.deinit(); // testing.allocator detects any leak.
}

// Note: BlockCache atomic-insert / partial-state invariant tests would need
// a real SignedBlock/BeamBlock builder; the contract is unit-tested via the
// `removeChildrenOf bounded` test below which exercises the BFS. Full
// triple-insert tests will land alongside the (a-3) network wiring once we
// have a SignedBlock test factory in pkgs/node, since the existing factories
// live in pkgs/state-transition under genMockChain and pulling that in here
// creates a test cycle.
//
// What we DO test in (a-2):
//   * removeChildrenOf bounded by MAX_CACHED_BLOCKS (the worst-case
//     critical-section claim from the design doc).

test "BlockCache: removeChildrenOf is bounded by MAX_CACHED_BLOCKS" {
    // We don't have a SignedBlock factory inline here, so this test only
    // verifies the bound on the children-only path: a children list with
    // 2*MAX_CACHED_BLOCKS entries should cause removeChildrenOf to iterate
    // exactly MAX_CACHED_BLOCKS times before bailing.
    var bc = BlockCache.init(testing.allocator);
    defer bc.deinit();

    const parent = std.mem.zeroes(types.Root);

    var children: std.ArrayListUnmanaged(types.Root) = .empty;
    defer children.deinit(testing.allocator);
    var i: u16 = 0;
    while (i < @as(u16, MAX_CACHED_BLOCKS) + 100) : (i += 1) {
        var r = std.mem.zeroes(types.Root);
        std.mem.writeInt(u16, r[0..2], i + 1, .little);
        try children.append(testing.allocator, r);
    }

    // Stash directly under the lock — using insert() would also need
    // SignedBlocks. We're only testing the BFS bound here.
    bc.mutex.lock();
    {
        const gop = try bc.children.getOrPut(parent);
        gop.value_ptr.* = .empty;
        try gop.value_ptr.appendSlice(testing.allocator, children.items);
    }
    bc.mutex.unlock();

    const removed = bc.removeChildrenOf(parent);
    try testing.expect(removed <= MAX_CACHED_BLOCKS);
    try testing.expect(removed > 0);
}

test "tier5 depth counter increments and decrements" {
    if (builtin.mode != .Debug) return error.SkipZigTest;
    try testing.expectEqual(@as(u32, 0), tier5_depth);
    enterTier5();
    try testing.expectEqual(@as(u32, 1), tier5_depth);
    leaveTier5();
    try testing.expectEqual(@as(u32, 0), tier5_depth);
}
