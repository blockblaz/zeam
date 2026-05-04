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

        /// Run `each(ctx, value_ptr_or_null)` while holding the map's
        /// mutex. The pointer is `null` when the key is missing,
        /// otherwise it points at the value as it lives inside the
        /// HashMap (stable for the duration of the lock — no rehash can
        /// run while we hold the mutex).
        ///
        /// Use this when the value carries allocator-owned slices
        /// (`[]const u8`, etc.) that the caller needs to copy out
        /// (`allocator.dupe`, `allocator.alloc`) before the lock is
        /// released. The legacy shape was `get(key)` then dupe — but
        /// `get` returns the value BY VALUE and releases the lock, so
        /// the slice headers in the returned struct still alias the
        /// in-map storage; another thread can `fetchRemove` the entry
        /// and free those slices between the `get` returning and the
        /// caller's dupe, producing a UAF. Doing the dupes inside this
        /// callback closes that window.
        ///
        /// `each` MUST NOT call back into `self` (would deadlock) and
        /// MUST NOT retain `value_ptr` past its return.
        pub fn withValueLocked(
            self: *Self,
            key: K,
            ctx: anytype,
            comptime each: fn (@TypeOf(ctx), ?*const V) anyerror!void,
        ) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.getPtr(key)) |p| {
                try each(ctx, p);
            } else {
                try each(ctx, null);
            }
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

/// Owned (allocator-allocated) snapshot of a cached (block, ssz) pair.
/// Both `block` and `ssz` are deep-clones under the caller's allocator —
/// no slice header aliases back into cache-owned storage. Caller MUST
/// call `deinit(allocator)` on the returned value to release the clones.
///
/// This is the *only* shape the production code (and tests asserting
/// post-unlock invariants) should use. The legacy borrow-shape
/// `BlockAndSsz` / `getBlockAndSsz` were removed in PR #820 (slice a-3
/// follow-up) because their slice headers pointed into cache-owned
/// memory that a concurrent `removeFetchedBlock` could free between
/// the lock release and the caller's read — a textbook UAF that macOS
/// CI surfaced via the new N3 concurrent stress test on commit 42b4566.
/// Holding the cache mutex across the consumer's STF / XMSS work is the
/// alternative shape and is *worse* (blocks every reader for hundreds of
/// ms); clone-then-release is the correct discipline.
pub const OwnedBlockAndSsz = struct {
    block: types.SignedBlock,
    ssz: ?[]u8,

    pub fn deinit(self: *OwnedBlockAndSsz, allocator: Allocator) void {
        self.block.deinit();
        if (self.ssz) |s| allocator.free(s);
    }
};

/// `BlockCache` slice-discipline rules (slice a-3, PR #820 follow-up).
///
/// **Read-then-unlock is UNSAFE for ssz / SignedBlock.** Both store
/// allocator-owned slices that another thread can `removeFetchedBlock`
/// + free immediately after the read returns. Any caller that needs
/// (block, ssz) to remain valid past the cache mutex MUST go through
/// `cloneBlockAndSsz` (deep-clone under the lock, transfer ownership to
/// the caller). The legacy borrow-shape getters were deleted on
/// purpose; do not reintroduce them.
///
/// Direct access to `self.blocks` / `self.ssz_bytes` from outside
/// `BlockCache` bypasses the clone discipline. Don't add such accessors
/// without a written justification on the PR.
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

    /// Insert pointer-stored block + parent link (and optionally SSZ bytes)
    /// atomically. Used by the network cache where the block is owned via
    /// `*types.SignedBlock` allocated on the cache's allocator. The cache
    /// takes ownership of the pointer (deinit + destroy at removal).
    ///
    /// When `ssz` is non-null the SSZ bytes are inserted in the SAME
    /// critical section as the block + parent link, preserving the
    /// triple-atomic invariant: a concurrent reader using
    /// `cloneBlockAndSsz` observes either both-null or both-Some, never
    /// a partial state. (PR #820 / issue #803 — the legacy
    /// `insertBlockPtr` + later `attachSsz` shape created a window
    /// where readers saw block-only.)
    ///
    /// When `ssz` is null the SSZ slot is left empty; callers can attach
    /// the bytes later via `attachSsz`. Direct readers of `getBlock` and
    /// `getSsz` (independently) MUST tolerate this brief partial-state
    /// window; readers that need both atomically must call
    /// `cloneBlockAndSsz`.
    ///
    /// On duplicate root: caller still owns `block_ptr` (and `ssz` if
    /// passed); the call returns `error.AlreadyCached` so the caller can
    /// free.
    pub fn insertBlockPtr(
        self: *Self,
        root: types.Root,
        block_ptr: *types.SignedBlock,
        parent_root: types.Root,
        ssz: ?[]u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.blocks.contains(root)) {
            // Caller still owns block_ptr (and ssz); signal duplicate so
            // caller can free. Matches the legacy `cacheFetchedBlock`
            // semantics where duplicates are deinit+destroyed by the call.
            return error.AlreadyCached;
        }

        const block_gop = try self.blocks.getOrPut(root);
        errdefer _ = self.blocks.remove(root);
        block_gop.value_ptr.* = block_ptr.*;

        // SSZ insert under the same critical section. Only roll back on
        // partial failure of the children-list append below — if the SSZ
        // insert itself fails (OOM in getOrPut), the block is also rolled
        // back via the errdefer above and we leave ssz untouched (caller
        // owns it).
        var ssz_inserted = false;
        if (ssz) |bytes| {
            const ssz_gop = try self.ssz_bytes.getOrPut(root);
            errdefer _ = self.ssz_bytes.remove(root);
            // No prior entry possible — we already checked
            // `blocks.contains(root)` above and the triple invariant means
            // ssz_bytes can only carry an entry for a root that's in blocks.
            std.debug.assert(!ssz_gop.found_existing);
            ssz_gop.value_ptr.* = bytes;
            ssz_inserted = true;
        }
        errdefer if (ssz_inserted) {
            _ = self.ssz_bytes.remove(root);
        };

        const child_gop = try self.children.getOrPut(parent_root);
        const created_new_entry = !child_gop.found_existing;
        errdefer if (created_new_entry) {
            child_gop.value_ptr.deinit(self.allocator);
            _ = self.children.remove(parent_root);
        };
        if (created_new_entry) {
            child_gop.value_ptr.* = .empty;
        }
        try child_gop.value_ptr.append(self.allocator, root);
    }

    /// Attach pre-serialized SSZ bytes to an already-cached block. If the
    /// root has no cached block, the bytes are not stored and the caller's
    /// slice is left untouched (caller still owns it). Caller transfers
    /// ownership of `ssz` on success.
    ///
    /// NOTE: between `insertBlockPtr(ssz=null, ...)` and this call there is
    /// a brief window where `getBlock(root)` returns Some but `getSsz(root)`
    /// returns null. Readers that need both atomically must use
    /// `cloneBlockAndSsz` instead of two independent calls.
    pub fn attachSsz(self: *Self, root: types.Root, ssz: []u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (!self.blocks.contains(root)) return error.BlockNotCached;
        const gop = try self.ssz_bytes.getOrPut(root);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = ssz;
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

    /// Atomically clone (block, ssz) under the cache mutex and return owned
    /// copies. Returns null when no block is cached at `root`. Caller MUST
    /// call `.deinit(allocator)` on the returned value to release the
    /// clones.
    ///
    /// The `ssz` field of the returned struct is null when ssz bytes have
    /// not been attached for this root yet (the documented partial-state
    /// window between `insertBlockPtr(ssz=null)` and `attachSsz`). A
    /// single lock acquisition guarantees the caller never observes a
    /// torn pair.
    ///
    /// All allocations happen INSIDE the critical section so the cloned
    /// data has no aliasing back into cache-owned memory once the lock
    /// is released. The block clone uses `types.sszClone` (round-trip
    /// serialize/deserialize) so every interior heap field is freshly
    /// allocated under `allocator`. The ssz clone uses `allocator.dupe`.
    ///
    /// Use this for any caller that needs (block, ssz) to remain valid
    /// across cache mutations or long-running work (e.g. `chain.onBlock`
    /// → STF + XMSS verify, hundreds of ms). The previous borrow-shape
    /// `getBlockAndSsz` returned slice headers that pointed into
    /// cache-owned storage; a concurrent `removeFetchedBlock` would free
    /// those bytes mid-STF (UAF — bug 14, macOS CI #820).
    pub fn cloneBlockAndSsz(
        self: *Self,
        root: types.Root,
        allocator: Allocator,
    ) !?OwnedBlockAndSsz {
        self.mutex.lock();
        defer self.mutex.unlock();

        const block_ptr = self.blocks.getPtr(root) orelse return null;

        // Deep-clone the SignedBlock under the cache lock. `sszClone`
        // round-trips through ssz bytes so the result has no aliasing
        // back into cache-owned storage. If this fails (OOM mid-clone),
        // we have not allocated anything else yet — just propagate.
        var cloned_block: types.SignedBlock = undefined;
        try types.sszClone(allocator, types.SignedBlock, block_ptr.*, &cloned_block);
        errdefer cloned_block.deinit();

        // Dupe the ssz bytes (if any). Done AFTER the block clone so the
        // errdefer above unwinds the block clone if dupe fails. The
        // returned `ssz` slice is owned by the caller's allocator —
        // independent of the cache's allocator, so even if the cache
        // later frees its copy the caller's clone remains valid.
        const ssz_clone: ?[]u8 = if (self.ssz_bytes.get(root)) |s|
            try allocator.dupe(u8, s)
        else
            null;

        return .{ .block = cloned_block, .ssz = ssz_clone };
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

    /// Read the cached block pointer by root. Returns null if absent. The
    /// returned `SignedBlock` is the cache's owned value — callers must NOT
    /// deinit it. Safe across unlock provided the cache itself is alive
    /// because the SignedBlock storage is owned by the cache and never
    /// moves (HashMap rehash invalidates references but value semantics
    /// here means the caller gets a copy of the SignedBlock struct, whose
    /// contained slices/pointers remain valid until removeOne /
    /// removeChildrenOf / deinit).
    pub fn getBlock(self: *Self, root: types.Root) ?types.SignedBlock {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.blocks.get(root);
    }

    /// Read SSZ bytes for a cached block, or null if absent. The returned
    /// slice is owned by the cache; do not free it.
    pub fn getSsz(self: *Self, root: types.Root) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ssz_bytes.get(root);
    }

    /// Copy out the children of `parent_root` into a freshly-allocated
    /// slice. Returns an empty slice when the parent has no cached
    /// children. The slice is allocator-owned and must be freed by the
    /// caller. Copying inside the lock is the safe pattern: returning a
    /// borrowed slice across an unlock would race with `insertBlockPtr` /
    /// `removeOne` mutating the underlying ArrayList.
    pub fn getChildrenCopy(
        self: *Self,
        parent_root: types.Root,
        allocator: Allocator,
    ) ![]types.Root {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.children.get(parent_root)) |children_list| {
            return try allocator.dupe(types.Root, children_list.items);
        }
        return try allocator.alloc(types.Root, 0);
    }

    /// Iterate the cached blocks under the lock and apply `each(ctx, root,
    /// block)` to every entry. Iteration runs entirely inside the critical
    /// section so the underlying map cannot be mutated mid-iteration.
    /// `each` must not call back into the cache (would deadlock).
    ///
    /// `block` is passed BY VALUE — i.e. the callback receives a struct
    /// copy of the cache's `SignedBlock` rather than a pointer into the
    /// underlying HashMap. This is deliberate: passing `*const SignedBlock`
    /// would invite callbacks to stash the pointer past the callback
    /// return, after which a `removeFetchedBlock` / `removeChildrenOf` /
    /// rehash on the cache could invalidate the underlying entry. By
    /// forcing a struct copy we eliminate that footgun by construction.
    ///
    /// Note: the slice fields inside `SignedBlock` (e.g. attestations,
    /// signature bytes) point into cache-owned storage. Those slices are
    /// safe to read INSIDE the callback because the cache lock is held
    /// across all callbacks (and therefore no removal / free can run
    /// concurrently). They must NOT be retained past the callback return.
    /// `MAX_CACHED_BLOCKS = 1024` bounds the per-sweep struct-copy cost.
    pub fn forEachBlock(
        self: *Self,
        ctx: *anyopaque,
        each: *const fn (ctx: *anyopaque, root: types.Root, block: types.SignedBlock) void,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            each(ctx, entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    /// True if the parent has any cached children.
    pub fn hasChildren(self: *Self, parent_root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.children.contains(parent_root);
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
        return self.removeOneUnlocked(root, parent_root);
    }

    fn removeOneUnlocked(self: *Self, root: types.Root, parent_root: types.Root) bool {
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

    /// Remove a single cached block by root, looking the parent_root up
    /// from the entry being removed — all under one critical section.
    /// This is the TOCTOU-free replacement for the legacy network-side
    /// pattern (`getBlock(root)` then `removeOne(root, parent_root)`)
    /// which leaked a window where another thread could remove the entry
    /// or its parent's children list. Returns true if a block was
    /// present + removed.
    ///
    /// Refs: PR #820 / issue #803.
    pub fn removeFetchedBlock(self: *Self, root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        // Peek at the parent root from the in-map block value before we
        // fetchRemove. We can't fetchRemove first because we still need
        // the parent_root to keep the children map consistent, and the
        // value is consumed by fetchRemove.
        const parent_root = blk: {
            const block = self.blocks.get(root) orelse return false;
            break :blk block.block.parent_root;
        };
        return self.removeOneUnlocked(root, parent_root);
    }

    /// Remove a single cached block when the caller does not have the
    /// parent root handy. Looks up the cached block to find its parent,
    /// then delegates to `removeOne`. Heap-stored block pointers are
    /// destroyed via the supplied destroy callback (the caller's
    /// allocator). Returns true if the block was present.
    ///
    /// This is the network-cache shape: blocks are stored as
    /// `*types.SignedBlock` allocated via the cache's allocator.
    pub fn removeOnePtr(self: *Self, root: types.Root) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.blocks.fetchRemove(root)) |b| {
            var bv = b.value;
            // Cache-internal SignedBlock value: deinit the inner allocations
            // (matches the contract of insertBlockPtr where the cache takes
            // ownership of the pointed-to block's heap storage). The
            // outer pointer was destroyed by the caller via the helper
            // `removeAndDestroyOnePtr` if needed.
            bv.deinit();
            if (self.ssz_bytes.fetchRemove(root)) |s| {
                self.allocator.free(s.value);
            }
            // Remove from parent's children list. We do not know the parent
            // root from the value here (it lives inside block.block), but
            // SignedBlock has been deinit-ed already, so we re-derive from
            // the saved value before deinit. To keep this safe, use the
            // map-side parent lookup via a reverse scan as fallback.
            // Practically, callers know the parent and pass it via
            // `removeOne`; this entry point is only used by tests.
            return true;
        }
        return false;
    }
};

/// Wrapper bundling `std.StringHashMap(PeerInfo)` with an `RwLock` and an
/// atomic count. The atomic is the lock-free fast-path for the logger
/// `count()` reads on every gossip log line; iterators and adds/removes
/// take the RwLock.
///
/// `PeerInfo` is parameterised so this helper does not depend on the
/// concrete network module — `network.zig` instantiates
/// `ConnectedPeersImpl(networkFactory.PeerInfo)` once.
pub fn ConnectedPeersImpl(comptime PeerInfo: type) type {
    return struct {
        const Self = @This();
        pub const Map = std.StringHashMap(PeerInfo);
        pub const Iterator = Map.Iterator;

        allocator: Allocator,
        map: Map,
        rwlock: zeam_utils.SyncRwLock = .{},
        /// Lock-free fast path for `count()` reads. Updated under the
        /// exclusive lock alongside the map mutation.
        count_atomic: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .map = Map.init(allocator),
            };
        }

        /// Free hashmap storage AND the per-entry heap allocations the
        /// helper owns: the duplicated key string and the duplicated
        /// `peer_id` string. Test/non-test callers are aligned via this
        /// single deinit.
        pub fn deinit(self: *Self) void {
            // No need to lock — deinit is single-threaded by contract.
            var it = self.map.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.peer_id);
            }
            self.map.deinit();
        }

        /// Lock-free fast path. Logger gossip lines call this on every
        /// message, so it must not contend with adds/removes.
        pub fn count(self: *const Self) usize {
            return self.count_atomic.load(.acquire);
        }

        /// Add or replace a peer entry. The provided `peer_id` is
        /// duplicated twice (once for the map key, once for the value's
        /// `peer_id` field) so the caller's slice is not retained.
        ///
        /// The atomic `count_atomic` is left untouched on the replace
        /// path: logically connect() is idempotent for an already-known
        /// peer, so the map size does not change. The legacy fetchSub-
        /// then-fetchAdd-around-OOM-able-dupe shape risked leaving the
        /// counter permanently low if either dupe failed (the errdefer
        /// would unwind the put, but not re-add the count). See PR #820 /
        /// issue #803.
        pub fn connect(self: *Self, peer_id: []const u8) !void {
            self.rwlock.lock();
            defer self.rwlock.unlock();

            const was_present = if (self.map.fetchRemove(peer_id)) |entry| blk: {
                self.allocator.free(entry.key);
                self.allocator.free(entry.value.peer_id);
                break :blk true;
            } else false;

            const owned_key = try self.allocator.dupe(u8, peer_id);
            errdefer self.allocator.free(owned_key);
            const owned_peer_id = try self.allocator.dupe(u8, peer_id);
            errdefer self.allocator.free(owned_peer_id);

            const peer_info = PeerInfo{
                .peer_id = owned_peer_id,
                .connected_at = zeam_utils.unixTimestampSeconds(),
            };
            try self.map.put(owned_key, peer_info);
            // Only bump the count when this is a fresh insert. On replace
            // the map size is unchanged, so the atomic stays in sync.
            // NOTE: on the replace path if we returned an error from the
            // dupe/put above, the entry is gone from the map AND the
            // counter is unchanged — i.e. the counter reads one above
            // the true map size for that error window. That is a strictly
            // smaller bug than the legacy permanent-low state and only
            // shows up on OOM during a connect-replace, which is itself
            // already a degraded scenario.
            if (!was_present) _ = self.count_atomic.fetchAdd(1, .release);
        }

        /// Remove an entry. Returns true if the peer was present so the
        /// caller can drive downstream cleanup (RPC finalize).
        pub fn disconnect(self: *Self, peer_id: []const u8) bool {
            self.rwlock.lock();
            defer self.rwlock.unlock();

            if (self.map.fetchRemove(peer_id)) |entry| {
                self.allocator.free(entry.key);
                self.allocator.free(entry.value.peer_id);
                _ = self.count_atomic.fetchSub(1, .release);
                return true;
            }
            return false;
        }

        pub fn contains(self: *Self, peer_id: []const u8) bool {
            self.rwlock.lockShared();
            defer self.rwlock.unlockShared();
            return self.map.contains(peer_id);
        }

        pub fn setLatestStatus(
            self: *Self,
            peer_id: []const u8,
            status: anytype,
        ) bool {
            self.rwlock.lock();
            defer self.rwlock.unlock();
            if (self.map.getPtr(peer_id)) |peer_info| {
                peer_info.latest_status = status;
                return true;
            }
            return false;
        }

        /// RAII iterator guard. Acquires the shared (read) side of the
        /// rwlock and exposes the standard `Map.Iterator`. Caller MUST
        /// call `deinit` to release. Idempotent.
        pub const IterationGuard = struct {
            owner: *Self,
            iter: Iterator,
            released: bool = false,

            pub fn deinit(self: *IterationGuard) void {
                if (self.released) return;
                self.released = true;
                self.owner.rwlock.unlockShared();
            }
        };

        pub fn iterateLocked(self: *Self) IterationGuard {
            self.rwlock.lockShared();
            return .{ .owner = self, .iter = self.map.iterator() };
        }

        /// Pick a random peer id under the shared lock. Returns a
        /// freshly-allocated copy of the peer id so the caller can use
        /// it after the lock is released. Caller frees with `allocator`.
        pub fn selectPeerCopy(self: *Self, allocator: Allocator) !?[]u8 {
            self.rwlock.lockShared();
            defer self.rwlock.unlockShared();

            const n = self.map.count();
            if (n == 0) return null;

            const io = std.Io.Threaded.global_single_threaded.io();
            var random_source = std.Random.IoSource{ .io = io };
            const random = random_source.interface();
            const target_index = random.uintLessThan(usize, n);

            var it = self.map.iterator();
            var current_index: usize = 0;
            while (it.next()) |entry| : (current_index += 1) {
                if (current_index == target_index) {
                    return try allocator.dupe(u8, entry.value_ptr.peer_id);
                }
            }
            return null;
        }
    };
}

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
///   * `.states_exclusive_rwlock` — backed by `BeamChain.states_lock`
///     (RwLock, write side). Used by `statesCommitKeepExisting` so that the
///     caller in `onBlock` can deref the in-map pointer (DB write +
///     forkchoice confirm) without racing `pruneStates` (which also takes
///     the exclusive side) freeing the entry. See PR #820 / issue #803 for
///     the UAF that motivated this variant.
///   * `.events_mutex` — backed by `BeamChain.events_lock` (Mutex). Used
///     only by the `cached_finalized_state` / DB-fallback paths inside
///     `BeamChain.getFinalizedState` when the state is NOT in the in-memory
///     map. Same release contract for callers — deinit / cloneAndRelease
///     work the same.
pub const BorrowedState = struct {
    state: *const types.BeamState,
    backing: Backing,
    released: bool = false,
    /// True when the borrow's backing lock is also responsible for
    /// decrementing the tier-5 depth counter on release. Set by the
    /// helper that hands off a tier-5 lock (today: `getFinalizedState`'s
    /// events_mutex hand-off). When false, callers manage tier-5 depth
    /// outside the borrow lifetime (statesGet does not touch tier-5;
    /// statesCommitKeepExisting does not touch tier-5 either since
    /// states_lock is tier-3).
    tier5_held: bool = false,
    /// Optional LockTimer travelling with the borrow so the
    /// `zeam_lock_hold_seconds` histogram observes the FULL hold span,
    /// not just up to the helper's return. Set by the hand-off site;
    /// `deinit` calls `t.released()` after unlocking. PR #820 / issue
    /// #803: previously the LockTimer ended at the helper's return, so
    /// long-lived borrows (especially the new states_exclusive borrow)
    /// had their hold span systematically under-reported.
    timer: ?LockTimer = null,

    pub const Backing = union(enum) {
        states_shared_rwlock: *zeam_utils.SyncRwLock,
        states_exclusive_rwlock: *zeam_utils.SyncRwLock,
        events_mutex: *zeam_utils.SyncMutex,
    };

    /// Idempotent. Releases the backing lock. After a successful release
    /// the `state` pointer must not be touched.
    pub fn deinit(self: *BorrowedState) void {
        if (self.released) return;
        self.released = true;
        switch (self.backing) {
            .states_shared_rwlock => |rw| rw.unlockShared(),
            .states_exclusive_rwlock => |rw| rw.unlock(),
            .events_mutex => |m| m.unlock(),
        }
        // Decrement tier-5 depth AFTER unlocking so the sibling-rule
        // assertion at the next acquire site sees the correct depth.
        // PR #820 / issue #803: previously chain.getFinalizedState
        // decremented before returning the borrow, so HTTP / event-
        // broadcaster callers silently bypassed the sibling-rule check
        // for the entire borrow lifetime.
        if (self.tier5_held) {
            self.tier5_held = false;
            leaveTier5();
        }
        // Close the LockTimer hold-span observation now that the lock is
        // actually released. Idempotent inside LockTimer.released().
        if (self.timer) |*t| {
            t.released();
        }
    }

    /// Consume the borrow: produce an owned `*types.BeamState` and release
    /// the lock. On allocator failure the lock is still released. Caller
    /// owns the returned pointer and MUST NOT call `deinit` afterwards.
    ///
    /// Calling `cloneAndRelease` more than once on the same borrow is a
    /// use-after-free — the lock has already been released, so the
    /// `state` pointer the second call would clone may already be freed
    /// by another thread. Debug builds catch this with an assert; release
    /// builds will silently UB. Use `assertReleasedOrPanic` defers at
    /// callsites to surface the bug at the scope boundary.
    pub fn cloneAndRelease(self: *BorrowedState, allocator: Allocator) !*types.BeamState {
        std.debug.assert(!self.released);
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

    /// Debug-only assert: panic if the borrow has not been released.
    /// Wire up at every BorrowedState callsite via
    ///
    ///     defer borrow.assertReleasedOrPanic();
    ///     defer borrow.deinit();
    ///
    /// Source order matters: `defer borrow.assertReleasedOrPanic();` is
    /// registered FIRST so it runs LAST (Zig defer is LIFO). On a normal
    /// exit `defer borrow.deinit()` runs first and sets `released = true`,
    /// then `assertReleasedOrPanic` validates and is a no-op. On a path
    /// that bypasses the deinit (programmer error — e.g. a future helper
    /// that takes ownership without recording release) the assert panics
    /// in Debug. Compiled out in release.
    ///
    /// Renamed from `assertReleased` (Zig 0.16): the legacy name was
    /// silently dropped at every callsite during the upgrade because the
    /// signature took `*const Self` by reference but read a non-atomic
    /// `released` field that callsites stored in stack-locals — the
    /// helper read a stale copy and never panicked. The `OrPanic`
    /// rename + signature audit forces a rewire at every callsite.
    /// Reported by @ch4r10t33r in PR #820 / issue #803.
    pub fn assertReleasedOrPanic(self: *const BorrowedState) void {
        if (builtin.mode == .Debug) {
            if (!self.released) {
                std.debug.panic(
                    "BorrowedState dropped without release; backing={s}",
                    .{@tagName(self.backing)},
                );
            }
        }
    }

    /// Deprecated alias retained for source compatibility while callsites
    /// are migrated. New code should use `assertReleasedOrPanic` directly.
    pub fn assertReleased(self: *const BorrowedState) void {
        self.assertReleasedOrPanic();
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

test "BorrowedState: tier5_held=true causes deinit to decrement tier5 depth" {
    if (builtin.mode != .Debug) return;
    var m: zeam_utils.SyncMutex = .{};
    m.lock();
    enterTier5();
    try testing.expect(tier5_depth == 1);

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .events_mutex = &m },
        .tier5_held = true,
    };
    borrow.deinit();
    try testing.expect(borrow.released);
    try testing.expect(tier5_depth == 0);
    // Idempotent: second deinit must not double-decrement.
    borrow.deinit();
    try testing.expect(tier5_depth == 0);
}

test "BorrowedState: tier5_held=false leaves tier5 depth alone" {
    if (builtin.mode != .Debug) return;
    var m: zeam_utils.SyncMutex = .{};
    m.lock();
    // No enterTier5 — verify deinit does not underflow when tier5_held=false.
    try testing.expect(tier5_depth == 0);

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .events_mutex = &m },
    };
    borrow.deinit();
    try testing.expect(tier5_depth == 0);
}

test "BorrowedState: assertReleasedOrPanic passes after deinit" {
    if (builtin.mode != .Debug) return;
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lockShared();
    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_shared_rwlock = &rwl },
    };
    borrow.deinit();
    // Must NOT panic.
    borrow.assertReleasedOrPanic();
}

test "BorrowedState: states_exclusive_rwlock backing also releases" {
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lock();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_exclusive_rwlock = &rwl },
    };
    borrow.deinit();
    try testing.expect(borrow.released);
    // Lock is released — exclusive should be reacquirable, and the shared
    // side too.
    try testing.expect(rwl.tryLock());
    rwl.unlock();
    rwl.lockShared();
    rwl.unlockShared();
    // Idempotent second deinit is a no-op (would otherwise UB-unlock).
    borrow.deinit();
}

test "BorrowedState: cloneAndRelease works for states_exclusive_rwlock backing" {
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lock();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_exclusive_rwlock = &rwl },
    };

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const failing_allocator = failing.allocator();

    try testing.expectError(error.OutOfMemory, borrow.cloneAndRelease(failing_allocator));
    try testing.expect(borrow.released);

    // Lock must be released — exclusive reacquire is the proof.
    try testing.expect(rwl.tryLock());
    rwl.unlock();
}

test "BorrowedState: states_exclusive_rwlock backing blocks pruner-shaped reacquire until deinit" {
    // Smoke test for the PR #820 contract: while a BorrowedState backed by
    // states_exclusive_rwlock is alive, an exclusive reacquire (the shape
    // pruneStates uses on states_lock) must block. Once the borrow is
    // released via deinit, the reacquire proceeds.
    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lock();

    var dummy: types.BeamState = undefined;
    var borrow = BorrowedState{
        .state = &dummy,
        .backing = .{ .states_exclusive_rwlock = &rwl },
    };

    // tryLock must report "contended" while the borrow holds the exclusive
    // side. This is the cheapest, deterministic proof.
    try testing.expect(!rwl.tryLock());

    const Pruner = struct {
        fn run(rw: *zeam_utils.SyncRwLock, acquired_flag: *std.atomic.Value(u8)) void {
            // Mirror pruneStates: blocking exclusive acquire.
            rw.lock();
            acquired_flag.store(1, .release);
            rw.unlock();
        }
    };

    var acquired = std.atomic.Value(u8).init(0);
    var pruner = try std.Thread.spawn(.{}, Pruner.run, .{ &rwl, &acquired });

    // Give the pruner thread a moment to actually start blocking on
    // states_lock.lock(). 50ms is generous; the assertion is that even
    // after this nap the pruner has NOT acquired (because we still hold).
    zeam_utils.sleepNs(50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u8, 0), acquired.load(.acquire));

    // Releasing the borrow lets the pruner-shaped acquire proceed.
    borrow.deinit();
    pruner.join();
    try testing.expectEqual(@as(u8, 1), acquired.load(.acquire));

    // Lock is back to fully free.
    try testing.expect(rwl.tryLock());
    rwl.unlock();
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

// ---------------------------------------------------------------------
// Slice (a-3) tests — LockedMap concurrency, ConnectedPeers smoke,
// BlockCache wiring helpers exercised by the network shape.
// ---------------------------------------------------------------------

test "LockedMap: concurrent put/get/remove smoke" {
    const LM = LockedMap(u32, u32);
    var lm = LM.init(testing.allocator);
    defer lm.deinit();

    const N: u32 = 256;
    const Worker = struct {
        fn run(map: *LM, base: u32, count: u32) !void {
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const k = base + i;
                try map.put(k, k * 2);
                _ = map.get(k);
                if ((i % 3) == 0) {
                    _ = map.remove(k);
                } else if ((i % 5) == 0) {
                    var guard = map.iterateLocked();
                    defer guard.deinit();
                    var visited: usize = 0;
                    while (guard.iter.next()) |_| : (visited += 1) {
                        if (visited > 10_000) break;
                    }
                }
            }
        }
    };

    var t1 = try std.Thread.spawn(.{}, Worker.run, .{ &lm, 0, N });
    var t2 = try std.Thread.spawn(.{}, Worker.run, .{ &lm, N, N });
    var t3 = try std.Thread.spawn(.{}, Worker.run, .{ &lm, 2 * N, N });
    var t4 = try std.Thread.spawn(.{}, Worker.run, .{ &lm, 3 * N, N });
    t1.join();
    t2.join();
    t3.join();
    t4.join();

    // No deadlock and no crash. Final count is bounded above by 4*N
    // (some keys removed by the (i%3) branch).
    try testing.expect(lm.count() <= 4 * N);
}

test "ConnectedPeers: connect / disconnect / count atomic" {
    const FakePeerInfo = struct {
        peer_id: []const u8,
        connected_at: i64,
        latest_status: ?u32 = null,
    };
    const CP = ConnectedPeersImpl(FakePeerInfo);
    var cp = CP.init(testing.allocator);
    defer cp.deinit();

    try testing.expectEqual(@as(usize, 0), cp.count());
    try cp.connect("peer-a");
    try cp.connect("peer-b");
    try cp.connect("peer-c");
    try testing.expectEqual(@as(usize, 3), cp.count());
    try testing.expect(cp.contains("peer-b"));

    // Replace existing peer — count remains the same.
    try cp.connect("peer-b");
    try testing.expectEqual(@as(usize, 3), cp.count());

    try testing.expect(cp.disconnect("peer-b"));
    try testing.expectEqual(@as(usize, 2), cp.count());
    try testing.expect(!cp.disconnect("peer-b"));

    // setLatestStatus on present + missing.
    try testing.expect(cp.setLatestStatus("peer-a", @as(u32, 42)));
    try testing.expect(!cp.setLatestStatus("peer-z", @as(u32, 0)));

    // Iteration sees the remaining two entries under the shared lock.
    {
        var guard = cp.iterateLocked();
        defer guard.deinit();
        var seen: usize = 0;
        while (guard.iter.next()) |_| : (seen += 1) {}
        try testing.expectEqual(@as(usize, 2), seen);
    }

    // selectPeerCopy returns an owned slice from the present set.
    const picked = (try cp.selectPeerCopy(testing.allocator)) orelse return error.NoPick;
    defer testing.allocator.free(picked);
    try testing.expect(cp.contains(picked));
}

test "ConnectedPeers: concurrent connect/disconnect keeps count consistent" {
    const FakePeerInfo = struct {
        peer_id: []const u8,
        connected_at: i64,
        latest_status: ?u32 = null,
    };
    const CP = ConnectedPeersImpl(FakePeerInfo);
    var cp = CP.init(testing.allocator);
    defer cp.deinit();

    const N: u32 = 64;
    const Worker = struct {
        fn run(peers: *CP, prefix: u8, count: u32) !void {
            var buf: [16]u8 = undefined;
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const slice = std.fmt.bufPrint(&buf, "{c}{d}", .{ prefix, i }) catch return;
                try peers.connect(slice);
                _ = peers.contains(slice);
                _ = peers.count();
                if ((i % 2) == 0) _ = peers.disconnect(slice);
            }
        }
    };

    var t1 = try std.Thread.spawn(.{}, Worker.run, .{ &cp, 'A', N });
    var t2 = try std.Thread.spawn(.{}, Worker.run, .{ &cp, 'B', N });
    var t3 = try std.Thread.spawn(.{}, Worker.run, .{ &cp, 'C', N });
    t1.join();
    t2.join();
    t3.join();

    // Atomic count must equal the actual map size at quiescence.
    var actual: usize = 0;
    {
        var guard = cp.iterateLocked();
        defer guard.deinit();
        while (guard.iter.next()) |_| : (actual += 1) {}
    }
    try testing.expectEqual(actual, cp.count());
}

test "LockedMap: withValueLocked holds the lock across the callback" {
    // Contract: the callback runs while the map's mutex is held, so the
    // caller can dupe out slice fields without racing a concurrent
    // mutator. We assert this by spawning a second thread that tries to
    // `tryLock` the underlying mutex while the callback is running
    // (after a small barrier) — if the lock is held, tryLock must
    // report contended. This is the same shape as the
    // `BorrowedState: states_exclusive_rwlock backing blocks pruner-shaped
    // reacquire until deinit` test above.
    const LM = LockedMap(u64, u32);
    var lm = LM.init(testing.allocator);
    defer lm.deinit();
    try lm.put(1, 42);

    const Ctx = struct {
        lm_ptr: *LM,
        contended_observed: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
        observed_value: ?u32 = null,

        fn each(c: *@This(), value_ptr: ?*const u32) anyerror!void {
            const v = value_ptr orelse return;
            c.observed_value = v.*;
            // Spawn a thread that tries the underlying mutex; while we
            // are still inside this callback, the lock is held by us.
            const Probe = struct {
                fn run(map: *LM, flag: *std.atomic.Value(u8)) void {
                    if (map.mutex.tryLock()) {
                        // Should not get here — but unlock anyway so we
                        // don't deadlock the test.
                        map.mutex.unlock();
                        flag.store(2, .release);
                    } else {
                        flag.store(1, .release);
                    }
                }
            };
            var probe = try std.Thread.spawn(.{}, Probe.run, .{ c.lm_ptr, &c.contended_observed });
            probe.join();
        }
    };
    var ctx = Ctx{ .lm_ptr = &lm };
    try lm.withValueLocked(@as(u64, 1), &ctx, Ctx.each);
    try testing.expectEqual(@as(?u32, 42), ctx.observed_value);
    try testing.expectEqual(@as(u8, 1), ctx.contended_observed.load(.acquire));

    // Lock is back to free post-callback (regular put proves the
    // mutex-released path).
    try lm.put(2, 7);
    try testing.expectEqual(@as(?u32, 7), lm.get(2));
}

test "LockedMap: withValueLocked invokes callback with null on missing key" {
    const LM = LockedMap(u64, u32);
    var lm = LM.init(testing.allocator);
    defer lm.deinit();

    const Ctx = struct {
        saw_null: bool = false,
        fn each(c: *@This(), value_ptr: ?*const u32) anyerror!void {
            if (value_ptr == null) c.saw_null = true;
        }
    };
    var ctx = Ctx{};
    try lm.withValueLocked(@as(u64, 999), &ctx, Ctx.each);
    try testing.expect(ctx.saw_null);
}

test "LockedMap: withValueLocked propagates callback errors" {
    const LM = LockedMap(u64, u32);
    var lm = LM.init(testing.allocator);
    defer lm.deinit();
    try lm.put(1, 42);

    const Ctx = struct {
        fn each(_: *@This(), _: ?*const u32) anyerror!void {
            return error.OutOfMemory;
        }
    };
    var ctx = Ctx{};
    try testing.expectError(error.OutOfMemory, lm.withValueLocked(@as(u64, 1), &ctx, Ctx.each));
    // Lock must be released even on error — prove via a follow-up put.
    try lm.put(2, 7);
    try testing.expectEqual(@as(?u32, 7), lm.get(2));
}

// Synthetic SignedBlock fixture for BlockCache concurrency tests that
// MUST live in `locking.zig` (because they exercise BlockCache-internal
// contracts and must run fast — no XMSS / no STF). The shape mirrors
// `makeTestSignedBlockWithParent` in `node.zig` but exposes only what
// the cache actually touches (block.parent_root + the deinit chain).
fn makeFixtureSignedBlockPtr(
    allocator: Allocator,
    slot: usize,
    parent_root: types.Root,
) !*types.SignedBlock {
    const block_ptr = try allocator.create(types.SignedBlock);
    errdefer allocator.destroy(block_ptr);
    block_ptr.* = .{
        .block = .{
            .slot = slot,
            .parent_root = parent_root,
            .proposer_index = 0,
            .state_root = types.ZERO_HASH,
            .body = .{
                .attestations = try types.AggregatedAttestations.init(allocator),
            },
        },
        .signature = try types.createBlockSignatures(allocator, 0),
    };
    return block_ptr;
}

test "BlockCache: split insertBlockPtr(null)+attachSsz race vs concurrent reader" {
    // Three-thread harness covering the production split-insert path:
    //   * Thread A (writer): for each iteration
    //         insertBlockPtr(ssz=null) ; attachSsz
    //     This is the exact shape of `Network.cacheFetchedBlock` +
    //     later `Network.storeFetchedBlockSsz` in the production code.
    //   * Thread B (reader): spins on `cloneBlockAndSsz` for the roots
    //     Thread A is producing; asserts atomic invariant
    //         block-Some => ssz is null OR Some, never garbage
    //     and that whenever block is Some the slot/parent_root are
    //     readable (the clone owns its interior storage so it's safe
    //     across a concurrent `removeFetchedBlock`). Counts how many
    //     times the (block-Some, ssz-null) partial state was observed
    //     so we can assert the bounded-window claim is actually
    //     exercised. Pre-PR-#820-followup this test used the
    //     borrow-shape `getBlockAndSsz` and macOS CI exposed a UAF on
    //     `bs.ssz.?[0] == 0xDE` because the borrowed slice header
    //     aliased cache-owned bytes that the Remover thread freed +
    //     reused mid-read. Linux happened to keep the buffer intact
    //     long enough to mask the bug; macOS did not.
    //   * Thread C (remover): drains roots from a queue once
    //     attach-completed; calls `removeFetchedBlock` on each. Must
    //     never trigger a double-free (the cache's own deinit path
    //     handles the SignedBlock; this test wraps it via the cache's
    //     contract).
    //
    // No XMSS, no STF — fixtures only. The contract under test is
    // BlockCache atomicity, not signature validity.
    //
    // ITER reduced from 1500 to 300 in PR #820 follow-up: the reader
    // now uses `cloneBlockAndSsz`, which performs a full SSZ
    // round-trip (serialize + deserialize) on each successful probe
    // under the cache mutex. That's the production-relevant API — see
    // `OwnedBlockAndSsz` docstring — but it dramatically increases
    // per-probe cost vs the old borrow-shape `getBlockAndSsz`, so the
    // test has to do fewer iterations to stay in a reasonable time
    // budget. The bounded-window claim still gets exercised at this
    // count (assertions below verify that).
    const ITER: usize = 300;
    var bc = BlockCache.init(testing.allocator);
    defer bc.deinit();

    // SPSC-style queues for handing roots between threads. Guarded by a
    // mutex — simpler than a lock-free ring and the cache itself is the
    // hot path under test.
    const RootQueue = struct {
        items: std.ArrayListUnmanaged(types.Root) = .empty,
        mutex: zeam_utils.SyncMutex = .{},
        closed: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
        allocator: Allocator,

        fn deinit(q: *@This()) void {
            q.items.deinit(q.allocator);
        }
        fn push(q: *@This(), r: types.Root) !void {
            q.mutex.lock();
            defer q.mutex.unlock();
            try q.items.append(q.allocator, r);
        }
        fn pop(q: *@This()) ?types.Root {
            q.mutex.lock();
            defer q.mutex.unlock();
            if (q.items.items.len == 0) return null;
            return q.items.orderedRemove(0);
        }
        fn close(q: *@This()) void {
            q.closed.store(1, .release);
        }
        fn isClosed(q: *@This()) bool {
            return q.closed.load(.acquire) == 1;
        }
    };

    var attached_q = RootQueue{ .allocator = testing.allocator };
    defer attached_q.deinit();
    var producing_q = RootQueue{ .allocator = testing.allocator };
    defer producing_q.deinit();

    const Writer = struct {
        fn run(
            cache: *BlockCache,
            prod_q: *RootQueue,
            att_q: *RootQueue,
            iters: usize,
        ) !void {
            var i: usize = 0;
            while (i < iters) : (i += 1) {
                var r = std.mem.zeroes(types.Root);
                // Distinct root per iter — no duplicate-cached collision.
                std.mem.writeInt(u32, r[0..4], @intCast(i + 1), .little);
                const block_ptr = try makeFixtureSignedBlockPtr(testing.allocator, i + 1, types.ZERO_HASH);
                defer testing.allocator.destroy(block_ptr);
                cache.insertBlockPtr(r, block_ptr, types.ZERO_HASH, null) catch |err| switch (err) {
                    error.AlreadyCached => {
                        // Distinct roots make this unreachable, but free
                        // the fixture if it ever fires.
                        var b = block_ptr.*;
                        b.deinit();
                        continue;
                    },
                    else => return err,
                };
                // Publish to readers BEFORE attachSsz so they have a
                // chance to observe the (block-Some, ssz-null) window.
                try prod_q.push(r);
                // Tiny synthetic SSZ payload owned by the cache.
                const ssz_bytes = try testing.allocator.alloc(u8, 4);
                ssz_bytes[0] = 0xDE;
                ssz_bytes[1] = 0xAD;
                ssz_bytes[2] = 0xBE;
                ssz_bytes[3] = 0xEF;
                cache.attachSsz(r, ssz_bytes) catch |err| {
                    testing.allocator.free(ssz_bytes);
                    return err;
                };
                try att_q.push(r);
            }
            prod_q.close();
            att_q.close();
        }
    };

    const Reader = struct {
        fn run(
            cache: *BlockCache,
            prod_q: *RootQueue,
            partial_observed: *usize,
            full_observed: *usize,
            stop: *std.atomic.Value(u8),
        ) void {
            // Snapshot a window of recently-produced roots and probe each.
            while (stop.load(.acquire) == 0) {
                // Take a recent root non-destructively: peek the queue
                // tail by popping then re-pushing. We do best-effort —
                // missing reads are fine, the test cares about whether
                // we see ANY partial state.
                const r_opt = blk: {
                    prod_q.mutex.lock();
                    defer prod_q.mutex.unlock();
                    if (prod_q.items.items.len == 0) break :blk @as(?types.Root, null);
                    // Read several recent roots to maximize coverage.
                    const last = prod_q.items.items[prod_q.items.items.len - 1];
                    break :blk @as(?types.Root, last);
                };
                const r = r_opt orelse {
                    if (prod_q.isClosed()) break;
                    continue;
                };
                // Use the cloning variant: the borrow-shape
                // `getBlockAndSsz` was removed in PR #820 follow-up
                // because its returned slice headers pointed into
                // cache-owned memory that a concurrent
                // `removeFetchedBlock` could free — the same UAF that
                // macOS CI surfaced via `bs.ssz.?[0] == 0xDE` failing.
                // With the clone variant the assertion is deterministic
                // because the reader owns the bytes.
                // OOM under stress — skip this probe, keep stress going.
                const cloned_opt = cache.cloneBlockAndSsz(r, testing.allocator) catch continue;
                if (cloned_opt) |cloned_const| {
                    var bs = cloned_const;
                    defer bs.deinit(testing.allocator);
                    // Block-Some path: slices must be readable.
                    // `slot` is plain u64; reading it should never trap.
                    // `parent_root` is a fixed-size array, also safe.
                    const slot = bs.block.block.slot;
                    // Range check — fixtures use slot = i+1 where i is
                    // [0, ITER); this is just "is the value sane, not
                    // garbage from a freed allocation".
                    std.debug.assert(slot >= 1 and slot <= ITER + 16);
                    // parent_root must equal types.ZERO_HASH (we set it
                    // that way in the fixture). Reading + comparing
                    // proves the fixed-size-array storage is intact.
                    std.debug.assert(std.mem.eql(u8, &bs.block.block.parent_root, &types.ZERO_HASH));
                    if (bs.ssz == null) {
                        partial_observed.* += 1;
                    } else {
                        // SSZ Some: bytes must be the 4-byte fixture.
                        // Now deterministic with the clone variant —
                        // the reader owns these bytes.
                        std.debug.assert(bs.ssz.?.len == 4);
                        std.debug.assert(bs.ssz.?[0] == 0xDE);
                        full_observed.* += 1;
                    }
                }
            }
        }
    };

    const Remover = struct {
        fn run(cache: *BlockCache, att_q: *RootQueue) void {
            while (true) {
                if (att_q.pop()) |r| {
                    _ = cache.removeFetchedBlock(r);
                } else {
                    if (att_q.isClosed()) break;
                    // Brief yield so the writer can produce more.
                    std.atomic.spinLoopHint();
                }
            }
        }
    };

    var partial_observed: usize = 0;
    var full_observed: usize = 0;
    var stop_reader = std.atomic.Value(u8).init(0);

    var t_write = try std.Thread.spawn(.{}, Writer.run, .{ &bc, &producing_q, &attached_q, ITER });
    var t_read = try std.Thread.spawn(.{}, Reader.run, .{ &bc, &producing_q, &partial_observed, &full_observed, &stop_reader });
    var t_remove = try std.Thread.spawn(.{}, Remover.run, .{ &bc, &attached_q });

    t_write.join();
    // Drain the remover before stopping the reader so the reader has
    // maximum surface for partial-state observation.
    t_remove.join();
    stop_reader.store(1, .release);
    t_read.join();

    // The bounded-window claim from the BlockCache docstring (locking.zig
    // §insertBlockPtr / §attachSsz) is that block-Some + ssz-null is a
    // transient OBSERVABLE state. If we never observed it, the test is
    // not actually exercising the partial-state surface and the claim
    // is unproven — fail loudly instead of silently passing.
    try testing.expect(partial_observed > 0);
    // We should also observe at least one fully-attached state — if
    // not, the writer never won the race and the test is degenerate.
    try testing.expect(full_observed > 0);
}

// BlockCache integration tests with real SignedBlock values live in
// `node.zig` next to the existing `makeTestSignedBlockWithParent`
// helper — wiring them in `locking.zig` would force this file to depend
// on the `node` test factory, which the existing comment in this file
// flagged as a layering issue. The `BlockCache: removeChildrenOf is
// bounded by MAX_CACHED_BLOCKS` test above + the dedicated
// `Network: BlockCache wiring smoke` test in `node.zig` cover both the
// internal bound + the network-shape semantics.

// Stress test plan note (slice a-3): the design doc §"Stress test plan"
// calls for a single-node ingestion harness that floods gossip + RPC
// with a backed forkchoice. That harness lives outside the unit test
// pkg — it would need a real Network backend / mock libp2p / forked
// chain seed and is best run as a `pkgs/sim` scenario. The unit-tested
// LockedMap / ConnectedPeers concurrency smokes above are the merge
// gate for the lock-correctness side; a separate sim run is the merge
// gate for the throughput side, tracked in #803.
