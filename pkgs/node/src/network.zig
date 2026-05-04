const std = @import("std");
const networks = @import("@zeam/network");
const types = @import("@zeam/types");
const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");
const locking = @import("./locking.zig");

const Allocator = std.mem.Allocator;

pub const PeerInfo = struct {
    peer_id: []const u8,
    connected_at: i64,
    latest_status: ?types.Status = null,
};

pub const StatusRequestContext = struct {
    peer_id: []const u8,

    pub fn deinit(self: *StatusRequestContext, allocator: Allocator) void {
        allocator.free(self.peer_id);
    }
};

pub const BlockByRootContext = struct {
    peer_id: []const u8,
    requested_roots: []types.Root,

    pub fn deinit(self: *BlockByRootContext, allocator: Allocator) void {
        allocator.free(self.peer_id);
        allocator.free(self.requested_roots);
    }
};

pub const PendingRPC = union(enum) {
    status: StatusRequestContext,
    blocks_by_root: BlockByRootContext,

    pub fn deinit(self: *PendingRPC, allocator: Allocator) void {
        switch (self.*) {
            .status => |*ctx| ctx.deinit(allocator),
            .blocks_by_root => |*ctx| ctx.deinit(allocator),
        }
    }
};

pub const PendingRPCEntry = struct {
    request: PendingRPC,
    created_at: i64,

    pub fn deinit(self: *PendingRPCEntry, allocator: Allocator) void {
        self.request.deinit(allocator);
    }
};

pub const ConnectedPeers = locking.ConnectedPeersImpl(PeerInfo);

/// Snapshot of a fetched block plus its (optional) SSZ bytes. The pointers
/// are owned by the cache; callers must not free them. Returned by value
/// so the caller can hold onto the immutable references after the cache
/// lock is released — the SignedBlock value itself is the cache-stored
/// instance whose internal allocations are stable until the entry is
/// removed via `removeFetchedBlock` (or pruned via `pruneCachedBlocks`).
pub const FetchedBlock = struct {
    block: types.SignedBlock,
    ssz: ?[]const u8 = null,
};

pub const PendingRPCMap = locking.LockedMap(u64, PendingRPCEntry);
// key: block root, value: depth
pub const PendingBlockRootMap = locking.LockedMap(types.Root, u32);

pub const BlocksByRootRequestResult = struct {
    peer_id: []u8,
    request_id: u64,

    /// Free the duplicated `peer_id` slice. The slice is owned by the
    /// caller of `ensureBlocksByRootRequest` (allocated via `selectPeerCopy`
    /// inside the network helper) so the caller is responsible for its
    /// lifetime. Callers typically do `defer result.deinit(allocator)`.
    pub fn deinit(self: *BlocksByRootRequestResult, allocator: Allocator) void {
        allocator.free(self.peer_id);
    }
};

pub const Network = struct {
    allocator: Allocator,
    backend: networks.NetworkInterface,
    /// Heap-allocated so `*const ConnectedPeers` references handed to
    /// `BeamChain` survive moves of the `Network` value.
    connected_peers: *ConnectedPeers,
    pending_rpc_requests: PendingRPCMap,
    pending_block_roots: PendingBlockRootMap,
    /// Atomic block triple (block + ssz + parent link) under a single
    /// `block_cache_lock`. Replaces the three independent maps from the
    /// pre-slice-(a-3) shape.
    block_cache: locking.BlockCache,
    /// Buffer of timed-out RPC ids. Mutex-guarded because `getTimedOutRequests`
    /// caps the buffer in place; the returned slice's lifetime ends at the
    /// next `getTimedOutRequests` call (caller is the libxev tick loop and
    /// no other thread reads it).
    timed_out_requests: std.ArrayList(u64) = .empty,
    timed_out_requests_lock: zeam_utils.SyncMutex = .{},

    const Self = @This();

    pub fn init(allocator: Allocator, backend: networks.NetworkInterface) !Self {
        const connected_peers = try allocator.create(ConnectedPeers);
        errdefer allocator.destroy(connected_peers);
        connected_peers.* = ConnectedPeers.init(allocator);
        errdefer connected_peers.deinit();

        var pending_rpc_requests = PendingRPCMap.init(allocator);
        errdefer pending_rpc_requests.deinit();

        var pending_block_roots = PendingBlockRootMap.init(allocator);
        errdefer pending_block_roots.deinit();

        var block_cache = locking.BlockCache.init(allocator);
        errdefer block_cache.deinit();

        return Self{
            .allocator = allocator,
            .backend = backend,
            .connected_peers = connected_peers,
            .pending_rpc_requests = pending_rpc_requests,
            .pending_block_roots = pending_block_roots,
            .block_cache = block_cache,
        };
    }

    pub fn deinit(self: *Self) void {
        // timed_out_requests
        self.timed_out_requests_lock.lock();
        self.timed_out_requests.deinit(self.allocator);
        self.timed_out_requests_lock.unlock();

        // pending_rpc_requests — drain values to free their per-entry heap
        // allocations before deinit.
        {
            var guard = self.pending_rpc_requests.iterateLocked();
            defer guard.deinit();
            while (guard.iter.next()) |entry| {
                entry.value_ptr.deinit(self.allocator);
            }
        }
        self.pending_rpc_requests.deinit();

        self.pending_block_roots.deinit();

        // BlockCache: its deinit handles the heap-stored values and the
        // children lists. NOTE the BlockCache here stores `SignedBlock`
        // values (not pointers) — the network always cloned via
        // `*types.SignedBlock` and stored the inner SignedBlock copy in the
        // cache. With the migration we hold a SignedBlock value directly,
        // so `BlockCache.deinit` (which iterates and calls `value.deinit()`
        // on each SignedBlock) is the right cleanup path.
        self.block_cache.deinit();

        self.connected_peers.deinit();
        self.allocator.destroy(self.connected_peers);
    }

    /// Publish a gossip message via the configured backend. Returns `true`
    /// when the message was successfully accepted by the backend, `false`
    /// when the backend dropped it (e.g. rust-libp2p command channel full,
    /// see issue #808). Callers should treat `false` as "this message did not
    /// leave the host" and surface it accordingly.
    pub fn publish(self: *Self, data: *const networks.GossipMessage) !bool {
        return self.backend.gossip.publish(data);
    }

    pub fn sendStatus(
        self: *Self,
        peer_id: []const u8,
        status: types.Status,
        callback: ?networks.OnReqRespResponseCbHandler,
    ) !u64 {
        var request = networks.ReqRespRequest{ .status = status };
        errdefer request.deinit();

        const request_id = try self.backend.reqresp.sendRequest(peer_id, &request, callback);
        request.deinit();
        return request_id;
    }

    pub fn requestBlocksByRoot(
        self: *Self,
        peer_id: []const u8,
        roots: []const types.Root,
        callback: ?networks.OnReqRespResponseCbHandler,
    ) !u64 {
        if (roots.len == 0) return error.NoBlockRootsRequested;

        var request = networks.ReqRespRequest{
            .blocks_by_root = .{ .roots = try ssz.utils.List(types.Root, params.MAX_REQUEST_BLOCKS).init(self.allocator) },
        };
        errdefer request.deinit();

        for (roots) |root| {
            try request.blocks_by_root.roots.append(root);
        }

        const request_id = try self.backend.reqresp.sendRequest(peer_id, &request, callback);
        request.deinit();
        return request_id;
    }

    /// Returns an owned copy of a randomly selected peer's id, or null when
    /// no peers are connected. Caller frees with `self.allocator.free`.
    pub fn selectPeer(self: *Self) !?[]u8 {
        return self.connected_peers.selectPeerCopy(self.allocator);
    }

    pub fn getPeerCount(self: *Self) usize {
        return self.connected_peers.count();
    }

    pub fn hasPeer(self: *Self, peer_id: []const u8) bool {
        return self.connected_peers.contains(peer_id);
    }

    pub fn setPeerLatestStatus(self: *Self, peer_id: []const u8, status: types.Status) bool {
        return self.connected_peers.setLatestStatus(peer_id, status);
    }

    pub fn connectPeer(self: *Self, peer_id: []const u8) !void {
        try self.connected_peers.connect(peer_id);
    }

    pub fn disconnectPeer(self: *Self, peer_id: []const u8) bool {
        if (!self.connected_peers.disconnect(peer_id)) return false;

        // Finalize all pending RPC requests for this peer. Snapshot the
        // request ids under the pending_rpc_requests lock first (no nested
        // chain locks; `finalizePendingRequest` re-acquires it for each id).
        var request_ids_to_remove: std.ArrayList(u64) = .empty;
        defer request_ids_to_remove.deinit(self.allocator);

        {
            var guard = self.pending_rpc_requests.iterateLocked();
            defer guard.deinit();
            while (guard.iter.next()) |rpc_entry| {
                const pending_peer_id = switch (rpc_entry.value_ptr.request) {
                    .status => |*ctx| ctx.peer_id,
                    .blocks_by_root => |*ctx| ctx.peer_id,
                };
                if (std.mem.eql(u8, pending_peer_id, peer_id)) {
                    request_ids_to_remove.append(self.allocator, rpc_entry.key_ptr.*) catch continue;
                }
            }
        }

        for (request_ids_to_remove.items) |request_id| {
            self.finalizePendingRequest(request_id);
        }

        return true;
    }

    pub fn hasPendingBlockRoot(self: *Self, root: types.Root) bool {
        return self.pending_block_roots.get(root) != null;
    }

    pub fn getPendingBlockRootDepth(self: *Self, root: types.Root) ?u32 {
        return self.pending_block_roots.get(root);
    }

    pub fn trackPendingBlockRoot(self: *Self, root: types.Root, depth: u32) !void {
        try self.pending_block_roots.put(root, depth);
    }

    pub fn removePendingBlockRoot(self: *Self, root: types.Root) bool {
        return self.pending_block_roots.remove(root);
    }

    pub fn shouldRequestBlocksByRoot(self: *Self, roots: []const types.Root) bool {
        for (roots) |root| {
            if (!self.hasPendingBlockRoot(root) and !self.hasFetchedBlock(root)) {
                return true;
            }
        }
        return false;
    }

    pub fn hasFetchedBlock(self: *Self, root: types.Root) bool {
        return self.block_cache.contains(root);
    }

    pub fn getFetchedBlockCount(self: *Self) usize {
        return self.block_cache.count();
    }

    /// Returns a copy of the cached SignedBlock by root, or null when not
    /// cached. The SignedBlock value is the cache-stored instance — its
    /// internal storage stays alive until the entry is removed.
    pub fn getFetchedBlock(self: *Self, root: types.Root) ?types.SignedBlock {
        return self.block_cache.getBlock(root);
    }

    /// Cache a fetched block. Takes ownership of `block_ptr`'s heap
    /// allocations: the inner SignedBlock value is moved into the cache,
    /// then the outer pointer is destroyed. On duplicate, the new pointer
    /// is freed (deinit + destroy) and no error is propagated — same
    /// observable behavior as the legacy `cacheFetchedBlock`.
    pub fn cacheFetchedBlock(self: *Self, root: types.Root, block_ptr: *types.SignedBlock) !void {
        const parent_root = block_ptr.block.parent_root;
        // SSZ is attached later via storeFetchedBlockSsz; readers that need
        // both atomically must use `cloneFetchedBlockAndSsz` to avoid the
        // partial-state window.
        self.block_cache.insertBlockPtr(root, block_ptr, parent_root, null) catch |err| {
            if (err == error.AlreadyCached) {
                // Duplicate: free the caller's pointer to match legacy
                // semantics. Returning `void` here keeps callsites happy.
                block_ptr.deinit();
                self.allocator.destroy(block_ptr);
                return;
            }
            return err;
        };
        // Cache took the inner SignedBlock value (struct copy). Free the
        // outer heap pointer; the inner allocations are now owned by the
        // cache and will be freed via `removeFetchedBlock` /
        // `BlockCache.deinit`.
        self.allocator.destroy(block_ptr);
    }

    /// Returns the pre-serialized SSZ bytes for a cached block, if stored.
    pub fn getFetchedBlockSsz(self: *Self, root: types.Root) ?[]const u8 {
        return self.block_cache.getSsz(root);
    }

    /// Atomically clone the cached `SignedBlock` + its SSZ bytes (if
    /// attached) under the cache mutex and return owned copies. Returns
    /// null when the root is not cached. Caller MUST call
    /// `.deinit(allocator)` on the returned value to release the clones.
    ///
    /// This is the only safe shape for callers that need (block, ssz) to
    /// outlive the cache mutex — in particular, anything that hands the
    /// data into `chain.onBlock` (STF + XMSS verify, hundreds of ms
    /// during which a concurrent `removeFetchedBlock` could free the
    /// underlying storage). The borrow-shape `getFetchedBlockWithSsz`
    /// was removed in PR #820 (slice a-3 follow-up); see the
    /// `OwnedBlockAndSsz` docstring in `locking.zig` for the full UAF
    /// rationale.
    pub fn cloneFetchedBlockAndSsz(
        self: *Self,
        root: types.Root,
        allocator: std.mem.Allocator,
    ) !?locking.OwnedBlockAndSsz {
        return self.block_cache.cloneBlockAndSsz(root, allocator);
    }

    /// Store pre-serialized SSZ bytes alongside a cached block. Caller
    /// transfers ownership of `ssz_bytes` to the cache on success.
    pub fn storeFetchedBlockSsz(self: *Self, root: types.Root, ssz_bytes: []u8) !void {
        try self.block_cache.attachSsz(root, ssz_bytes);
    }

    /// Remove a fetched block (block + ssz + parent-link) from the cache.
    /// Returns true if the block was present.
    ///
    /// All three updates happen under the cache's lock in one critical
    /// section — the legacy two-step (getBlock then removeOne) leaked a
    /// TOCTOU window where another thread could remove the entry or its
    /// parent's children list, leaving the cache in a torn state. See
    /// PR #820 / issue #803.
    pub fn removeFetchedBlock(self: *Self, root: types.Root) bool {
        return self.block_cache.removeFetchedBlock(root);
    }

    /// Returns the cached children of the given parent block root as a
    /// freshly-allocated slice. Caller frees with `self.allocator.free`.
    /// Empty slice when the parent has no cached children.
    pub fn getChildrenOfBlock(self: *Self, parent_root: types.Root) ![]types.Root {
        return self.block_cache.getChildrenCopy(parent_root, self.allocator);
    }

    /// Internal context used by `pruneCachedBlocks` to collect every
    /// cached block whose slot is at or before `finalized.slot`. We avoid
    /// holding the cache lock across mutation by snapshotting the roots of
    /// candidates first.
    const PruneAtOrBelowCtx = struct {
        finalized_slot: types.Slot,
        roots: *std.ArrayList(types.Root),
        allocator: Allocator,
    };

    fn pruneAtOrBelowEach(ctx_ptr: *anyopaque, root: types.Root, block: types.SignedBlock) void {
        const ctx: *PruneAtOrBelowCtx = @ptrCast(@alignCast(ctx_ptr));
        if (block.block.slot <= ctx.finalized_slot) {
            ctx.roots.append(ctx.allocator, root) catch return;
        }
    }

    /// Collect every cached block whose slot is at or before
    /// `finalized.slot`. Caller owns the returned slice.
    pub fn collectCachedBlocksAtOrBelowSlot(
        self: *Self,
        finalized_slot: types.Slot,
    ) ![]types.Root {
        var roots: std.ArrayList(types.Root) = .empty;
        errdefer roots.deinit(self.allocator);

        var ctx = PruneAtOrBelowCtx{
            .finalized_slot = finalized_slot,
            .roots = &roots,
            .allocator = self.allocator,
        };
        self.block_cache.forEachBlock(&ctx, pruneAtOrBelowEach);
        return roots.toOwnedSlice(self.allocator);
    }

    /// Snapshot the set of (root, parent_root, slot) tuples for cached
    /// blocks whose slot is at or below `current_slot`. Used by
    /// `processReadyCachedBlocks`. Caller owns the returned slice.
    pub const CachedBlockSummary = struct {
        root: types.Root,
        parent_root: types.Root,
        slot: types.Slot,
    };

    const CollectReadyCtx = struct {
        current_slot: types.Slot,
        out: *std.ArrayList(CachedBlockSummary),
        allocator: Allocator,
    };

    fn collectReadyEach(ctx_ptr: *anyopaque, root: types.Root, block: types.SignedBlock) void {
        const ctx: *CollectReadyCtx = @ptrCast(@alignCast(ctx_ptr));
        if (block.block.slot <= ctx.current_slot) {
            ctx.out.append(ctx.allocator, .{
                .root = root,
                .parent_root = block.block.parent_root,
                .slot = block.block.slot,
            }) catch return;
        }
    }

    pub fn collectReadyCachedBlocks(
        self: *Self,
        current_slot: types.Slot,
    ) ![]CachedBlockSummary {
        var out: std.ArrayList(CachedBlockSummary) = .empty;
        errdefer out.deinit(self.allocator);

        var ctx = CollectReadyCtx{
            .current_slot = current_slot,
            .out = &out,
            .allocator = self.allocator,
        };
        self.block_cache.forEachBlock(&ctx, collectReadyEach);
        return out.toOwnedSlice(self.allocator);
    }

    /// Remove a block and its entire chain: walk up to ancestors (parents)
    /// and down to descendants (children), removing all from cache and
    /// clearing any matching pending block roots.
    /// Uses a set for the worklist to handle multiple chains sharing common blocks.
    /// Returns the number of blocks removed.
    pub fn pruneCachedBlocks(self: *Self, root: types.Root, finalized_checkpoint: ?types.Checkpoint) usize {
        if (finalized_checkpoint) |fc| {
            if (std.mem.eql(u8, &root, &fc.root)) {
                // Never prune the finalized checkpoint root directly; keep it cached for descendants.
                return 0;
            }
        }

        var to_remove_set = std.AutoHashMap(types.Root, void).init(self.allocator);
        defer to_remove_set.deinit();
        var to_remove_order: std.ArrayList(types.Root) = .empty;
        defer to_remove_order.deinit(self.allocator);

        const root_gop = to_remove_set.getOrPut(root) catch return 0;
        if (!root_gop.found_existing) {
            to_remove_order.append(self.allocator, root) catch return 0;
        }

        // Walk up: traverse parent chain and add all cached ancestors
        var current = root;
        while (self.getFetchedBlock(current)) |block| {
            const parent_root = block.block.parent_root;
            if (self.hasFetchedBlock(parent_root)) {
                const parent_gop = to_remove_set.getOrPut(parent_root) catch break;
                if (!parent_gop.found_existing) {
                    to_remove_order.append(self.allocator, parent_root) catch break;
                }
                current = parent_root;
            } else {
                break;
            }
        }

        // Walk down: process entries, expanding children as we go.
        // We iterate by index since new entries may be appended during iteration.
        var i: usize = 0;
        while (i < to_remove_order.items.len) : (i += 1) {
            const current_root = to_remove_order.items[i];

            // Enqueue children before removing (since removal modifies the children map)
            const children_slice = self.getChildrenOfBlock(current_root) catch &[_]types.Root{};
            defer if (children_slice.len > 0) self.allocator.free(children_slice);
            for (children_slice) |child_root| {
                // When pruning due to finalization, keep children that are on
                // the finalized chain (matching root at or after finalized slot).
                if (finalized_checkpoint) |fc| {
                    if (self.getFetchedBlock(child_root)) |child_block| {
                        if (child_block.block.slot >= fc.slot and
                            std.mem.eql(u8, &child_root, &fc.root))
                        {
                            // This child is the finalized block — skip it (keep it and its descendants)
                            continue;
                        }
                    }
                }
                const child_gop = to_remove_set.getOrPut(child_root) catch continue;
                if (!child_gop.found_existing) {
                    to_remove_order.append(self.allocator, child_root) catch continue;
                }
            }
        }

        // Remove all collected roots
        var pruned: usize = 0;
        for (to_remove_order.items) |entry_root| {
            if (self.removeFetchedBlock(entry_root)) {
                pruned += 1;
            }
            _ = self.removePendingBlockRoot(entry_root);
        }
        return pruned;
    }

    pub fn sendStatusRequest(
        self: *Self,
        peer_id: []const u8,
        status: types.Status,
        handler: networks.OnReqRespResponseCbHandler,
    ) !u64 {
        const peer_copy = try self.allocator.dupe(u8, peer_id);
        var peer_copy_owned = true;
        errdefer if (peer_copy_owned) self.allocator.free(peer_copy);

        var pending = PendingRPC{ .status = .{ .peer_id = peer_copy } };
        var pending_owned = false;
        errdefer if (!pending_owned) pending.deinit(self.allocator);

        // ownership transferred to pending
        peer_copy_owned = false;

        const request_id = try self.sendStatus(peer_id, status, handler);

        self.pending_rpc_requests.put(request_id, PendingRPCEntry{
            .request = pending,
            .created_at = zeam_utils.unixTimestampSeconds(),
        }) catch |err| {
            pending.deinit(self.allocator);
            return err;
        };

        pending_owned = true;

        return request_id;
    }

    pub fn sendStatusToPeer(
        self: *Self,
        peer_id: []const u8,
        status: types.Status,
        handler: networks.OnReqRespResponseCbHandler,
    ) !u64 {
        return self.sendStatusRequest(peer_id, status, handler);
    }

    pub fn sendBlocksByRootRequest(
        self: *Self,
        peer_id: []const u8,
        roots: []const types.Root,
        depth: u32,
        handler: networks.OnReqRespResponseCbHandler,
    ) !u64 {
        if (roots.len == 0) return error.NoBlockRootsRequested;

        const peer_copy = try self.allocator.dupe(u8, peer_id);
        var peer_copy_owned = true;
        errdefer if (peer_copy_owned) self.allocator.free(peer_copy);

        const roots_copy = try self.allocator.alloc(types.Root, roots.len);
        var roots_copy_owned = true;
        errdefer if (roots_copy_owned) self.allocator.free(roots_copy);
        std.mem.copyForwards(types.Root, roots_copy, roots);

        var pending = PendingRPC{ .blocks_by_root = .{
            .peer_id = peer_copy,
            .requested_roots = roots_copy,
        } };
        var pending_owned = false;
        errdefer if (!pending_owned) pending.deinit(self.allocator);

        // ownership transferred to pending
        peer_copy_owned = false;
        roots_copy_owned = false;

        const request_id = self.requestBlocksByRoot(peer_id, roots, handler) catch |err| {
            return err;
        };

        self.pending_rpc_requests.put(request_id, PendingRPCEntry{
            .request = pending,
            .created_at = zeam_utils.unixTimestampSeconds(),
        }) catch |err| {
            pending.deinit(self.allocator);
            return err;
        };

        pending_owned = true;

        for (roots) |root| {
            if (self.hasPendingBlockRoot(root)) continue;
            self.trackPendingBlockRoot(root, depth) catch |err| {
                self.finalizePendingRequest(request_id);
                return err;
            };
        }

        return request_id;
    }

    pub fn ensureBlocksByRootRequest(
        self: *Self,
        roots: []const types.Root,
        depth: u32,
        handler: networks.OnReqRespResponseCbHandler,
    ) !?BlocksByRootRequestResult {
        if (roots.len == 0) return null;

        if (!self.shouldRequestBlocksByRoot(roots)) return null;

        const peer = (try self.selectPeer()) orelse return error.NoPeersAvailable;
        var peer_owned = true;
        errdefer if (peer_owned) self.allocator.free(peer);

        const request_id = try self.sendBlocksByRootRequest(peer, roots, depth, handler);
        peer_owned = false; // ownership transferred to result

        return BlocksByRootRequestResult{
            .peer_id = peer,
            .request_id = request_id,
        };
    }

    /// Direct lock-protected access to a pending RPC entry. Callers that
    /// need cross-call lifetime (the timeout sweep loop) must read the
    /// fields they need under this snapshot — the returned struct carries
    /// owned copies of any caller-visible strings.
    pub const PendingRequestSnapshot = struct {
        request_kind: enum { status, blocks_by_root },
        peer_id_copy: []u8,
        requested_roots_copy: []types.Root = &[_]types.Root{},
        created_at: i64,

        pub fn deinit(self: *PendingRequestSnapshot, allocator: Allocator) void {
            allocator.free(self.peer_id_copy);
            if (self.requested_roots_copy.len > 0) allocator.free(self.requested_roots_copy);
        }
    };

    pub fn snapshotPendingRequest(self: *Self, request_id: u64) !?PendingRequestSnapshot {
        // O(1) lookup but ALL slice dupes happen inside the callback so
        // they run while the LockedMap mutex is still held. The previous
        // shape (commit 60761c9 era) used `get()` + dupe-after-unlock,
        // which returned the value by-value and dropped the lock; the
        // returned struct's slice headers (`peer_id`, `requested_roots`)
        // aliased the in-map allocator-owned bytes, and a concurrent
        // `finalizePendingRequest` could `fetchRemove` + free the entry
        // between the `get` returning and the dupes running — UAF.
        // PR #820 / issue #803.
        const Ctx = struct {
            self: *Self,
            out: ?PendingRequestSnapshot = null,

            fn each(c: *@This(), value_ptr: ?*const PendingRPCEntry) anyerror!void {
                const entry = value_ptr orelse return;
                switch (entry.request) {
                    .status => |s| {
                        const peer_id_copy = try c.self.allocator.dupe(u8, s.peer_id);
                        c.out = .{
                            .request_kind = .status,
                            .peer_id_copy = peer_id_copy,
                            .created_at = entry.created_at,
                        };
                    },
                    .blocks_by_root => |b| {
                        const peer_id_copy = try c.self.allocator.dupe(u8, b.peer_id);
                        errdefer c.self.allocator.free(peer_id_copy);
                        const roots_copy = try c.self.allocator.dupe(types.Root, b.requested_roots);
                        c.out = .{
                            .request_kind = .blocks_by_root,
                            .peer_id_copy = peer_id_copy,
                            .requested_roots_copy = roots_copy,
                            .created_at = entry.created_at,
                        };
                    },
                }
            }
        };
        var ctx = Ctx{ .self = self };
        try self.pending_rpc_requests.withValueLocked(request_id, &ctx, Ctx.each);
        return ctx.out;
    }

    /// Returns the time-out request ids as an owned slice. Caller frees
    /// with `self.allocator.free`.
    pub fn getTimedOutRequests(self: *Self, current_time: i64, timeout_seconds: i64) ![]u64 {
        var ids: std.ArrayList(u64) = .empty;
        errdefer ids.deinit(self.allocator);

        {
            var guard = self.pending_rpc_requests.iterateLocked();
            defer guard.deinit();
            while (guard.iter.next()) |entry| {
                if (current_time - entry.value_ptr.created_at >= timeout_seconds) {
                    try ids.append(self.allocator, entry.key_ptr.*);
                }
            }
        }
        return ids.toOwnedSlice(self.allocator);
    }

    pub fn finalizePendingRequest(self: *Self, request_id: u64) void {
        if (self.pending_rpc_requests.fetchRemove(request_id)) |entry| {
            var rpc_entry = entry.value;
            switch (rpc_entry.request) {
                .blocks_by_root => |block_ctx| {
                    for (block_ctx.requested_roots) |root| {
                        _ = self.removePendingBlockRoot(root);
                    }
                },
                .status => {},
            }
            rpc_entry.deinit(self.allocator);
        }
    }
};
