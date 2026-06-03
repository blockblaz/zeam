const std = @import("std");
const blocks_by_range_sync = @import("./blocks_by_range_sync.zig");
const networks = @import("@zeam/network");
const types = @import("@zeam/types");
const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");
const ssz = @import("ssz");
const locking = @import("./locking.zig");

const Allocator = std.mem.Allocator;

pub const PeerInfo = struct {
    peer_id: []const u8,
    connected_at: i64,
    latest_status: ?types.Status = null,
    /// Set when a `blocks_by_range` RPC fails with an "unsupported / not available"
    /// error so catch-up uses `blocks_by_root` instead of retrying range on this peer.
    blocks_by_range_unavailable: bool = false,
};

test "Network: preferred blocks_by_root peer is a hint with fallback" {
    const allocator = std.testing.allocator;

    const Ctx = struct {
        allocator: Allocator,
        last_peer: ?[]u8 = null,
        next_request_id: u64 = 1,

        fn deinit(self: *@This()) void {
            if (self.last_peer) |peer| self.allocator.free(peer);
        }

        fn publish(_: *anyopaque, _: *const networks.GossipMessage) anyerror!bool {
            return true;
        }

        fn subscribeGossip(_: *anyopaque, _: []networks.GossipTopic, _: networks.OnGossipCbHandler) anyerror!void {}
        fn onGossip(_: *anyopaque, _: *networks.GossipMessage, _: []const u8) anyerror!void {}

        fn sendRequest(
            ptr: *anyopaque,
            peer_id: []const u8,
            _: *const networks.ReqRespRequest,
            _: ?networks.OnReqRespResponseCbHandler,
        ) anyerror!u64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.last_peer) |old| self.last_peer = blk: {
                self.allocator.free(old);
                break :blk null;
            };
            self.last_peer = try self.allocator.dupe(u8, peer_id);
            const id = self.next_request_id;
            self.next_request_id += 1;
            return id;
        }

        fn onReqRespRequest(_: *anyopaque, _: *networks.ReqRespRequest, _: networks.ReqRespServerStream) anyerror!void {}
        fn subscribeReqResp(_: *anyopaque, _: networks.OnReqRespRequestCbHandler) anyerror!void {}
        fn cancelInflightRequest(_: *anyopaque, _: u64) void {}
        fn subscribePeers(_: *anyopaque, _: networks.OnPeerEventCbHandler) anyerror!void {}
    };

    var ctx = Ctx{ .allocator = allocator };
    defer ctx.deinit();

    var network = try Network.init(allocator, .{
        .gossip = .{
            .ptr = &ctx,
            .publishFn = Ctx.publish,
            .subscribeFn = Ctx.subscribeGossip,
            .onGossipFn = Ctx.onGossip,
        },
        .reqresp = .{
            .ptr = &ctx,
            .sendRequestFn = Ctx.sendRequest,
            .onReqRespRequestFn = Ctx.onReqRespRequest,
            .subscribeFn = Ctx.subscribeReqResp,
            .cancelInflightRequestFn = Ctx.cancelInflightRequest,
        },
        .peers = .{ .ptr = &ctx, .subscribeFn = Ctx.subscribePeers },
    });
    defer network.deinit();

    try network.connectPeer("serving-peer");
    try network.connectPeer("fallback-peer");

    const root_a: types.Root = [_]u8{0xaa} ** 32;
    const handler: networks.OnReqRespResponseCbHandler = .{
        .ptr = &ctx,
        .onReqRespResponseCb = struct {
            fn cb(_: *anyopaque, _: *const networks.ReqRespResponseEvent) anyerror!void {}
        }.cb,
    };

    var pinned = (try network.ensureBlocksByRootRequest(&[_]types.Root{root_a}, 0, handler, "serving-peer")).?;
    defer pinned.deinit(allocator);
    try std.testing.expectEqualStrings("serving-peer", pinned.peer_id);
    try std.testing.expectEqualStrings("serving-peer", ctx.last_peer.?);
    network.finalizePendingRequest(pinned.request_id);

    try std.testing.expect(network.disconnectPeer("serving-peer"));

    const root_b: types.Root = [_]u8{0xbb} ** 32;
    var fallback = (try network.ensureBlocksByRootRequest(&[_]types.Root{root_b}, 0, handler, "serving-peer")).?;
    defer fallback.deinit(allocator);
    try std.testing.expectEqualStrings("fallback-peer", fallback.peer_id);
    try std.testing.expectEqualStrings("fallback-peer", ctx.last_peer.?);
}

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

pub const BlockByRangeContext = struct {
    peer_id: []const u8,
    start_slot: types.Slot,
    count: u64,
    /// Peer head when this catch-up was scheduled (pagination + gap sanity).
    peer_head_slot: types.Slot,
    /// Fallback target when range sync cannot link to our chain.
    peer_head_root: types.Root,
    /// Our forkchoice head root at request start — the first returned chunk must extend this.
    our_head_root_at_start: types.Root,
    attempt: u8 = 1,
    chunks_received: u32 = 0,
    chunks_imported: u32 = 0,
    /// Chunks rejected at or below our finalized slot (peer served stale history).
    chunks_pre_finalized: u32 = 0,
    /// Chunks queued on the chain-worker; sync-end runs after this hits zero.
    chunks_async_pending: u32 = 0,
    /// RPC stream finished; defer `handleBlocksByRangeSyncEnd` until async imports drain.
    sync_end_pending: bool = false,
    /// Set when the first chunk cannot attach to `our_head_root_at_start`; further chunks are ignored.
    aborted: bool = false,

    pub fn deinit(self: *BlockByRangeContext, allocator: Allocator) void {
        allocator.free(self.peer_id);
    }
};

/// Identifies an outbound `blocks_by_range` request by its slot window.
/// Issue #893: allow many concurrent ranges, but reject overlapping slot windows
/// (review PR #894 / zclawz: overlapping windows corrupt async import accounting).
pub const BlocksByRangeKey = struct {
    start_slot: types.Slot,
    count: u64,

    pub fn eql(a: BlocksByRangeKey, b: BlocksByRangeKey) bool {
        return a.start_slot == b.start_slot and a.count == b.count;
    }

    pub fn hash(self: BlocksByRangeKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.start_slot));
        hasher.update(std.mem.asBytes(&self.count));
        return hasher.final();
    }
};

pub const BlocksByRangeSyncParams = struct {
    peer_id: []const u8,
    start_slot: types.Slot,
    count: u64,
    peer_head_slot: types.Slot,
    peer_head_root: types.Root,
    our_head_root_at_start: types.Root,
    attempt: u8 = 1,
};

pub const PendingRPC = union(enum) {
    status: StatusRequestContext,
    blocks_by_root: BlockByRootContext,
    blocks_by_range: BlockByRangeContext,

    pub fn deinit(self: *PendingRPC, allocator: Allocator) void {
        switch (self.*) {
            .status => |*ctx| ctx.deinit(allocator),
            .blocks_by_root => |*ctx| ctx.deinit(allocator),
            .blocks_by_range => |*ctx| ctx.deinit(allocator),
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

/// Issue #863 P3: cap on outbound `BlocksByRoot` RPCs in flight at any
/// given moment. The pre-#863 path issued one RPC per attestation that
/// referenced an unknown head, multiplied by 4× subnet fanout for an
/// aggregator — under flood the libxev thread fanned hundreds of
/// concurrent RPCs that themselves timed out (8s default per
/// `RPC_REQUEST_TIMEOUT_SECONDS`) and retried, saturating the loop and
/// the timed-out-requests sweep.
///
/// 8 is empirically generous: each RPC fetches up to MAX_BLOCKS_BY_ROOT
/// roots in one batch, so 8 in-flight covers ~64 missing roots
/// concurrently — comfortably above the worst observed sustained
/// missing-root rate while keeping the RPC dispatch fan-out bounded.
/// Tune by watching `zeam_blocks_by_root_inflight` saturate at this
/// value combined with `lean_block_fetch_dedup_total{outcome="inflight_cap"}`
/// climbing — under healthy operation neither should be hot.
pub const MAX_CONCURRENT_BLOCKS_BY_ROOT: u32 = 8;

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

    /// Issue #863 P3: in-flight outbound `BlocksByRoot` RPC count.
    /// Incremented by `ensureBlocksByRootRequest` after a successful
    /// dispatch, decremented by `finalizePendingRequest` regardless of
    /// success / timeout / peer disconnect. Read by
    /// `ensureBlocksByRootRequest` to enforce
    /// `MAX_CONCURRENT_BLOCKS_BY_ROOT` and exported as
    /// `zeam_blocks_by_root_inflight`. Atomic so the timeout sweep
    /// thread (`processTimedOutRequests`) and the gossip dispatch
    /// path on the libxev thread don't tear it.
    blocks_by_root_inflight: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Issue #893: active outbound `blocks_by_range` windows (one in-flight per key).
    blocks_by_range_active: std.AutoHashMap(BlocksByRangeKey, void),
    blocks_by_range_active_lock: zeam_utils.SyncMutex = .{},

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

        var blocks_by_range_active = std.AutoHashMap(BlocksByRangeKey, void).init(allocator);
        errdefer blocks_by_range_active.deinit();

        return Self{
            .allocator = allocator,
            .backend = backend,
            .connected_peers = connected_peers,
            .pending_rpc_requests = pending_rpc_requests,
            .pending_block_roots = pending_block_roots,
            .block_cache = block_cache,
            .blocks_by_range_active = blocks_by_range_active,
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

        {
            self.blocks_by_range_active_lock.lock();
            self.blocks_by_range_active.deinit();
            self.blocks_by_range_active_lock.unlock();
        }

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

    pub fn refreshGossipMesh(self: *Self) void {
        self.backend.gossip.refreshMesh();
    }

    pub fn gossipMeshPeerCount(self: *Self) u64 {
        return self.backend.gossip.meshPeerCount();
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

    pub fn requestBlocksByRange(
        self: *Self,
        peer_id: []const u8,
        start_slot: types.Slot,
        count: u64,
        callback: ?networks.OnReqRespResponseCbHandler,
    ) !u64 {
        if (count == 0) return error.NoBlocksRequested;

        var request = networks.ReqRespRequest{
            .blocks_by_range = .{ .start_slot = start_slot, .count = count },
        };
        errdefer request.deinit();

        const request_id = try self.backend.reqresp.sendRequest(peer_id, &request, callback);
        request.deinit();
        return request_id;
    }

    /// Returns an owned copy of a randomly selected peer's id, or null when
    /// no peers are connected. Caller frees with `self.allocator.free`.
    pub fn selectPeer(self: *Self, min_slot: ?u64) !?[]u8 {
        return self.connected_peers.selectPeerCopy(self.allocator, min_slot);
    }

    pub fn selectPeerExcluding(self: *Self, exclude: ?[]const u8, min_slot: ?u64) !?[]u8 {
        return self.connected_peers.selectPeerExcluding(self.allocator, exclude, false, min_slot);
    }

    pub fn selectPeerForRangeSyncExcluding(self: *Self, exclude: ?[]const u8) !?[]u8 {
        return self.connected_peers.selectPeerExcluding(self.allocator, exclude, true, null);
    }

    pub fn peerSupportsBlocksByRange(self: *Self, peer_id: []const u8) bool {
        return self.connected_peers.peerSupportsBlocksByRange(peer_id);
    }

    pub fn markPeerBlocksByRangeUnavailable(self: *Self, peer_id: []const u8) void {
        self.connected_peers.markBlocksByRangeUnavailable(peer_id);
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

    pub fn getPeerLatestStatus(self: *Self, peer_id: []const u8) ?types.Status {
        var guard = self.connected_peers.iterateLocked();
        defer guard.deinit();

        while (guard.iter.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, peer_id)) {
                return entry.value_ptr.latest_status;
            }
        }
        return null;
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
                    .blocks_by_range => |*ctx| ctx.peer_id,
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

    pub fn blocksByRangeKey(range_sync: BlocksByRangeSyncParams) BlocksByRangeKey {
        return .{
            .start_slot = range_sync.start_slot,
            .count = range_sync.count,
        };
    }

    pub fn isBlocksByRangeActive(self: *Self, key: BlocksByRangeKey) bool {
        self.blocks_by_range_active_lock.lock();
        defer self.blocks_by_range_active_lock.unlock();
        return self.blocks_by_range_active.contains(key);
    }

    pub fn blocksByRangeOverlapsActive(self: *Self, start_slot: types.Slot, count: u64) bool {
        self.blocks_by_range_active_lock.lock();
        defer self.blocks_by_range_active_lock.unlock();
        var it = self.blocks_by_range_active.keyIterator();
        while (it.next()) |active| {
            if (blocks_by_range_sync.rangesOverlap(active.start_slot, active.count, start_slot, count)) {
                return true;
            }
        }
        return false;
    }

    fn reserveBlocksByRangeActive(self: *Self, key: BlocksByRangeKey) !void {
        self.blocks_by_range_active_lock.lock();
        defer self.blocks_by_range_active_lock.unlock();
        var it = self.blocks_by_range_active.keyIterator();
        while (it.next()) |active| {
            if (blocks_by_range_sync.rangesOverlap(active.start_slot, active.count, key.start_slot, key.count)) {
                return error.BlocksByRangeOverlap;
            }
        }
        const gop = try self.blocks_by_range_active.getOrPut(key);
        if (gop.found_existing) return error.BlocksByRangeAlreadyActive;
    }

    fn releaseBlocksByRangeActive(self: *Self, key: BlocksByRangeKey) void {
        self.blocks_by_range_active_lock.lock();
        defer self.blocks_by_range_active_lock.unlock();
        _ = self.blocks_by_range_active.remove(key);
    }

    pub fn sendBlocksByRangeRequest(
        self: *Self,
        range_sync: BlocksByRangeSyncParams,
        handler: networks.OnReqRespResponseCbHandler,
    ) !u64 {
        if (range_sync.count == 0) return error.NoBlocksRequested;

        const range_key = blocksByRangeKey(range_sync);
        try self.reserveBlocksByRangeActive(range_key);
        var range_key_reserved = true;
        errdefer if (range_key_reserved) self.releaseBlocksByRangeActive(range_key);

        const peer_copy = try self.allocator.dupe(u8, range_sync.peer_id);
        var peer_copy_owned = true;
        errdefer if (peer_copy_owned) self.allocator.free(peer_copy);

        var pending = PendingRPC{ .blocks_by_range = .{
            .peer_id = peer_copy,
            .start_slot = range_sync.start_slot,
            .count = range_sync.count,
            .peer_head_slot = range_sync.peer_head_slot,
            .peer_head_root = range_sync.peer_head_root,
            .our_head_root_at_start = range_sync.our_head_root_at_start,
            .attempt = range_sync.attempt,
        } };
        var pending_owned = false;
        errdefer if (!pending_owned) pending.deinit(self.allocator);

        peer_copy_owned = false;

        const request_id = self.requestBlocksByRange(range_sync.peer_id, range_sync.start_slot, range_sync.count, handler) catch |err| {
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
        range_key_reserved = false;

        return request_id;
    }

    pub const BlocksByRangeChunkView = struct {
        start_slot: types.Slot,
        our_head_root_at_start: types.Root,
        aborted: bool,
        /// True for the first chunk recorded on this request (before `record_received`).
        is_first_chunk: bool = false,
    };

    pub const BlocksByRangeChunkUpdate = struct {
        record_received: bool = false,
        record_imported: bool = false,
        record_pre_finalized: bool = false,
        record_async_submitted: bool = false,
        record_async_finished: bool = false,
        mark_aborted: bool = false,
        mark_sync_end_pending: bool = false,
    };

    pub const BlocksByRangeRequestUpdate = struct {
        view: ?BlocksByRangeChunkView = null,
        /// True when the RPC stream has ended and all async imports have drained.
        run_sync_end: bool = false,
    };

    /// Single lock acquisition for range-chunk bookkeeping (issue #893).
    pub fn updateBlocksByRangeRequest(
        self: *Self,
        request_id: u64,
        update: BlocksByRangeChunkUpdate,
    ) BlocksByRangeRequestUpdate {
        const Ctx = struct {
            update: BlocksByRangeChunkUpdate,
            result: BlocksByRangeRequestUpdate = .{},
            fn each(c: *@This(), value_ptr: ?*PendingRPCEntry) anyerror!void {
                const entry = value_ptr orelse return;
                switch (entry.request) {
                    .blocks_by_range => |*ctx| {
                        const is_first_chunk = c.update.record_received and ctx.chunks_received == 0;
                        if (c.update.record_received) ctx.chunks_received += 1;
                        if (c.update.record_imported) ctx.chunks_imported += 1;
                        if (c.update.record_pre_finalized) ctx.chunks_pre_finalized += 1;
                        if (c.update.record_async_submitted) ctx.chunks_async_pending += 1;
                        if (c.update.record_async_finished) {
                            if (ctx.chunks_async_pending > 0) ctx.chunks_async_pending -= 1;
                        }
                        if (c.update.mark_aborted) ctx.aborted = true;
                        if (c.update.mark_sync_end_pending) ctx.sync_end_pending = true;
                        c.result.view = .{
                            .start_slot = ctx.start_slot,
                            .our_head_root_at_start = ctx.our_head_root_at_start,
                            .aborted = ctx.aborted,
                            .is_first_chunk = is_first_chunk,
                        };
                        if (ctx.sync_end_pending and ctx.chunks_async_pending == 0) {
                            c.result.run_sync_end = true;
                        }
                    },
                    else => {},
                }
            }
        };
        var ctx = Ctx{ .update = update };
        self.pending_rpc_requests.withMutableValueLocked(request_id, &ctx, Ctx.each) catch {};
        return ctx.result;
    }

    /// Issue #863 P3: errors that signal "request would exceed the
    /// in-flight cap" so the caller can bucket them as a soft-rejection
    /// rather than a hard error. This is intentionally a separate error
    /// from `error.NoPeersAvailable` because the calling code in
    /// `BeamNode.fetchBlockByRoots` accounts for both in different
    /// `lean_block_fetch_dedup_total{outcome=…}` buckets.
    pub const EnsureBlocksByRootError = error{InFlightCapReached};

    /// Issue #909 review #5: single public entry-point for blocks-by-root
    /// requests.  `preferred_peer` is a **hint**, not a hard requirement
    /// (see TOCTOU contract below): when the preferred peer is still
    /// connected it will be used; otherwise we fall back to `selectPeer()`.
    pub fn ensureBlocksByRootRequest(
        self: *Self,
        roots: []const types.Root,
        depth: u32,
        handler: networks.OnReqRespResponseCbHandler,
        preferred_peer: ?[]const u8,
    ) !?BlocksByRootRequestResult {
        if (roots.len == 0) return null;

        if (!self.shouldRequestBlocksByRoot(roots)) return null;

        // Issue #863 P3: enforce the in-flight cap BEFORE `selectPeer`
        // so a saturated cap doesn't burn a peer-selection round trip.
        // The compare-and-set loop is monotonic; under contention each
        // attempt observes the latest count, so a concurrent finalize
        // (decrement) is reflected on the next iteration.
        while (true) {
            const cur = self.blocks_by_root_inflight.load(.monotonic);
            if (cur >= MAX_CONCURRENT_BLOCKS_BY_ROOT) {
                return error.InFlightCapReached;
            }
            if (self.blocks_by_root_inflight.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) {
                // Reservation succeeded — we now own one in-flight slot
                // until either (a) the dispatch path below errors and we
                // release explicitly, or (b) the request completes and
                // `finalizePendingRequest` releases it.
                break;
            }
        }

        // Reservation released on any error path before the request_id
        // is recorded in `pending_rpc_requests`. After dispatch, the
        // slot stays held until `finalizePendingRequest` runs.
        var reservation_owned = true;
        errdefer if (reservation_owned) {
            _ = self.blocks_by_root_inflight.fetchSub(1, .acq_rel);
            zeam_metrics.metrics.zeam_blocks_by_root_inflight.set(self.blocks_by_root_inflight.load(.monotonic));
        };

        // `preferred_peer` is a routing hint, not a hard requirement. It keeps
        // checkpoint/parent walks on the peer that just proved it can serve the
        // chain, but if that peer disconnects before the next request, fall
        // back to normal peer selection instead of stalling the walk.
        // There is still an unavoidable TOCTOU window between this check and
        // the transport dispatch below; in that case sendBlocksByRootRequest
        // returns the backend error and the existing retry paths handle it.
        const peer = if (preferred_peer) |peer_id| blk: {
            if (self.hasPeer(peer_id)) break :blk try self.allocator.dupe(u8, peer_id);
            break :blk (try self.selectPeer(null)) orelse return error.NoPeersAvailable;
        } else (try self.selectPeer(null)) orelse return error.NoPeersAvailable;
        var peer_owned = true;
        errdefer if (peer_owned) self.allocator.free(peer);

        const request_id = try self.sendBlocksByRootRequest(peer, roots, depth, handler);
        peer_owned = false; // ownership transferred to result
        reservation_owned = false; // ownership transferred to pending_rpc_requests

        zeam_metrics.metrics.zeam_blocks_by_root_inflight.set(self.blocks_by_root_inflight.load(.monotonic));

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
        request_kind: enum { status, blocks_by_root, blocks_by_range },
        peer_id_copy: []u8,
        requested_roots_copy: []types.Root = &[_]types.Root{},
        start_slot: types.Slot = 0,
        count: u64 = 0,
        peer_head_slot: types.Slot = 0,
        peer_head_root: types.Root = types.ZERO_HASH,
        our_head_root_at_start: types.Root = types.ZERO_HASH,
        range_attempt: u8 = 1,
        range_chunks_received: u32 = 0,
        range_chunks_imported: u32 = 0,
        range_chunks_pre_finalized: u32 = 0,
        range_aborted: bool = false,
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
                    .blocks_by_range => |r| {
                        const peer_id_copy = try c.self.allocator.dupe(u8, r.peer_id);
                        c.out = .{
                            .request_kind = .blocks_by_range,
                            .peer_id_copy = peer_id_copy,
                            .start_slot = r.start_slot,
                            .count = r.count,
                            .peer_head_slot = r.peer_head_slot,
                            .peer_head_root = r.peer_head_root,
                            .our_head_root_at_start = r.our_head_root_at_start,
                            .range_attempt = r.attempt,
                            .range_chunks_received = r.chunks_received,
                            .range_chunks_imported = r.chunks_imported,
                            .range_chunks_pre_finalized = r.chunks_pre_finalized,
                            .range_aborted = r.aborted,
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
        // Drop the transport callback so a late rust-bridge response cannot
        // invoke the handler after this request is finalized (timeout,
        // disconnect bookkeeping, etc.).
        self.backend.reqresp.cancelInflightRequest(request_id);

        if (self.pending_rpc_requests.fetchRemove(request_id)) |entry| {
            var rpc_entry = entry.value;
            switch (rpc_entry.request) {
                .blocks_by_root => |block_ctx| {
                    for (block_ctx.requested_roots) |root| {
                        _ = self.removePendingBlockRoot(root);
                    }
                    // Issue #863 P3: release the in-flight slot reserved by
                    // `ensureBlocksByRootRequest`. Decrement is unconditional
                    // (success / timeout / disconnect / cancellation all flow
                    // through here).
                    _ = self.blocks_by_root_inflight.fetchSub(1, .acq_rel);
                    zeam_metrics.metrics.zeam_blocks_by_root_inflight.set(self.blocks_by_root_inflight.load(.monotonic));
                },
                .blocks_by_range => |block_ctx| {
                    const key = BlocksByRangeKey{
                        .start_slot = block_ctx.start_slot,
                        .count = block_ctx.count,
                    };
                    self.releaseBlocksByRangeActive(key);
                },
                .status => {},
            }
            rpc_entry.deinit(self.allocator);
        }
    }
};
