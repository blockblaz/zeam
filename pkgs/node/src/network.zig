const std = @import("std");
const networks = @import("@zeam/network");
const types = @import("@zeam/types");
const params = @import("@zeam/params");
const ssz = @import("ssz");

const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;

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

pub const PendingRPCMap = std.AutoHashMap(u64, PendingRPCEntry);
// key: block root, value: depth
pub const PendingBlockRootMap = std.AutoHashMap(types.Root, u32);
// key: block root, value: pointer to block
pub const FetchedBlockMap = std.AutoHashMap(types.Root, *types.SignedBlockWithAttestation);
// key: parent root, value: list of child roots (for O(1) child lookup)
pub const ChildrenMap = std.AutoHashMap(types.Root, std.ArrayList(types.Root));

pub const BlocksByRootRequestResult = struct {
    peer_id: []const u8,
    request_id: u64,
};

pub const Network = struct {
    allocator: Allocator,
    backend: networks.NetworkInterface,
    connected_peers: *StringHashMap(PeerInfo),
    pending_rpc_requests: PendingRPCMap,
    pending_block_roots: PendingBlockRootMap,
    fetched_blocks: FetchedBlockMap,
    fetched_block_children: ChildrenMap,
    timed_out_requests: std.ArrayList(u64),

    const Self = @This();

    pub fn init(allocator: Allocator, backend: networks.NetworkInterface) !Self {
        const connected_peers = try allocator.create(StringHashMap(PeerInfo));
        errdefer allocator.destroy(connected_peers);

        connected_peers.* = StringHashMap(PeerInfo).init(allocator);
        errdefer connected_peers.deinit();

        var pending_rpc_requests = PendingRPCMap.init(allocator);
        errdefer pending_rpc_requests.deinit();

        var pending_block_roots = PendingBlockRootMap.init(allocator);
        errdefer pending_block_roots.deinit();

        var fetched_blocks = FetchedBlockMap.init(allocator);
        errdefer fetched_blocks.deinit();

        var fetched_block_children = ChildrenMap.init(allocator);
        errdefer fetched_block_children.deinit();

        return Self{
            .allocator = allocator,
            .backend = backend,
            .connected_peers = connected_peers,
            .pending_rpc_requests = pending_rpc_requests,
            .pending_block_roots = pending_block_roots,
            .fetched_blocks = fetched_blocks,
            .fetched_block_children = fetched_block_children,
            .timed_out_requests = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.timed_out_requests.deinit(self.allocator);

        var rpc_it = self.pending_rpc_requests.iterator();
        while (rpc_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_rpc_requests.deinit();

        self.pending_block_roots.deinit();

        var fetched_it = self.fetched_blocks.iterator();
        while (fetched_it.next()) |entry| {
            var block_ptr = entry.value_ptr.*;
            block_ptr.deinit();
            self.allocator.destroy(block_ptr);
        }
        self.fetched_blocks.deinit();

        var children_it = self.fetched_block_children.iterator();
        while (children_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.fetched_block_children.deinit();

        var peer_it = self.connected_peers.iterator();
        while (peer_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.peer_id);
        }
        self.connected_peers.deinit();
        self.allocator.destroy(self.connected_peers);
    }

    pub fn publish(self: *Self, data: *const networks.GossipMessage) !void {
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
            .blocks_by_root = try types.BlockByRootRequest.init(self.allocator),
        };
        errdefer request.deinit();

        for (roots) |root| {
            try request.blocks_by_root.append(root);
        }

        const request_id = try self.backend.reqresp.sendRequest(peer_id, &request, callback);
        request.deinit();
        return request_id;
    }

    pub fn selectPeer(self: *Self) ?[]const u8 {
        const peer_count = self.connected_peers.count();
        if (peer_count == 0) return null;

        const target_index = std.crypto.random.uintLessThan(usize, peer_count);

        var it = self.connected_peers.iterator();
        var current_index: usize = 0;
        while (it.next()) |entry| : (current_index += 1) {
            if (current_index == target_index) {
                return entry.value_ptr.peer_id;
            }
        }

        return null;
    }

    pub fn getPeerCount(self: *Self) usize {
        return self.connected_peers.count();
    }

    pub fn hasPeer(self: *Self, peer_id: []const u8) bool {
        return self.connected_peers.contains(peer_id);
    }

    pub fn setPeerLatestStatus(self: *Self, peer_id: []const u8, status: types.Status) bool {
        if (self.connected_peers.getPtr(peer_id)) |peer_info| {
            peer_info.latest_status = status;
            return true;
        }
        return false;
    }

    pub fn connectPeer(self: *Self, peer_id: []const u8) !void {
        if (self.connected_peers.fetchRemove(peer_id)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.peer_id);
        }

        const owned_key = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_key);

        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);

        const peer_info = PeerInfo{
            .peer_id = owned_peer_id,
            .connected_at = std.time.timestamp(),
        };

        self.connected_peers.put(owned_key, peer_info) catch |err| {
            self.allocator.free(owned_peer_id);
            return err;
        };
    }

    pub fn disconnectPeer(self: *Self, peer_id: []const u8) bool {
        if (self.connected_peers.fetchRemove(peer_id)) |peer_entry| {
            self.allocator.free(peer_entry.key);
            self.allocator.free(peer_entry.value.peer_id);

            // Finalize all pending RPC requests for this peer
            var rpc_it = self.pending_rpc_requests.iterator();
            var request_ids_to_remove: std.ArrayList(u64) = .empty;
            defer request_ids_to_remove.deinit(self.allocator);

            while (rpc_it.next()) |rpc_entry| {
                const pending_peer_id = switch (rpc_entry.value_ptr.request) {
                    .status => |*ctx| ctx.peer_id,
                    .blocks_by_root => |*ctx| ctx.peer_id,
                };
                if (std.mem.eql(u8, pending_peer_id, peer_id)) {
                    // If we can't allocate, skip this request (should be rare)
                    request_ids_to_remove.append(self.allocator, rpc_entry.key_ptr.*) catch continue;
                }
            }

            for (request_ids_to_remove.items) |request_id| {
                self.finalizePendingRequest(request_id);
            }

            return true;
        }
        return false;
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
        return self.fetched_blocks.get(root) != null;
    }

    pub fn getFetchedBlock(self: *Self, root: types.Root) ?*types.SignedBlockWithAttestation {
        return self.fetched_blocks.get(root);
    }

    pub fn cacheFetchedBlock(self: *Self, root: types.Root, block: *types.SignedBlockWithAttestation) !void {
        const block_gop = try self.fetched_blocks.getOrPut(root);

        // If we already have this block cached, free the duplicate and return early
        if (block_gop.found_existing) {
            block.deinit();
            self.allocator.destroy(block);
            return;
        }

        block_gop.value_ptr.* = block;
        errdefer {
            _ = self.fetched_blocks.remove(root);
            block.deinit();
            self.allocator.destroy(block);
        }

        const parent_root = block.message.block.parent_root;
        const gop = try self.fetched_block_children.getOrPut(parent_root);

        const created_new_entry = !gop.found_existing;
        if (created_new_entry) {
            gop.value_ptr.* = .empty;
        }
        errdefer if (created_new_entry) {
            gop.value_ptr.deinit(self.allocator);
            _ = self.fetched_block_children.remove(parent_root);
        };
        try gop.value_ptr.append(self.allocator, root);
    }

    pub fn removeFetchedBlock(self: *Self, root: types.Root) bool {
        if (self.fetched_blocks.fetchRemove(root)) |entry| {
            var block_ptr = entry.value;

            // Remove this block from its parent's children list
            const parent_root = block_ptr.message.block.parent_root;
            if (self.fetched_block_children.getPtr(parent_root)) |children_list| {
                // Find and remove this root from the parent's children list
                for (children_list.items, 0..) |child_root, i| {
                    if (std.mem.eql(u8, child_root[0..], root[0..])) {
                        _ = children_list.swapRemove(i);
                        break;
                    }
                }
                // Clean up the parent entry if no children remain
                if (children_list.items.len == 0) {
                    children_list.deinit(self.allocator);
                    _ = self.fetched_block_children.remove(parent_root);
                }
            }

            block_ptr.deinit();
            self.allocator.destroy(block_ptr);
            return true;
        }
        return false;
    }

    /// Returns the cached children of the given parent block root.
    /// This is O(1) lookup instead of iterating over all fetched blocks.
    pub fn getChildrenOfBlock(self: *Self, parent_root: types.Root) []const types.Root {
        if (self.fetched_block_children.get(parent_root)) |children_list| {
            return children_list.items;
        }
        return &[_]types.Root{};
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

        var to_remove = std.AutoArrayHashMap(types.Root, void).init(self.allocator);
        defer to_remove.deinit();

        to_remove.put(root, {}) catch return 0;

        // Walk up: traverse parent chain and add all cached ancestors
        var current = root;
        while (self.getFetchedBlock(current)) |block_ptr| {
            const parent_root = block_ptr.message.block.parent_root;
            if (self.hasFetchedBlock(parent_root)) {
                to_remove.put(parent_root, {}) catch break;
                current = parent_root;
            } else {
                break;
            }
        }

        // Walk down: process entries, expanding children as we go.
        // We iterate by index since new entries may be appended during iteration.
        var i: usize = 0;
        while (i < to_remove.count()) : (i += 1) {
            const current_root = to_remove.keys()[i];

            // Enqueue children before removing (since removal modifies the children map)
            const children_slice = self.getChildrenOfBlock(current_root);
            for (children_slice) |child_root| {
                // When pruning due to finalization, keep children that are on
                // the finalized chain (matching root at or after finalized slot).
                if (finalized_checkpoint) |fc| {
                    if (self.getFetchedBlock(child_root)) |child_block| {
                        if (child_block.message.block.slot >= fc.slot and
                            std.mem.eql(u8, &child_root, &fc.root))
                        {
                            // This child is the finalized block — skip it (keep it and its descendants)
                            continue;
                        }
                    }
                }
                to_remove.put(child_root, {}) catch continue;
            }
        }

        // Remove all collected roots
        var pruned: usize = 0;
        for (to_remove.keys()) |entry_root| {
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
            .created_at = std.time.timestamp(),
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
            .created_at = std.time.timestamp(),
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

        const peer = self.selectPeer() orelse return error.NoPeersAvailable;

        const request_id = try self.sendBlocksByRootRequest(peer, roots, depth, handler);

        return BlocksByRootRequestResult{
            .peer_id = peer,
            .request_id = request_id,
        };
    }

    pub fn getPendingRequestPtr(self: *Self, request_id: u64) ?*PendingRPCEntry {
        return self.pending_rpc_requests.getPtr(request_id);
    }

    pub fn getTimedOutRequests(self: *Self, current_time: i64, timeout_seconds: i64) ![]const u64 {
        self.timed_out_requests.clearAndFree(self.allocator);
        var it = self.pending_rpc_requests.iterator();
        while (it.next()) |entry| {
            if (current_time - entry.value_ptr.created_at >= timeout_seconds) {
                try self.timed_out_requests.append(self.allocator, entry.key_ptr.*);
            }
        }
        return self.timed_out_requests.items;
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
