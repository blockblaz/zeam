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

pub const PendingRPCMap = std.AutoHashMap(u64, PendingRPC);
pub const PendingBlockRootSet = std.AutoHashMap(types.Root, void);

pub const BlocksByRootRequestResult = struct {
    peer_id: []const u8,
    request_id: u64,
};

pub const Network = struct {
    allocator: Allocator,
    backend: networks.NetworkInterface,
    connected_peers: *StringHashMap(PeerInfo),
    pending_rpc_requests: PendingRPCMap,
    pending_block_roots: PendingBlockRootSet,

    const Self = @This();

    pub fn init(allocator: Allocator, backend: networks.NetworkInterface) !Self {
        const connected_peers = try allocator.create(StringHashMap(PeerInfo));
        errdefer allocator.destroy(connected_peers);

        connected_peers.* = StringHashMap(PeerInfo).init(allocator);
        errdefer connected_peers.deinit();

        var pending_rpc_requests = PendingRPCMap.init(allocator);
        errdefer pending_rpc_requests.deinit();

        var pending_block_roots = PendingBlockRootSet.init(allocator);
        errdefer pending_block_roots.deinit();

        return Self{
            .allocator = allocator,
            .backend = backend,
            .connected_peers = connected_peers,
            .pending_rpc_requests = pending_rpc_requests,
            .pending_block_roots = pending_block_roots,
        };
    }

    pub fn deinit(self: *Self) void {
        var rpc_it = self.pending_rpc_requests.iterator();
        while (rpc_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_rpc_requests.deinit();

        self.pending_block_roots.deinit();

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
            var request_ids_to_remove = std.ArrayList(u64).init(self.allocator);
            defer request_ids_to_remove.deinit();

            while (rpc_it.next()) |rpc_entry| {
                const pending_peer_id = switch (rpc_entry.value_ptr.*) {
                    .status => |*ctx| ctx.peer_id,
                    .blocks_by_root => |*ctx| ctx.peer_id,
                };
                if (std.mem.eql(u8, pending_peer_id, peer_id)) {
                    // If we can't allocate, skip this request (should be rare)
                    request_ids_to_remove.append(rpc_entry.key_ptr.*) catch continue;
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

    pub fn trackPendingBlockRoot(self: *Self, root: types.Root) !void {
        try self.pending_block_roots.put(root, {});
    }

    pub fn removePendingBlockRoot(self: *Self, root: types.Root) bool {
        return self.pending_block_roots.remove(root);
    }

    pub fn shouldRequestBlocksByRoot(self: *Self, roots: []const types.Root) bool {
        for (roots) |root| {
            if (!self.hasPendingBlockRoot(root)) {
                return true;
            }
        }
        return false;
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

        self.pending_rpc_requests.put(request_id, pending) catch |err| {
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

        self.pending_rpc_requests.put(request_id, pending) catch |err| {
            pending.deinit(self.allocator);
            return err;
        };

        pending_owned = true;

        for (roots) |root| {
            if (self.hasPendingBlockRoot(root)) continue;
            self.trackPendingBlockRoot(root) catch |err| {
                self.finalizePendingRequest(request_id);
                return err;
            };
        }

        return request_id;
    }

    pub fn ensureBlocksByRootRequest(
        self: *Self,
        roots: []const types.Root,
        handler: networks.OnReqRespResponseCbHandler,
    ) !?BlocksByRootRequestResult {
        if (roots.len == 0) return null;

        if (!self.shouldRequestBlocksByRoot(roots)) return null;

        const peer = self.selectPeer() orelse return error.NoPeersAvailable;

        const request_id = try self.sendBlocksByRootRequest(peer, roots, handler);

        return BlocksByRootRequestResult{
            .peer_id = peer,
            .request_id = request_id,
        };
    }

    pub fn getPendingRequestPtr(self: *Self, request_id: u64) ?*PendingRPC {
        return self.pending_rpc_requests.getPtr(request_id);
    }

    pub fn finalizePendingRequest(self: *Self, request_id: u64) void {
        if (self.pending_rpc_requests.fetchRemove(request_id)) |entry| {
            var ctx = entry.value;
            switch (ctx) {
                .blocks_by_root => |block_ctx| {
                    for (block_ctx.requested_roots) |root| {
                        _ = self.removePendingBlockRoot(root);
                    }
                },
                .status => {},
            }
            ctx.deinit(self.allocator);
        }
    }
};
