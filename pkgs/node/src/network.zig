const std = @import("std");
const networks = @import("@zeam/network");
const types = @import("@zeam/types");
const params = @import("@zeam/params");
const ssz = @import("ssz");

const Allocator = std.mem.Allocator;

const NetworkBackend = union(enum) {
    mock: networks.Mock,
    ethlibp2p: networks.EthLibp2p,
};

pub const Network = struct {
    backend: networks.NetworkInterface,

    const Self = @This();
    pub fn init(backend: networks.NetworkInterface) Self {
        return Self{ .backend = backend };
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
        allocator: Allocator,
        peer_id: []const u8,
        roots: []const types.Root,
        callback: ?networks.OnReqRespResponseCbHandler,
    ) !u64 {
        if (roots.len == 0) return error.NoBlockRootsRequested;

        var request = networks.ReqRespRequest{
            .block_by_root = .{ .roots = try ssz.utils.List(types.Root, params.MAX_REQUEST_BLOCKS).init(allocator) },
        };
        errdefer request.deinit();

        for (roots) |root| {
            try request.block_by_root.roots.append(root);
        }

        const request_id = try self.backend.reqresp.sendRequest(peer_id, &request, callback);
        request.deinit();
        return request_id;
    }
};
