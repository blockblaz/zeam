const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

export fn handleMsgFromRustBridge(zigHandler: *EthLibp2p, message_ptr: [*]const u8, message_len: usize) void {
    const message: []const u8 = message_ptr[0..message_len];
    _ = message;
    _ = zigHandler;
}

// TODO: change listen port and connect port both to list of multiaddrs
pub extern fn createAndRunNetwork(a: *EthLibp2p, listenPort: i32, connectPort: i32) u32;
pub extern fn publishMsgToRustBridge(message_ptr: [*]const u8, message_len: usize) void;

pub const EthLibp2pParams = struct {
    port: isize,
    // TODO convert into array multiaddrs
    // right now just take a connect peer port for testing ease
    peers: isize,
};

pub const EthLibp2p = struct {
    gossipHandler: interface.GenericGossipHandler,
    params: EthLibp2pParams,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthLibp2pParams,
    ) !Self {
        return Self{ .params = params, .gossipHandler = try interface.GenericGossipHandler.init(allocator, loop) };
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.subscribe(topics, handler);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data);
    }

    pub fn reqResp(ptr: *anyopaque, obj: *interface.ReqRespRequest) anyerror!void {
        _ = ptr;
        _ = obj;
    }

    pub fn onReq(ptr: *anyopaque, data: *interface.ReqRespRequest) anyerror!void {
        _ = ptr;
        _ = data;
    }

    pub fn getNetworkInterface(self: *Self) NetworkInterface {
        return .{ .gossip = .{
            .ptr = self,
            .publishFn = publish,
            .subscribeFn = subscribe,
            .onGossipFn = onGossip,
        }, .reqresp = .{
            .ptr = self,
            .reqRespFn = reqResp,
            .onReqFn = onReq,
        } };
    }
};
