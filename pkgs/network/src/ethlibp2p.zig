const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const EthLibp2p = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn publish(ptr: *anyopaque, obj: *interface.GossipMessage) anyerror!void {
        _ = ptr;
        _ = obj;
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        _ = ptr;
        _ = topics;
        _ = handler;
    }

    pub fn onGossip(ptr: *anyopaque, data: *interface.GossipMessage) anyerror!void {
        _ = ptr;
        _ = data;
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
            .onGossipFn = onGossip,
        }, .reqresp = .{
            .ptr = self,
            .reqRespFn = reqResp,
            .onReqFn = onReq,
        } };
    }
};
