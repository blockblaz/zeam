const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const EthLibp2p = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn publish(ptr: *anyopaque, comptime T: type, obj: *anyopaque) anyerror!void {
        _ = ptr;
        _ = T;
        _ = obj;
    }

    pub fn onGossip(ptr: *anyopaque, data: []const u8) anyerror!void {
        _ = ptr;
        _ = data;
    }

    pub fn reqResp(ptr: *anyopaque, comptime T: type, obj: *anyopaque) anyerror!void {
        _ = ptr;
        _ = T;
        _ = obj;
    }

    pub fn onReq(ptr: *anyopaque, data: []const u8) anyerror!void {
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
