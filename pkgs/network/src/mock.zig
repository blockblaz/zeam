const std = @import("std");
const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const Mock = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn publish(ptr: *anyopaque, comptime T: type, obj: *anyopaque) anyerror!void {
        _ = ptr;
        _ = T;
        _ = obj;
    }

    pub fn subscribe(ptr: *anyopaque, topic: []const u8, handler: *anyopaque) anyerror!void {
        // std.debug.print("TTTTTTTTTTTTTTTTTT = {any} handler={any} \n", .{ topic, handler });
        _ = ptr;
        _ = topic;
        _ = handler;
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
            .subscribeFn = subscribe,
            .onGossipFn = onGossip,
        }, .reqresp = .{
            .ptr = self,
            .reqRespFn = reqResp,
            .onReqFn = onReq,
        } };
    }
};
