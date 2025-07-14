const std = @import("std");
const Allocator = std.mem.Allocator;

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const Mock = struct {
    onGossipHandlers: std.ArrayList(interface.OnGossipCbHandler),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .onGossipHandlers = std.ArrayList(interface.OnGossipCbHandler).init(allocator),
        };
    }

    pub fn publish(ptr: *anyopaque, obj: *anyopaque) anyerror!void {
        _ = ptr;
        // _ = T;
        _ = obj;
    }

    pub fn subscribe(ptr: *anyopaque, topic: []const u8, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        try self.onGossipHandlers.append(handler);

        // try to check the callback too remove it later
        try Self.onGossip(self, topic);
        // _ = topic;
        // _ = handler;
    }

    pub fn onGossip(ptr: *anyopaque, data: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        for (self.onGossipHandlers.items) |handler| {
            try handler.onGossip(data);
        }
    }

    pub fn reqResp(ptr: *anyopaque, obj: *anyopaque) anyerror!void {
        _ = ptr;
        // _ = T;
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
