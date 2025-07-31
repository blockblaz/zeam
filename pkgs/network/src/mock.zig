const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const Mock = struct {
    onGossipHandlers: std.AutoHashMap(interface.GossipTopic, std.ArrayList(interface.OnGossipCbHandler)),

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var onGossipHandlers = std.AutoHashMap(interface.GossipTopic, std.ArrayList(interface.OnGossipCbHandler)).init(allocator);
        for (std.enums.values(interface.GossipTopic)) |topic| {
            try onGossipHandlers.put(topic, std.ArrayList(interface.OnGossipCbHandler).init(allocator));
        }
        return Self{
            .onGossipHandlers = onGossipHandlers,
        };
    }

    pub fn publish(ptr: *anyopaque, data: *interface.GossipMessage) anyerror!void {
        // TODO: prevent from publishing to self handler
        return Self.onGossip(ptr, data);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        for (topics) |topic| {
            // handlerarr should already be there
            var handlerArr = self.onGossipHandlers.get(topic).?;
            try handlerArr.append(handler);
            try self.onGossipHandlers.put(topic, handlerArr);
        }
    }

    pub fn onGossip(ptr: *anyopaque, data: *interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const topic = data.getTopic();
        const handlerArr = self.onGossipHandlers.get(topic).?;
        std.debug.print("\n\n\n ongossip handlerarr {any} for topic {any}\n", .{ handlerArr.items, topic });
        for (handlerArr.items) |handler| {
            try handler.onGossip(data);
        }
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
