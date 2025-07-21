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

    pub fn publish(ptr: *anyopaque, obj: *interface.GossipMessage) anyerror!void {
        _ = ptr;
        _ = obj;
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        for (topics) |topic| {
            // handlerarr should already be there
            var handlerArr = self.onGossipHandlers.get(topic).?;
            try handlerArr.append(handler);
            try self.onGossipHandlers.put(topic, handlerArr);
        }

        // TODO: try to check the callback too remove it later
        const signed_block = types.SignedBeamBlock{
            .message = .{
                .slot = 9,
                .proposer_index = 3,
                .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
                .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
                .body = .{ .execution_payload_header = types.ExecutionPayloadHeader{ .timestamp = 23 }, .votes = &[_]types.Mini3SFVote{} },
            },
            .signature = [_]u8{2} ** 48,
        };
        var signed_block_message = interface.GossipMessage{ .block = signed_block };
        try Self.onGossip(self, &signed_block_message);
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
