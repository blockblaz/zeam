const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const Mock = struct {
    gossipHandler: interface.GenericGossipHandler,
    const Self = @This();

    pub fn init(allocator: Allocator, loop: *xev.Loop, logger: *const zeam_utils.ZeamLogger) !Self {
        return Self{ .gossipHandler = try interface.GenericGossipHandler.init(allocator, loop, 0, logger) };
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        // TODO: prevent from publishing to self handler
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, true);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.subscribe(topics, handler);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, true);
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

test "Mock messaging across two subscribers" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger = zeam_utils.getTestLogger();
    var mock = try Mock.init(allocator, &loop, &logger);

    // Track calls and capture received messages
    var subscriber1_calls: u32 = 0;
    var subscriber2_calls: u32 = 0;
    var subscriber1_received_message: ?interface.GossipMessage = null;
    var subscriber2_received_message: ?interface.GossipMessage = null;

    // Inline callback functions
    const subscriber1_callback = struct {
        fn onGossip(ptr: *anyopaque, message: *const interface.GossipMessage) anyerror!void {
            const data: *struct { calls: *u32, received: *?interface.GossipMessage } = @ptrCast(@alignCast(ptr));
            data.calls.* += 1;
            data.received.* = message.*;
        }
    }.onGossip;

    const subscriber2_callback = struct {
        fn onGossip(ptr: *anyopaque, message: *const interface.GossipMessage) anyerror!void {
            const data: *struct { calls: *u32, received: *?interface.GossipMessage } = @ptrCast(@alignCast(ptr));
            data.calls.* += 1;
            data.received.* = message.*;
        }
    }.onGossip;

    // Both subscribers subscribe to the same block topic
    var topics = [_]interface.GossipTopic{.block};
    var subscriber1_data = struct { calls: *u32, received: *?interface.GossipMessage }{ .calls = &subscriber1_calls, .received = &subscriber1_received_message };
    var subscriber2_data = struct { calls: *u32, received: *?interface.GossipMessage }{ .calls = &subscriber2_calls, .received = &subscriber2_received_message };

    try Mock.subscribe(@ptrCast(&mock), &topics, .{
        .ptr = &subscriber1_data,
        .onGossipCb = subscriber1_callback,
    });
    try Mock.subscribe(@ptrCast(&mock), &topics, .{
        .ptr = &subscriber2_data,
        .onGossipCb = subscriber2_callback,
    });

    // Create a simple block message
    const block_message = try allocator.create(interface.GossipMessage);
    defer allocator.destroy(block_message);
    block_message.* = .{ .block = .{
        .message = .{
            .slot = 1,
            .proposer_index = 0,
            .parent_root = [_]u8{1} ** 32,
            .state_root = [_]u8{2} ** 32,
            .body = .{
                .attestations = &[_]types.SignedVote{},
            },
        },
        .signature = [_]u8{3} ** types.SIGSIZE,
    } };
}
