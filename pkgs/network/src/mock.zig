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

test "mock network publish/subscribe" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var test_logger = zeam_utils.getLogger(null, null);
    var mock_net = try Mock.init(allocator, &loop, &test_logger);
    const net_if = mock_net.getNetworkInterface();

    var received_block = false;
    const TestContext = struct {
        received_block: *bool,
    };
    var test_ctx = TestContext{ .received_block = &received_block };

    const on_gossip = struct {
        fn callback(ptr: *anyopaque, data: *const interface.GossipMessage) !void {
            const ctx: *TestContext = @ptrCast(@alignCast(ptr));
            if (data.* == .block) {
                ctx.received_block.* = true;
            }
        }
    }.callback;

    const handler = interface.OnGossipCbHandler{
        .ptr = &test_ctx,
        .onGossipCb = on_gossip,
    };

    var topics_array = [_]interface.GossipTopic{.block};
    const topics_slice = topics_array[0..];

    try net_if.gossip.subscribe(topics_slice, handler);

    const block_msg = interface.GossipMessage{
        .block = .{
            .message = .{
                .slot = 1,
                .proposer_index = 1,
                .parent_root = [_]u8{1} ** 32,
                .state_root = [_]u8{2} ** 32,
                .body = .{
                    .attestations = &.{},
                },
            },
            .signature = [_]u8{0} ** 40,
        },
    };

    try net_if.gossip.publish(&block_msg);

    // Run the event loop once to process the scheduled gossip event
    try loop.run(.once);

    try std.testing.expect(received_block == true);
}