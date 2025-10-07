const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const Mock = struct {
    gossipHandler: interface.GenericGossipHandler,
    peerEventHandler: interface.PeerEventHandler,
    const Self = @This();

    pub fn init(allocator: Allocator, loop: *xev.Loop, logger: zeam_utils.ModuleLogger) !Self {
        const gossip_handler = try interface.GenericGossipHandler.init(allocator, loop, 0, logger);
        errdefer gossip_handler.deinit();

        const peer_event_handler = try interface.PeerEventHandler.init(allocator, 0, logger);
        errdefer peer_event_handler.deinit();

        return Self{
            .gossipHandler = gossip_handler,
            .peerEventHandler = peer_event_handler,
        };
    }

    pub fn deinit(self: *Self) void {
        self.gossipHandler.deinit();
        self.peerEventHandler.deinit();
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

    pub fn subscribePeerEvents(ptr: *anyopaque, handler: interface.OnPeerEventCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.peerEventHandler.subscribe(handler);
    }

    pub fn getNetworkInterface(self: *Self) NetworkInterface {
        return .{
            .gossip = .{
                .ptr = self,
                .publishFn = publish,
                .subscribeFn = subscribe,
                .onGossipFn = onGossip,
            },
            .reqresp = .{
                .ptr = self,
                .reqRespFn = reqResp,
                .onReqFn = onReq,
            },
            .peers = .{
                .ptr = self,
                .subscribeFn = subscribePeerEvents,
            },
        };
    }
};

test "Mock messaging across two subscribers" {
    const TestSubscriber = struct {
        calls: u32 = 0,
        received_message: ?interface.GossipMessage = null,

        fn onGossip(ptr: *anyopaque, message: *const interface.GossipMessage) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            self.received_message = message.*;
        }

        fn getCallbackHandler(self: *@This()) interface.OnGossipCbHandler {
            return .{
                .ptr = self,
                .onGossipCb = onGossip,
            };
        }
    };
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.mock);
    var mock = try Mock.init(allocator, &loop, logger);

    // Create test subscribers with embedded data
    var subscriber1 = TestSubscriber{};
    var subscriber2 = TestSubscriber{};

    // Both subscribers subscribe to the same block topic using the complete network interface
    var topics = [_]interface.GossipTopic{.block};
    const network = mock.getNetworkInterface();
    try network.gossip.subscribe(&topics, subscriber1.getCallbackHandler());
    try network.gossip.subscribe(&topics, subscriber2.getCallbackHandler());

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
                .attestations = try types.SignedVotes.init(allocator),
            },
        },
        .signature = [_]u8{3} ** types.SIGSIZE,
    } };

    // Publish the message using the network interface - both subscribers should receive it
    try network.gossip.publish(block_message);

    // Run the event loop to process scheduled callbacks
    try loop.run(.until_done);

    // Verify both subscribers received the message
    try std.testing.expect(subscriber1.calls == 1);
    try std.testing.expect(subscriber2.calls == 1);

    // Verify both subscribers received the same message content
    try std.testing.expect(subscriber1.received_message != null);
    try std.testing.expect(subscriber2.received_message != null);

    const received1 = subscriber1.received_message.?;
    const received2 = subscriber2.received_message.?;

    // Verify both received block messages
    try std.testing.expect(received1 == .block);
    try std.testing.expect(received2 == .block);

    // Verify the block content is identical
    try std.testing.expect(std.mem.eql(u8, &received1.block.message.parent_root, &received2.block.message.parent_root));
    try std.testing.expect(std.mem.eql(u8, &received1.block.message.state_root, &received2.block.message.state_root));
    try std.testing.expect(received1.block.message.slot == received2.block.message.slot);
    try std.testing.expect(received1.block.message.proposer_index == received2.block.message.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &received1.block.signature, &received2.block.signature));
}
