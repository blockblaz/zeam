const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const mock = @import("./mock.zig");

// Test data factory functions
fn createTestSignedBeamBlock(slot: u64) types.SignedBeamBlock {
    return types.SignedBeamBlock{
        .message = .{
            .slot = slot,
            .proposer_index = 1,
            .parent_root = [_]u8{0x01} ** 32,
            .state_root = [_]u8{0x02} ** 32,
            .body = .{
                .attestations = &[_]types.SignedVote{},
            },
        },
        .signature = [_]u8{0x03} ** types.SIGSIZE,
    };
}

fn createTestSignedVote(slot: u64, validator_id: u64) types.SignedVote {
    return types.SignedVote{
        .validator_id = validator_id,
        .message = .{
            .slot = slot,
            .head = .{ .root = [_]u8{0x04} ** 32, .slot = slot },
            .target = .{ .root = [_]u8{0x05} ** 32, .slot = slot },
            .source = .{ .root = [_]u8{0x06} ** 32, .slot = slot - 1 },
        },
        .signature = [_]u8{0x07} ** types.SIGSIZE,
    };
}

fn createTestGossipMessage(message_type: interface.GossipTopic, slot: u64) interface.GossipMessage {
    return switch (message_type) {
        .block => .{ .block = createTestSignedBeamBlock(slot) },
        .vote => .{ .vote = createTestSignedVote(slot, TestConstants.DEFAULT_VALIDATOR_ID) },
    };
}

fn createTestReqRespRequest() interface.ReqRespRequest {
    const roots = [_]types.Root{[_]u8{0x08} ** 32};
    return .{ .block_by_root = .{ .roots = @constCast(&roots) } };
}

// Test fixture for reducing setup/teardown duplication
const TestFixture = struct {
    allocator: Allocator,
    loop: xev.Loop,
    test_logger: zeam_utils.ZeamLogger,

    const Self = @This();

    pub fn init() !Self {
        const allocator = testing.allocator;
        const loop = try xev.Loop.init(.{});
        const test_logger = zeam_utils.getTestLogger();

        return Self{
            .allocator = allocator,
            .loop = loop,
            .test_logger = test_logger,
        };
    }

    pub fn deinit(self: *Self) void {
        self.loop.deinit();
    }

    pub fn createGossipHandler(self: *Self, network_id: u32) !interface.GenericGossipHandler {
        return interface.GenericGossipHandler.init(self.allocator, &self.loop, network_id, &self.test_logger);
    }

    pub fn createMockNetwork(self: *Self) !mock.Mock {
        return mock.Mock.init(self.allocator, &self.loop, &self.test_logger);
    }

    pub fn cleanupGossipHandler(self: *Self, handler: *interface.GenericGossipHandler) void {
        _ = self;
        var iter = handler.onGossipHandlers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        handler.onGossipHandlers.deinit();
        handler.timer.deinit();
    }

    pub fn cleanupMockNetwork(self: *Self, network: *mock.Mock) void {
        _ = self;
        var iter = network.gossipHandler.onGossipHandlers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        network.gossipHandler.onGossipHandlers.deinit();
        network.gossipHandler.timer.deinit();
    }
};

// Test constants to eliminate magic numbers
const TestConstants = struct {
    const DEFAULT_SLOT: u64 = 100;
    const DEFAULT_NETWORK_ID: u32 = 1;
    const DEFAULT_VALIDATOR_ID: u64 = 1;
    const TEST_SLOTS = struct {
        const SLOT_1: u64 = 50;
        const SLOT_2: u64 = 200;
        const SLOT_3: u64 = 300;
        const SLOT_4: u64 = 400;
        const SLOT_5: u64 = 500;
        const WORKFLOW_START: u64 = 1000;
        const WORKFLOW_VOTE: u64 = 1001;
        const WORKFLOW_BLOCK2: u64 = 1002;
        const WORKFLOW_VOTE2: u64 = 1003;
    };
};

// Test helper for message reception tracking
const TestMessageReceiver = struct {
    received_messages: std.ArrayList(interface.GossipMessage),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .received_messages = std.ArrayList(interface.GossipMessage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.received_messages.deinit();
    }

    pub fn onGossipCallback(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const cloned_message = try data.clone(self.allocator);
        defer self.allocator.destroy(cloned_message);
        try self.received_messages.append(cloned_message.*);
    }

    pub fn getHandler(self: *Self) interface.OnGossipCbHandler {
        return .{
            .ptr = self,
            .onGossipCb = onGossipCallback,
        };
    }

    pub fn getReceivedCount(self: *const Self) usize {
        return self.received_messages.items.len;
    }

    pub fn getLastMessage(self: *const Self) ?interface.GossipMessage {
        if (self.received_messages.items.len == 0) return null;
        return self.received_messages.items[self.received_messages.items.len - 1];
    }
};

// ============================================================================
// UNIT TESTS FOR GOSSIP TOPIC PARSING
// ============================================================================

test "GossipTopic.parseTopic - valid topics" {
    try testing.expect(interface.GossipTopic.parseTopic("block") == .block);
    try testing.expect(interface.GossipTopic.parseTopic("vote") == .vote);
}

test "GossipTopic.parseTopic - invalid topic" {
    try testing.expect(interface.GossipTopic.parseTopic("invalid") == null);
    try testing.expect(interface.GossipTopic.parseTopic("") == null);
}

// ============================================================================
// UNIT TESTS FOR GOSSIP MESSAGE OPERATIONS
// ============================================================================

test "GossipMessage.getTopic - block message" {
    const block_message = createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);
    try testing.expect(block_message.getTopic() == .block);
}

test "GossipMessage.getTopic - vote message" {
    const vote_message = createTestGossipMessage(.vote, TestConstants.DEFAULT_SLOT);
    try testing.expect(vote_message.getTopic() == .vote);
}

test "GossipMessage.clone - block message" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    const original = createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);

    const cloned = try original.clone(fixture.allocator);
    defer fixture.allocator.destroy(cloned);

    try testing.expect(cloned.getTopic() == original.getTopic());
    try testing.expect(cloned.block.message.slot == original.block.message.slot);
    try testing.expect(cloned.block.message.proposer_index == original.block.message.proposer_index);
    try testing.expectEqualSlices(u8, &cloned.block.message.parent_root, &original.block.message.parent_root);
}

test "GossipMessage.clone - vote message" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    const original = createTestGossipMessage(.vote, TestConstants.DEFAULT_SLOT);

    const cloned = try original.clone(fixture.allocator);
    defer fixture.allocator.destroy(cloned);

    try testing.expect(cloned.getTopic() == original.getTopic());
    try testing.expect(cloned.vote.validator_id == original.vote.validator_id);
    try testing.expect(cloned.vote.message.slot == original.vote.message.slot);
    try testing.expectEqualSlices(u8, &cloned.vote.message.head.root, &original.vote.message.head.root);
}

// ============================================================================
// UNIT TESTS FOR GENERIC GOSSIP HANDLER
// ============================================================================

test "GenericGossipHandler.init - successful initialization" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer fixture.cleanupGossipHandler(&handler);

    try testing.expect(handler.networkId == TestConstants.DEFAULT_NETWORK_ID);
    try testing.expect(handler.onGossipHandlers.count() == 2); // block and vote topics
}

test "GenericGossipHandler.subscribe - single topic subscription" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer fixture.cleanupGossipHandler(&handler);

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{.block};
    try handler.subscribe(@constCast(&topics), receiver.getHandler());

    const block_handlers = handler.onGossipHandlers.get(.block).?;
    try testing.expect(block_handlers.items.len == 1);

    const vote_handlers = handler.onGossipHandlers.get(.vote).?;
    try testing.expect(vote_handlers.items.len == 0);
}

test "GenericGossipHandler.subscribe - multiple topic subscription" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer fixture.cleanupGossipHandler(&handler);

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{ .block, .vote };
    try handler.subscribe(@constCast(&topics), receiver.getHandler());

    const block_handlers = handler.onGossipHandlers.get(.block).?;
    try testing.expect(block_handlers.items.len == 1);

    const vote_handlers = handler.onGossipHandlers.get(.vote).?;
    try testing.expect(vote_handlers.items.len == 1);
}

test "GenericGossipHandler.onGossip - block message delivery" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer fixture.cleanupGossipHandler(&handler);

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{.block};
    try handler.subscribe(@constCast(&topics), receiver.getHandler());

    const test_message = createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);
    try handler.onGossip(&test_message, false);

    try testing.expect(receiver.getReceivedCount() == 1);

    const received = receiver.getLastMessage().?;
    try testing.expect(received.getTopic() == .block);
    try testing.expect(received.block.message.slot == TestConstants.DEFAULT_SLOT);
}

test "GenericGossipHandler.onGossip - vote message delivery" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer fixture.cleanupGossipHandler(&handler);

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{.vote};
    try handler.subscribe(@constCast(&topics), receiver.getHandler());

    const test_message = createTestGossipMessage(.vote, TestConstants.TEST_SLOTS.SLOT_1);
    try handler.onGossip(&test_message, false);

    try testing.expect(receiver.getReceivedCount() == 1);

    const received = receiver.getLastMessage().?;
    try testing.expect(received.getTopic() == .vote);
    try testing.expect(received.vote.message.slot == TestConstants.TEST_SLOTS.SLOT_1);
}

test "GenericGossipHandler.onGossip - multiple subscribers" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer fixture.cleanupGossipHandler(&handler);

    var receiver1 = TestMessageReceiver.init(fixture.allocator);
    defer receiver1.deinit();
    var receiver2 = TestMessageReceiver.init(fixture.allocator);
    defer receiver2.deinit();

    const topics = [_]interface.GossipTopic{.block};
    try handler.subscribe(@constCast(&topics), receiver1.getHandler());
    try handler.subscribe(@constCast(&topics), receiver2.getHandler());

    const test_message = createTestGossipMessage(.block, TestConstants.TEST_SLOTS.SLOT_2);
    try handler.onGossip(&test_message, false);

    try testing.expect(receiver1.getReceivedCount() == 1);
    try testing.expect(receiver2.getReceivedCount() == 1);

    try testing.expect(receiver1.getLastMessage().?.block.message.slot == TestConstants.TEST_SLOTS.SLOT_2);
    try testing.expect(receiver2.getLastMessage().?.block.message.slot == TestConstants.TEST_SLOTS.SLOT_2);
}

// ============================================================================
// UNIT TESTS FOR NETWORK INTERFACE ABSTRACTION
// ============================================================================

test "GossipSub interface - publish and subscribe" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_network = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&mock_network);

    const network_interface = mock_network.getNetworkInterface();

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{.block};
    try network_interface.gossip.subscribe(@constCast(&topics), receiver.getHandler());

    const test_message = createTestGossipMessage(.block, TestConstants.TEST_SLOTS.SLOT_2);
    try network_interface.gossip.publish(&test_message);

    try testing.expect(receiver.getReceivedCount() == 1);
    try testing.expect(receiver.getLastMessage().?.block.message.slot == TestConstants.TEST_SLOTS.SLOT_2);
}

test "ReqResp interface - basic request handling" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_network = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&mock_network);

    const network_interface = mock_network.getNetworkInterface();
    const test_request = createTestReqRespRequest();

    // This should not error (basic smoke test for now since reqResp is stub)
    _ = network_interface.reqresp.reqRespFn(network_interface.reqresp.ptr, @constCast(&test_request)) catch {};
    _ = network_interface.reqresp.onReqFn(network_interface.reqresp.ptr, @constCast(&test_request)) catch {};
}

// ============================================================================
// UNIT TESTS FOR MOCK NETWORK IMPLEMENTATION
// ============================================================================

test "Mock.init - successful initialization" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_network = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&mock_network);

    try testing.expect(mock_network.gossipHandler.networkId == 0);
}

test "Mock network - end-to-end message flow" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_network = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&mock_network);

    const network_interface = mock_network.getNetworkInterface();

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    // Subscribe to both topics
    const topics = [_]interface.GossipTopic{ .block, .vote };
    try network_interface.gossip.subscribe(@constCast(&topics), receiver.getHandler());

    // Publish block message
    const block_message = createTestGossipMessage(.block, TestConstants.TEST_SLOTS.SLOT_3);
    try network_interface.gossip.publish(&block_message);

    // Publish vote message
    const vote_message = createTestGossipMessage(.vote, TestConstants.TEST_SLOTS.SLOT_3);
    try network_interface.gossip.publish(&vote_message);

    try testing.expect(receiver.getReceivedCount() == 2);
}

// ============================================================================
// UNIT TESTS FOR CONNECTION SCENARIOS
// ============================================================================

test "Network interface - multiple mock networks communication simulation" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    // Create two mock networks
    var network1 = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&network1);

    var network2 = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&network2);

    const interface1 = network1.getNetworkInterface();
    const interface2 = network2.getNetworkInterface();

    var receiver1 = TestMessageReceiver.init(fixture.allocator);
    defer receiver1.deinit();
    var receiver2 = TestMessageReceiver.init(fixture.allocator);
    defer receiver2.deinit();

    // Subscribe receivers to their respective networks
    const topics = [_]interface.GossipTopic{.block};
    try interface1.gossip.subscribe(@constCast(&topics), receiver1.getHandler());
    try interface2.gossip.subscribe(@constCast(&topics), receiver2.getHandler());

    // Simulate cross-network message forwarding by manually calling onGossip
    const test_message = createTestGossipMessage(.block, TestConstants.TEST_SLOTS.SLOT_4);

    // Message published on network1
    try interface1.gossip.publish(&test_message);
    // Simulate network1 forwarding to network2
    try interface2.gossip.onGossipFn(interface2.gossip.ptr, @constCast(&test_message));

    try testing.expect(receiver1.getReceivedCount() == 1);
    try testing.expect(receiver2.getReceivedCount() == 1);

    try testing.expect(receiver1.getLastMessage().?.block.message.slot == TestConstants.TEST_SLOTS.SLOT_4);
    try testing.expect(receiver2.getLastMessage().?.block.message.slot == TestConstants.TEST_SLOTS.SLOT_4);
}

test "Network interface - message filtering by topic subscription" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_network = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&mock_network);

    const network_interface = mock_network.getNetworkInterface();

    var block_receiver = TestMessageReceiver.init(fixture.allocator);
    defer block_receiver.deinit();
    var vote_receiver = TestMessageReceiver.init(fixture.allocator);
    defer vote_receiver.deinit();

    // Subscribe to different topics
    const block_topics = [_]interface.GossipTopic{.block};
    const vote_topics = [_]interface.GossipTopic{.vote};
    try network_interface.gossip.subscribe(@constCast(&block_topics), block_receiver.getHandler());
    try network_interface.gossip.subscribe(@constCast(&vote_topics), vote_receiver.getHandler());

    // Publish messages of both types
    const block_message = createTestGossipMessage(.block, TestConstants.TEST_SLOTS.SLOT_5);
    const vote_message = createTestGossipMessage(.vote, TestConstants.TEST_SLOTS.SLOT_5);

    try network_interface.gossip.publish(&block_message);
    try network_interface.gossip.publish(&vote_message);

    // Verify filtering - each receiver should only get their subscribed topic
    try testing.expect(block_receiver.getReceivedCount() == 1);
    try testing.expect(vote_receiver.getReceivedCount() == 1);

    try testing.expect(block_receiver.getLastMessage().?.getTopic() == .block);
    try testing.expect(vote_receiver.getLastMessage().?.getTopic() == .vote);
}

// ============================================================================
// UNIT TESTS FOR ERROR HANDLING AND EDGE CASES
// ============================================================================

test "OnGossipCbHandler - error handling in callback" {
    const ErrorHandler = struct {
        fn errorCallback(_: *anyopaque, _: *const interface.GossipMessage) anyerror!void {
            return error.TestError;
        }
    };

    var dummy_ptr: u8 = 0;
    const handler = interface.OnGossipCbHandler{
        .ptr = &dummy_ptr,
        .onGossipCb = ErrorHandler.errorCallback,
    };

    const test_message = createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);

    // Should return the error from callback
    try testing.expectError(error.TestError, handler.onGossip(&test_message));
}

test "GossipMessage operations - memory management" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    // Test that clone properly allocates and we can free it
    const original = createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);
    const cloned = try original.clone(fixture.allocator);

    // Verify it's a different memory location
    try testing.expect(&original != cloned);
    try testing.expect(&original.block != &cloned.block);

    // Clean up
    fixture.allocator.destroy(cloned);
}

// ============================================================================
// INTEGRATION TEST FOR COMPLETE WORKFLOW
// ============================================================================

test "Complete network workflow - publish, subscribe, receive" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_network = try fixture.createMockNetwork();
    defer fixture.cleanupMockNetwork(&mock_network);

    const network_interface = mock_network.getNetworkInterface();

    // Setup multiple receivers for comprehensive testing
    var block_receiver1 = TestMessageReceiver.init(fixture.allocator);
    defer block_receiver1.deinit();
    var block_receiver2 = TestMessageReceiver.init(fixture.allocator);
    defer block_receiver2.deinit();
    var vote_receiver = TestMessageReceiver.init(fixture.allocator);
    defer vote_receiver.deinit();

    // Subscribe to topics
    const block_topics = [_]interface.GossipTopic{.block};
    const all_topics = [_]interface.GossipTopic{ .block, .vote };

    try network_interface.gossip.subscribe(@constCast(&block_topics), block_receiver1.getHandler());
    try network_interface.gossip.subscribe(@constCast(&block_topics), block_receiver2.getHandler());
    try network_interface.gossip.subscribe(@constCast(&all_topics), vote_receiver.getHandler());

    // Publish various messages
    const messages = [_]interface.GossipMessage{
        createTestGossipMessage(.block, TestConstants.TEST_SLOTS.WORKFLOW_START),
        createTestGossipMessage(.vote, TestConstants.TEST_SLOTS.WORKFLOW_VOTE),
        createTestGossipMessage(.block, TestConstants.TEST_SLOTS.WORKFLOW_BLOCK2),
        createTestGossipMessage(.vote, TestConstants.TEST_SLOTS.WORKFLOW_VOTE2),
    };

    for (messages) |message| {
        try network_interface.gossip.publish(&message);
    }

    // Verify message distribution
    try testing.expect(block_receiver1.getReceivedCount() == 2); // 2 blocks
    try testing.expect(block_receiver2.getReceivedCount() == 2); // 2 blocks
    try testing.expect(vote_receiver.getReceivedCount() == 4); // all messages (subscribed to both topics)

    // Verify message ordering and content
    try testing.expect(block_receiver1.received_messages.items[0].block.message.slot == TestConstants.TEST_SLOTS.WORKFLOW_START);
    try testing.expect(block_receiver1.received_messages.items[1].block.message.slot == TestConstants.TEST_SLOTS.WORKFLOW_BLOCK2);

    try testing.expect(vote_receiver.received_messages.items[0].block.message.slot == TestConstants.TEST_SLOTS.WORKFLOW_START);
    try testing.expect(vote_receiver.received_messages.items[1].vote.message.slot == TestConstants.TEST_SLOTS.WORKFLOW_VOTE);
    try testing.expect(vote_receiver.received_messages.items[2].block.message.slot == TestConstants.TEST_SLOTS.WORKFLOW_BLOCK2);
    try testing.expect(vote_receiver.received_messages.items[3].vote.message.slot == TestConstants.TEST_SLOTS.WORKFLOW_VOTE2);
}
