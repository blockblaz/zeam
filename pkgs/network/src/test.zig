const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

// Test-only stub to satisfy FFI symbol referenced by EthLibp2p.publish.
// test.zig is only compiled in the test build, so exporting here is safe.
export fn publish_msg_to_rust_bridge(_: u32, _: [*:0]const u8, _: [*]const u8, _: usize) void {}

const ssz = @import("ssz");
const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const mock = @import("./mock.zig");
const ethlibp2p = @import("./ethlibp2p.zig");

// Test data factory functions
fn createTestSignedBeamBlock(slot: u64) !types.SignedBeamBlock {
    return types.SignedBeamBlock{
        .message = .{
            .slot = slot,
            .proposer_index = 1,
            .parent_root = [_]u8{0x01} ** 32,
            .state_root = [_]u8{0x02} ** 32,
            .body = .{
                .attestations = try types.SignedVotes.init(testing.allocator),
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

fn createTestGossipMessage(message_type: interface.GossipTopic, slot: u64) !interface.GossipMessage {
    return switch (message_type) {
        .block => .{ .block = try createTestSignedBeamBlock(slot) },
        .vote => .{ .vote = createTestSignedVote(slot, TestConstants.DEFAULT_VALIDATOR_ID) },
    };
}

// Test fixture for reducing setup/teardown duplication
const TestFixture = struct {
    allocator: Allocator,
    loop: xev.Loop,
    test_logger_config: zeam_utils.ZeamLoggerConfig,

    const Self = @This();

    pub fn init() !Self {
        const allocator = testing.allocator;
        const loop = try xev.Loop.init(.{});
        const test_logger_config = zeam_utils.getTestLoggerConfig();

        return Self{
            .allocator = allocator,
            .loop = loop,
            .test_logger_config = test_logger_config,
        };
    }

    pub fn deinit(self: *Self) void {
        self.loop.deinit();
    }

    pub fn createGossipHandler(self: *Self, network_id: u32) !interface.GenericGossipHandler {
        return interface.GenericGossipHandler.init(self.allocator, &self.loop, network_id, self.test_logger_config.logger(.network));
    }

    pub fn createMockNetwork(self: *Self) !mock.Mock {
        return mock.Mock.init(self.allocator, &self.loop, self.test_logger_config.logger(.network));
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
        // Deinit any inner allocations inside stored messages
        for (self.received_messages.items) |*m| {
            switch (m.*) {
                .block => m.block.deinit(),
                .vote => {},
            }
        }
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

// =========================================================================
// Interface helpers
// =========================================================================

test "GossipEncoding encode/decode roundtrip" {
    try testing.expectEqual(interface.GossipEncoding.ssz_snappy, try interface.GossipEncoding.decode(interface.GossipEncoding.ssz_snappy.encode()));
}

test "GossipTopic encode/decode roundtrip" {
    try testing.expectEqual(interface.GossipTopic.block, try interface.GossipTopic.decode(interface.GossipTopic.block.encode()));
    try testing.expectEqual(interface.GossipTopic.vote, try interface.GossipTopic.decode(interface.GossipTopic.vote.encode()));
}

test "GossipMessage.getGossipTopic returns active tag" {
    const m1 = try createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);
    try testing.expectEqual(interface.GossipTopic.block, m1.getGossipTopic());
    const m2 = try createTestGossipMessage(.vote, TestConstants.DEFAULT_SLOT);
    try testing.expectEqual(interface.GossipTopic.vote, m2.getGossipTopic());
}

// =========================================================================
// GenericGossipHandler
// =========================================================================

test "GenericGossipHandler subscribe and deliver (block)" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var handler = try fixture.createGossipHandler(TestConstants.DEFAULT_NETWORK_ID);
    defer handler.deinit();

    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{.block};
    try handler.subscribe(@constCast(&topics), receiver.getHandler());

    const msg = try createTestGossipMessage(.block, TestConstants.DEFAULT_SLOT);
    try handler.onGossip(&msg, false);
    try testing.expectEqual(@as(usize, 1), receiver.getReceivedCount());
    try testing.expectEqual(interface.GossipTopic.block, receiver.getLastMessage().?.getGossipTopic());
}

// =========================================================================
// Mock network smoke tests (kept minimal)
// =========================================================================

test "Mock network publish->receive" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var mock_net = try fixture.createMockNetwork();
    defer mock_net.gossipHandler.deinit();

    const iface = mock_net.getNetworkInterface();
    var receiver = TestMessageReceiver.init(fixture.allocator);
    defer receiver.deinit();

    const topics = [_]interface.GossipTopic{ .block, .vote };
    try iface.gossip.subscribe(@constCast(&topics), receiver.getHandler());

    const msg1 = try createTestGossipMessage(.block, TestConstants.TEST_SLOTS.SLOT_2);
    const msg2 = try createTestGossipMessage(.vote, TestConstants.TEST_SLOTS.SLOT_3);
    try iface.gossip.publish(&msg1);
    try iface.gossip.publish(&msg2);
    try testing.expectEqual(@as(usize, 2), receiver.getReceivedCount());
}

// =========================================================================
// EthLibp2p tests: focus on subscription and inbound message handling
// =========================================================================

test "EthLibp2p subscribe and handle inbound block via bridge" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const logger = zeam_logger_config.logger(.network);

    // Minimal params: we will NOT call run() to avoid spawning threads in unit tests
    const Multiaddr = @import("multiformats").multiaddr.Multiaddr;
    // No actual network thread; provide empty listen addresses
    const listen_addrs = try testing.allocator.alloc(Multiaddr, 0);

    const params = ethlibp2p.EthLibp2pParams{
        .networkId = 7,
        .network_name = try testing.allocator.dupe(u8, "devnet0"),
        .local_private_key = try testing.allocator.dupe(u8, "000102030405"),
        .listen_addresses = listen_addrs,
        .connect_peers = null,
    };
    // Ownership of params fields is released to EthLibp2p and freed in deinit

    var handler = try ethlibp2p.EthLibp2p.init(testing.allocator, &fixture.loop, params, logger);
    defer handler.deinit();

    const iface = handler.getNetworkInterface();
    var receiver = TestMessageReceiver.init(testing.allocator);
    defer receiver.deinit();
    const topics = [_]interface.GossipTopic{.block};
    try iface.gossip.subscribe(@constCast(&topics), receiver.getHandler());

    // Simulate inbound gossip via public NetworkInterface without bridge
    var msg = try createTestGossipMessage(.block, 12345);
    defer msg.block.deinit();
    try iface.gossip.onGossipFn(iface.gossip.ptr, &msg);

    try testing.expectEqual(@as(usize, 1), receiver.getReceivedCount());
    try testing.expectEqual(interface.GossipTopic.block, receiver.getLastMessage().?.getGossipTopic());
    try testing.expectEqual(@as(u64, 12345), receiver.getLastMessage().?.block.message.slot);
}

test "EthLibp2p subscribe and handle inbound vote via bridge" {
    var fixture = try TestFixture.init();
    defer fixture.deinit();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const logger = zeam_logger_config.logger(.network);

    const Multiaddr = @import("multiformats").multiaddr.Multiaddr;
    const listen_addrs = try testing.allocator.alloc(Multiaddr, 0);

    const params = ethlibp2p.EthLibp2pParams{
        .networkId = 8,
        .network_name = try testing.allocator.dupe(u8, "devnet0"),
        .local_private_key = try testing.allocator.dupe(u8, "000102030405"),
        .listen_addresses = listen_addrs,
        .connect_peers = null,
    };
    // Ownership managed by EthLibp2p

    var handler = try ethlibp2p.EthLibp2p.init(testing.allocator, &fixture.loop, params, logger);
    defer handler.deinit();

    const iface = handler.getNetworkInterface();
    var receiver = TestMessageReceiver.init(testing.allocator);
    defer receiver.deinit();
    const topics = [_]interface.GossipTopic{.vote};
    try iface.gossip.subscribe(@constCast(&topics), receiver.getHandler());

    var msg = try createTestGossipMessage(.vote, 222);
    try iface.gossip.onGossipFn(iface.gossip.ptr, &msg);

    try testing.expectEqual(@as(usize, 1), receiver.getReceivedCount());
    try testing.expectEqual(interface.GossipTopic.vote, receiver.getLastMessage().?.getGossipTopic());
    try testing.expectEqual(@as(u64, 222), receiver.getLastMessage().?.vote.message.slot);
}
