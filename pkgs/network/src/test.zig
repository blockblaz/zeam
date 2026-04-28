/// Unit tests for eth2network connections and primary messaging.
/// Uses only network interface objects — no node dependencies.
const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev").Dynamic;
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const mock_mod = @import("./mock.zig");
const node_registry = @import("./node_registry.zig");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn detectBackendOrFail() !void {
    if (@hasDecl(xev, "detect")) {
        try xev.detect();
    }
}

/// Build a minimal SignedBlock for use in tests.
fn makeBlock(allocator: Allocator, slot: u64) !interface.GossipMessage {
    var attestations = try types.AggregatedAttestations.init(allocator);
    errdefer attestations.deinit();
    const sig = try types.createBlockSignatures(allocator, 0);
    return interface.GossipMessage{ .block = .{
        .block = .{
            .slot = slot,
            .proposer_index = 0,
            .parent_root = [_]u8{0xAB} ** 32,
            .state_root = [_]u8{0xCD} ** 32,
            .body = .{ .attestations = attestations },
        },
        .signature = sig,
    } };
}

/// Build a minimal attestation GossipMessage for use in tests.
fn makeAttestation(subnet_id: types.SubnetId, slot: u64, validator_id: u64) interface.GossipMessage {
    const checkpoint = types.Checkpoint{
        .root = [_]u8{0x01} ** 32,
        .slot = slot,
    };
    return interface.GossipMessage{ .attestation = .{
        .subnet_id = subnet_id,
        .message = .{
            .validator_id = @intCast(validator_id),
            .message = .{
                .slot = slot,
                .head = checkpoint,
                .target = checkpoint,
                .source = checkpoint,
            },
            .signature = [_]u8{0} ** types.SIGSIZE,
        },
    } };
}

// ---------------------------------------------------------------------------
// 1. Interface encoding tests
// ---------------------------------------------------------------------------

test "GossipEncoding encode/decode roundtrip" {
    const enc = interface.GossipEncoding.ssz_snappy;
    const decoded = try interface.GossipEncoding.decode(enc.encode());
    try testing.expectEqual(enc, decoded);
}

test "GossipEncoding decode unknown returns error" {
    try testing.expectError(error.InvalidDecoding, interface.GossipEncoding.decode("unknown_encoding"));
}

test "GossipTopic block encode/decode roundtrip" {
    const allocator = testing.allocator;
    const topic = interface.GossipTopic{ .kind = .block };
    const encoded = try topic.encode(allocator);
    defer allocator.free(encoded);
    const decoded = try interface.GossipTopic.decode(encoded);
    try testing.expectEqual(topic.kind, decoded.kind);
    try testing.expectEqual(topic.subnet_id, decoded.subnet_id);
}

test "GossipTopic aggregation encode/decode roundtrip" {
    const allocator = testing.allocator;
    const topic = interface.GossipTopic{ .kind = .aggregation };
    const encoded = try topic.encode(allocator);
    defer allocator.free(encoded);
    const decoded = try interface.GossipTopic.decode(encoded);
    try testing.expectEqual(topic.kind, decoded.kind);
}

test "GossipTopic attestation with subnet_id encode/decode roundtrip" {
    const allocator = testing.allocator;
    const topic = interface.GossipTopic{ .kind = .attestation, .subnet_id = 3 };
    const encoded = try topic.encode(allocator);
    defer allocator.free(encoded);
    const decoded = try interface.GossipTopic.decode(encoded);
    try testing.expectEqual(interface.GossipTopicKind.attestation, decoded.kind);
    try testing.expectEqual(@as(?types.SubnetId, 3), decoded.subnet_id);
}

test "GossipTopic decode unknown returns error" {
    try testing.expectError(error.InvalidDecoding, interface.GossipTopic.decode("not_a_topic"));
}

test "GossipMessage.getGossipTopic returns active tag" {
    const allocator = testing.allocator;

    var block_msg = try makeBlock(allocator, 10);
    defer block_msg.block.deinit();
    try testing.expectEqual(interface.GossipTopicKind.block, block_msg.getGossipTopic().kind);

    const att_msg = makeAttestation(0, 10, 1);
    try testing.expectEqual(interface.GossipTopicKind.attestation, att_msg.getGossipTopic().kind);
}

// ---------------------------------------------------------------------------
// 2. GenericGossipHandler — direct subscribe + deliver
// ---------------------------------------------------------------------------

test "GenericGossipHandler subscribe and deliver block message" {
    const CallTracker = struct {
        count: u32 = 0,
        last_slot: u64 = 0,

        fn onGossip(ptr: *anyopaque, msg: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count += 1;
            self.last_slot = msg.block.block.slot;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.network);

    var registry = node_registry.NodeNameRegistry.init(allocator);
    defer registry.deinit();

    var gh = try interface.GenericGossipHandler.init(allocator, &loop, 1, logger, &registry);
    defer gh.deinit();

    var tracker = CallTracker{};
    var topics = [_]interface.GossipTopic{.{ .kind = .block }};
    try gh.subscribe(&topics, tracker.handler());

    var msg = try makeBlock(allocator, 42);
    defer msg.block.deinit();
    try gh.onGossip(&msg, "test-peer", false);

    try testing.expectEqual(@as(u32, 1), tracker.count);
    try testing.expectEqual(@as(u64, 42), tracker.last_slot);
}

test "GenericGossipHandler delivers to multiple subscribers" {
    const Recv = struct {
        count: u32 = 0,

        fn onGossip(ptr: *anyopaque, _: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count += 1;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.network);

    var registry = node_registry.NodeNameRegistry.init(allocator);
    defer registry.deinit();

    var gh = try interface.GenericGossipHandler.init(allocator, &loop, 2, logger, &registry);
    defer gh.deinit();

    var r1 = Recv{};
    var r2 = Recv{};
    var topics = [_]interface.GossipTopic{.{ .kind = .block }};
    try gh.subscribe(&topics, r1.handler());
    try gh.subscribe(&topics, r2.handler());

    var msg = try makeBlock(allocator, 99);
    defer msg.block.deinit();
    try gh.onGossip(&msg, "peer-x", false);

    try testing.expectEqual(@as(u32, 1), r1.count);
    try testing.expectEqual(@as(u32, 1), r2.count);
}

test "GenericGossipHandler does not deliver to unsubscribed topic" {
    const Recv = struct {
        count: u32 = 0,

        fn onGossip(ptr: *anyopaque, _: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count += 1;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.network);

    var registry = node_registry.NodeNameRegistry.init(allocator);
    defer registry.deinit();

    var gh = try interface.GenericGossipHandler.init(allocator, &loop, 3, logger, &registry);
    defer gh.deinit();

    // Subscribe to block only
    var receiver = Recv{};
    var block_topic = [_]interface.GossipTopic{.{ .kind = .block }};
    try gh.subscribe(&block_topic, receiver.handler());

    // Publish an attestation — receiver should NOT get it
    const att_msg = makeAttestation(0, 10, 1);
    try gh.onGossip(&att_msg, "peer-y", false);

    try testing.expectEqual(@as(u32, 0), receiver.count);
}

test "GenericGossipHandler subscribe and deliver attestation message" {
    const Recv = struct {
        count: u32 = 0,
        received_slot: u64 = 0,

        fn onGossip(ptr: *anyopaque, msg: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count += 1;
            self.received_slot = msg.attestation.message.message.slot;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.network);

    var registry = node_registry.NodeNameRegistry.init(allocator);
    defer registry.deinit();

    var gh = try interface.GenericGossipHandler.init(allocator, &loop, 4, logger, &registry);
    defer gh.deinit();

    const subnet: types.SubnetId = 7;
    var receiver = Recv{};
    var att_topic = [_]interface.GossipTopic{.{ .kind = .attestation, .subnet_id = subnet }};
    try gh.subscribe(&att_topic, receiver.handler());

    const att_msg = makeAttestation(subnet, 55, 42);
    try gh.onGossip(&att_msg, "peer-z", false);

    try testing.expectEqual(@as(u32, 1), receiver.count);
    try testing.expectEqual(@as(u64, 55), receiver.received_slot);
}

// ---------------------------------------------------------------------------
// 3. Mock network — attestation gossip
// ---------------------------------------------------------------------------

test "Mock network publish attestation and receive" {
    const Recv = struct {
        count: u32 = 0,
        received_validator_id: u64 = 0,

        fn onGossip(ptr: *anyopaque, msg: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count += 1;
            self.received_validator_id = msg.attestation.message.validator_id;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.mock);

    var mock = try mock_mod.Mock.init(allocator, &loop, logger, null);
    defer mock.deinit();

    const net = mock.getNetworkInterface();
    var recv = Recv{};
    const subnet: types.SubnetId = 2;
    var topics = [_]interface.GossipTopic{.{ .kind = .attestation, .subnet_id = subnet }};
    try net.gossip.subscribe(&topics, recv.handler());

    const att_msg = makeAttestation(subnet, 77, 99);
    try net.gossip.publish(&att_msg);
    try loop.run(.until_done);

    try testing.expectEqual(@as(u32, 1), recv.count);
    try testing.expectEqual(@as(u64, 99), recv.received_validator_id);
}

test "Mock network topic isolation: block subscriber does not receive attestation" {
    const Recv = struct {
        count: u32 = 0,

        fn onGossip(ptr: *anyopaque, _: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count += 1;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.mock);

    var mock = try mock_mod.Mock.init(allocator, &loop, logger, null);
    defer mock.deinit();

    const net = mock.getNetworkInterface();

    // Subscribe to blocks only
    var block_recv = Recv{};
    var block_topics = [_]interface.GossipTopic{.{ .kind = .block }};
    try net.gossip.subscribe(&block_topics, block_recv.handler());

    // Publish attestation — block subscriber should not receive
    const att_msg = makeAttestation(0, 10, 1);
    try net.gossip.publish(&att_msg);
    try loop.run(.until_done);

    try testing.expectEqual(@as(u32, 0), block_recv.count);
}

test "Mock network multiple topics: subscriber receives only its subscribed type" {
    const BlockRecv = struct {
        count: u32 = 0,

        fn onGossip(ptr: *anyopaque, msg: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (msg.* == .block) self.count += 1;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const AttRecv = struct {
        count: u32 = 0,

        fn onGossip(ptr: *anyopaque, msg: *const interface.GossipMessage, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (msg.* == .attestation) self.count += 1;
        }

        fn handler(self: *@This()) interface.OnGossipCbHandler {
            return .{ .ptr = self, .onGossipCb = onGossip };
        }
    };

    const allocator = testing.allocator;
    try detectBackendOrFail();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.mock);

    var mock = try mock_mod.Mock.init(allocator, &loop, logger, null);
    defer mock.deinit();

    const net = mock.getNetworkInterface();

    var block_recv = BlockRecv{};
    var att_recv = AttRecv{};

    var block_topics = [_]interface.GossipTopic{.{ .kind = .block }};
    var att_topics = [_]interface.GossipTopic{.{ .kind = .attestation, .subnet_id = 0 }};
    try net.gossip.subscribe(&block_topics, block_recv.handler());
    try net.gossip.subscribe(&att_topics, att_recv.handler());

    // Publish block
    var block_msg = try makeBlock(allocator, 5);
    defer block_msg.block.deinit();
    try net.gossip.publish(&block_msg);

    // Publish attestation
    const att_msg = makeAttestation(0, 5, 1);
    try net.gossip.publish(&att_msg);

    try loop.run(.until_done);

    // Each subscriber should receive only its type
    try testing.expectEqual(@as(u32, 1), block_recv.count);
    try testing.expectEqual(@as(u32, 1), att_recv.count);
}
