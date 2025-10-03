const std = @import("std");
const Allocator = std.mem.Allocator;

pub const database = @import("@zeam/database");
const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");
pub const validators = @import("./validator.zig");
const constants = @import("./constants.zig");

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: *const types.BeamState,
    backend: networks.NetworkInterface,
    clock: *clockFactory.Clock,
    validator_ids: ?[]usize = null,
    nodeId: u32 = 0,
    db: database.Db,
    logger_config: *zeam_utils.ZeamLoggerConfig,
};

pub const PeerInfo = struct {
    peer_id: []const u8,
    connected_at: i64, // timestamp in seconds
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validators.BeamValidator = null,
    nodeId: u32,
    logger: zeam_utils.ModuleLogger,
    connected_peers: *std.StringHashMap(PeerInfo),

    const Self = @This();
    pub fn init(self: *Self, allocator: Allocator, opts: NodeOpts) !void {
        var validator: ?validators.BeamValidator = null;

        // Allocate connected_peers on the heap
        const connected_peers = try allocator.create(std.StringHashMap(PeerInfo));
        connected_peers.* = std.StringHashMap(PeerInfo).init(allocator);

        const chain = try allocator.create(chainFactory.BeamChain);
        const network = networkFactory.Network.init(opts.backend);

        chain.* = try chainFactory.BeamChain.init(
            allocator,
            chainFactory.ChainOpts{
                .config = opts.config,
                .anchorState = opts.anchorState,
                .nodeId = opts.nodeId,
                .db = opts.db,
                .logger_config = opts.logger_config,
            },
            connected_peers,
        );
        if (opts.validator_ids) |ids| {
            validator = validators.BeamValidator.init(allocator, opts.config, .{ .ids = ids, .chain = chain, .network = network, .logger = opts.logger_config.logger(.validator) });
            chain.registerValidatorIds(ids);
        }

        self.* = Self{
            .allocator = allocator,
            .clock = opts.clock,
            .chain = chain,
            .network = network,
            .validator = validator,
            .nodeId = opts.nodeId,
            .logger = opts.logger_config.logger(.node),
            .connected_peers = connected_peers,
        };

        // Subscribe to peer events
        const peer_handler = self.getPeerEventHandler();
        try opts.backend.peers.subscribe(peer_handler);
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self.chain);

        // Clean up peer info
        var iter = self.connected_peers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.peer_id);
        }
        self.connected_peers.deinit();
        self.allocator.destroy(self.connected_peers);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        try self.chain.onGossip(data);
    }

    pub fn getOnGossipCbHandler(self: *Self) !networks.OnGossipCbHandler {
        return .{
            .ptr = self,
            .onGossipCb = onGossip,
        };
    }

    pub fn onPeerConnected(ptr: *anyopaque, peer_id: []const u8) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const owned_key = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_key);

        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);

        const peer_info = PeerInfo{
            .peer_id = owned_peer_id,
            .connected_at = std.time.timestamp(),
        };

        try self.connected_peers.put(owned_key, peer_info);
        self.logger.info("Peer connected: {s}, total peers: {d}", .{ peer_id, self.connected_peers.count() });
    }

    pub fn onPeerDisconnected(ptr: *anyopaque, peer_id: []const u8) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (self.connected_peers.fetchRemove(peer_id)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.peer_id);
            self.logger.info("Peer disconnected: {s}, total peers: {d}", .{ peer_id, self.connected_peers.count() });
        }
    }

    pub fn getPeerEventHandler(self: *Self) networks.OnPeerEventCbHandler {
        return .{
            .ptr = self,
            .onPeerConnectedCb = onPeerConnected,
            .onPeerDisconnectedCb = onPeerDisconnected,
        };
    }

    pub fn getOnIntervalCbWrapper(self: *Self) !*OnIntervalCbWrapper {
        // need a stable pointer across threads
        const cb_ptr = try self.allocator.create(OnIntervalCbWrapper);
        cb_ptr.* = .{
            .ptr = self,
            .onIntervalCb = onInterval,
        };

        return cb_ptr;
    }

    pub fn onInterval(ptr: *anyopaque, itime_intervals: isize) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // till its time to attest atleast for first time don't run onInterval,
        // just print chain status i.e avoid zero slot zero interval block production
        if (itime_intervals < 1) {
            const islot = @divFloor(itime_intervals, constants.INTERVALS_PER_SLOT);
            const interval = @mod(itime_intervals, constants.INTERVALS_PER_SLOT);

            if (interval == 1) {
                self.chain.printSlot(islot, self.connected_peers.count());
            }
            return;
        }
        const interval: usize = @intCast(itime_intervals);

        self.chain.onInterval(interval) catch |e| {
            self.logger.err("Error ticking chain to time(intervals)={d} err={any}", .{ interval, e });
            // no point going further if chain is not ticked properly
            return e;
        };
        if (self.validator) |*validator| {
            // we also tick validator per interval in case it would
            // need to sync its future duties when its an independent validator
            const validator_output = validator.onInterval(interval) catch |e| {
                self.logger.err("Error ticking validator to time(intervals)={d} err={any}", .{ interval, e });
                return e;
            };

            if (validator_output) |output| {
                var mutable_output = output;
                defer mutable_output.deinit();
                for (mutable_output.gossip_messages.items) |gossip_msg| {

                    // Process based on message type
                    switch (gossip_msg) {
                        .block => |signed_block| {
                            self.publishBlock(signed_block) catch |e| {
                                self.logger.err("Error publishing block from validator: err={any}", .{e});
                                return e;
                            };
                        },
                        .vote => |signed_vote| {
                            self.publishVote(signed_vote) catch |e| {
                                self.logger.err("Error publishing vote from validator: err={any}", .{e});
                                return e;
                            };
                        },
                    }
                }
            }
        }
    }

    pub fn publishBlock(self: *Self, signed_block: types.SignedBeamBlock) !void {
        // 1. publish gossip message
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.network.publish(&gossip_msg);

        self.logger.info("Published block to network: slot={d} proposer={d}", .{
            signed_block.message.slot,
            signed_block.message.proposer_index,
        });

        // 2. Process locally through chain
        var block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, signed_block.message, &block_root, self.allocator);

        // check if the block has not already been received through the network
        const hasBlock = self.chain.forkChoice.hasBlock(block_root);
        if (!hasBlock) {
            try self.chain.onBlock(signed_block, .{
                .postState = self.chain.states.get(block_root),
                .blockRoot = block_root,
            });
        } else {
            self.logger.debug("Skip adding produced block to chain as already present: slot={d} proposer={d}", .{
                signed_block.message.slot,
                signed_block.message.proposer_index,
            });
        }
    }

    pub fn publishVote(self: *Self, signed_vote: types.SignedVote) !void {
        // 1. publish gossip message
        const gossip_msg = networks.GossipMessage{ .vote = signed_vote };
        try self.network.publish(&gossip_msg);

        self.logger.info("Published vote to network: slot={d} validator={d}", .{
            signed_vote.message.slot,
            signed_vote.validator_id,
        });

        // 2. Process locally through chain
        // no need to see if we produced this vote as everything is trusted in-process lifecycle
        // validate when validator is separated out
        return self.chain.onAttestation(signed_vote);
    }

    pub fn run(self: *Self) !void {
        const handler = try self.getOnGossipCbHandler();
        var topics = [_]networks.GossipTopic{ .block, .vote };
        try self.network.backend.gossip.subscribe(&topics, handler);

        const chainOnSlot = try self.getOnIntervalCbWrapper();
        try self.clock.subscribeOnSlot(chainOnSlot);
    }
};

const xev = @import("xev");

test "Node peer tracking on connect/disconnect" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    var mock = try networks.Mock.init(allocator, &loop, logger_config.logger(.mock));
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const genesis_config = types.GenesisSpec{
        .genesis_time = 0,
        .num_validators = 4,
    };

    var anchor_state: types.BeamState = undefined;
    try anchor_state.genGenesisState(allocator, genesis_config);
    defer anchor_state.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, logger_config.logger(.database), data_dir);
    defer db.deinit();

    const spec_name = try allocator.dupe(u8, "zeamdev");
    defer allocator.free(spec_name);

    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = genesis_config,
        .spec = .{
            .preset = params.Preset.minimal,
            .name = spec_name,
        },
    };

    var clock = try clockFactory.Clock.init(allocator, genesis_config.genesis_time, &loop);
    defer clock.deinit(allocator);

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = &anchor_state,
        .backend = backend,
        .clock = &clock,
        .validator_ids = null,
        .nodeId = 0,
        .db = db,
        .logger_config = &logger_config,
    });
    defer node.deinit();

    const peer_handler = node.getPeerEventHandler();
    try backend.peers.subscribe(peer_handler);

    // Verify initial state: 0 peers
    try std.testing.expectEqual(@as(usize, 0), node.connected_peers.count());

    // Simulate peer connections by manually triggering the event handler
    const peer1_id = "PEE_POW_1";
    const peer2_id = "PEE_POW_2";
    const peer3_id = "PEE_POW_3";

    // Connect peer 1
    try mock.peerEventHandler.onPeerConnected(peer1_id);
    try std.testing.expectEqual(@as(usize, 1), node.connected_peers.count());

    // Connect peer 2
    try mock.peerEventHandler.onPeerConnected(peer2_id);
    try std.testing.expectEqual(@as(usize, 2), node.connected_peers.count());

    // Connect peer 3
    try mock.peerEventHandler.onPeerConnected(peer3_id);
    try std.testing.expectEqual(@as(usize, 3), node.connected_peers.count());

    // Verify peer 1 exists
    try std.testing.expect(node.connected_peers.contains(peer1_id));

    // Disconnect peer 2
    try mock.peerEventHandler.onPeerDisconnected(peer2_id);
    try std.testing.expectEqual(@as(usize, 2), node.connected_peers.count());
    try std.testing.expect(!node.connected_peers.contains(peer2_id));

    // Disconnect peer 1
    try mock.peerEventHandler.onPeerDisconnected(peer1_id);
    try std.testing.expectEqual(@as(usize, 1), node.connected_peers.count());
    try std.testing.expect(!node.connected_peers.contains(peer1_id));

    // Verify peer 3 is still connected
    try std.testing.expect(node.connected_peers.contains(peer3_id));

    // Disconnect peer 3
    try mock.peerEventHandler.onPeerDisconnected(peer3_id);
    try std.testing.expectEqual(@as(usize, 0), node.connected_peers.count());
}
