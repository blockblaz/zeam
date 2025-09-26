const std = @import("std");
const Allocator = std.mem.Allocator;

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

// TODO: find a in mem level db for this
const LevelDB = struct {};

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: *const types.BeamState,
    backend: networks.NetworkInterface,
    clock: *clockFactory.Clock,
    db: LevelDB,
    validator_ids: ?[]usize = null,
    nodeId: u32 = 0,
    logger_config: *zeam_utils.ZeamLoggerConfig,
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validators.BeamValidator = null,
    nodeId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: NodeOpts) !Self {
        var validator: ?validators.BeamValidator = null;

        const chain = try allocator.create(chainFactory.BeamChain);
        const network = networkFactory.Network.init(opts.backend);

        chain.* = try chainFactory.BeamChain.init(
            allocator,
            chainFactory.ChainOpts{
                .config = opts.config,
                .anchorState = opts.anchorState,
                .nodeId = opts.nodeId,
                .logger_config = opts.logger_config,
            },
        );
        if (opts.validator_ids) |ids| {
            validator = validators.BeamValidator.init(allocator, opts.config, .{ .ids = ids, .chain = chain, .network = network, .logger = opts.logger_config.logger(.validator) });
            chain.registerValidatorIds(ids);
        }

        return Self{
            .allocator = allocator,
            .clock = opts.clock,
            .chain = chain,
            .network = network,
            .validator = validator,
            .nodeId = opts.nodeId,
            .logger = opts.logger_config.logger(.node),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self.chain);
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

    pub fn getOnIntervalCbWrapper(self: *Self) !*OnIntervalCbWrapper {
        // need a stable pointer across threads
        const cb_ptr = try self.allocator.create(OnIntervalCbWrapper);
        cb_ptr.* = .{
            .ptr = self,
            .onIntervalCb = onInterval,
        };

        return cb_ptr;
    }

    pub fn onInterval(ptr: *anyopaque, iinterval: isize) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const interval: usize = @intCast(iinterval);

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
        try self.chain.onBlock(signed_block, .{
            .postState = self.chain.states.get(block_root),
            .blockRoot = block_root,
        });
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
