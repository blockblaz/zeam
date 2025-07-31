const std = @import("std");
const Allocator = std.mem.Allocator;

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");

const utils = @import("./utils.zig");
const OnSlotCbWrapper = utils.OnSlotCbWrapper;

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");
pub const validators = @import("./validator.zig");

// TODO: find a in mem level db for this
const LevelDB = struct {};

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: types.BeamState,
    db: LevelDB,
    validator_ids: ?[]usize = null,
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validators.BeamValidator = null,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: NodeOpts) !Self {
        var mock_network: *networks.Mock = try allocator.create(networks.Mock);
        mock_network.* = try networks.Mock.init(allocator);
        const backend = mock_network.getNetworkInterface();
        std.debug.print("---\n\n mock gossip {any}\n\n", .{backend.gossip});

        const network = networkFactory.Network.init(backend);
        var validator: ?validators.BeamValidator = null;

        const chain = try allocator.create(chainFactory.BeamChain);
        chain.* = try chainFactory.BeamChain.init(allocator, opts.config, opts.anchorState);
        if (opts.validator_ids) |ids| {
            validator = validators.BeamValidator.init(allocator, opts.config, .{ .ids = ids, .chain = chain, .network = network });
        }

        return Self{
            .allocator = allocator,
            .clock = try clockFactory.Clock.init(allocator, opts.config.genesis.genesis_time),
            .chain = chain,
            .network = network,
            .validator = validator,
        };
    }

    pub fn onGossip(ptr: *anyopaque, data: *networks.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        try self.chain.onGossip(data);
    }

    pub fn getOnGossipCbHandler(self: *Self) !networks.OnGossipCbHandler {
        return .{
            .ptr = self,
            .onGossipCb = onGossip,
        };
    }

    pub fn getOnSlotCbWrapper(self: *Self) !*OnSlotCbWrapper {
        // need a stable pointer across threads
        const cb_ptr = try self.allocator.create(OnSlotCbWrapper);
        cb_ptr.* = .{
            .ptr = self,
            .onSlotCb = onSlot,
        };

        return cb_ptr;
    }

    pub fn onSlot(ptr: *anyopaque, islot: isize) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const slot: usize = @intCast(islot);

        try self.chain.onSlot(slot);
        // _ = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot });
        if (self.validator) |*validator| {
            // _ = try validator.chain.produceBlock(.{ .slot = slot, .proposer_index = slot });
            try validator.onSlot(slot);
        }
    }

    pub fn run(self: *Self) !void {
        const handler = try self.getOnGossipCbHandler();
        var topics = [_]networks.GossipTopic{.block};
        try self.network.backend.gossip.subscribe(&topics, handler);

        const chainOnSlot = try self.getOnSlotCbWrapper();
        try self.clock.subscribeOnSlot(chainOnSlot);

        // this is a blocking run
        try self.clock.run();
    }
};
