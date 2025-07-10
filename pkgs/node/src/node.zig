const std = @import("std");
const Allocator = std.mem.Allocator;

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");

// TODO: find a in mem level db for this
const LevelDB = struct {};

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: types.BeamState,
    db: LevelDB,
};

pub const BeamNode = struct {
    clock: clockFactory.Clock,
    chain: chainFactory.BeamChain,
    network: networkFactory.Network,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: NodeOpts) !Self {
        var clock = try clockFactory.Clock.init(allocator, opts.config.genesis.genesis_time);
        var chain = try chainFactory.BeamChain.init(allocator, opts.config, opts.anchorState);
        const chainOnSlot = try chain.getOnSlotCbWrapper();
        try clock.subscribeOnSlot(chainOnSlot);

        return Self{
            .clock = clock,
            .chain = chain,
            .network = networkFactory.default_network,
        };
    }

    pub fn run(self: *Self) !void {
        try self.clock.run();
        // just subscribe to the block topic for now
        try self.network.backend.gossip.subscribe("block", self);
    }
};
