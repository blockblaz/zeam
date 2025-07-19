const std = @import("std");
const Allocator = std.mem.Allocator;

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");

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
    allocator: Allocator,
    clock: clockFactory.Clock,
    chain: chainFactory.BeamChain,
    network: networkFactory.Network,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: NodeOpts) !Self {
        var clock = try clockFactory.Clock.init(allocator, opts.config.genesis.genesis_time);
        var chain = try chainFactory.BeamChain.init(allocator, opts.config, opts.anchorState);

        var mock_network: networks.Mock = try networks.Mock.init(allocator);
        const backend = mock_network.getNetworkInterface();
        std.debug.print("---\n\n mock gossip {any}\n\n", .{backend.gossip});

        const network = networkFactory.Network.init(backend);

        const chainOnSlot = try chain.getOnSlotCbWrapper();
        try clock.subscribeOnSlot(chainOnSlot);

        return Self{
            .allocator = allocator,
            .clock = clock,
            .chain = chain,
            .network = network,
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

    pub fn run(self: *Self) !void {
        const handler = try self.getOnGossipCbHandler();
        var topics = [_]networks.GossipTopic{.block};
        try self.network.backend.gossip.subscribe(&topics, handler);

        // this is a blocking run
        try self.clock.run();
    }
};
