const std = @import("std");

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");

// TODO: find a in mem level db for this
const LevelDB = struct {};

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: ?types.BeamChain,
    db: LevelDB,
};

pub const BeamNode = struct {
    clock: clockFactory.Clock,
    chain: chainFactory.BeamChain,

    const Self = @This();
    pub fn init(opts: NodeOpts) !Self {
        const clock = try clockFactory.Clock.init(opts.config);
        const chain = try chainFactory.BeamChain.init(opts.config, opts.anchorState);

        return Self{
            clock,
            chain,
        };
    }
};
