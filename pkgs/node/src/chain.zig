const std = @import("std");
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");

pub const forkchoice = @import("./forkchoice.zig");

pub const BeamChain = struct {
    config: configs.ChainConfig,
    fork_choice: forkchoice.ForkChoice,

    const Self = @This();
    pub fn init(config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const fork_choice = try forkchoice.init(config, anchorState);
        return Self{
            config,
            fork_choice,
        };
    }
};
