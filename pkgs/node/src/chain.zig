const std = @import("std");
const Allocator = std.mem.Allocator;

const configs = @import("@zeam/configs");
const types = @import("@zeam/types");

pub const fcFactory = @import("./forkchoice.zig");

pub const BeamChain = struct {
    config: configs.ChainConfig,
    forkChoice: fcFactory.ForkChoice,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const fork_choice = try fcFactory.ForkChoice.init(allocator, config, anchorState);
        return Self{
            .config = config,
            .forkChoice = fork_choice,
        };
    }
};
