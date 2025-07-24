const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");

const nodeFac = @import("./node.zig");

pub const ValidatorOpts = struct {
    // could be keys when deposit mechanism is implememted
    ids: []usize,
    node: nodeFac.BeamNode,
};

pub const BeamValidator = struct {
    allocator: Allocator,
    config: configs.ChainConfig,
    opts: ValidatorOpts,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, opts: ValidatorOpts) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .opts = opts,
        };
    }

    fn onSlot(self: *Self, slot: usize) !void {
        const num_validators: usize = @intCast(self.config.genesis.num_validators);

        // check for block production
        const block_producer_id = slot % num_validators;
        if (std.mem.indexOfScalar(usize, self.ids, block_producer_id)) {
            const block = try self.opts.node.chain.produceBlock();
            const signed_block = types.SignedBeamBlock{
                .message = block,
                .signature = [_]u8{0} * 48,
            };
            try self.opts.node.publish(.{ .block = signed_block });
        }
    }
};
