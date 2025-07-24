const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");

const chains = @import("./chain.zig");
const networks = @import("./network.zig");

pub const ValidatorOpts = struct {
    // could be keys when deposit mechanism is implememted
    ids: []usize,
    chain: chains.BeamChain,
    network: networks.Network,
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

    pub fn onSlot(self: *Self, slot: usize) !void {
        const num_validators: usize = @intCast(self.config.genesis.num_validators);

        // check for block production
        const slot_proposer_id = slot % num_validators;
        if (std.mem.indexOfScalar(usize, self.opts.ids, slot_proposer_id)) |index| {
            _ = index;
            std.debug.print("\n\n\n going for block production slot={any} proposer={any}\n\n", .{ slot, slot_proposer_id });
            const block = self.opts.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id }) catch |err| {
                std.debug.print("\n\n\n block production error = {any}\n\n", .{err});
                @panic("block production error");
            };
            const signed_block = types.SignedBeamBlock{
                .message = block,
                .signature = [_]u8{0} ** 48,
            };
            std.debug.print("\n\n\n validator block production slot={any} block={any}\n\n\n", .{ slot, signed_block });
            // try self.opts.network.publish(.{ .block = signed_block });
        }
    }
};
