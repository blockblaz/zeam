const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");

const chains = @import("./chain.zig");
const networkFactory = @import("./network.zig");
const networks = @import("@zeam/network");

const constants = @import("./constants.zig");

pub const ValidatorParams = struct {
    // could be keys when deposit mechanism is implemented
    ids: []usize,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
};

pub const BeamValidator = struct {
    allocator: Allocator,
    config: configs.ChainConfig,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
    ids: []usize,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, opts: ValidatorParams) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .chain = opts.chain,
            .network = opts.network,
            .ids = opts.ids,
        };
    }

    pub fn onInterval(self: *Self, time_intervals: usize) !void {
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        const interval = time_intervals % constants.INTERVALS_PER_SLOT;

        // if a new slot interval may be do a proposal
        if (interval == 0) {
            return maybeDoProposal(self, slot);
        }
    }

    pub fn maybeDoProposal(self: *Self, slot: usize) !void {
        const num_validators: usize = @intCast(self.config.genesis.num_validators);

        // check for block production
        const slot_proposer_id = slot % num_validators;
        if (std.mem.indexOfScalar(usize, self.ids, slot_proposer_id)) |index| {
            std.debug.print("\n\n\n going for block production slot={any} proposer={any} index={any}\n\n", .{ slot, slot_proposer_id, index });
            const block = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id });

            const signed_block = types.SignedBeamBlock{
                .message = block,
                .signature = [_]u8{0} ** 48,
            };
            const signed_block_message = try self.allocator.create(networks.GossipMessage);
            signed_block_message.* = networks.GossipMessage{ .block = signed_block };
            std.debug.print("\n\n\n validator block production slot={any} block={any}\n\n\n", .{ slot, signed_block_message });
            try self.network.publish(signed_block_message);
        }
    }
};
