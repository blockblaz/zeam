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
        switch (interval) {
            0 => return self.maybeDoProposal(slot),
            1 => return self.mayBeDoAttestation(slot),
            2 => {},
            3 => {},
            else => @panic("interval error"),
        }
    }

    pub fn maybeDoProposal(self: *Self, slot: usize) !void {
        const num_validators: usize = @intCast(self.config.genesis.num_validators);

        // check for block production
        const slot_proposer_id = slot % num_validators;
        if (std.mem.indexOfScalar(usize, self.ids, slot_proposer_id)) |index| {
            _ = index;
            std.debug.print("constructing block message slot={any} proposer={any}\n", .{ slot, slot_proposer_id });
            const block = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id });

            const signed_block = types.SignedBeamBlock{
                .message = block,
                .signature = [_]u8{0} ** 48,
            };
            const signed_block_message = networks.GossipMessage{ .block = signed_block };
            std.debug.print("validator block production slot={any} block={any}\n", .{ slot, signed_block_message });
            // publish block is right now a no-op however move gossip message construction and publish there
            try self.chain.publishBlock(signed_block);
            try self.network.publish(&signed_block_message);
        }
    }

    pub fn mayBeDoAttestation(self: *Self, slot: usize) !void {
        if (self.ids.len == 0) return;

        std.debug.print("constructing vote message for slot={any}\n", .{slot});
        const vote = try self.chain.constructVote(.{ .slot = slot });

        for (self.ids) |validator_id| {
            const signed_vote: types.SignedVote = .{
                .validator_id = validator_id,
                .message = vote,
                .signature = [_]u8{0} ** 48,
            };

            const signed_vote_message = networks.GossipMessage{ .vote = signed_vote };
            std.debug.print("validator construced vote slot={any} vote={any}\n", .{ slot, signed_vote_message });
            try self.chain.publishVote(signed_vote);
            // move gossip message construction and publish to publishVote
            try self.network.publish(&signed_vote_message);
        }
    }
};
