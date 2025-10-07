const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const jsonToString = zeam_utils.jsonToString;

const chains = @import("./chain.zig");
const networkFactory = @import("./network.zig");
const networks = @import("@zeam/network");

const constants = @import("./constants.zig");

pub const ValidatorOutput = struct {
    gossip_messages: std.ArrayList(networks.GossipMessage),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .gossip_messages = std.ArrayList(networks.GossipMessage).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.gossip_messages.deinit();
    }

    pub fn addBlock(self: *Self, signed_block: types.SignedBeamBlock) !void {
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.gossip_messages.append(gossip_msg);
    }

    pub fn addVote(self: *Self, signed_vote: types.SignedVote) !void {
        const gossip_msg = networks.GossipMessage{ .vote = signed_vote };
        try self.gossip_messages.append(gossip_msg);
    }
};

pub const ValidatorParams = struct {
    // could be keys when deposit mechanism is implemented
    ids: []usize,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
    logger: zeam_utils.ModuleLogger,
};

pub const BeamValidator = struct {
    allocator: Allocator,
    config: configs.ChainConfig,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
    ids: []usize,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, opts: ValidatorParams) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .chain = opts.chain,
            .network = opts.network,
            .ids = opts.ids,
            .logger = opts.logger,
        };
    }

    pub fn onInterval(self: *Self, time_intervals: usize) !?ValidatorOutput {
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        const interval = time_intervals % constants.INTERVALS_PER_SLOT;

        // if a new slot interval may be do a proposal
        switch (interval) {
            0 => return self.maybeDoProposal(slot),
            1 => return self.mayBeDoAttestation(slot),
            2 => return null,
            3 => return null,
            else => @panic("interval error"),
        }
    }

    pub fn maybeDoProposal(self: *Self, slot: usize) !?ValidatorOutput {
        const num_validators: usize = @intCast(self.config.genesis.num_validators);

        // check for block production
        const slot_proposer_id = slot % num_validators;
        if (std.mem.indexOfScalar(usize, self.ids, slot_proposer_id)) |index| {
            _ = index;
            self.logger.info("constructing block message slot={d} proposer={d}", .{ slot, slot_proposer_id });
            const produced_block = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id });

            const signed_block = types.SignedBeamBlock{
                .message = produced_block.block,
                .signature = [_]u8{0} ** types.SIGSIZE,
            };

            const signed_block_json = try signed_block.toJson(self.allocator);
            const block_str = try jsonToString(self.allocator, signed_block_json);
            defer self.allocator.free(block_str);

            self.logger.info("validator produced block slot={d} block={s}", .{ slot, block_str });

            // Create ValidatorOutput
            var result = ValidatorOutput.init(self.allocator);
            try result.addBlock(signed_block);
            return result;
        }
        return null;
    }

    pub fn mayBeDoAttestation(self: *Self, slot: usize) !?ValidatorOutput {
        if (self.ids.len == 0) return null;

        self.logger.info("constructing vote message for slot={d}", .{slot});
        const vote = try self.chain.constructVote(.{ .slot = slot });

        var result = ValidatorOutput.init(self.allocator);
        for (self.ids) |validator_id| {
            const signed_vote: types.SignedVote = .{
                .validator_id = validator_id,
                .message = vote,
                .signature = [_]u8{0} ** types.SIGSIZE,
            };

            try result.addVote(signed_vote);
            self.logger.info("constructed vote slot={d} validator={d}", .{ slot, validator_id });
        }
        return result;
    }
};
