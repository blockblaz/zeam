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

pub const ValidatorClientOutput = struct {
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

    pub fn addBlock(self: *Self, signed_block: types.SignedBlockWithAttestation) !void {
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.gossip_messages.append(gossip_msg);
    }

    pub fn addAttestation(self: *Self, signed_attestation: types.SignedAttestation) !void {
        const gossip_msg = networks.GossipMessage{ .attestation = signed_attestation };
        try self.gossip_messages.append(gossip_msg);
    }
};

pub const ValidatorClientParams = struct {
    // could be keys when deposit mechanism is implemented
    ids: []usize,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
    logger: zeam_utils.ModuleLogger,
};

pub const ValidatorClient = struct {
    allocator: Allocator,
    config: configs.ChainConfig,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
    ids: []usize,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, opts: ValidatorClientParams) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .chain = opts.chain,
            .network = opts.network,
            .ids = opts.ids,
            .logger = opts.logger,
        };
    }

    pub fn onInterval(self: *Self, time_intervals: usize) !?ValidatorClientOutput {
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

    pub fn getSlotProposer(self: *Self, slot: usize) ?usize {
        const num_validators: usize = @intCast(self.config.genesis.num_validators);
        const slot_proposer_id = slot % num_validators;
        if (std.mem.indexOfScalar(usize, self.ids, slot_proposer_id)) |index| {
            _ = index;
            return slot_proposer_id;
        } else {
            return null;
        }
    }

    pub fn maybeDoProposal(self: *Self, slot: usize) !?ValidatorClientOutput {
        if (self.getSlotProposer(slot)) |slot_proposer_id| {
            // 1. construct the block
            self.logger.info("constructing block message slot={d} proposer={d}", .{ slot, slot_proposer_id });
            const produced_block = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id });

            // 2. construct proposer attestation for the produced block which should already be in forkchoice
            // including its attestations
            const proposer_attestation_data = try self.chain.constructAttestationData(.{ .slot = slot });
            const proposer_attestation = types.Attestation{
                .validator_id = slot_proposer_id,
                .data = proposer_attestation_data,
            };

            // 3. construct the message to be signed
            const block_with_attestation = types.BlockWithAttestation{
                .block = produced_block.block,
                .proposer_attestation = proposer_attestation,
            };

            // 4. proposer signature which is currently over just proposer_attestation but will eventually
            //  be over the full message when the leanVM signature validation is introduced which can validate
            //  the proposer_attestation with that combined signature
            const signed_block = types.SignedBlockWithAttestation{
                .message = block_with_attestation,
                .signature = try types.createBlockSignatures(self.allocator, produced_block.block.body.attestations.len()),
            };

            const signed_block_json = try signed_block.toJson(self.allocator);
            const block_str = try jsonToString(self.allocator, signed_block_json);
            defer self.allocator.free(block_str);

            self.logger.info("validator produced block slot={d} block={s}", .{ slot, block_str });

            // Create ValidatorOutput
            var result = ValidatorClientOutput.init(self.allocator);
            try result.addBlock(signed_block);
            return result;
        }
        return null;
    }

    pub fn mayBeDoAttestation(self: *Self, slot: usize) !?ValidatorClientOutput {
        if (self.ids.len == 0) return null;
        const slot_proposer_id = self.getSlotProposer(slot);

        self.logger.info("constructing attestation message for slot={d}", .{slot});
        const attestation_data = try self.chain.constructAttestationData(.{ .slot = slot });

        var result = ValidatorClientOutput.init(self.allocator);
        for (self.ids) |validator_id| {
            // if this validator had proposal its vote would have already been casted
            // with the block proposal
            if (validator_id == slot_proposer_id) {
                self.logger.info("skipping separate attestation for proposer slot={d} validator={d}", .{ slot, validator_id });
                continue;
            }

            const attestation: types.Attestation = .{
                .validator_id = validator_id,
                .data = attestation_data,
            };
            const signed_attestation: types.SignedAttestation = .{
                .message = attestation,
                .signature = [_]u8{0} ** types.SIGSIZE,
            };

            try result.addAttestation(signed_attestation);
            self.logger.info("constructed attestation slot={d} validator={d}", .{ slot, validator_id });
        }
        return result;
    }
};
