const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const jsonToString = zeam_utils.jsonToString;
const key_manager_lib = @import("@zeam/key-manager");

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
    key_manager: *const key_manager_lib.KeyManager,
};

pub const ValidatorClient = struct {
    allocator: Allocator,
    config: configs.ChainConfig,
    chain: *chains.BeamChain,
    network: networkFactory.Network,
    ids: []usize,
    logger: zeam_utils.ModuleLogger,
    key_manager: *const key_manager_lib.KeyManager,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, opts: ValidatorClientParams) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .chain = opts.chain,
            .network = opts.network,
            .ids = opts.ids,
            .logger = opts.logger,
            .key_manager = opts.key_manager,
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
        const num_validators: usize = @intCast(self.config.genesis.numValidators());
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
            // Check if chain is synced before producing a block
            const sync_status = self.chain.getSyncStatus();
            switch (sync_status) {
                .synced => {},
                .no_peers => {
                    self.logger.warn("skipping block production for slot={d} proposer={d}: no peers connected", .{ slot, slot_proposer_id });
                    return null;
                },
                .behind_peers => |info| {
                    self.logger.warn("skipping block production for slot={d} proposer={d}: behind peers (head_slot={d}, finalized_slot={d}, max_peer_finalized_slot={d})", .{
                        slot,
                        slot_proposer_id,
                        info.head_slot,
                        info.finalized_slot,
                        info.max_peer_finalized_slot,
                    });
                    return null;
                },
            }

            // 1. construct the block
            self.logger.debug("constructing block message & proposer attestation data for slot={d} proposer={d}", .{ slot, slot_proposer_id });
            const produced_block = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id });
            self.logger.info("produced block for slot={d} proposer={d} with root={s}", .{ slot, slot_proposer_id, std.fmt.fmtSliceHexLower(&produced_block.blockRoot) });

            // 2. construct proposer attestation for the produced block which should already be in forkchoice
            // including its attestations
            const proposer_attestation_data = try self.chain.constructAttestationData(.{ .slot = slot });
            const proposer_attestation = types.Attestation{
                .validator_id = slot_proposer_id,
                .data = proposer_attestation_data,
            };
            const attestation_str = try proposer_attestation_data.toJsonString(self.allocator);
            defer self.allocator.free(attestation_str);
            self.logger.info("packing proposer attestation for slot={d} proposer={d}: {s}", .{ slot, slot_proposer_id, attestation_str });

            // 3. construct the message to be signed
            const block_with_attestation = types.BlockWithAttestation{
                .block = produced_block.block,
                .proposer_attestation = proposer_attestation,
            };

            // 4. Sign proposer attestation and build block signatures from the already-aggregated
            //    attestation signatures returned by block production.
            const proposer_signature = try self.key_manager.signAttestation(&proposer_attestation, self.allocator);
            const signatures = types.BlockSignatures{
                .attestation_signatures = produced_block.attestation_signatures,
                .proposer_signature = proposer_signature,
            };

            const signed_block = types.SignedBlockWithAttestation{
                .message = block_with_attestation,
                .signature = signatures,
            };

            self.logger.info("signed produced block with attestation for slot={d} root={s}", .{ slot, std.fmt.fmtSliceHexLower(&produced_block.blockRoot) });

            // 6. Create ValidatorOutput
            var result = ValidatorClientOutput.init(self.allocator);
            try result.addBlock(signed_block);
            return result;
        }
        return null;
    }

    pub fn mayBeDoAttestation(self: *Self, slot: usize) !?ValidatorClientOutput {
        if (self.ids.len == 0) return null;

        // Check if chain is synced before producing attestations
        const sync_status = self.chain.getSyncStatus();
        switch (sync_status) {
            .synced => {},
            .no_peers => {
                self.logger.warn("skipping attestation production for slot={d}: no peers connected", .{slot});
                return null;
            },
            .behind_peers => |info| {
                self.logger.warn("skipping attestation production for slot={d}: behind peers (head_slot={d}, finalized_slot={d}, max_peer_finalized_slot={d})", .{
                    slot,
                    info.head_slot,
                    info.finalized_slot,
                    info.max_peer_finalized_slot,
                });
                return null;
            },
        }

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

            // Sign the attestation using keymanager
            const signature = try self.key_manager.signAttestation(&attestation, self.allocator);

            const signed_attestation: types.SignedAttestation = .{
                .validator_id = validator_id,
                .message = attestation_data,
                .signature = signature,
            };

            try result.addAttestation(signed_attestation);
            self.logger.info("constructed attestation slot={d} validator={d}", .{ slot, validator_id });
        }
        return result;
    }
};
