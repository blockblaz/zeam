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
const zeam_metrics = @import("@zeam/metrics");

const constants = @import("./constants.zig");

pub const ValidatorClientOutput = struct {
    allocator: Allocator,
    gossip_messages: std.ArrayList(networks.GossipMessage),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .gossip_messages = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.gossip_messages.items) |*gossip_msg| {
            switch (gossip_msg.*) {
                .aggregation => |*signed_aggregation| signed_aggregation.deinit(),
                else => {},
            }
        }
        self.gossip_messages.deinit(self.allocator);
    }

    pub fn addBlock(self: *Self, signed_block: types.SignedBlock) !void {
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.gossip_messages.append(self.allocator, gossip_msg);
    }

    pub fn addAttestation(self: *Self, subnet_id: types.SubnetId, signed_attestation: types.SignedAttestation) !void {
        var cloned_attestation: types.SignedAttestation = undefined;
        try types.sszClone(self.allocator, types.SignedAttestation, signed_attestation, &cloned_attestation);
        const gossip_msg = networks.GossipMessage{ .attestation = .{ .subnet_id = subnet_id, .message = cloned_attestation } };
        try self.gossip_messages.append(self.allocator, gossip_msg);
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
            4 => return null,
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
                .fc_initing => {
                    self.logger.info("skipping block production for slot={d} proposer={d}: forkchoice still initing (awaiting first justified checkpoint)", .{ slot, slot_proposer_id });
                    return null;
                },
                .no_peers => {
                    // A validator has a duty to propose at its assigned slot regardless of
                    // peer connectivity. The block is self-imported (advancing local
                    // fork-choice and persisted to DB) and will be gossiped once peers
                    // connect. This also enables reqresp tests that isolate zeam from
                    // the gossip mesh while still expecting block production.
                    self.logger.info("producing block for slot={d} proposer={d} with no peers (self-import only)", .{ slot, slot_proposer_id });
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

            self.logger.debug("constructing block for slot={d} proposer={d}", .{ slot, slot_proposer_id });
            const produced_block = try self.chain.produceBlock(.{ .slot = slot, .proposer_index = slot_proposer_id });
            self.logger.info("produced block for slot={d} proposer={d} with root={x}", .{ slot, slot_proposer_id, &produced_block.blockRoot });

            // Sign block root with proposer's proposal key
            const proposer_signature = try self.key_manager.signBlockRoot(
                slot_proposer_id,
                &produced_block.blockRoot,
                @intCast(slot),
            );

            const signed_block = types.SignedBlock{
                .block = produced_block.block,
                .signature = .{
                    .attestation_signatures = produced_block.attestation_signatures,
                    .proposer_signature = proposer_signature,
                },
            };

            self.logger.info("signed produced block for slot={d} root={x}", .{ slot, &produced_block.blockRoot });

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
            .fc_initing => {
                self.logger.info("skipping attestation production for slot={d}: forkchoice still initing (awaiting first justified checkpoint)", .{slot});
                return null;
            },
            .no_peers => {
                // Attest even with no peers: local fork-choice benefits from attestations
                // and they will propagate once peers connect.
                self.logger.info("attesting for slot={d} with no peers (self-import only)", .{slot});
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

        const _attest_timer = zeam_metrics.lean_attestations_production_time_seconds.start();
        defer _ = _attest_timer.observe();
        self.logger.info("constructing attestation message for slot={d}", .{slot});
        const attestation_data = try self.chain.constructAttestationData(.{ .slot = slot });

        var result = ValidatorClientOutput.init(self.allocator);
        for (self.ids) |validator_id| {
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

            // TODO: Cache validator_id -> subnet_id mapping to avoid recomputing per interval for large validator sets.
            const subnet_id = try types.computeSubnetId(@intCast(validator_id), self.config.spec.attestation_committee_count);
            try result.addAttestation(subnet_id, signed_attestation);
            self.logger.info("constructed attestation slot={d} validator={d}", .{ slot, validator_id });
        }
        return result;
    }
};
