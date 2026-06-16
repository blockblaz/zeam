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
        const cloned_attestation = try zeam_utils.clone(types.SignedAttestation, &signed_attestation, self.allocator);
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

    pub fn onInterval(self: *Self, node: *@import("./node.zig").BeamNode, time_intervals: usize) !?ValidatorClientOutput {
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        const interval = time_intervals % constants.INTERVALS_PER_SLOT;

        // if a new slot interval may be do a proposal
        switch (interval) {
            // Block production is a proposer duty — the "am I proposer this slot?" decision is
            // resolved HERE in the validator client; the chain receives the already-resolved
            // duty and owns only chain-state gating (sync status) plus the off-loop dispatch.
            // The heavy work runs on a thread_pool worker, since the prod-scheme Type-2 merge
            // is multi-second and would freeze gossip/tick handling if run inline. The worker
            // produces, merges, and publishes itself, so this interval emits no synchronous
            // output.
            0 => {
                const proposer_id = self.getSlotProposer(slot) orelse return null;
                self.chain.submitPropose(node, slot, proposer_id);
                return null;
            },
            1 => return self.mayBeDoAttestation(slot),
            2 => return null,
            3 => return null,
            // Interval-4 proposer pre-aggregation: if THIS node proposes the NEXT
            // slot, pre-build its Type-1 attestation set now (one interval early)
            // so the interval-0 proposal can skip the Type-1 compact and start the
            // Type-2 merge immediately. Off-loop dispatch; returns immediately.
            4 => {
                const next_proposer = self.getSlotProposer(slot + 1) orelse return null;
                self.chain.submitPreAggregate(slot + 1, next_proposer);
                return null;
            },
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

    // Block production moved off the slot loop to submitPropose / proposeImpl (a
    // thread_pool worker). The old on-loop maybeDoProposal — which built the multi-second Type-2
    // merge inline and would freeze gossip/tick handling — was removed in favour of that single
    // off-loop path. main's improvements to the old maybeDoProposal (the
    // .behind_peers → .peers_materially_ahead rename, logBehindPeersDebug, behind_peer_count, and
    // the submitBlockBuildOnInterval/finalizeProposalIfReady build/sign split) now live in the
    // off-loop chain.proposeImpl path and in mayBeDoAttestation below.

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
            .peers_materially_ahead => |info| {
                self.chain.logBehindPeersDebug("skipping attestation production", info);
                self.logger.warn("skipping attestation production for slot={d}: behind peers (head_slot={d}, finalized_slot={d}, max_peer_finalized_slot={d}, behind_peer_count={d})", .{
                    slot,
                    info.head_slot,
                    info.finalized_slot,
                    info.max_peer_finalized_slot,
                    info.peer_count,
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
