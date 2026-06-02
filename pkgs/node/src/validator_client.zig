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
                .peers_materially_ahead => |info| {
                    self.chain.logBehindPeersDebug("skipping block production", info);
                    self.logger.warn("skipping block production for slot={d} proposer={d}: behind peers (head_slot={d}, finalized_slot={d}, max_peer_finalized_slot={d}, behind_peer_count={d})", .{
                        slot,
                        slot_proposer_id,
                        info.head_slot,
                        info.finalized_slot,
                        info.max_peer_finalized_slot,
                        info.peer_count,
                    });
                    return null;
                },
            }

            self.logger.debug("constructing block for slot={d} proposer={d}", .{ slot, slot_proposer_id });
            // Spawn the deadline-bounded build/aggregation worker and block
            // (work-stealing) until it self-truncates at
            // `chain.proposal_deadline_pct` of the interval. We then finalize +
            // sign within the SAME interval's remaining budget — an
            // intra-interval build/sign split, not a cross-interval one.
            self.chain.submitBlockBuildOnInterval(slot, slot_proposer_id);
            self.chain.thread_pool.waitAndWork(&self.chain.proposal_build_wg);

            var produced = (try self.chain.finalizeProposalIfReady(slot, slot_proposer_id)) orelse return null;
            var produced_cleanup = true;
            errdefer if (produced_cleanup) produced.deinit();

            self.logger.info("produced block for slot={d} proposer={d} with root={x}", .{ slot, slot_proposer_id, &produced.blockRoot });

            // Sign block root with proposer's proposal key
            const proposer_signature = try self.key_manager.signBlockRoot(
                slot_proposer_id,
                &produced.blockRoot,
                @intCast(slot),
            );

            const signed_block = types.SignedBlock{
                .block = produced.block,
                .signature = .{
                    .attestation_signatures = produced.attestation_signatures,
                    .proposer_signature = proposer_signature,
                },
            };
            produced_cleanup = false; // ownership moved into signed_block

            self.logger.info("signed produced block for slot={d} root={x}", .{ slot, &produced.blockRoot });

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
            .peers_materially_ahead => |info| {
                // Pre-finalization cold-start exception: when BOTH our own
                // finalized slot AND the best peer's finalized slot are 0,
                // the `peers_materially_ahead` signal is coming from
                // `isWallHeadLagSyncing` (`blocks_by_range_sync.zig:72`),
                // which fires as soon as `wall_head_lag >= 4` on a fresh
                // chain. Refusing to attest in that state is the wrong
                // response — attestations on the best-current-head are
                // exactly what fork choice needs to accumulate weight,
                // reach supermajority, and produce the FIRST justified
                // checkpoint. Without attestations, finalized_slot stays
                // 0 forever, the wall-lag check keeps firing, and the
                // chain never finalises (observed on PR #966 deploy:
                // head frozen at slot 316 while wall clock at 505+,
                // 100% of attestation production gated out).
                //
                // Once any finalization has happened (ours OR a peer's),
                // `peers_materially_ahead` is reverting to its proper meaning —
                // deep-sync, where attesting on an old head would be
                // wasted weight — so we resume gating.
                if (info.finalized_slot == 0 and info.max_peer_finalized_slot == 0) {
                    self.logger.info(
                        "peers_materially_ahead but pre-finalization (finalized_slot=0, max_peer_finalized_slot=0): attesting on current head_slot={d} to help reach first justification",
                        .{info.head_slot},
                    );
                } else {
                    self.chain.logBehindPeersDebug("skipping attestation production", info);
                    self.logger.warn("skipping attestation production for slot={d}: behind peers (head_slot={d}, finalized_slot={d}, max_peer_finalized_slot={d}, behind_peer_count={d})", .{
                        slot,
                        info.head_slot,
                        info.finalized_slot,
                        info.max_peer_finalized_slot,
                        info.peer_count,
                    });
                    return null;
                }
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
