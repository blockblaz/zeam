const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const stf = @import("@zeam/state-transition");
const ssz = @import("ssz");
const networks = @import("@zeam/network");
const params = @import("@zeam/params");
const api = @import("@zeam/api");
const zeam_metrics = @import("@zeam/metrics");
const database = @import("@zeam/database");

const event_broadcaster = api.event_broadcaster;

const zeam_utils = @import("@zeam/utils");
const keymanager = @import("@zeam/key-manager");
const xmss = @import("@zeam/xmss");

const utils = @import("./utils.zig");
pub const fcFactory = @import("./forkchoice.zig");
const constants = @import("./constants.zig");

const networkFactory = @import("./network.zig");
const PeerInfo = networkFactory.PeerInfo;

const NodeNameRegistry = networks.NodeNameRegistry;
const ZERO_SIGBYTES = types.ZERO_SIGBYTES;

pub const BlockProductionParams = struct {
    slot: usize,
    proposer_index: usize,

    pub fn format(self: BlockProductionParams, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("BlockProductionParams{{ slot={d}, proposer_index={d} }}", .{ self.slot, self.proposer_index });
    }
};

pub const AttestationConstructionParams = struct {
    slot: types.Slot,
};

pub const ChainOpts = struct {
    config: configs.ChainConfig,
    anchorState: *types.BeamState,
    nodeId: u32,
    logger_config: *zeam_utils.ZeamLoggerConfig,
    db: database.Db,
    node_registry: *const NodeNameRegistry,
    force_block_production: bool = false,
};

pub const CachedProcessedBlockInfo = struct {
    postState: ?*types.BeamState = null,
    blockRoot: ?types.Root = null,
    pruneForkchoice: bool = true,
};

pub const GossipProcessingResult = struct {
    processed_block_root: ?types.Root = null,
    missing_attestation_roots: []types.Root = &[_]types.Root{},
};

pub const ProducedBlock = struct {
    block: types.BeamBlock,
    blockRoot: types.Root,

    // Aggregated signatures corresponding to attestations in the block body.
    attestation_signatures: types.AttestationSignatures,

    pub fn deinit(self: *ProducedBlock) void {
        self.block.deinit();
        for (self.attestation_signatures.slice()) |*sig_group| {
            sig_group.deinit();
        }
        self.attestation_signatures.deinit();
    }
};

pub const BeamChain = struct {
    config: configs.ChainConfig,
    anchor_state: *types.BeamState,

    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,
    // from finalized onwards to recent
    states: std.AutoHashMap(types.Root, *types.BeamState),
    nodeId: u32,
    // This struct needs to contain the zeam_logger_config to be able to call `maybeRotate`
    // For all other modules, we just need module_logger
    zeam_logger_config: *zeam_utils.ZeamLoggerConfig,
    module_logger: zeam_utils.ModuleLogger,
    stf_logger: zeam_utils.ModuleLogger,
    block_building_logger: zeam_utils.ModuleLogger,
    registered_validator_ids: []usize = &[_]usize{},
    db: database.Db,
    // Track last-emitted checkpoints to avoid duplicate SSE events (e.g., genesis spam)
    last_emitted_justified: types.Checkpoint,
    last_emitted_finalized: types.Checkpoint,
    connected_peers: *const std.StringHashMap(PeerInfo),
    node_registry: *const NodeNameRegistry,
    force_block_production: bool,
    // Cached finalized state loaded from database (separate from states map to avoid affecting pruning)
    cached_finalized_state: ?*types.BeamState = null,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        opts: ChainOpts,
        connected_peers: *const std.StringHashMap(PeerInfo),
    ) !Self {
        const logger_config = opts.logger_config;
        const fork_choice = try fcFactory.ForkChoice.init(allocator, .{
            .config = opts.config,
            .anchorState = opts.anchorState,
            .logger = logger_config.logger(.forkchoice),
        });

        var states = std.AutoHashMap(types.Root, *types.BeamState).init(allocator);
        const cloned_anchor_state = try allocator.create(types.BeamState);
        try types.sszClone(allocator, types.BeamState, opts.anchorState.*, cloned_anchor_state);
        try states.put(fork_choice.head.blockRoot, cloned_anchor_state);

        return Self{
            .nodeId = opts.nodeId,
            .config = opts.config,
            .forkChoice = fork_choice,
            .allocator = allocator,
            .states = states,
            .anchor_state = opts.anchorState,
            .zeam_logger_config = logger_config,
            .module_logger = logger_config.logger(.chain),
            .stf_logger = logger_config.logger(.state_transition),
            .block_building_logger = logger_config.logger(.state_transition_block_building),
            .db = opts.db,
            .last_emitted_justified = fork_choice.fcStore.latest_justified,
            .last_emitted_finalized = fork_choice.fcStore.latest_finalized,
            .connected_peers = connected_peers,
            .node_registry = opts.node_registry,
            .force_block_production = opts.force_block_production,
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up forkchoice resources (gossip_signatures, aggregated_payloads)
        self.forkChoice.deinit();

        var it = self.states.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.states.deinit();

        // Clean up cached finalized state if present
        if (self.cached_finalized_state) |cached_state| {
            cached_state.deinit();
            self.allocator.destroy(cached_state);
        }

        // assume the allocator of config is same as self.allocator
        self.config.deinit(self.allocator);
        // self.anchor_state.deinit();
    }

    pub fn registerValidatorIds(self: *Self, validator_ids: []usize) void {
        // right now it's simple assignment but eventually it should be a set
        // tacking registrations and keeping it alive for 3*2=6 slots
        self.registered_validator_ids = validator_ids;
        zeam_metrics.metrics.lean_validators_count.set(self.registered_validator_ids.len);
    }

    pub fn onInterval(self: *Self, time_intervals: usize) !void {
        // see if the node has a proposal this slot to properly tick
        // forkchoice head
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        const interval = time_intervals % constants.INTERVALS_PER_SLOT;

        // Update current slot metric (wall-clock time slot)
        zeam_metrics.metrics.lean_current_slot.set(slot);

        var has_proposal = false;
        if (interval == 0) {
            const num_validators: usize = @intCast(self.config.genesis.numValidators());
            const slot_proposer_id = slot % num_validators;
            if (std.mem.indexOfScalar(usize, self.registered_validator_ids, slot_proposer_id)) |index| {
                _ = index;
                has_proposal = true;
            }
        }

        self.module_logger.debug("ticking chain to time(intervals)={d} = slot={d} interval={d} has_proposal={} ", .{
            time_intervals,
            slot,
            interval,
            has_proposal,
        });

        try self.forkChoice.onInterval(time_intervals, has_proposal);
        if (interval == 1) {
            // interval to attest so we should put out the chain status information to the user along with
            // latest head which most likely should be the new block received and processed
            const islot: isize = @intCast(slot);
            self.printSlot(islot, self.connected_peers.count());

            // Periodic pruning: prune old non-canonical states every N slots
            // This ensures we prune even when finalization doesn't advance
            if (slot > 0 and slot % constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS == 0) {
                const finalized = self.forkChoice.fcStore.latest_finalized;
                // no need to work extra if finalization is not far behind
                if (finalized.slot + 2 * constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS < slot) {
                    self.module_logger.warn("finalization slot={d} too far behind the current slot={d}", .{ finalized.slot, slot });
                    const pruningAnchor = try self.forkChoice.getCanonicalAncestorAtDepth(constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS);

                    // prune if finalization hasn't happened since a long time
                    if (pruningAnchor.slot > finalized.slot) {
                        self.module_logger.info("periodic pruning triggered at slot {d} (finalized slot={d} pruning anchor={d})", .{
                            slot,
                            finalized.slot,
                            pruningAnchor.slot,
                        });
                        const analysis_result = try self.forkChoice.getCanonicalityAnalysis(pruningAnchor.blockRoot, finalized.root, null);
                        const depth_confirmed_roots = analysis_result[0];
                        const non_finalized_descendants = analysis_result[1];
                        const non_canonical_roots = analysis_result[2];
                        defer self.allocator.free(depth_confirmed_roots);
                        defer self.allocator.free(non_finalized_descendants);
                        defer self.allocator.free(non_canonical_roots);

                        const states_count_before: isize = self.states.count();
                        _ = self.pruneStates(depth_confirmed_roots[1..depth_confirmed_roots.len], "confirmed ancestors");
                        _ = self.pruneStates(non_canonical_roots, "confirmed non canonical");
                        const pruned_count = states_count_before - self.states.count();
                        self.module_logger.info("pruned states={d} at slot={d} (finalized slot={d} pruning anchor={d})", .{
                            //
                            pruned_count,
                            slot,
                            finalized.slot,
                            pruningAnchor.slot,
                        });
                    } else {
                        self.module_logger.info("skipping periodic pruning at slot={d} since finalization not behind pruning anchor (finalized slot={d} pruning anchor={d})", .{
                            slot,
                            finalized.slot,
                            pruningAnchor.slot,
                        });
                    }
                } else {
                    self.module_logger.info("skipping periodic pruning at current slot={d} since finalization slot={d} not behind", .{
                        slot,
                        finalized.slot,
                    });
                }
            }
        }
        // check if log rotation is needed
        self.zeam_logger_config.maybeRotate() catch |err| {
            self.module_logger.err("error rotating log file: {any}", .{err});
        };
    }

    pub fn produceBlock(self: *Self, opts: BlockProductionParams) !ProducedBlock {
        // dump the vote tracker, letting this stay here commented for handy debugging activation
        // var iterator = self.forkChoice.attestations.iterator();
        // while (iterator.next()) |entry| {
        //     var latest_new: []const u8 = "null";
        //     if (entry.value_ptr.latestNew) |latest_new_in| {
        //         if (latest_new_in.attestation) |latest_new_att| {
        //             latest_new = try latest_new_att.message.toJsonString(self.allocator);
        //         }
        //     }
        //     self.module_logger.warn("validator id={d} vote is={s}", .{ entry.key_ptr.*, latest_new });
        // }

        // right now with integrated validator into node produceBlock is always gurranteed to be
        // called post ticking the chain to the correct time, but once validator is separated
        // one must make the forkchoice tick to the right time if there is a race condition
        // however in that scenario forkchoice also needs to be protected by mutex/kept thread safe
        const chainHead = try self.forkChoice.updateHead();
        const attestations = try self.forkChoice.getProposalAttestations();
        defer self.allocator.free(attestations);

        const parent_root = chainHead.blockRoot;

        const pre_state = self.states.get(parent_root) orelse return BlockProductionError.MissingPreState;
        var post_state_opt: ?*types.BeamState = try self.allocator.create(types.BeamState);
        errdefer if (post_state_opt) |post_state_ptr| {
            post_state_ptr.deinit();
            self.allocator.destroy(post_state_ptr);
        };
        const post_state = post_state_opt.?;
        try types.sszClone(self.allocator, types.BeamState, pre_state.*, post_state);

        // Use the two-phase aggregation algorithm:
        // Phase 1: Collect individual signatures from gossip_signatures
        // Phase 2: Fallback to aggregated_payloads using greedy set-cover
        var aggregation = try types.AggregatedAttestationsResult.init(self.allocator);
        var agg_att_cleanup = true;
        var agg_sig_cleanup = true;
        errdefer if (agg_att_cleanup) {
            for (aggregation.attestations.slice()) |*att| {
                att.deinit();
            }
            aggregation.attestations.deinit();
        };
        errdefer if (agg_sig_cleanup) {
            for (aggregation.attestation_signatures.slice()) |*sig| {
                sig.deinit();
            }
            aggregation.attestation_signatures.deinit();
        };
        try aggregation.computeAggregatedSignatures(
            attestations,
            &pre_state.validators,
            &self.forkChoice.gossip_signatures,
            &self.forkChoice.aggregated_payloads,
        );

        // keeping for later when execution will be integrated into lean
        // const timestamp = self.config.genesis.genesis_time + opts.slot * params.SECONDS_PER_SLOT;

        var block = types.BeamBlock{
            .slot = opts.slot,
            .proposer_index = opts.proposer_index,
            .parent_root = parent_root,
            .state_root = undefined,
            .body = types.BeamBlockBody{
                // .execution_payload_header = .{ .timestamp = timestamp },
                .attestations = aggregation.attestations,
            },
        };
        agg_att_cleanup = false; // Ownership moved to block.body.attestations
        errdefer block.deinit();

        var attestation_signatures = aggregation.attestation_signatures;
        agg_sig_cleanup = false; // Ownership moved to attestation_signatures
        errdefer {
            for (attestation_signatures.slice()) |*sig_group| {
                sig_group.deinit();
            }
            attestation_signatures.deinit();
        }

        const block_str = try block.toJsonString(self.allocator);
        defer self.allocator.free(block_str);

        self.module_logger.debug("node-{d}::going for block production opts={any} raw block={s}", .{ self.nodeId, opts, block_str });

        // 2. apply STF to get post state & update post state root & cache it
        try stf.apply_raw_block(self.allocator, post_state, &block, self.block_building_logger);

        const block_str_2 = try block.toJsonString(self.allocator);
        defer self.allocator.free(block_str_2);

        self.module_logger.debug("applied raw block opts={any} raw block={s}", .{ opts, block_str_2 });

        // 3. cache state to save recompute while adding the block on publish
        var block_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);

        try self.states.put(block_root, post_state);
        post_state_opt = null;

        var forkchoice_added = false;
        errdefer if (!forkchoice_added) {
            if (self.states.fetchRemove(block_root)) |entry| {
                entry.value.deinit();
                self.allocator.destroy(entry.value);
            }
        };

        // 4. Add the block to directly forkchoice as this proposer will next need to construct its vote
        //   note - attestations packed in the block are already in the knownVotes so we don't need to re-import
        //   them in the forkchoice
        _ = try self.forkChoice.onBlock(block, post_state, .{
            .currentSlot = block.slot,
            .blockDelayMs = 0,
            .blockRoot = block_root,
            // confirmed in publish
            .confirmed = false,
        });
        forkchoice_added = true;
        _ = try self.forkChoice.updateHead();

        return .{
            .block = block,
            .blockRoot = block_root,
            .attestation_signatures = attestation_signatures,
        };
    }

    pub fn constructAttestationData(self: *Self, opts: AttestationConstructionParams) !types.AttestationData {
        const slot = opts.slot;

        // const head = try self.forkChoice.getProposalHead(slot);
        const head_proto = self.forkChoice.head;
        const head: types.Checkpoint = .{
            .root = head_proto.blockRoot,
            .slot = head_proto.slot,
        };
        const head_str = try head.toJsonString(self.allocator);
        defer self.allocator.free(head_str);

        const safe_target_proto = self.forkChoice.safeTarget;
        const safe_target: types.Checkpoint = .{
            .root = safe_target_proto.blockRoot,
            .slot = safe_target_proto.slot,
        };
        const safe_target_str = try safe_target.toJsonString(self.allocator);
        defer self.allocator.free(safe_target_str);

        self.module_logger.info("constructing attestation data at slot={d} with chain head={s} safe_target={s}", .{
            slot,
            head_str,
            safe_target_str,
        });

        const target = try self.forkChoice.getAttestationTarget();
        const target_str = try target.toJsonString(self.allocator);
        defer self.allocator.free(target_str);

        self.module_logger.info("calculated target for attestations at slot={d}: {s}", .{ slot, target_str });

        const attestation_data = types.AttestationData{
            .slot = slot,
            .head = head,
            .target = target,
            .source = self.forkChoice.fcStore.latest_justified,
        };

        return attestation_data;
    }

    pub fn printSlot(self: *Self, islot: isize, peer_count: usize) void {
        // head should be auto updated if receieved a block or block proposal done
        // however it doesn't get updated unless called updatehead even though process block
        // logs show it has been updated. debug and fix the call below
        const fc_head = if (islot > 0)
            self.forkChoice.updateHead() catch |err| {
                self.module_logger.err("forkchoice updatehead error={any}", .{err});
                return;
            }
        else
            self.forkChoice.head;

        // Get additional chain information
        const justified = self.forkChoice.fcStore.latest_justified;
        const finalized = self.forkChoice.fcStore.latest_finalized;

        // Calculate chain progress
        const slot: usize = if (islot < 0) 0 else @intCast(islot);
        const blocks_behind = if (slot > fc_head.slot) slot - fc_head.slot else 0;
        const is_timely = fc_head.timeliness;

        const states_count = self.states.count();
        const fc_nodes_count = self.forkChoice.protoArray.nodes.items.len;

        self.module_logger.debug("cached states={d}, forkchoice nodes={d}", .{ states_count, fc_nodes_count });
        self.module_logger.info(
            \\
            \\+===============================================================+
            \\  CHAIN STATUS: Current Slot: {d} | Head Slot: {d} | Behind: {d}
            \\+---------------------------------------------------------------+
            \\  Connected Peers:    {d}
            \\+---------------------------------------------------------------+
            \\  Head Block Root:    0x{any}
            \\  Parent Block Root:  0x{any}
            \\  State Root:         0x{any}
            \\  Timely:             {s}
            \\+---------------------------------------------------------------+
            \\  Latest Justified:   Slot {d:>6} | Root: 0x{any}
            \\  Latest Finalized:   Slot {d:>6} | Root: 0x{any}
            \\+===============================================================+
            \\
        , .{
            islot,
            fc_head.slot,
            blocks_behind,
            peer_count,
            std.fmt.fmtSliceHexLower(&fc_head.blockRoot),
            std.fmt.fmtSliceHexLower(&fc_head.parentRoot),
            std.fmt.fmtSliceHexLower(&fc_head.stateRoot),
            if (is_timely) "YES" else "NO",
            justified.slot,
            std.fmt.fmtSliceHexLower(&justified.root),
            finalized.slot,
            std.fmt.fmtSliceHexLower(&finalized.root),
        });
    }

    pub fn onGossip(self: *Self, data: *const networks.GossipMessage, sender_peer_id: []const u8) !GossipProcessingResult {
        switch (data.*) {
            .block => |signed_block| {
                const block = signed_block.message.block;
                var block_root: [32]u8 = undefined;
                try zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);

                //check if we have the block already in forkchoice
                const hasBlock = self.forkChoice.hasBlock(block_root);

                self.module_logger.debug("chain received gossip block for slot={d} blockroot=0x{s} proposer={d}{} hasBlock={} from peer={s}{}", .{
                    block.slot,
                    std.fmt.fmtSliceHexLower(&block_root),
                    block.proposer_index,
                    self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
                    hasBlock,
                    sender_peer_id,
                    self.node_registry.getNodeNameFromPeerId(sender_peer_id),
                });

                if (!hasBlock) {
                    self.validateBlock(block, true) catch |err| {
                        self.module_logger.warn("gossip block validation failed: {any}", .{err});
                        return .{}; // Drop invalid gossip attestations
                    };
                    const missing_roots = self.onBlock(signed_block, .{
                        .blockRoot = block_root,
                    }) catch |err| {
                        self.module_logger.err("error processing block for slot={d} root=0x{s}: {any}", .{
                            block.slot,
                            std.fmt.fmtSliceHexLower(&block_root),
                            err,
                        });
                        return err;
                    };
                    // followup with additional housekeeping tasks
                    self.onBlockFollowup(true, &signed_block);
                    // NOTE: ownership of `missing_roots` is transferred to the caller (BeamNode),
                    // which is responsible for freeing it after optionally fetching those roots.

                    // Return both the block root and missing attestation roots so the node can:
                    // 1. Call processCachedDescendants(block_root) to retry any cached children
                    // 2. Fetch missing attestation head blocks via RPC
                    return .{
                        .processed_block_root = block_root,
                        .missing_attestation_roots = missing_roots,
                    };
                } else {
                    self.module_logger.debug("skipping processing the already present block slot={d} blockroot=0x{s}", .{
                        block.slot,
                        std.fmt.fmtSliceHexLower(&block_root),
                    });
                }
                return .{};
            },
            .attestation => |signed_attestation| {
                const slot = signed_attestation.message.slot;
                const validator_id = signed_attestation.validator_id;
                const validator_node_name = self.node_registry.getNodeNameFromValidatorIndex(validator_id);

                const sender_node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
                self.module_logger.debug("chain received gossip attestation for slot={d} validator={d}{} from peer={s}{}", .{
                    slot,
                    validator_id,
                    validator_node_name,
                    sender_peer_id,
                    sender_node_name,
                });

                // Validate attestation before processing (gossip = not from block)
                self.validateAttestation(signed_attestation.toAttestation(), false) catch |err| {
                    self.module_logger.warn("gossip attestation validation failed: {any}", .{err});
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                    return .{}; // Drop invalid gossip attestations
                };

                // Process validated attestation
                self.onGossipAttestation(signed_attestation) catch |err| {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                    self.module_logger.err("attestation processing error: {any}", .{err});
                    return err;
                };
                self.module_logger.info("processed gossip attestation for slot={d} validator={d}{}", .{
                    slot,
                    validator_id,
                    validator_node_name,
                });
                zeam_metrics.metrics.lean_attestations_valid_total.incr(.{ .source = "gossip" }) catch {};
                return .{};
            },
        }
    }

    // import block assuming it is gossip validated or synced
    // this onBlock corresponds to spec's forkchoice's onblock with some functionality split between this and
    // our implemented forkchoice's onblock. this is to parallelize "apply transition" with other verifications
    // Returns a list of missing block roots that need to be fetched from the network
    pub fn onBlock(self: *Self, signedBlock: types.SignedBlockWithAttestation, blockInfo: CachedProcessedBlockInfo) ![]types.Root {
        const onblock_timer = zeam_metrics.chain_onblock_duration_seconds.start();

        const block = signedBlock.message.block;

        const block_root: types.Root = blockInfo.blockRoot orelse computedroot: {
            var cblock_root: [32]u8 = undefined;
            try zeam_utils.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
            break :computedroot cblock_root;
        };

        const post_state = if (blockInfo.postState) |post_state_ptr| post_state_ptr else computedstate: {
            // 1. get parent state
            const pre_state = self.states.get(block.parent_root) orelse return BlockProcessingError.MissingPreState;
            const cpost_state = try self.allocator.create(types.BeamState);
            try types.sszClone(self.allocator, types.BeamState, pre_state.*, cpost_state);

            // 2. verify XMSS signatures (independent step; placed before STF for now, parallelizable later)
            try stf.verifySignatures(self.allocator, pre_state, &signedBlock);

            // 3. apply state transition assuming signatures are valid (STF does not re-verify)
            try stf.apply_transition(self.allocator, cpost_state, block, .{
                //
                .logger = self.stf_logger,
                .validSignatures = true,
            });
            break :computedstate cpost_state;
        };

        var missing_roots = std.ArrayList(types.Root).init(self.allocator);
        errdefer missing_roots.deinit();

        // 3. fc onblock if the block was not pre added by the block production
        const fcBlock = self.forkChoice.getBlock(block_root) orelse fcprocessing: {
            const freshFcBlock = try self.forkChoice.onBlock(block, post_state, .{
                .currentSlot = block.slot,
                .blockDelayMs = 0,
                .blockRoot = block_root,
                // confirmed in next steps post written to db
                .confirmed = false,
            });

            // 4. fc onattestations
            self.module_logger.debug("processing attestations of block with root=0x{s} slot={d}", .{
                std.fmt.fmtSliceHexLower(&freshFcBlock.blockRoot),
                block.slot,
            });

            const aggregated_attestations = block.body.attestations.constSlice();
            const signature_groups = signedBlock.signature.attestation_signatures.constSlice();

            if (aggregated_attestations.len != signature_groups.len) {
                self.module_logger.err(
                    "signature group count mismatch for block root=0x{s}: attestations={d} signature_groups={d}",
                    .{ std.fmt.fmtSliceHexLower(&freshFcBlock.blockRoot), aggregated_attestations.len, signature_groups.len },
                );
            }

            for (aggregated_attestations, 0..) |aggregated_attestation, index| {
                var validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, self.allocator);
                defer validator_indices.deinit();

                // Get participant indices from the signature proof
                const signature_proof = if (index < signature_groups.len)
                    &signature_groups[index]
                else
                    null;

                var participant_indices = if (signature_proof) |proof|
                    try types.aggregationBitsToValidatorIndices(&proof.participants, self.allocator)
                else
                    std.ArrayList(usize).init(self.allocator);
                defer participant_indices.deinit();

                if (validator_indices.items.len != participant_indices.items.len) {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "block" }) catch {};
                    self.module_logger.err(
                        "attestation signature mismatch index={d} validators={d} participants={d}",
                        .{ index, validator_indices.items.len, participant_indices.items.len },
                    );
                    continue;
                }

                for (validator_indices.items) |validator_index| {
                    const validator_id: types.ValidatorIndex = @intCast(validator_index);
                    const attestation = types.Attestation{
                        .validator_id = validator_id,
                        .data = aggregated_attestation.data,
                    };

                    self.validateAttestation(attestation, true) catch |e| {
                        zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "block" }) catch {};
                        if (e == AttestationValidationError.UnknownHeadBlock) {
                            try missing_roots.append(attestation.data.head.root);
                        }

                        self.module_logger.err("invalid attestation in block: validator={d} error={any}", .{
                            validator_index,
                            e,
                        });
                        continue;
                    };

                    self.forkChoice.onAttestation(attestation, true) catch |e| {
                        zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "block" }) catch {};
                        self.module_logger.err("error processing block attestation={any} error={any}", .{ attestation, e });
                        continue;
                    };
                    zeam_metrics.metrics.lean_attestations_valid_total.incr(.{ .source = "block" }) catch {};
                }
            }

            // 5. fc update head
            _ = try self.forkChoice.updateHead();

            break :fcprocessing freshFcBlock;
        };
        try self.states.put(fcBlock.blockRoot, post_state);

        // 6. proposer attestation
        const proposer_signature = signedBlock.signature.proposer_signature;
        const signed_proposer_attestation = types.SignedAttestation{
            .validator_id = signedBlock.message.proposer_attestation.validator_id,
            .message = signedBlock.message.proposer_attestation.data,
            .signature = proposer_signature,
        };
        self.forkChoice.onGossipAttestation(signed_proposer_attestation, false) catch |e| {
            self.module_logger.err("error processing proposer attestation={any} error={any}", .{ signed_proposer_attestation, e });
        };

        const processing_time = onblock_timer.observe();

        // 7. Save block and state to database and confirm the block in forkchoice
        self.updateBlockDb(signedBlock, fcBlock.blockRoot, post_state.*, block.slot) catch |err| {
            self.module_logger.err("failed to update block database for block root=0x{s}: {any}", .{
                std.fmt.fmtSliceHexLower(&fcBlock.blockRoot),
                err,
            });
        };
        try self.forkChoice.confirmBlock(block_root);

        self.module_logger.info("processed block with root=0x{s} slot={d} processing time={d} (computed root={} computed state={})", .{
            std.fmt.fmtSliceHexLower(&fcBlock.blockRoot),
            block.slot,
            processing_time,
            blockInfo.blockRoot == null,
            blockInfo.postState == null,
        });
        return missing_roots.toOwnedSlice();
    }

    pub fn onBlockFollowup(self: *Self, pruneForkchoice: bool, signedBlock: ?*const types.SignedBlockWithAttestation) void {
        // 8. Asap emit new events via SSE (use forkchoice ProtoBlock directly)
        const new_head = self.forkChoice.head;
        if (api.events.NewHeadEvent.fromProtoBlock(self.allocator, new_head)) |head_event| {
            var chain_event = api.events.ChainEvent{ .new_head = head_event };
            event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                self.module_logger.warn("failed to broadcast head event: {any}", .{err});
                chain_event.deinit(self.allocator);
            };
        } else |err| {
            self.module_logger.warn("failed to create head event: {any}", .{err});
        }

        const store = self.forkChoice.fcStore;
        const latest_justified = store.latest_justified;
        const latest_finalized = store.latest_finalized;

        // 9. Asap emit justification/finalization events based on forkchoice store
        // Emit justification event only when slot increases beyond last emitted
        if (latest_justified.slot > self.last_emitted_justified.slot) {
            if (api.events.NewJustificationEvent.fromCheckpoint(self.allocator, latest_justified, new_head.slot)) |just_event| {
                var chain_event = api.events.ChainEvent{ .new_justification = just_event };
                event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                    self.module_logger.warn("failed to broadcast justification event: {any}", .{err});
                    chain_event.deinit(self.allocator);
                };
                self.last_emitted_justified = latest_justified;
            } else |err| {
                self.module_logger.warn("failed to create justification event: {any}", .{err});
            }
        }

        // Emit finalization event only when slot increases beyond last emitted
        const last_emitted_finalized = self.last_emitted_finalized;
        if (latest_finalized.slot > last_emitted_finalized.slot) {
            if (api.events.NewFinalizationEvent.fromCheckpoint(self.allocator, latest_finalized, new_head.slot)) |final_event| {
                var chain_event = api.events.ChainEvent{ .new_finalization = final_event };
                event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                    self.module_logger.warn("failed to broadcast finalization event: {any}", .{err});
                    chain_event.deinit(self.allocator);
                };
                self.last_emitted_finalized = latest_finalized;
            } else |err| {
                self.module_logger.warn("failed to create finalization event: {any}", .{err});
            }
        }

        // Update finalized slot indices and cleanup if finalization has advanced
        // note use presaved local last_emitted_finalized as self.last_emitted_finalized has been updated above
        if (latest_finalized.slot > last_emitted_finalized.slot) {
            self.processFinalizationAdvancement(last_emitted_finalized, latest_finalized, pruneForkchoice) catch |err| {
                // Record failed finalization attempt
                zeam_metrics.metrics.lean_finalizations_total.incr(.{ .result = "error" }) catch {};
                self.module_logger.err("failed to process finalization advancement from slot {d} to {d}: {any}", .{
                    last_emitted_finalized.slot,
                    latest_finalized.slot,
                    err,
                });
            };

            // Prune gossip_signatures and aggregated_payloads for finalized attestations
            self.forkChoice.pruneSignatureMaps(latest_finalized.slot) catch |err| {
                self.module_logger.warn("failed to prune signature maps: {any}", .{err});
            };
        }

        // Store aggregated payloads from the block for future block building
        if (signedBlock) |block| {
            self.storeAggregatedPayloads(block) catch |err| {
                self.module_logger.warn("failed to store aggregated payloads: {any}", .{err});
            };
        }

        const states_count_after_block = self.states.count();
        const fc_nodes_count_after_block = self.forkChoice.protoArray.nodes.items.len;
        self.module_logger.info("completed on block followup with states_count={d} fc_nodes_count={d}", .{
            states_count_after_block,
            fc_nodes_count_after_block,
        });

        zeam_metrics.metrics.lean_latest_justified_slot.set(latest_justified.slot);
        zeam_metrics.metrics.lean_latest_finalized_slot.set(latest_finalized.slot);
    }

    /// Store aggregated signature payloads from a block for future block building
    fn storeAggregatedPayloads(self: *Self, signedBlock: *const types.SignedBlockWithAttestation) !void {
        const block = signedBlock.message.block;
        const aggregated_attestations = block.body.attestations.constSlice();
        const signature_groups = signedBlock.signature.attestation_signatures.constSlice();

        for (aggregated_attestations, 0..) |aggregated_attestation, index| {
            const signature_proof = if (index < signature_groups.len)
                &signature_groups[index]
            else
                continue;

            var validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, self.allocator);
            defer validator_indices.deinit();

            for (validator_indices.items) |validator_index| {
                const validator_id: types.ValidatorIndex = @intCast(validator_index);

                // Clone the proof since we need to store it and the block data may be freed
                var cloned_proof: types.AggregatedSignatureProof = undefined;
                types.sszClone(self.allocator, types.AggregatedSignatureProof, signature_proof.*, &cloned_proof) catch |e| {
                    self.module_logger.warn("failed to clone aggregated proof for validator={d}: {any}", .{ validator_index, e });
                    continue;
                };

                self.forkChoice.storeAggregatedPayload(validator_id, &aggregated_attestation.data, cloned_proof) catch |e| {
                    self.module_logger.warn("failed to store aggregated payload for validator={d}: {any}", .{ validator_index, e });
                    cloned_proof.deinit();
                };
            }
        }
    }

    /// Update block database with block, state, and slot indices
    fn updateBlockDb(self: *Self, signedBlock: types.SignedBlockWithAttestation, blockRoot: types.Root, postState: types.BeamState, slot: types.Slot) !void {
        var batch = self.db.initWriteBatch();
        defer batch.deinit();

        // Store block and state
        batch.putBlock(database.DbBlocksNamespace, blockRoot, signedBlock);
        batch.putState(database.DbStatesNamespace, blockRoot, postState);

        // TODO: uncomment this code if there is a need of slot to unfinalized index
        _ = slot;
        // primarily this is served by the forkchoice
        // update unfinalized slot index
        // if (slot > finalizedSlot) {
        //     const existing_blockroots = self.db.loadUnfinalizedSlotIndex(database.DbUnfinalizedSlotsNamespace, slot) orelse &[_]types.Root{};
        //     if (existing_blockroots.len > 0) {
        //         defer self.allocator.free(existing_blockroots);
        //     }
        //     var updated_blockroots = std.ArrayList(types.Root).init(self.allocator);
        //     defer updated_blockroots.deinit();

        //     updated_blockroots.appendSlice(existing_blockroots) catch {};
        //     updated_blockroots.append(blockRoot) catch {};

        //     batch.putUnfinalizedSlotIndex(database.DbUnfinalizedSlotsNamespace, slot, updated_blockroots.items);
        // }

        self.db.commit(&batch);
    }

    /// Prune old non-canonical states from memory
    /// canonical_blocks: set of block roots that should be kept (e.g., canonical chain from finalized to head)
    ///                    All states in canonical_blocks are kept, all others are pruned
    fn pruneStates(self: *Self, roots: []types.Root, pruneType: []const u8) usize {
        const states_count_before = self.states.count();
        self.module_logger.debug("pruning for {s} (states_count={d}, roots={d})", .{
            pruneType,
            states_count_before,
            roots.len,
        });

        // We keep the canonical chain from finalized to head, so we can safely prune all non-canonical states
        // Actually remove and deallocate the pruned states
        for (roots) |root| {
            if (self.states.fetchRemove(root)) |entry| {
                const state_ptr = entry.value;
                state_ptr.deinit();
                self.allocator.destroy(state_ptr);
                self.module_logger.debug("pruned state for root 0x{s}", .{
                    std.fmt.fmtSliceHexLower(&root),
                });
            }
        }

        const states_count_after = self.states.count();
        const pruned_count = states_count_before - states_count_after;
        self.module_logger.debug("pruning completed for {s} removed {d} states (states: {d} -> {d})", .{
            pruneType,
            pruned_count,
            states_count_before,
            states_count_after,
        });
        return pruned_count;
    }

    /// Process finalization advancement: move canonical blocks to finalized index and cleanup unfinalized indices
    fn processFinalizationAdvancement(self: *Self, previousFinalized: types.Checkpoint, latestFinalized: types.Checkpoint, pruneForkchoice: bool) !void {
        var batch = self.db.initWriteBatch();
        defer batch.deinit();

        self.module_logger.debug("processing finalization advancement from slot={d} to slot={d}", .{ previousFinalized.slot, latestFinalized.slot });

        // 1. Do canonoical analysis to segment forkchoice
        var canonical_view = std.AutoHashMap(types.Root, void).init(self.allocator);
        defer canonical_view.deinit();
        try self.forkChoice.getCanonicalView(&canonical_view, latestFinalized.root, null);
        const analysis_result = try self.forkChoice.getCanonicalityAnalysis(latestFinalized.root, null, &canonical_view);

        const finalized_roots = analysis_result[0];
        const non_finalized_descendants = analysis_result[1];
        const non_canonical_roots = analysis_result[2];
        defer self.allocator.free(finalized_roots);
        defer self.allocator.free(non_finalized_descendants);
        defer self.allocator.free(non_canonical_roots);

        // finalized_ancestor_roots has the previous finalized included
        const newly_finalized_count = finalized_roots.len - 1;
        self.module_logger.info("finalization canonicality analysis (previousFinalized slot={d} to latestFinalized slot={d}): newly finalized={d}, orphaned/missing={d}, non finalized descendants={d} & finalized non canonical={d}", .{
            previousFinalized.slot,
            //
            latestFinalized.slot,
            newly_finalized_count,
            latestFinalized.slot - previousFinalized.slot - newly_finalized_count,
            non_finalized_descendants.len,
            non_canonical_roots.len,
        });

        // 2. Put all newly finalized roots in DbFinalizedSlotsNamespace
        for (finalized_roots) |root| {
            const idx = self.forkChoice.protoArray.indices.get(root) orelse return error.FinalizedBlockNotInForkChoice;
            const node = self.forkChoice.protoArray.nodes.items[idx];
            batch.putFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, node.slot, root);
            self.module_logger.debug("added block 0x{s} at slot {d} to finalized index", .{
                std.fmt.fmtSliceHexLower(&root),
                node.slot,
            });
        }

        // Update the latest finalized slot metadata
        batch.putLatestFinalizedSlot(database.DbDefaultNamespace, latestFinalized.slot);

        // 3. commit all batch ops for finalized indices before we prune
        self.db.commit(&batch);

        // 4. Prunestates from memory
        // Get all canonical blocks from finalized to head (not just newly finalized)
        const states_count_before: isize = self.states.count();
        // first root is the new finalized, we need to retain it and will be pruned in the next round
        _ = self.pruneStates(finalized_roots[1..finalized_roots.len], "finalized ancestors");
        _ = self.pruneStates(non_canonical_roots, "finalized non canonical");
        const pruned_count = states_count_before - self.states.count();
        self.module_logger.info("state pruning completed (slots latestFinalized={d} to latestFinalized={d}) removed {d} states", .{
            previousFinalized.slot,
            latestFinalized.slot,
            pruned_count,
        });

        // 5 Rebase forkchouce
        if (pruneForkchoice)
            try self.forkChoice.rebase(latestFinalized.root, &canonical_view);

        // TODO:
        // 6. Remove orphaned blocks from database and cleanup unfinalized indices of there are any
        // for (previousFinalizedSlot + 1..finalizedSlot + 1) |slot| {
        //     var slot_orphaned_count: usize = 0;
        //     // Get all unfinalized blocks at this slot before deleting the index
        //     if (self.db.loadUnfinalizedSlotIndex(database.DbUnfinalizedSlotsNamespace, slot)) |unfinalized_blockroots| {
        //         defer self.allocator.free(unfinalized_blockroots);
        //         // Remove blocks not in the canonical finalized chain
        //         for (unfinalized_blockroots) |blockroot| {
        //             if (!canonical_blocks.contains(blockroot)) {
        //                 // This block is orphaned - remove it from database
        //                 batch.delete(database.DbBlocksNamespace, &blockroot);
        //                 batch.delete(database.DbStatesNamespace, &blockroot);
        //                 slot_orphaned_count += 1;
        //             }
        //         }
        //         if (slot_orphaned_count > 0) {
        //             self.module_logger.debug("Removed {d} orphaned block at slot {d} from database", .{
        //                 slot_orphaned_count,
        //                 slot,
        //             });
        //         }

        //         // Remove the unfinalized slot index
        //         batch.deleteUnfinalizedSlotIndexFromBatch(database.DbUnfinalizedSlotsNamespace, slot);
        //         self.module_logger.debug("Removed {d} unfinalized index for slot {d}", .{ unfinalized_blockroots.len, slot });
        //     }
        // }

        // Record successful finalization
        zeam_metrics.metrics.lean_finalizations_total.incr(.{ .result = "success" }) catch {};

        self.module_logger.debug("finalization advanced  previousFinalized slot={d} to latestFinalized slot={d}", .{ previousFinalized.slot, latestFinalized.slot });
    }

    pub fn validateBlock(self: *Self, block: types.BeamBlock, is_from_gossip: bool) !void {
        _ = is_from_gossip;
        const hasParentBlock = self.forkChoice.hasBlock(block.parent_root);

        if (!hasParentBlock) {
            self.module_logger.warn("gossip block validation failed slot={d} with unknown parent=0x{s}", .{
                block.slot,
                std.fmt.fmtSliceHexLower(&block.parent_root),
            });
            return BlockValidationError.UnknownParentBlock;
        }
    }

    /// Validate incoming attestation before processing.
    ///
    /// is_from_block: true if attestation came from a block, false if from network gossip
    ///
    /// Per leanSpec:
    /// - Gossip attestations (is_from_block=false): attestation.slot <= current_slot (no future tolerance)
    /// - Block attestations (is_from_block=true): attestation.slot <= current_slot + 1 (lenient)
    pub fn validateAttestation(self: *Self, attestation: types.Attestation, is_from_block: bool) !void {
        const timer = zeam_metrics.lean_attestation_validation_time_seconds.start();
        defer _ = timer.observe();
        const data = attestation.data;

        // 1. Validate that source, target, and head blocks exist in proto array
        const source_idx = self.forkChoice.protoArray.indices.get(data.source.root) orelse {
            self.module_logger.debug("attestation validation failed: unknown source block root=0x{s}", .{
                std.fmt.fmtSliceHexLower(&data.source.root),
            });
            return AttestationValidationError.UnknownSourceBlock;
        };

        const target_idx = self.forkChoice.protoArray.indices.get(data.target.root) orelse {
            self.module_logger.debug("attestation validation failed: unknown target block slot={d} root=0x{s}", .{
                data.target.slot,
                std.fmt.fmtSliceHexLower(&data.target.root),
            });
            return AttestationValidationError.UnknownTargetBlock;
        };

        const head_idx = self.forkChoice.protoArray.indices.get(data.head.root) orelse {
            self.module_logger.debug("attestation validation failed: unknown head block slot={d} root=0x{s}", .{
                data.head.slot,
                std.fmt.fmtSliceHexLower(&data.head.root),
            });
            return AttestationValidationError.UnknownHeadBlock;
        };

        const source_block = self.forkChoice.protoArray.nodes.items[source_idx];
        const target_block = self.forkChoice.protoArray.nodes.items[target_idx];
        const head_block = self.forkChoice.protoArray.nodes.items[head_idx];
        _ = head_block; // Will be used in future validations

        // 2. Validate slot relationships
        if (source_block.slot > target_block.slot) {
            self.module_logger.debug("attestation validation failed: source slot {d} > target slot {d}", .{
                source_block.slot,
                target_block.slot,
            });
            return AttestationValidationError.SourceSlotExceedsTarget;
        }

        //    This corresponds to leanSpec's: assert attestation.source.slot <= attestation.target.slot
        if (data.source.slot > data.target.slot) {
            self.module_logger.debug("attestation validation failed: source checkpoint slot {d} > target checkpoint slot {d}", .{
                data.source.slot,
                data.target.slot,
            });
            return AttestationValidationError.SourceCheckpointExceedsTarget;
        }

        // 3. Validate checkpoint slots match block slots
        if (source_block.slot != data.source.slot) {
            self.module_logger.debug("attestation validation failed: source block slot {d} != source checkpoint slot {d}", .{
                source_block.slot,
                data.source.slot,
            });
            return AttestationValidationError.SourceCheckpointSlotMismatch;
        }

        //    This corresponds to leanSpec's: assert target_block.slot == attestation.target.slot
        if (target_block.slot != data.target.slot) {
            self.module_logger.debug("attestation validation failed: target block slot {d} != target checkpoint slot {d}", .{
                target_block.slot,
                data.target.slot,
            });
            return AttestationValidationError.TargetCheckpointSlotMismatch;
        }

        // 4. Validate attestation is not too far in the future
        //
        //    Gossip attestations must be for current or past slots only. Validators attest
        //    in interval 1 of the current slot, so they cannot attest for future slots.
        //    Block attestations can be more lenient since the block itself was validated.
        const current_slot = self.forkChoice.fcStore.timeSlots;
        const max_allowed_slot = if (is_from_block)
            current_slot + constants.MAX_FUTURE_SLOT_TOLERANCE // Block attestations: allow +1
        else
            current_slot; // Gossip attestations: no future slots allowed

        if (data.slot > max_allowed_slot) {
            self.module_logger.debug("attestation validation failed: attestation slot {d} > max allowed slot {d} (is_from_block={any})", .{
                data.slot,
                max_allowed_slot,
                is_from_block,
            });
            return AttestationValidationError.AttestationTooFarInFuture;
        }
        self.module_logger.debug("attestation validation passed: validator={d} slot={d} source={d} target={d} is_from_block={any}", .{
            attestation.validator_id,
            data.slot,
            data.source.slot,
            data.target.slot,
            is_from_block,
        });
    }

    pub fn onGossipAttestation(self: *Self, signedAttestation: types.SignedAttestation) !void {
        // Validate attestation before processing (gossip = not from block)
        const attestation = signedAttestation.toAttestation();
        try self.validateAttestation(attestation, false);

        const state = self.states.get(attestation.data.target.root) orelse return AttestationValidationError.MissingState;

        try stf.verifySingleAttestation(
            self.allocator,
            state,
            @intCast(signedAttestation.validator_id),
            &signedAttestation.message,
            &signedAttestation.signature,
        );

        return self.forkChoice.onGossipAttestation(signedAttestation, false);
    }

    pub fn getStatus(self: *Self) types.Status {
        const finalized = self.forkChoice.fcStore.latest_finalized;
        const head = self.forkChoice.head;

        return .{
            .finalized_root = finalized.root,
            .finalized_slot = finalized.slot,
            .head_root = head.blockRoot,
            .head_slot = head.slot,
        };
    }

    /// Get the finalized checkpoint state (BeamState) if available
    /// First checks in-memory states map, then cached DB state, then falls back to database
    /// Returns null if the state is not available in any location
    pub fn getFinalizedState(self: *Self) ?*const types.BeamState {
        const finalized_checkpoint = self.forkChoice.fcStore.latest_finalized;

        // First try to get from in-memory states map
        if (self.states.get(finalized_checkpoint.root)) |state| {
            return state;
        }

        // Check if we already have a cached state from DB
        if (self.cached_finalized_state) |cached_state| {
            return cached_state;
        }

        // Fallback: try to load from database
        const state_ptr = self.allocator.create(types.BeamState) catch |err| {
            self.module_logger.warn("failed to allocate memory for finalized state: {}", .{err});
            return null;
        };

        self.db.loadLatestFinalizedState(state_ptr) catch |err| {
            self.allocator.destroy(state_ptr);
            self.module_logger.warn("finalized state not available in database: {}", .{err});
            return null;
        };

        // Cache in separate field (not in states map to avoid affecting pruning)
        self.cached_finalized_state = state_ptr;

        self.module_logger.info("loaded finalized state from database at slot {d}", .{state_ptr.slot});
        return state_ptr;
    }

    /// Get the latest justified checkpoint
    /// Returns the checkpoint with slot and root of the most recent justified checkpoint
    pub fn getJustifiedCheckpoint(self: *Self) types.Checkpoint {
        return self.forkChoice.fcStore.latest_justified;
    }

    pub const SyncStatus = union(enum) {
        synced,
        no_peers,
        behind_peers: struct {
            head_slot: types.Slot,
            max_peer_finalized_slot: types.Slot,
        },
    };

    /// Returns detailed sync status information.
    pub fn getSyncStatus(self: *Self) SyncStatus {
        // If no peers connected, we can't verify sync status - assume not synced
        // Unless force_block_production is enabled, which allows block generation without peers
        if (self.connected_peers.count() == 0 and !self.force_block_production) {
            return .no_peers;
        }

        const our_head_slot = self.forkChoice.head.slot;
        const our_finalized_slot = self.forkChoice.fcStore.latest_finalized.slot;

        // Find the maximum finalized slot reported by any peer
        var max_peer_finalized_slot: types.Slot = our_finalized_slot;

        var peer_iter = self.connected_peers.iterator();
        while (peer_iter.next()) |entry| {
            const peer_info = entry.value_ptr;
            if (peer_info.latest_status) |status| {
                if (status.finalized_slot > max_peer_finalized_slot) {
                    max_peer_finalized_slot = status.finalized_slot;
                }
            }
        }

        // We must also be synced with peers (at or past max peer finalized slot)
        if (our_head_slot < max_peer_finalized_slot) {
            return .{ .behind_peers = .{
                .head_slot = our_head_slot,
                .max_peer_finalized_slot = max_peer_finalized_slot,
            } };
        }

        return .synced;
    }
};

pub const BlockProcessingError = error{MissingPreState};
const BlockProductionError = error{ NotImplemented, MissingPreState };
const AttestationValidationError = error{
    MissingState,
    UnknownSourceBlock,
    UnknownTargetBlock,
    UnknownHeadBlock,
    SourceSlotExceedsTarget,
    SourceCheckpointExceedsTarget,
    SourceCheckpointSlotMismatch,
    TargetCheckpointSlotMismatch,
    AttestationTooFarInFuture,
};
const BlockValidationError = error{
    UnknownParentBlock,
};

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_pubkeys instead of num_validators
test "process and add mock blocks into a node's chain" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Generate a mock chain with validator pubkeys baked into the genesis spec.
    const mock_chain = try stf.genMockChain(allocator, 5, null);
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };
    var beam_state = mock_chain.genesis_state;
    const nodeId = 10; // random value
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(std.StringHashMap(PeerInfo));
    connected_peers.* = std.StringHashMap(PeerInfo).init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_finalized.root, &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.block.state_root[0..], &beam_chain.forkChoice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.message.block;
        const block_root = mock_chain.blockRoots[i];
        const current_slot = block.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{ .pruneForkchoice = false });
        allocator.free(missing_roots);

        try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &beam_chain.forkChoice.protoArray.nodes.items[i].blockRoot));
        const searched_idx = beam_chain.forkChoice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);

        // should have matching states in the state
        const block_state = beam_chain.states.get(block_root) orelse @panic("state root should have been found");
        var state_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(*types.BeamState, block_state, &state_root, allocator);
        try std.testing.expect(std.mem.eql(u8, &state_root, &block.state_root));

        // fcstore checkpoints should match
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_justified.root, &mock_chain.latestJustified[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_finalized.root, &mock_chain.latestFinalized[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.head.blockRoot, &mock_chain.latestHead[i].root));
    }

    const num_validators: usize = @intCast(mock_chain.genesis_config.numValidators());
    for (0..num_validators) |validator_id| {
        // all validators should have attested as per the mock chain
        const attestations_tracker = beam_chain.forkChoice.attestations.get(validator_id);
        try std.testing.expect(attestations_tracker != null);
    }
}

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_pubkeys instead of num_validators
test "printSlot output demonstration" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Create a mock chain with some blocks
    const mock_chain = try stf.genMockChain(allocator, 3, null);
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };
    var beam_state = mock_chain.genesis_state;
    const nodeId = 42; // Test node ID
    var zeam_logger_config = zeam_utils.getLoggerConfig(.info, null);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    // Initialize the beam chain
    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, &std.StringHashMap(PeerInfo).init(allocator));

    // Process some blocks to have a more interesting chain state
    for (1..mock_chain.blocks.len) |i| {
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.message.block;
        const current_slot = block.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{});
        allocator.free(missing_roots);
    }

    // Register some validators to make the output more interesting
    var validator_ids = [_]usize{ 0, 1, 2 };
    beam_chain.registerValidatorIds(&validator_ids);

    // Test printSlot at different slots to see the output
    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 0 ===\n", .{});
    beam_chain.printSlot(0, beam_chain.connected_peers.count());

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 1 ===\n", .{});
    beam_chain.printSlot(1, beam_chain.connected_peers.count());

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 2 ===\n", .{});
    beam_chain.printSlot(2, beam_chain.connected_peers.count());

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 5 (BEHIND) ===\n", .{});
    beam_chain.printSlot(5, beam_chain.connected_peers.count());

    // Verify that the chain state is as expected
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == mock_chain.blocks.len);
    try std.testing.expect(beam_chain.registered_validator_ids.len == 3);
}

// Attestation Validation Tests
// These tests align with leanSpec's test_attestation_processing.py

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_pubkeys instead of num_validators
test "attestation validation - comprehensive" {
    // Comprehensive test covering all attestation validation rules
    // This consolidates multiple validation checks into one test to avoid redundant setup
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 3, null);
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(std.StringHashMap(PeerInfo));
    connected_peers.* = std.StringHashMap(PeerInfo).init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain (slots 1 and 2)
    for (1..mock_chain.blocks.len) |i| {
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.message.block;
        try beam_chain.forkChoice.onInterval(block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{});
        allocator.free(missing_roots);
    }

    // Test 1: Valid attestation (baseline - should pass)
    {
        const source_slot: types.Slot = 1;
        const target_slot: types.Slot = 2;
        const valid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = target_slot,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[target_slot],
                    .slot = target_slot,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[source_slot],
                    .slot = source_slot,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[target_slot],
                    .slot = target_slot,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        // Should pass validation
        try beam_chain.validateAttestation(valid_attestation.toAttestation(), false);
    }

    // Test 2: Unknown source block
    {
        const unknown_root = [_]u8{0xFF} ** 32;
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = unknown_root, // Unknown block
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.UnknownSourceBlock, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }

    // Test 3: Unknown target block
    {
        const unknown_root = [_]u8{0xEE} ** 32;
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = unknown_root, // Unknown block
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.UnknownTargetBlock, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }

    // Test 4: Unknown head block
    {
        const unknown_root = [_]u8{0xDD} ** 32;
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = unknown_root, // Unknown block
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.UnknownHeadBlock, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }
    // Test 5: Source slot exceeds target slot (block slots)
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.SourceSlotExceedsTarget, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }

    // Test 6: Source checkpoint slot exceeds target checkpoint slot
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.SourceSlotExceedsTarget, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }

    // Test 7: Source checkpoint slot mismatch
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 0,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.SourceCheckpointSlotMismatch, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }

    // Test 8: Target checkpoint slot mismatch
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 1, // Checkpoint claims slot 1 (mismatch)
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.TargetCheckpointSlotMismatch, beam_chain.validateAttestation(invalid_attestation.toAttestation(), false));
    }

    // Test 9: Attestation too far in future (for gossip)
    {
        const future_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 3, // Future slot (current is 2)
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestation(future_attestation.toAttestation(), false));
    }
}

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_pubkeys instead of num_validators
test "attestation validation - gossip vs block future slot handling" {
    // Test that gossip and block attestations have different future slot tolerances
    // Gossip: must be <= current_slot
    // Block: can be <= current_slot + 1
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 2, null);
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(std.StringHashMap(PeerInfo));
    connected_peers.* = std.StringHashMap(PeerInfo).init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Add one block (slot 1)
    const block = mock_chain.blocks[1];
    try beam_chain.forkChoice.onInterval(block.message.block.slot * constants.INTERVALS_PER_SLOT, false);
    const missing_roots = try beam_chain.onBlock(block, .{});
    allocator.free(missing_roots);

    // Current time is at slot 1, create attestation for slot 2 (next slot)
    const next_slot_attestation: types.SignedAttestation = .{
        .validator_id = 0,
        .message = .{
            .slot = 2,
            .head = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Checkpoint{
                .root = mock_chain.blockRoots[0],
                .slot = 0,
            },
            .target = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
        },
        .signature = ZERO_SIGBYTES,
    };

    // Gossip attestations: should FAIL for next slot (current + 1)
    // Per spec store.py:177: assert attestation.slot <= time_slots
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestation(next_slot_attestation.toAttestation(), false));

    // Block attestations: should PASS for next slot (current + 1)
    // Per spec store.py:140: assert attestation.slot <= Slot(current_slot + Slot(1))
    try beam_chain.validateAttestation(next_slot_attestation.toAttestation(), true);
    const too_far_attestation: types.SignedAttestation = .{
        .validator_id = 0,
        .message = .{
            .slot = 3, // Too far in future
            .head = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Checkpoint{
                .root = mock_chain.blockRoots[0],
                .slot = 0,
            },
            .target = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
        },
        .signature = ZERO_SIGBYTES,
    };
    // Both should fail for slot 3 when current is slot 1
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestation(too_far_attestation.toAttestation(), false));
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestation(too_far_attestation.toAttestation(), true));
}
// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_pubkeys instead of num_validators
test "attestation processing - valid block attestation" {
    // Test that valid attestations from blocks are processed correctly
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 3, null);
    const spec_name = try allocator.dupe(u8, "beamdev");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
        },
    };
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(std.StringHashMap(PeerInfo));
    connected_peers.* = std.StringHashMap(PeerInfo).init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.message.block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(block, .{});
        allocator.free(missing_roots);
    }

    // Create a valid attestation
    const message = types.Attestation{
        .validator_id = 1,
        .data = .{
            .slot = 2,
            .head = types.Checkpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
            .source = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .target = types.Checkpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
        },
    };

    var key_manager = try keymanager.getTestKeyManager(allocator, 4, 3);
    defer key_manager.deinit();

    const signature = try key_manager.signAttestation(&message, allocator);

    const valid_attestation: types.SignedAttestation = .{
        .validator_id = message.validator_id,
        .message = message.data,
        .signature = signature,
    };

    // Process attestation through chain (this validates and then processes)
    try beam_chain.onGossipAttestation(valid_attestation);

    // Verify the attestation was recorded in attestations
    const attestations_tracker = beam_chain.forkChoice.attestations.get(1);
    try std.testing.expect(attestations_tracker != null);
    try std.testing.expect(attestations_tracker.?.latestNew != null);
    try std.testing.expect(attestations_tracker.?.latestNew.?.slot == 2);
}
