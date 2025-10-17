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
const database = @import("@zeam/database");

const event_broadcaster = api.event_broadcaster;

const zeam_utils = @import("@zeam/utils");
const jsonToString = zeam_utils.jsonToString;

pub const fcFactory = @import("./forkchoice.zig");
const constants = @import("./constants.zig");

const node = @import("./node.zig");
const PeerInfo = node.PeerInfo;

pub const BlockProductionParams = struct {
    slot: usize,
    proposer_index: usize,
};

pub const VoteConstructionParams = struct {
    slot: usize,
};

pub const ChainOpts = struct {
    config: configs.ChainConfig,
    anchorState: *types.BeamState,
    nodeId: u32,
    logger_config: *zeam_utils.ZeamLoggerConfig,
    db: database.Db,
};

pub const CachedProcessedBlockInfo = struct {
    postState: ?*types.BeamState = null,
    blockRoot: ?types.Root = null,
};

pub const ProducedBlock = struct {
    block: types.BeamBlock,
    blockRoot: types.Root,
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
    last_emitted_justified_slot: u64 = 0,
    last_emitted_finalized_slot: u64 = 0,
    connected_peers: *const std.StringHashMap(PeerInfo),

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
            .last_emitted_justified_slot = 0,
            .last_emitted_finalized_slot = 0,
            .connected_peers = connected_peers,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.states.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.states.deinit();
        // assume the allocator of config is same as self.allocator
        self.config.deinit(self.allocator);
        self.anchor_state.deinit();
    }

    pub fn registerValidatorIds(self: *Self, validator_ids: []usize) void {
        // right now it's simple assignment but eventually it should be a set
        // tacking registrations and keeping it alive for 3*2=6 slots
        self.registered_validator_ids = validator_ids;
    }

    pub fn onInterval(self: *Self, time_intervals: usize) !void {
        // see if the node has a proposal this slot to properly tick
        // forkchoice head
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        const interval = time_intervals % constants.INTERVALS_PER_SLOT;

        var has_proposal = false;
        if (interval == 0) {
            const num_validators: usize = @intCast(self.config.genesis.num_validators);
            const slot_proposer_id = slot % num_validators;
            if (std.mem.indexOfScalar(usize, self.registered_validator_ids, slot_proposer_id)) |index| {
                _ = index;
                has_proposal = true;
            }
        }

        self.module_logger.debug("Ticking chain to time(intervals)={d} = slot={d} interval={d} has_proposal={} ", .{
            time_intervals,
            slot,
            interval,
            has_proposal,
        });

        try self.forkChoice.onInterval(time_intervals, has_proposal);
        if (interval == 1) {
            // interval to vote so we should put out the chain status information to the user along with
            // latest head which most likely should be the new block received and processed
            const islot: isize = @intCast(slot);
            self.printSlot(islot, self.connected_peers.count());
        }
        // check if log rotation is needed
        self.zeam_logger_config.maybeRotate() catch |err| {
            self.module_logger.err("error rotating log file: {any}", .{err});
        };
    }

    pub fn produceBlock(self: *Self, opts: BlockProductionParams) !ProducedBlock {
        // right now with integrated validator into node produceBlock is always gurranteed to be
        // called post ticking the chain to the correct time, but once validator is separated
        // one must make the forkchoice tick to the right time if there is a race condition
        // however in that scenario forkchoice also needs to be protected by mutex/kept thread safe
        const chainHead = try self.forkChoice.updateHead();
        const votes = try self.forkChoice.getProposalVotes();
        const parent_root = chainHead.blockRoot;

        const pre_state = self.states.get(parent_root) orelse return BlockProductionError.MissingPreState;
        const post_state = try self.allocator.create(types.BeamState);
        try types.sszClone(self.allocator, types.BeamState, pre_state.*, post_state);

        // keeping for later when execution will be integrated into lean
        // const timestamp = self.config.genesis.genesis_time + opts.slot * params.SECONDS_PER_SLOT;

        var block = types.BeamBlock{
            .slot = opts.slot,
            .proposer_index = opts.proposer_index,
            .parent_root = parent_root,
            .state_root = undefined,
            .body = types.BeamBlockBody{
                // .execution_payload_header = .{ .timestamp = timestamp },
                .attestations = votes,
            },
        };

        var block_json = try block.toJson(self.allocator);
        const block_str = try jsonToString(self.allocator, block_json);
        defer self.allocator.free(block_str);

        self.module_logger.debug("node-{d}::going for block production opts={any} raw block={s}", .{ self.nodeId, opts, block_str });

        // 2. apply STF to get post state & update post state root & cache it
        try stf.apply_raw_block(self.allocator, post_state, &block, self.block_building_logger);

        block_json = try block.toJson(self.allocator);
        const block_str_2 = try jsonToString(self.allocator, block_json);
        defer self.allocator.free(block_str_2);

        self.module_logger.debug("applied raw block opts={any} raw block={s}", .{ opts, block_str_2 });

        // 3. cache state to save recompute while adding the block on publish
        var block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);
        try self.states.put(block_root, post_state);

        return .{
            .block = block,
            .blockRoot = block_root,
        };
    }

    pub fn constructVote(self: *Self, opts: VoteConstructionParams) !types.Mini3SFVote {
        const slot = opts.slot;

        const head = try self.forkChoice.getProposalHead(slot);
        const target = try self.forkChoice.getVoteTarget();

        const vote = types.Mini3SFVote{
            //
            .slot = slot,
            .head = head,
            .target = target,
            .source = self.forkChoice.fcStore.latest_justified,
        };

        return vote;
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

    pub fn onGossip(self: *Self, data: *const networks.GossipMessage) !void {
        switch (data.*) {
            .block => |signed_block| {
                const block = signed_block.message;
                var block_root: [32]u8 = undefined;
                try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);

                //check if we have the block already in forkchoice
                const hasBlock = self.forkChoice.hasBlock(block_root);
                const signed_block_json = try signed_block.toJson(self.allocator);

                // Convert JSON value to string for proper logging
                const signed_block_str = try jsonToString(self.allocator, signed_block_json);
                defer self.allocator.free(signed_block_str);

                self.module_logger.debug("chain received block onGossip cb at slot={any} blockroot={any} hasBlock={any}", .{
                    //
                    signed_block_str,
                    block_root,
                    hasBlock,
                });

                if (!hasBlock) {
                    const hasParentBlock = self.forkChoice.hasBlock(block.parent_root);
                    self.module_logger.debug("block processing is required hasParentBlock={any}", .{hasParentBlock});
                    if (hasParentBlock) {
                        self.onBlock(signed_block, .{}) catch |err| {
                            self.module_logger.debug(" ^^^^^^^^ Block processing error ^^^^^^ {any}", .{err});
                        };
                    }
                }
            },
            .vote => |signed_vote| {
                const signed_vote_json = try signed_vote.toJson(self.allocator);

                // Convert JSON value to string for proper logging
                const signed_vote_str = try jsonToString(self.allocator, signed_vote_json);
                defer self.allocator.free(signed_vote_str);

                self.module_logger.debug("chain received vote onGossip cb: {s}", .{signed_vote_str});

                // Validate attestation before processing
                self.validateAttestation(signed_vote) catch |err| {
                    self.module_logger.debug("Gossip attestation validation failed: {any}", .{err});
                    return; // Drop invalid gossip attestations
                };

                // Process validated attestation
                self.onAttestation(signed_vote) catch |err| {
                    self.module_logger.debug("Attestation processing error: {any}", .{err});
                };
            },
        }
    }

    // import block assuming it is gossip validated or synced
    // this onBlock corresponds to spec's forkchoice's onblock with some functionality split between this and
    // our implemented forkchoice's onblock. this is to parallelize "apply transition" with other verifications
    pub fn onBlock(self: *Self, signedBlock: types.SignedBeamBlock, blockInfo: CachedProcessedBlockInfo) !void {
        const onblock_timer = api.chain_onblock_duration_seconds.start();

        const block = signedBlock.message;
        const block_root: types.Root = blockInfo.blockRoot orelse computedroot: {
            var cblock_root: [32]u8 = undefined;
            try ssz.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
            break :computedroot cblock_root;
        };
        self.module_logger.debug("processing block with root=0x{s} slot={d}", .{
            std.fmt.fmtSliceHexLower(&block_root),
            block.slot,
        });

        const post_state = if (blockInfo.postState) |post_state_ptr| post_state_ptr else computedstate: {
            // 1. get parent state
            const pre_state = self.states.get(signedBlock.message.parent_root) orelse return BlockProcessingError.MissingPreState;
            const cpost_state = try self.allocator.create(types.BeamState);
            try types.sszClone(self.allocator, types.BeamState, pre_state.*, cpost_state);

            // 2. apply STF to get post state
            var validSignatures = true;
            stf.verify_signatures(signedBlock) catch {
                validSignatures = false;
            };
            try stf.apply_transition(self.allocator, cpost_state, signedBlock, .{
                //
                .logger = self.stf_logger,
                .validSignatures = validSignatures,
            });
            break :computedstate cpost_state;
        };

        // 3. fc onblock
        const fcBlock = try self.forkChoice.onBlock(block, post_state, .{
            .currentSlot = block.slot,
            .blockDelayMs = 0,
            .blockRoot = block_root,
        });
        try self.states.put(fcBlock.blockRoot, post_state);

        // 4. fc onvotes
        self.module_logger.debug("processing attestations of block with root=0x{s} slot={d}", .{
            std.fmt.fmtSliceHexLower(&fcBlock.blockRoot),
            block.slot,
        });
        for (block.body.attestations.constSlice()) |signed_vote| {
            // Validate attestation before processing
            self.validateAttestation(signed_vote) catch |e| {
                self.module_logger.err("invalid attestation in block: validator={d} error={any}", .{ signed_vote.validator_id, e });
                // Skip invalid attestations but continue processing the block
                continue;
            };

            self.forkChoice.onAttestation(signed_vote, true) catch |e| {
                self.module_logger.err("error processing block attestation={any} e={any}", .{ signed_vote, e });
            };
        }

        // 5. fc update head
        const new_head = try self.forkChoice.updateHead();
        const processing_time = onblock_timer.observe();

        // 6. Emit new head event via SSE (use forkchoice ProtoBlock directly)
        if (api.events.NewHeadEvent.fromProtoBlock(self.allocator, new_head)) |head_event| {
            var chain_event = api.events.ChainEvent{ .new_head = head_event };
            event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                self.module_logger.warn("Failed to broadcast head event: {any}", .{err});
                chain_event.deinit(self.allocator);
            };
        } else |err| {
            self.module_logger.warn("Failed to create head event: {any}", .{err});
        }

        // 7. Emit justification/finalization events based on forkchoice store
        const store = self.forkChoice.fcStore;
        const latest_justified = store.latest_justified;
        const latest_finalized = store.latest_finalized;

        // Emit justification event only when slot increases beyond last emitted
        if (latest_justified.slot > self.last_emitted_justified_slot) {
            if (api.events.NewJustificationEvent.fromCheckpoint(self.allocator, latest_justified, new_head.slot)) |just_event| {
                var chain_event = api.events.ChainEvent{ .new_justification = just_event };
                event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                    self.module_logger.warn("Failed to broadcast justification event: {any}", .{err});
                    chain_event.deinit(self.allocator);
                };
                self.last_emitted_justified_slot = latest_justified.slot;
            } else |err| {
                self.module_logger.warn("Failed to create justification event: {any}", .{err});
            }
        }

        // Emit finalization event only when slot increases beyond last emitted
        if (latest_finalized.slot > self.last_emitted_finalized_slot) {
            if (api.events.NewFinalizationEvent.fromCheckpoint(self.allocator, latest_finalized, new_head.slot)) |final_event| {
                var chain_event = api.events.ChainEvent{ .new_finalization = final_event };
                event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                    self.module_logger.warn("Failed to broadcast finalization event: {any}", .{err});
                    chain_event.deinit(self.allocator);
                };
                self.last_emitted_finalized_slot = latest_finalized.slot;
            } else |err| {
                self.module_logger.warn("Failed to create finalization event: {any}", .{err});
            }
        }

        // 8. Save block and state to database
        var batch = self.db.initWriteBatch();
        defer batch.deinit();

        batch.putBlock(database.DbBlocksNamespace, fcBlock.blockRoot, signedBlock);
        batch.putState(database.DbStatesNamespace, fcBlock.blockRoot, post_state.*);

        self.db.commit(&batch);

        self.module_logger.info("processed block with root=0x{s} slot={d} processing time={d} (computed root={} computed state={})", .{
            std.fmt.fmtSliceHexLower(&fcBlock.blockRoot),
            block.slot,
            processing_time,
            blockInfo.blockRoot == null,
            blockInfo.postState == null,
        });
    }

    /// Validate incoming attestation before processing.
    pub fn validateAttestation(self: *Self, signed_vote: types.SignedVote) !void {
        const vote = signed_vote.message;

        // 1. Validate that source, target, and head blocks exist in proto array
        const source_idx = self.forkChoice.protoArray.indices.get(vote.source.root) orelse {
            self.module_logger.debug("Attestation validation failed: unknown source block root=0x{s}", .{
                std.fmt.fmtSliceHexLower(&vote.source.root),
            });
            return AttestationValidationError.UnknownSourceBlock;
        };

        const target_idx = self.forkChoice.protoArray.indices.get(vote.target.root) orelse {
            self.module_logger.debug("Attestation validation failed: unknown target block root=0x{s}", .{
                std.fmt.fmtSliceHexLower(&vote.target.root),
            });
            return AttestationValidationError.UnknownTargetBlock;
        };

        const head_idx = self.forkChoice.protoArray.indices.get(vote.head.root) orelse {
            self.module_logger.debug("Attestation validation failed: unknown head block root=0x{s}", .{
                std.fmt.fmtSliceHexLower(&vote.head.root),
            });
            return AttestationValidationError.UnknownHeadBlock;
        };

        const source_block = self.forkChoice.protoArray.nodes.items[source_idx];
        const target_block = self.forkChoice.protoArray.nodes.items[target_idx];
        const head_block = self.forkChoice.protoArray.nodes.items[head_idx];
        _ = head_block; // Will be used in future validations

        // 2. Validate slot relationships
        if (source_block.slot > target_block.slot) {
            self.module_logger.debug("Attestation validation failed: source slot {d} > target slot {d}", .{
                source_block.slot,
                target_block.slot,
            });
            return AttestationValidationError.SourceSlotExceedsTarget;
        }

        //    This corresponds to leanSpec's: assert vote.source.slot <= vote.target.slot
        if (vote.source.slot > vote.target.slot) {
            self.module_logger.debug("Attestation validation failed: source checkpoint slot {d} > target checkpoint slot {d}", .{
                vote.source.slot,
                vote.target.slot,
            });
            return AttestationValidationError.SourceCheckpointExceedsTarget;
        }

        // 3. Validate checkpoint slots match block slots
        if (source_block.slot != vote.source.slot) {
            self.module_logger.debug("Attestation validation failed: source block slot {d} != source checkpoint slot {d}", .{
                source_block.slot,
                vote.source.slot,
            });
            return AttestationValidationError.SourceCheckpointSlotMismatch;
        }

        //    This corresponds to leanSpec's: assert target_block.slot == vote.target.slot
        if (target_block.slot != vote.target.slot) {
            self.module_logger.debug("Attestation validation failed: target block slot {d} != target checkpoint slot {d}", .{
                target_block.slot,
                vote.target.slot,
            });
            return AttestationValidationError.TargetCheckpointSlotMismatch;
        }

        // 4. Validate attestation is not too far in the future
        //    current_slot = Slot(self.time // SECONDS_PER_INTERVAL)
        //    assert vote.slot <= Slot(current_slot + Slot(1))
        const max_allowed_slot = self.forkChoice.fcStore.timeSlots + constants.MAX_FUTURE_SLOT_TOLERANCE;
        if (vote.slot > max_allowed_slot) {
            self.module_logger.debug("Attestation validation failed: vote slot {d} > max allowed slot {d}", .{
                vote.slot,
                max_allowed_slot,
            });
            return AttestationValidationError.AttestationTooFarInFuture;
        }

        self.module_logger.debug("Attestation validation passed: validator={d} slot={d} source={d} target={d}", .{
            signed_vote.validator_id,
            vote.slot,
            vote.source.slot,
            vote.target.slot,
        });
    }

    pub fn onAttestation(self: *Self, signedVote: types.SignedVote) !void {
        // Validate attestation before processing
        try self.validateAttestation(signedVote);
        return self.forkChoice.onAttestation(signedVote, false);
    }
};

const BlockProcessingError = error{MissingPreState};
const BlockProductionError = error{ NotImplemented, MissingPreState };
const AttestationValidationError = error{
    UnknownSourceBlock,
    UnknownTargetBlock,
    UnknownHeadBlock,
    SourceSlotExceedsTarget,
    SourceCheckpointExceedsTarget,
    SourceCheckpointSlotMismatch,
    TargetCheckpointSlotMismatch,
    AttestationTooFarInFuture,
};

test "process and add mock blocks into a node's chain" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 5, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_finalized.root, &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.state_root[0..], &beam_chain.forkChoice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const block = mock_chain.blocks[i];
        const block_root = mock_chain.blockRoots[i];
        const current_slot = block.message.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, .{});

        try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &beam_chain.forkChoice.protoArray.nodes.items[i].blockRoot));
        const searched_idx = beam_chain.forkChoice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);

        // should have matching states in the state
        const block_state = beam_chain.states.get(block_root) orelse @panic("state root should have been found");
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(*types.BeamState, block_state, &state_root, allocator);
        try std.testing.expect(std.mem.eql(u8, &state_root, &block.message.state_root));

        // fcstore checkpoints should match
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_justified.root, &mock_chain.latestJustified[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.latest_finalized.root, &mock_chain.latestFinalized[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.head.blockRoot, &mock_chain.latestHead[i].root));
    }

    const num_validators: usize = @intCast(mock_chain.genesis_config.num_validators);
    for (0..num_validators) |validator_id| {
        // all validators should have voted as per the mock chain
        const vote_tracker = beam_chain.forkChoice.votes.get(validator_id);
        try std.testing.expect(vote_tracker != null);
    }
}

test "printSlot output demonstration" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Create a chain configuration
    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    // Create a mock chain with some blocks
    const mock_chain = try stf.genMockChain(allocator, 3, chain_config.genesis);
    var beam_state = mock_chain.genesis_state;
    const nodeId = 42; // Test node ID
    var zeam_logger_config = zeam_utils.getLoggerConfig(.info, null);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Initialize the beam chain
    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db }, &std.StringHashMap(PeerInfo).init(allocator));

    // Process some blocks to have a more interesting chain state
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        const current_slot = block.message.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, .{});
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

test "attestation validation - valid attestation" {
    // Test that a valid attestation passes all validation checks
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 3, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, .{});
    }

    // Create a valid attestation
    const source_slot: types.Slot = 1;
    const target_slot: types.Slot = 2;
    const valid_vote = types.SignedVote{
        .validator_id = 0,
        .message = types.Mini3SFVote{
            .slot = target_slot,
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[target_slot],
                .slot = target_slot,
            },
            .source = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[source_slot],
                .slot = source_slot,
            },
            .target = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[target_slot],
                .slot = target_slot,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // This should pass validation
    try beam_chain.validateAttestation(valid_vote);
}

test "attestation validation - unknown source block" {
    // Test that validation fails when source block is not in proto array
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 2, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add one block
    const block = mock_chain.blocks[1];
    try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
    try beam_chain.onBlock(block, .{});

    // Create attestation with unknown source block
    const unknown_root = [_]u8{0xFF} ** 32;
    const invalid_vote = types.SignedVote{
        .validator_id = 0,
        .message = types.Mini3SFVote{
            .slot = 1,
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Mini3SFCheckpoint{
                .root = unknown_root, // Unknown block
                .slot = 0,
            },
            .target = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // Should fail with UnknownSourceBlock error
    try std.testing.expectError(error.UnknownSourceBlock, beam_chain.validateAttestation(invalid_vote));
}

test "attestation validation - unknown target block" {
    // Test that validation fails when target block is not in proto array
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 2, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add one block
    const block = mock_chain.blocks[1];
    try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
    try beam_chain.onBlock(block, .{});

    // Create attestation with unknown target block
    const unknown_root = [_]u8{0xFF} ** 32;
    const invalid_vote = types.SignedVote{
        .validator_id = 0,
        .message = types.Mini3SFVote{
            .slot = 1,
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[0],
                .slot = 0,
            },
            .target = types.Mini3SFCheckpoint{
                .root = unknown_root, // Unknown block
                .slot = 2,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // Should fail with UnknownTargetBlock error
    try std.testing.expectError(error.UnknownTargetBlock, beam_chain.validateAttestation(invalid_vote));
}

test "attestation validation - source slot exceeds target slot" {
    // Test that validation fails when source block slot > target block slot
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 3, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, .{});
    }

    // Create attestation where source slot (2) > target slot (1) - invalid ordering
    const invalid_vote = types.SignedVote{
        .validator_id = 0,
        .message = types.Mini3SFVote{
            .slot = 2,
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[2], // Later slot
                .slot = 2,
            },
            .target = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1], // Earlier slot
                .slot = 1,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // Should fail with SourceSlotExceedsTarget error
    try std.testing.expectError(error.SourceSlotExceedsTarget, beam_chain.validateAttestation(invalid_vote));
}

test "attestation validation - checkpoint slot mismatch" {
    // Test that validation fails when checkpoint slots don't match block slots
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 3, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, .{});
    }

    // Create attestation where source checkpoint slot doesn't match block slot
    const invalid_vote = types.SignedVote{
        .validator_id = 0,
        .message = types.Mini3SFVote{
            .slot = 2,
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
            .source = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 0, // Mismatch: block is at slot 1, checkpoint says slot 0
            },
            .target = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // Should fail with SourceCheckpointSlotMismatch error
    try std.testing.expectError(error.SourceCheckpointSlotMismatch, beam_chain.validateAttestation(invalid_vote));
}

test "attestation validation - attestation too far in future" {
    // Test that validation fails for attestations too far in the future
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 2, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add one block (slot 1)
    const block = mock_chain.blocks[1];
    try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
    try beam_chain.onBlock(block, .{});

    // Current time is at slot 1, so max allowed attestation slot is 2 (current + 1)
    // Create attestation for slot 100 (too far in future)
    const future_vote = types.SignedVote{
        .validator_id = 0,
        .message = types.Mini3SFVote{
            .slot = 100, // Way too far in the future
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[0],
                .slot = 0,
            },
            .target = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // Should fail with AttestationTooFarInFuture error
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestation(future_vote));
}

test "attestation processing - valid block attestation" {
    // Test that valid attestations from blocks are processed correctly
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev", "genesis_time": 1234, "num_validators": 4}
    ;
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parsed_chain_spec = (try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options)).value;
    const chain_config = try configs.ChainConfig.init(configs.Chain.custom, parsed_chain_spec);

    const mock_chain = try stf.genMockChain(allocator, 3, chain_config.genesis);
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

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.message.slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, .{});
    }

    // Create a valid attestation
    const valid_vote = types.SignedVote{
        .validator_id = 1,
        .message = types.Mini3SFVote{
            .slot = 2,
            .head = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
            .source = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .target = types.Mini3SFCheckpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
        },
        .signature = [_]u8{0} ** types.SIGSIZE,
    };

    // Process attestation through chain (this validates and then processes)
    try beam_chain.onAttestation(valid_vote);

    // Verify the vote was recorded in latestKnown
    const vote_tracker = beam_chain.forkChoice.votes.get(1);
    try std.testing.expect(vote_tracker != null);
    try std.testing.expect(vote_tracker.?.latestNew != null);
    try std.testing.expect(vote_tracker.?.latestNew.?.slot == 2);
}
