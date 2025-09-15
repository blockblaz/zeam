const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const stf = @import("@zeam/state-transition");
const ssz = @import("ssz");
const networks = @import("@zeam/network");
const params = @import("@zeam/params");
const metrics = @import("@zeam/metrics");

const zeam_utils = @import("@zeam/utils");

pub const fcFactory = @import("./forkchoice.zig");
const constants = @import("./constants.zig");

pub const BlockProductionParams = struct {
    slot: usize,
    proposer_index: usize,
};

pub const VoteConstructionParams = struct {
    slot: usize,
};

pub const BeamChain = struct {
    config: configs.ChainConfig,
    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,
    // from finalized onwards to recent
    states: std.AutoHashMap(types.Root, types.BeamState),
    nodeId: u32,
    logger: *zeam_utils.ZeamLogger,
    registered_validator_ids: []usize = &[_]usize{},

    const Self = @This();
    pub fn init(
        allocator: Allocator,
        config: configs.ChainConfig,
        anchorState: types.BeamState,
        nodeId: u32,
        logger: *zeam_utils.ZeamLogger,
    ) !Self {
        const fork_choice = try fcFactory.ForkChoice.init(allocator, config, anchorState, logger);

        var states = std.AutoHashMap(types.Root, types.BeamState).init(allocator);
        try states.put(fork_choice.head.blockRoot, anchorState);

        return Self{
            .nodeId = nodeId,
            .config = config,
            .forkChoice = fork_choice,
            .allocator = allocator,
            .states = states,
            .logger = logger,
        };
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

        self.logger.debug("Ticking chain to time(intervals)={d} = slot={d} interval={d} has_proposal={} ", .{
            time_intervals,
            slot,
            interval,
            has_proposal,
        });

        try self.forkChoice.onInterval(time_intervals, has_proposal);
        if (interval == 1) {
            // interval to vote so we should put out the chain status information to the user along with
            // latest head which most likely should be the new block recieved and processed
            self.printSlot(slot);
        }
        // check if log rotation is needed
        self.logger.maybeRotate() catch |err| {
            self.logger.err("error rotating log file: {any}", .{err});
        };
    }

    pub fn produceBlock(self: *Self, opts: BlockProductionParams) !types.BeamBlock {
        // right now with integrated validator into node produceBlock is always gurranteed to be
        // called post ticking the chain to the correct time, but once validator is separated
        // one must make the forkchoice tick to the right time if there is a race condition
        // however in that scenario forkchoice also needs to be protected by mutex/kept thread safe
        const chainHead = try self.forkChoice.updateHead();
        const votes = try self.forkChoice.getProposalVotes();
        const parent_root = chainHead.blockRoot;

        const pre_state = self.states.get(parent_root) orelse return BlockProductionError.MissingPreState;
        var post_state = try types.sszClone(self.allocator, types.BeamState, pre_state);

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

        self.logger.debug("node-{d}::going for block production opts={any} raw block={any}", .{ self.nodeId, opts, block });

        // 2. apply STF to get post state & update post state root & cache it
        try stf.apply_raw_block(self.allocator, &post_state, &block, self.logger);
        self.logger.debug("applied raw block opts={any} raw block={any}", .{ opts, block });

        // 3. cache state to save recompute while adding the block on publish
        var block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);
        try self.states.put(block_root, post_state);

        return block;
    }

    // TODO: right now validator indepdently publishes to the network but move gossip message
    // construction and publishing from there to here
    pub fn publishBlock(self: *Self, signedBlock: types.SignedBeamBlock) !void {
        var block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, signedBlock.message, &block_root, self.allocator);
        try self.onBlock(signedBlock, self.states.get(block_root));
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

    // TODO: right now validator indepdently publishes to the network but move the gossip
    // message construction and publish at a refactor PR
    pub fn publishVote(self: *Self, signedVote: types.SignedVote) !void {
        // no need to see if we produced this vote as everything is trusted in-process lifecycle
        // validate when validator is separated out
        return self.onAttestation(signedVote);
    }

    pub fn printSlot(self: *Self, slot: usize) void {
        // head should be auto updated if receieved a block or block proposal done
        // however it doesn't get updated unless called updatehead even though processs block
        // logs show it has been updated. debug and fix the call below
        const fc_head = self.forkChoice.updateHead() catch |err| {
            self.logger.err("forkchoice updatehead error={any}", .{err});
            return;
        };

        // Get additional chain information
        const justified = self.forkChoice.fcStore.latest_justified;
        const finalized = self.forkChoice.fcStore.latest_finalized;

        // Calculate chain progress
        const blocks_behind = if (slot > fc_head.slot) slot - fc_head.slot else 0;
        const is_timely = fc_head.timeliness;

        self.logger.info(
            \\
            \\+===============================================================+
            \\                         CHAIN STATUS                            
            \\+===============================================================+
            \\  Current Slot: {d} | Head Slot: {d} | Behind: {d}
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
            slot,
            fc_head.slot,
            blocks_behind,
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
                self.logger.debug("chain received block onGossip cb at slot={any} blockroot={any} hasBlock={any}", .{
                    //
                    signed_block,
                    block_root,
                    hasBlock,
                });

                if (!hasBlock) {
                    const hasParentBlock = self.forkChoice.hasBlock(block.parent_root);
                    self.logger.debug("block processing is required hasParentBlock={any}", .{hasParentBlock});
                    if (hasParentBlock) {
                        self.onBlock(signed_block, null) catch |err| {
                            self.logger.debug(" ^^^^^^^^ Block processing error ^^^^^^ {any}", .{err});
                        };
                    }
                }
            },
            .vote => |signed_vote| {
                const vote = signed_vote.message;
                const hasHead = self.forkChoice.hasBlock(vote.head.root);
                self.logger.debug("chain received vote onGossip cb at slot={any} hasHead={any}", .{
                    //
                    signed_vote,
                    hasHead,
                });

                if (hasHead) {
                    self.onAttestation(signed_vote) catch |err| {
                        self.logger.debug(" ^^^^^^^^ Attestation processing error ^^^^^^ {any}", .{err});
                    };
                }
            },
        }
    }

    // import block assuming it is gossip validated or synced
    // this onBlock corresponds to spec's forkchoice's onblock with some functionality split between this and
    // our implemented forkchoice's onblock. this is to parallelize "apply transition" with other verifications
    fn onBlock(self: *Self, signedBlock: types.SignedBeamBlock, ipost_state: ?types.BeamState) !void {
        const onblock_timer = metrics.chain_onblock_duration_seconds.start();

        const post_state = ipost_state orelse computedstate: {
            // 1. get parent state
            const pre_state = self.states.get(signedBlock.message.parent_root) orelse return BlockProcessingError.MissingPreState;
            var cpost_state = try types.sszClone(self.allocator, types.BeamState, pre_state);

            // 2. apply STF to get post state
            var validSignatures = true;
            stf.verify_signatures(signedBlock) catch {
                validSignatures = false;
            };
            try stf.apply_transition(self.allocator, &cpost_state, signedBlock, .{
                //
                .logger = self.logger,
                .validSignatures = validSignatures,
            });
            break :computedstate cpost_state;
        };

        // 3. fc onblock
        const block = signedBlock.message;
        const fcBlock = try self.forkChoice.onBlock(block, post_state, .{ .currentSlot = block.slot, .blockDelayMs = 0 });
        try self.states.put(fcBlock.blockRoot, post_state);

        // 4. fc onvotes
        for (block.body.attestations) |signed_vote| {
            self.forkChoice.onAttestation(signed_vote, true) catch |e| {
                self.logger.err("error processing block attestation={any} e={any}", .{ signed_vote, e });
            };
        }

        // 5. fc update head
        _ = try self.forkChoice.updateHead();
        onblock_timer.observe();
    }

    fn onAttestation(self: *Self, signedVote: types.SignedVote) !void {
        return self.forkChoice.onAttestation(signedVote, false);
    }
};

const BlockProcessingError = error{MissingPreState};
const BlockProductionError = error{ NotImplemented, MissingPreState };

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
    const beam_state = mock_chain.genesis_state;
    const nodeid = 10; // random value
    var logger = zeam_utils.getTestLogger();

    var beam_chain = try BeamChain.init(allocator, chain_config, beam_state, nodeid, &logger);

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
        try beam_chain.onBlock(block, null);

        try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &beam_chain.forkChoice.protoArray.nodes.items[i].blockRoot));
        const searched_idx = beam_chain.forkChoice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);

        // should have matching states in the state
        const block_state = beam_chain.states.get(block_root) orelse @panic("state root should have been found");
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamState, block_state, &state_root, allocator);
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
    const beam_state = mock_chain.genesis_state;
    const nodeid = 42; // Test node ID
    var logger = zeam_utils.getLogger(.info, null);

    // Initialize the beam chain
    var beam_chain = try BeamChain.init(allocator, chain_config, beam_state, nodeid, &logger);

    // Process some blocks to have a more interesting chain state
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        const current_slot = block.message.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        try beam_chain.onBlock(block, null);
    }

    // Register some validators to make the output more interesting
    var validator_ids = [_]usize{ 0, 1, 2 };
    beam_chain.registerValidatorIds(&validator_ids);

    // Test printSlot at different slots to see the output
    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 0 ===\n", .{});
    beam_chain.printSlot(0);

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 1 ===\n", .{});
    beam_chain.printSlot(1);

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 2 ===\n", .{});
    beam_chain.printSlot(2);

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 5 (BEHIND) ===\n", .{});
    beam_chain.printSlot(5);

    // Verify that the chain state is as expected
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == mock_chain.blocks.len);
    try std.testing.expect(beam_chain.registered_validator_ids.len == 3);
}
