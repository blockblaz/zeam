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

pub const BlockProductionParams = struct {
    slot: usize,
    proposer_index: usize,
};

pub const BeamChain = struct {
    config: configs.ChainConfig,
    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,
    // from finalized onwards to recent
    states: std.AutoHashMap(types.Root, types.BeamState),
    nodeId: u32,
    logger: *const zeam_utils.ZeamLogger,

    const Self = @This();
    pub fn init(
        allocator: Allocator,
        config: configs.ChainConfig,
        anchorState: types.BeamState,
        nodeId: u32,
        logger: *const zeam_utils.ZeamLogger,
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

    pub fn onSlot(self: *Self, slot: usize) !void {
        // see if you need to product block before you tick the slot to get correct canonical head
        // ideally this section should be called an interval before the slot is ticked
        self.prepareNextSlot(slot);
        self.tickSlot(slot);
    }

    fn prepareNextSlot(self: *Self, nextSlot: usize) void {
        // nothing to prep for now
        _ = self;
        _ = nextSlot;
    }

    fn tickSlot(self: *Self, slot: usize) void {
        self.forkChoice.tickSlot(slot);
        // self.printSlot(slot);
    }

    pub fn produceBlock(self: *Self, opts: BlockProductionParams) !types.BeamBlock {
        const chainHead = try self.forkChoice.updateHead();
        const parent_root = chainHead.blockRoot;

        const pre_state = self.states.get(parent_root) orelse return BlockProductionError.MissingPreState;
        var post_state = try types.sszClone(self.allocator, types.BeamState, pre_state);

        const timestamp = self.config.genesis.genesis_time + opts.slot * params.SECONDS_PER_SLOT;

        const votes = [_]types.Mini3SFVote{};
        var block = types.BeamBlock{
            .slot = opts.slot,
            .proposer_index = opts.proposer_index,
            .parent_root = parent_root,
            .state_root = undefined,
            .body = types.BeamBlockBody{
                .execution_payload_header = .{ .timestamp = timestamp },
                .votes = &votes,
            },
        };

        self.logger.debug("node-{d}::going for block production opts={any} raw block={any}", .{ self.nodeId, opts, block });

        // 2. apply STF to get post state
        try stf.apply_raw_block(self.allocator, &post_state, &block, self.logger);

        self.logger.debug("applied raw block opts={any} raw block={any}", .{ opts, block });

        // 3. fc onblock
        const fcBlock = try self.forkChoice.onBlock(block, post_state, .{ .currentSlot = block.slot, .blockDelayMs = 0 });
        try self.states.put(fcBlock.blockRoot, post_state);

        return block;
    }

    pub fn printSlot(self: *Self, slot: usize) !void {
        const fcHead = try self.forkChoice.updateHead();
        self.logger.debug("node-{d}::chain received on slot cb at slot={d} head={any} headslot={d}", .{ self.nodeId, slot, fcHead.blockRoot, fcHead.slot });
    }

    pub fn onGossip(self: *Self, data: *const networks.GossipMessage) !void {
        switch (data.*) {
            .block => |block| {
                self.logger.debug("node-{d}::chain received block onGossip cb at slot={any}", .{ self.nodeId, block });
                var block_root: [32]u8 = undefined;
                try ssz.hashTreeRoot(types.BeamBlock, block.message, &block_root, self.allocator);

                //check if we have the block already in forkchoice
                const hasBlock = self.forkChoice.hasBlock(block_root);
                self.logger.debug("blockroot={any} hasblock={any}", .{ block_root, hasBlock });
                if (!hasBlock) {
                    const hasParentBlock = self.forkChoice.hasBlock(block.message.parent_root);
                    self.logger.debug("block processing is required hasParentBlock={any}", .{hasParentBlock});
                    if (hasParentBlock) {
                        self.onBlock(block) catch |err| {
                            self.logger.debug(" ^^^^^^^^ Block processing error ^^^^^^ {any}", .{err});
                        };
                    }
                }
            },
        }

        try self.printSlot(self.forkChoice.fcStore.currentSlot);
    }

    // import block assuming it is validated
    fn onBlock(self: *Self, signedBlock: types.SignedBeamBlock) !void {
        const onblock_timer = metrics.chain_onblock_duration_seconds.start();
        // 1. get parent state
        const pre_state = self.states.get(signedBlock.message.parent_root) orelse return BlockProcessingError.MissingPreState;
        var post_state = try types.sszClone(self.allocator, types.BeamState, pre_state);

        // 2. apply STF to get post state
        try stf.apply_transition(self.allocator, &post_state, signedBlock, .{ .logger = self.logger });

        // 3. fc onblock
        const block = signedBlock.message;
        const fcBlock = try self.forkChoice.onBlock(block, post_state, .{ .currentSlot = block.slot, .blockDelayMs = 0 });
        try self.states.put(fcBlock.blockRoot, post_state);
        // 3. fc onvotes
        for (block.body.votes) |vote| {
            try self.forkChoice.onAttestation(vote);
        }
        // 3. fc update head
        _ = try self.forkChoice.updateHead();
        onblock_timer.observe();
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
    const logger = zeam_utils.getLogger(.info);

    var beam_chain = try BeamChain.init(allocator, chain_config, beam_state, nodeid, &logger);

    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.finalized.root, &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.state_root[0..], &beam_chain.forkChoice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const block = mock_chain.blocks[i];
        const block_root = mock_chain.blockRoots[i];
        const current_slot = block.message.slot;

        beam_chain.forkChoice.tickSlot(current_slot);
        try beam_chain.onBlock(block);

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
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.justified.root, &mock_chain.latestJustified[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.fcStore.finalized.root, &mock_chain.latestFinalized[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.head.blockRoot, &mock_chain.latestHead[i].root));
    }

    const num_validators: usize = @intCast(mock_chain.genesis_config.num_validators);
    for (0..num_validators) |validator_id| {
        // all validators should have voted as per the mock chain
        const vote_tracker = beam_chain.forkChoice.votes.get(validator_id);
        try std.testing.expect(vote_tracker != null);
    }
}
