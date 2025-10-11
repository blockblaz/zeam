const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const zeam_utils = @import("@zeam/utils");
const stf = @import("@zeam/state-transition");
const api = @import("@zeam/api");

const constants = @import("./constants.zig");

const ProtoBlock = types.ProtoBlock;
const ProtoMeta = struct {
    parent: ?usize,
    weight: isize,
    bestChild: ?usize,
    bestDescendant: ?usize,
};
pub const ProtoNode = zeam_utils.MixIn(ProtoBlock, ProtoMeta);

pub const ProtoArray = struct {
    nodes: std.ArrayList(ProtoNode),
    indices: std.AutoHashMap(types.Root, usize),

    const Self = @This();
    pub fn init(allocator: Allocator, anchorBlock: ProtoBlock) !Self {
        const nodes = std.ArrayList(ProtoNode).init(allocator);
        const indices = std.AutoHashMap(types.Root, usize).init(allocator);

        var proto_array = Self{
            .nodes = nodes,
            .indices = indices,
        };
        try proto_array.onBlock(anchorBlock, anchorBlock.slot);
        return proto_array;
    }

    pub fn onBlock(self: *Self, block: ProtoBlock, currentSlot: types.Slot) !void {
        // currentSlot might be needed in future for finding the viable head
        _ = currentSlot;
        const node_or_null = self.indices.get(block.blockRoot);
        if (node_or_null) |node| {
            _ = node;
            return;
        }

        const parent = self.indices.get(block.parentRoot);

        // TODO extend is not working so copy data for now
        // const node = utils.Extend(ProtoNode, block, .{
        //     .parent = parent,
        //     .weight = weight,
        //     // bestChild and bestDescendant are left null
        // });
        const node = ProtoNode{
            .slot = block.slot,
            .blockRoot = block.blockRoot,
            .parentRoot = block.parentRoot,
            .stateRoot = block.stateRoot,
            .timeliness = block.timeliness,
            .parent = parent,
            .weight = 0,
            .bestChild = null,
            .bestDescendant = null,
        };
        const node_index = self.nodes.items.len;
        try self.nodes.append(node);
        try self.indices.put(node.blockRoot, node_index);
    }

    fn getNode(self: *Self, blockRoot: types.Root) ?ProtoNode {
        const block_index = self.indices.get(blockRoot);
        if (block_index) |blkidx| {
            const node = self.nodes.items[blkidx];
            return node;
        } else {
            return null;
        }
    }

    pub fn getBlock(self: *Self, blockRoot: types.Root) ?ProtoBlock {
        const nodeOrNull = self.getNode(blockRoot);
        if (nodeOrNull) |node| {
            // TODO cast doesn't seem to be working find resolution
            // const block = utils.Cast(ProtoBlock, node);
            const block = ProtoBlock{
                .slot = node.slot,
                .blockRoot = node.blockRoot,
                .parentRoot = node.parentRoot,
                .stateRoot = node.stateRoot,
                .timeliness = node.timeliness,
            };
            return block;
        } else {
            return null;
        }
    }

    pub fn applyDeltas(self: *Self, deltas: []isize, cutoff_weight: u64) !void {
        if (deltas.len != self.nodes.items.len) {
            return ForkChoiceError.InvalidDeltas;
        }

        // iterate backwards apply deltas and propagating deltas to parents
        for (0..self.nodes.items.len) |i| {
            const node_idx = self.nodes.items.len - 1 - i;
            const node_delta = deltas[node_idx];
            self.nodes.items[node_idx].weight += node_delta;
            if (self.nodes.items[node_idx].parent) |parent_idx| {
                deltas[parent_idx] += node_delta;
            }
        }

        // re-iterate backwards and calc best child and descendant
        // there seems to be no filter block tree in the mini3sf fc
        for (0..self.nodes.items.len) |i| {
            const node_idx = self.nodes.items.len - 1 - i;
            const node = self.nodes.items[node_idx];

            if (self.nodes.items[node_idx].parent) |parent_idx| {
                const nodeBestDescendant = node.bestDescendant orelse (
                    // by recurssion, we will always have a bestDescendant >= cutoff
                    if (self.nodes.items[node_idx].weight >= cutoff_weight) node_idx else null
                    //
                );

                const parent = self.nodes.items[parent_idx];
                var updateBest = false;

                if (parent.bestChild == node_idx) {
                    // check if bestDescendant needs to be updated even if best child is same
                    if (parent.bestDescendant != nodeBestDescendant) {
                        updateBest = true;
                    }
                } else {
                    const bestChildOrNull = if (parent.bestChild) |bestChildIdx| self.nodes.items[bestChildIdx] else null;

                    // see if we can update parent's best
                    if (bestChildOrNull) |bestChild| {
                        if (bestChild.weight < node.weight) {
                            updateBest = true;
                        } else if (bestChild.weight == node.weight) {
                            // tie break by slot else by hash
                            if (node.slot > bestChild.slot) {
                                updateBest = true;
                            } else if (node.slot == bestChild.slot and (std.mem.order(u8, &bestChild.blockRoot, &node.blockRoot) == .lt)) {
                                updateBest = true;
                            }
                        }
                    } else {
                        updateBest = true;
                    }
                }

                if (updateBest) {
                    self.nodes.items[parent_idx].bestChild = node_idx;
                    self.nodes.items[parent_idx].bestDescendant = nodeBestDescendant;
                }
            }
        }
    }
};

const OnBlockOpts = struct {
    currentSlot: types.Slot,
    blockDelayMs: u64,
    blockRoot: ?types.Root = null,
};

pub const ForkChoiceStore = struct {
    // time in intervals and slots since genesis
    time: types.Interval,
    timeSlots: types.Slot,

    latest_justified: types.Mini3SFCheckpoint,
    // finalized is not tracked the same way in 3sf mini as it corresponds to head's finalized
    // however its unlikely that a finalized can be rolled back in a normal node operation
    // (for example a buggy chain has been finalized in which case node should be started with
    //  anchor of the new non buggy branch)
    latest_finalized: types.Mini3SFCheckpoint,

    const Self = @This();
    pub fn update(self: *Self, justified: types.Mini3SFCheckpoint, finalized: types.Mini3SFCheckpoint) void {
        if (justified.slot > self.latest_justified.slot) {
            self.latest_justified = justified;
        }

        if (finalized.slot > self.latest_finalized.slot) {
            self.latest_finalized = finalized;
        }
    }
};

const ProtoVote = struct {
    //
    index: usize = 0,
    slot: types.Slot = 0,
    // we can construct proto votes from the anchor state justifications but will not exactly know
    // the votes
    vote: ?types.SignedVote = null,
};

const VoteTracker = struct {
    // prev latest vote applied index null if not applied
    appliedIndex: ?usize = null,
    // latest known on-chain vote of the validator
    latestKnown: ?ProtoVote = null,
    // nlatest new vote of validator not yet seen on-chain
    latestNew: ?ProtoVote = null,
};

pub const ForkChoiceParams = struct {
    config: configs.ChainConfig,
    anchorState: *const types.BeamState,
    logger: zeam_utils.ModuleLogger,
};

pub const ForkChoice = struct {
    protoArray: ProtoArray,
    anchorState: *const types.BeamState,
    config: configs.ChainConfig,
    fcStore: ForkChoiceStore,
    allocator: Allocator,
    // map of validator ids to vote tracker, better to have a map instead of array
    // because of churn in validators
    votes: std.AutoHashMap(usize, VoteTracker),
    head: ProtoBlock,
    safeTarget: ProtoBlock,
    // data structure to hold validator deltas, could be grown over time as more validators
    // get added
    deltas: std.ArrayList(isize),
    logger: zeam_utils.ModuleLogger,

    const Self = @This();
    pub fn init(allocator: Allocator, opts: ForkChoiceParams) !Self {
        const anchor_block_header = try stf.genStateBlockHeader(allocator, opts.anchorState.*);
        var anchor_block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            types.BeamBlockHeader,
            anchor_block_header,
            &anchor_block_root,
            allocator,
        );

        const anchor_block = ProtoBlock{
            .slot = opts.anchorState.slot,
            .blockRoot = anchor_block_root,
            .parentRoot = anchor_block_header.parent_root,
            .stateRoot = anchor_block_header.state_root,
            .timeliness = true,
        };
        const proto_array = try ProtoArray.init(allocator, anchor_block);
        const anchorCP = types.Mini3SFCheckpoint{ .slot = opts.anchorState.slot, .root = anchor_block_root };
        const fc_store = ForkChoiceStore{
            .time = opts.anchorState.slot * constants.INTERVALS_PER_SLOT,
            .timeSlots = opts.anchorState.slot,
            .latest_justified = anchorCP,
            .latest_finalized = anchorCP,
        };
        const votes = std.AutoHashMap(usize, VoteTracker).init(allocator);
        const deltas = std.ArrayList(isize).init(allocator);

        var fc = Self{
            .allocator = allocator,
            .protoArray = proto_array,
            .anchorState = opts.anchorState,
            .config = opts.config,
            .fcStore = fc_store,
            .votes = votes,
            .head = anchor_block,
            .safeTarget = anchor_block,
            .deltas = deltas,
            .logger = opts.logger,
        };
        _ = try fc.updateHead();
        return fc;
    }

    fn isBlockTimely(self: *Self, blockDelayMs: usize) bool {
        _ = self;
        _ = blockDelayMs;
        return true;
    }

    fn isFinalizedDescendant(self: *Self, blockRoot: types.Root) bool {
        const finalized_slot = self.fcStore.latest_finalized.slot;
        const finalized_root = self.fcStore.latest_finalized.root;

        var searched_idx_or_null = self.protoArray.indices.get(blockRoot);

        while (searched_idx_or_null) |searched_idx| {
            const searched_node_or_null: ?ProtoNode = self.protoArray.nodes.items[searched_idx];
            if (searched_node_or_null) |searched_node| {
                if (searched_node.slot <= finalized_slot) {
                    if (std.mem.eql(u8, searched_node.blockRoot[0..], finalized_root[0..])) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    searched_idx_or_null = searched_node.parent;
                }
            } else {
                break;
            }
        }

        return false;
    }

    pub fn tickInterval(self: *Self, hasProposal: bool) !void {
        self.fcStore.time += 1;
        const currentInterval = self.fcStore.time % constants.INTERVALS_PER_SLOT;

        switch (currentInterval) {
            0 => {
                self.fcStore.timeSlots += 1;
                if (hasProposal) {
                    _ = try self.acceptNewVotes();
                }
            },
            1 => {},
            2 => {
                _ = try self.updateSafeTarget();
            },
            3 => {
                _ = try self.acceptNewVotes();
            },
            else => @panic("invalid interval"),
        }
        self.logger.debug("forkchoice ticked to time(intervals)={d} slot={d}", .{ self.fcStore.time, self.fcStore.timeSlots });
    }

    pub fn onInterval(self: *Self, time_intervals: usize, has_proposal: bool) !void {
        while (self.fcStore.time < time_intervals) {
            try self.tickInterval(has_proposal and (self.fcStore.time + 1) == time_intervals);
        }
    }

    pub fn acceptNewVotes(self: *Self) !ProtoBlock {
        for (0..self.config.genesis.num_validators) |validator_id| {
            var vote_tracker = self.votes.get(validator_id) orelse VoteTracker{};
            if (vote_tracker.latestNew) |new_vote| {
                // we can directly assign because we always make sure that new vote is fresher
                // than an onchain vote by purging those which are earlier than those seen on chain
                vote_tracker.latestKnown = new_vote;
            }

            try self.votes.put(validator_id, vote_tracker);
        }

        return self.updateHead();
    }

    pub fn getProposalHead(self: *Self, slot: types.Slot) !types.Mini3SFCheckpoint {
        const time_intervals = slot * constants.INTERVALS_PER_SLOT;
        // this could be called independently by the validator when its a separate process
        // and FC would need to be protected by mutex to make it thread safe but for now
        // this is deterministally called after the fc has been ticked ahead
        // so the following call should be a no-op
        try self.onInterval(time_intervals, true);
        // accept any new votes in case previous ontick was a no-op and either the validator
        // wasn't registered or there have been new votes
        const head = try self.acceptNewVotes();

        return types.Mini3SFCheckpoint{
            .root = head.blockRoot,
            .slot = head.slot,
        };
    }

    pub fn getProposalVotes(self: *Self) !types.SignedVotes {
        var included_votes = try types.SignedVotes.init(self.allocator);
        const latest_justified = self.fcStore.latest_justified;

        // TODO naive strategy to include all votes that are consistent with the latest justified
        // replace by the other mini 3sf simple strategy to loop and see if justification happens and
        // till no further votes can be added
        for (0..self.config.genesis.num_validators) |validator_id| {
            const validator_vote = ((self.votes.get(validator_id) orelse VoteTracker{})
                //
                .latestKnown orelse ProtoVote{}).vote;

            if (validator_vote) |signed_vote| {
                if (std.mem.eql(u8, &latest_justified.root, &signed_vote.message.source.root)) {
                    try included_votes.append(signed_vote);
                }
            }
        }
        return included_votes;
    }

    pub fn getVoteTarget(self: *Self) !types.Mini3SFCheckpoint {
        var target_idx = self.protoArray.indices.get(self.head.blockRoot) orelse return ForkChoiceError.InvalidHeadIndex;
        const nodes = self.protoArray.nodes.items;

        for (0..3) |i| {
            _ = i;
            if (nodes[target_idx].slot > self.safeTarget.slot) {
                target_idx = nodes[target_idx].parent orelse return ForkChoiceError.InvalidTargetSearch;
            }
        }

        while (!try stf.is_justifiable_slot(self.fcStore.latest_finalized.slot, nodes[target_idx].slot)) {
            target_idx = nodes[target_idx].parent orelse return ForkChoiceError.InvalidTargetSearch;
        }

        return types.Mini3SFCheckpoint{
            .root = nodes[target_idx].blockRoot,
            .slot = nodes[target_idx].slot,
        };
    }

    pub fn computeDeltas(self: *Self, from_known: bool) ![]isize {
        // prep the deltas data structure
        while (self.deltas.items.len < self.protoArray.nodes.items.len) {
            try self.deltas.append(0);
        }
        for (0..self.deltas.items.len) |i| {
            self.deltas.items[i] = 0;
        }
        // balances are right now same for the dummy chain and each weighing 1
        const validatorWeight = 1;

        for (0..self.config.genesis.num_validators) |validator_id| {
            var vote_tracker = self.votes.get(validator_id) orelse VoteTracker{};
            if (vote_tracker.appliedIndex) |applied_index| {
                self.deltas.items[applied_index] -= validatorWeight;
            }
            vote_tracker.appliedIndex = null;

            // new index could be null if validator exits from the state
            // we don't need to null the new index after application because
            // applied and new will be same will no impact but this could still be a
            // relevant operation if/when the validator weight changes
            const latest_vote = if (from_known) vote_tracker.latestKnown else vote_tracker.latestNew;
            if (latest_vote) |delta_vote| {
                self.deltas.items[delta_vote.index] += validatorWeight;
                vote_tracker.appliedIndex = delta_vote.index;
            }
            try self.votes.put(validator_id, vote_tracker);
        }

        return self.deltas.items;
    }

    pub fn computeFCHead(self: *Self, from_known: bool, cutoff_weight: u64) !ProtoBlock {
        const deltas = try self.computeDeltas(from_known);
        try self.protoArray.applyDeltas(deltas, cutoff_weight);

        // head is the best descendant of latest justified
        const justified_idx = self.protoArray.indices.get(self.fcStore.latest_justified.root) orelse return ForkChoiceError.InvalidJustifiedRoot;
        const justified_node = self.protoArray.nodes.items[justified_idx];

        // if case of no best descendant latest justified is always best descendant
        const best_descendant_idx = justified_node.bestDescendant orelse justified_idx;
        const best_descendant = self.protoArray.nodes.items[best_descendant_idx];

        self.logger.debug("computeFCHead from_known={} cutoff_weight={d} deltas={any} justified_node={any} best_descendant_idx={d}", .{
            //
            from_known,
            cutoff_weight,
            deltas,
            justified_node,
            best_descendant_idx,
        });

        const fcHead = zeam_utils.Cast(ProtoBlock, best_descendant);
        return fcHead;
    }

    pub fn updateHead(self: *Self) !ProtoBlock {
        self.head = try self.computeFCHead(true, 0);
        // Update the lean_head_slot metric
        api.setLeanHeadSlot(self.head.slot);
        return self.head;
    }

    pub fn updateSafeTarget(self: *Self) !ProtoBlock {
        const cutoff_weight = try std.math.divCeil(u64, 2 * self.config.genesis.num_validators, 3);
        self.safeTarget = try self.computeFCHead(false, cutoff_weight);
        return self.safeTarget;
    }

    /// Validate attestation before processing
    /// Following leanSpec pattern: validates blocks exist, slot relationships, and checkpoint consistency
    pub fn validateAttestation(self: *Self, signed_vote: types.SignedVote) !void {
        const vote = signed_vote.message;

        // 1. Validate that referenced blocks exist in the fork choice store
        const source_exists = self.protoArray.indices.contains(vote.source.root);
        const target_exists = self.protoArray.indices.contains(vote.target.root);

        if (!source_exists) {
            self.logger.debug("Unknown source block: 0x{s}", .{std.fmt.fmtSliceHexLower(&vote.source.root)});
            return ForkChoiceError.UnknownSourceBlock;
        }
        if (!target_exists) {
            self.logger.debug("Unknown target block: 0x{s}", .{std.fmt.fmtSliceHexLower(&vote.target.root)});
            return ForkChoiceError.UnknownTargetBlock;
        }

        // 2. Get the blocks to validate slot relationships
        const source_block = self.protoArray.getNode(vote.source.root) orelse unreachable;
        const target_block = self.protoArray.getNode(vote.target.root) orelse unreachable;

        // 3. Validate slot relationships
        if (source_block.slot > target_block.slot) {
            self.logger.debug("Source slot {} exceeds target slot {}", .{ source_block.slot, target_block.slot });
            return ForkChoiceError.SourceSlotExceedsTarget;
        }
        if (vote.source.slot > vote.target.slot) {
            self.logger.debug("Source checkpoint slot {} exceeds target checkpoint slot {}", .{ vote.source.slot, vote.target.slot });
            return ForkChoiceError.SourceCheckpointExceedsTarget;
        }

        // 4. Validate checkpoint slots match block slots
        if (source_block.slot != vote.source.slot) {
            self.logger.debug("Source checkpoint slot {} does not match block slot {}", .{ vote.source.slot, source_block.slot });
            return ForkChoiceError.SourceCheckpointSlotMismatch;
        }
        if (target_block.slot != vote.target.slot) {
            self.logger.debug("Target checkpoint slot {} does not match block slot {}", .{ vote.target.slot, target_block.slot });
            return ForkChoiceError.TargetCheckpointSlotMismatch;
        }

        // 5. Validate attestation is not too far in the future
        const current_slot = self.fcStore.timeSlots;
        if (vote.slot > current_slot + 1) {
            self.logger.debug("Attestation slot {} too far in future (current: {})", .{ vote.slot, current_slot });
            return ForkChoiceError.AttestationTooFarInFuture;
        }
    }

    pub fn onAttestation(self: *Self, signed_vote: types.SignedVote, is_from_block: bool) !void {
        // Validate attestation structure and constraints before processing
        try self.validateAttestation(signed_vote);

        // vote has to be of an ancestor of the current slot
        const validator_id = signed_vote.validator_id;
        const vote = signed_vote.message;
        const new_head_index = self.protoArray.indices.get(vote.head.root) orelse return ForkChoiceError.InvalidAttestation;

        var vote_tracker = self.votes.get(validator_id) orelse VoteTracker{};
        // update latest known voted head of the validator if already included on chain
        if (is_from_block) {
            const vote_tracker_latest_known_slot = (vote_tracker.latestKnown orelse ProtoVote{}).slot;
            if (vote.slot > vote_tracker_latest_known_slot) {
                vote_tracker.latestKnown = .{
                    //
                    .index = new_head_index,
                    .slot = vote.slot,
                    .vote = signed_vote,
                };
            }

            // also clear out our latest new non included vote if this is even later than that
            const vote_tracker_latest_new_slot = (vote_tracker.latestNew orelse ProtoVote{}).slot;
            if (vote.slot > vote_tracker_latest_new_slot) {
                vote_tracker.latestNew = null;
            }
        } else {
            if (vote.slot > self.fcStore.timeSlots) return ForkChoiceError.InvalidFutureAttestation;
            // just update latest new voted head of the validator
            const vote_tracker_latest_new_slot = (vote_tracker.latestNew orelse ProtoVote{}).slot;
            if (vote.slot > vote_tracker_latest_new_slot) {
                vote_tracker.latestNew = .{
                    //
                    .index = new_head_index,
                    .slot = vote.slot,
                    .vote = signed_vote,
                };
            }
        }

        try self.votes.put(validator_id, vote_tracker);
    }

    // we process state outside forkchoice onblock to parallize verifications and just use the post state here
    pub fn onBlock(self: *Self, block: types.BeamBlock, state: *const types.BeamState, opts: OnBlockOpts) !ProtoBlock {
        const parent_root = block.parent_root;
        const slot = block.slot;

        const parent_block_or_null = self.protoArray.getBlock(parent_root);
        if (parent_block_or_null) |parent_block| {
            // we will use parent block later as per the finalization gadget
            _ = parent_block;

            if (slot * constants.INTERVALS_PER_SLOT > self.fcStore.time) {
                return ForkChoiceError.FutureSlot;
            } else if (slot < self.fcStore.latest_finalized.slot) {
                return ForkChoiceError.PreFinalizedSlot;
            }

            const is_finalized_descendant = self.isFinalizedDescendant(parent_root);
            if (is_finalized_descendant != true) {
                return ForkChoiceError.NotFinalizedDesendant;
            }

            // update the checkpoints
            const justified = state.latest_justified;
            const finalized = state.latest_finalized;
            self.fcStore.update(justified, finalized);

            const block_root: [32]u8 = opts.blockRoot orelse computedroot: {
                var cblock_root: [32]u8 = undefined;
                try ssz.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
                break :computedroot cblock_root;
            };
            const is_timely = self.isBlockTimely(opts.blockDelayMs);

            const proto_block = ProtoBlock{
                .slot = slot,
                .blockRoot = block_root,
                .parentRoot = parent_root,
                .stateRoot = block.state_root,
                .timeliness = is_timely,
            };

            try self.protoArray.onBlock(proto_block, opts.currentSlot);
            return proto_block;
        } else {
            return ForkChoiceError.UnknownParent;
        }
    }

    pub fn hasBlock(self: *Self, blockRoot: types.Root) bool {
        const block_or_null = self.protoArray.getBlock(blockRoot);
        if (block_or_null) |_| {
            return true;
        }

        return false;
    }
};

const ForkChoiceError = error{
    NotImplemented,
    UnknownParent,
    FutureSlot,
    InvalidFutureAttestation,
    InvalidOnChainAttestation,
    PreFinalizedSlot,
    NotFinalizedDesendant,
    InvalidAttestation,
    InvalidDeltas,
    InvalidJustifiedRoot,
    InvalidBestDescendant,
    InvalidHeadIndex,
    InvalidTargetSearch,
    // New validation errors
    UnknownSourceBlock,
    UnknownTargetBlock,
    SourceSlotExceedsTarget,
    SourceCheckpointExceedsTarget,
    SourceCheckpointSlotMismatch,
    TargetCheckpointSlotMismatch,
    AttestationTooFarInFuture,
};

test "forkchoice block tree" {
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
    const module_logger = zeam_logger_config.logger(.forkchoice);
    var fork_choice = try ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &beam_state,
        .logger = module_logger,
    });

    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.latest_finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.latest_finalized.root, &fork_choice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.state_root[0..], &fork_choice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &fork_choice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const block = mock_chain.blocks[i];
        try stf.apply_transition(allocator, &beam_state, block, .{ .logger = module_logger });

        // shouldn't accept a future slot
        const current_slot = block.message.slot;
        try std.testing.expectError(error.FutureSlot, fork_choice.onBlock(block.message, &beam_state, .{ .currentSlot = current_slot, .blockDelayMs = 0 }));

        try fork_choice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        _ = try fork_choice.onBlock(block.message, &beam_state, .{ .currentSlot = block.message.slot, .blockDelayMs = 0 });
        try std.testing.expect(fork_choice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &fork_choice.protoArray.nodes.items[i].blockRoot));

        const searched_idx = fork_choice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);
    }
}
