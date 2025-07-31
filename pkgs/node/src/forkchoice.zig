const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const utils = @import("@zeam/utils");
const stf = @import("@zeam/state-transition");

pub const ProtoBlock = struct {
    slot: types.Slot,
    // we can keep these in hex not hex strings because stringhashmap just relies on []
    blockRoot: types.Root,
    parentRoot: types.Root,
    stateRoot: types.Root,
    targetRoot: types.Root,
    timeliness: bool,
};
const ProtoMeta = struct {
    parent: ?usize,
    weight: isize,
    bestChild: ?usize,
    bestDescendant: ?usize,
};
pub const ProtoNode = utils.MixIn(ProtoBlock, ProtoMeta);

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
            .targetRoot = block.targetRoot,
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
                .targetRoot = node.targetRoot,
                .timeliness = node.timeliness,
            };
            return block;
        } else {
            return null;
        }
    }

    pub fn applyDeltas(self: *Self, deltas: []isize) !void {
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
                const parent = self.nodes.items[parent_idx];
                var updateBest = false;

                if (parent.bestChild == node_idx) {
                    // check if bestDescendant needs to be updated even if best child is same
                    if (parent.bestDescendant != node.bestDescendant) {
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
                    self.nodes.items[parent_idx].bestDescendant = node.bestDescendant orelse node_idx;
                }
            }
        }
    }
};

const OnBlockOpts = struct {
    currentSlot: types.Slot,
    blockDelayMs: u64,
};

pub const ForkChoiceStore = struct {
    currentSlot: types.Slot,
    justified: types.Mini3SFCheckpoint,
    finalized: types.Mini3SFCheckpoint,

    const Self = @This();
    pub fn update(self: *Self, justified: types.Mini3SFCheckpoint, finalized: types.Mini3SFCheckpoint) void {
        if (justified.slot > self.justified.slot) {
            self.justified = justified;
        }

        if (finalized.slot > self.finalized.slot) {
            self.finalized = finalized;
        }
    }
};

const VoteTracker = struct {
    // prev latest vote applied index null if not applied or removed
    appliedIndex: ?usize = null,
    // new index at which to apply the latest vote at null if to be removed
    newIndex: ?usize = null,
    newSlot: ?types.Slot = null,
};

pub const ForkChoice = struct {
    protoArray: ProtoArray,
    anchorState: types.BeamState,
    config: configs.ChainConfig,
    fcStore: ForkChoiceStore,
    allocator: Allocator,
    // map of validator ids to vote tracker, better to have a map instead of array
    // because of churn in validators
    votes: std.AutoHashMap(usize, VoteTracker),
    head: ProtoBlock,
    // data structure to hold validator deltas, could be grown over time as more validators
    // get added
    deltas: std.ArrayList(isize),

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const anchor_block_header = try stf.genStateBlockHeader(allocator, anchorState);
        var anchor_block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            types.BeamBlockHeader,
            anchor_block_header,
            &anchor_block_root,
            allocator,
        );

        const anchor_block = ProtoBlock{
            .slot = anchorState.slot,
            .blockRoot = anchor_block_root,
            .parentRoot = anchor_block_header.parent_root,
            .stateRoot = anchor_block_header.state_root,
            .targetRoot = anchor_block_root,
            .timeliness = true,
        };
        const proto_array = try ProtoArray.init(allocator, anchor_block);
        const anchorCP = types.Mini3SFCheckpoint{ .slot = anchorState.slot, .root = anchor_block_root };
        const fc_store = ForkChoiceStore{
            .currentSlot = anchorState.slot,
            .justified = anchorCP,
            .finalized = anchorCP,
        };
        const votes = std.AutoHashMap(usize, VoteTracker).init(allocator);
        const deltas = std.ArrayList(isize).init(allocator);

        var fc = Self{
            .allocator = allocator,
            .protoArray = proto_array,
            .anchorState = anchorState,
            .config = config,
            .fcStore = fc_store,
            .votes = votes,
            .head = anchor_block,
            .deltas = deltas,
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
        const finalized_slot = self.fcStore.finalized.slot;
        const finalized_root = self.fcStore.finalized.root;

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

    pub fn tickSlot(self: *Self, currentSlot: types.Slot) void {
        if (self.fcStore.currentSlot >= currentSlot) {
            return;
        }

        self.fcStore.currentSlot = currentSlot;
        std.debug.print("\n\n forkchoice ticked slot to {any}\n", .{self.fcStore.currentSlot});
        // reset attestations or process checkpoints as prescribed in the specs
    }

    pub fn updateHead(self: *Self) !ProtoBlock {
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
            if (vote_tracker.newIndex) |new_index| {
                self.deltas.items[new_index] += validatorWeight;
                vote_tracker.appliedIndex = new_index;
            }
            try self.votes.put(validator_id, vote_tracker);
        }

        try self.protoArray.applyDeltas(self.deltas.items);

        // head is the best descendant of latest justified
        const justified_idx = self.protoArray.indices.get(self.fcStore.justified.root) orelse return ForkChoiceError.InvalidJustifiedRoot;
        const justified_node = self.protoArray.nodes.items[justified_idx];

        // if case of no best descendant latest justified is always best descendant
        const best_descendant_idx = justified_node.bestDescendant orelse justified_idx;
        const best_descendant = self.protoArray.nodes.items[best_descendant_idx];

        self.head = utils.Cast(ProtoBlock, best_descendant);
        return self.head;
    }

    pub fn onAttestation(self: *Self, vote: types.Mini3SFVote) !void {
        // vote has to be of an ancestor of the current slot
        const new_index = self.protoArray.indices.get(vote.head.root) orelse return ForkChoiceError.InvalidAttestation;
        if (vote.slot < self.fcStore.currentSlot) {
            var vote_tracker = self.votes.get(vote.validator_id) orelse VoteTracker{};
            const vote_tracker_new_slot = vote_tracker.newSlot orelse 0;
            if (vote.head.slot > vote_tracker_new_slot) {
                vote_tracker.newIndex = new_index;
                vote_tracker.newSlot = vote.head.slot;
            }
            try self.votes.put(vote.validator_id, vote_tracker);
        }
    }

    pub fn onBlock(self: *Self, block: types.BeamBlock, state: types.BeamState, opts: OnBlockOpts) !ProtoBlock {
        const parent_root = block.parent_root;
        const slot = block.slot;

        const parent_block_or_null = self.protoArray.getBlock(parent_root);
        if (parent_block_or_null) |parent_block| {
            // we will use parent block later as per the finalization gadget
            _ = parent_block;

            if (slot > self.fcStore.currentSlot) {
                std.debug.print("\n\n slot={any} currentslot={any}\n\n", .{ slot, self.fcStore.currentSlot });
                // instead of returning error for now, roll forward the slot till we fix the async events
                // because mock network sends gossip forwards without letting the onslot fire for all the
                // nodes
                // return ForkChoiceError.FutureSlot;

                self.tickSlot(slot);
            } else if (slot < self.fcStore.finalized.slot) {
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

            var block_root: [32]u8 = undefined;
            try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);
            const is_timely = self.isBlockTimely(opts.blockDelayMs);

            const proto_block = ProtoBlock{
                .slot = slot,
                .blockRoot = block_root,
                .parentRoot = parent_root,
                .stateRoot = block.state_root,
                // depends on the finalization gadget
                .targetRoot = block_root,
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

const ForkChoiceError = error{ NotImplemented, UnknownParent, FutureSlot, PreFinalizedSlot, NotFinalizedDesendant, InvalidAttestation, InvalidDeltas, InvalidJustifiedRoot, InvalidBestDescendant };

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
    var fork_choice = try ForkChoice.init(allocator, chain_config, beam_state);

    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.finalized.root, &mock_chain.blockRoots[0]));
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.finalized.root, &fork_choice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].message.state_root[0..], &fork_choice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &fork_choice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const block = mock_chain.blocks[i];
        try stf.apply_transition(allocator, &beam_state, block, .{});

        // shouldn't accept a future slot
        const current_slot = block.message.slot;
        try std.testing.expectError(error.FutureSlot, fork_choice.onBlock(block.message, beam_state, .{ .currentSlot = current_slot, .blockDelayMs = 0 }));

        fork_choice.tickSlot(current_slot);
        _ = try fork_choice.onBlock(block.message, beam_state, .{ .currentSlot = block.message.slot, .blockDelayMs = 0 });
        try std.testing.expect(fork_choice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &fork_choice.protoArray.nodes.items[i].blockRoot));

        const searched_idx = fork_choice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);
    }
}
