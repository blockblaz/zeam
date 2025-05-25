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
    weight: ?usize,
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
        var weight: usize = undefined;
        if (block.timeliness) {
            weight = 1;
        } else {
            weight = 0;
        }

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
            .weight = weight,
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
};

const OnBlockOpts = struct {
    currentSlot: types.Slot,
    blockDelayMs: u64,
};

pub const ForkChoiceStore = struct {
    currentSlot: types.Slot,
    finalizedSlot: types.Slot,
    finalizedRoot: types.Root,
};

pub const ForkChoice = struct {
    protoArray: ProtoArray,
    anchorState: types.BeamState,
    config: configs.ChainConfig,
    fcStore: ForkChoiceStore,
    allocator: Allocator,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const finalized_header = try stf.genStateBlockHeader(allocator, anchorState);
        var finalized_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            types.BeamBlockHeader,
            finalized_header,
            &finalized_root,
            allocator,
        );

        const anchor_block = ProtoBlock{
            .slot = anchorState.slot,
            .blockRoot = finalized_root,
            .parentRoot = finalized_header.parent_root,
            .stateRoot = finalized_header.state_root,
            .targetRoot = finalized_root,
            .timeliness = true,
        };
        const proto_array = try ProtoArray.init(allocator, anchor_block);

        const fc_store = ForkChoiceStore{
            .currentSlot = anchorState.slot,
            .finalizedSlot = anchorState.slot,
            .finalizedRoot = finalized_root,
        };

        return Self{
            .allocator = allocator,
            .protoArray = proto_array,
            .anchorState = anchorState,
            .config = config,
            .fcStore = fc_store,
        };
    }

    fn isBlockTimely(self: *Self, blockDelayMs: usize) bool {
        _ = self;
        _ = blockDelayMs;
        return true;
    }

    fn isFinalizedDescendant(self: *Self, blockRoot: types.Root) bool {
        const finalized_slot = self.fcStore.finalizedSlot;
        const finalized_root = self.fcStore.finalizedRoot;

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
        // reset attestations or process checkpoints as prescribed in the specs
    }

    pub fn onBlock(self: *Self, block: types.BeamBlock, state: types.BeamState, opts: OnBlockOpts) !void {
        _ = state;

        const parent_root = block.parent_root;
        const slot = block.slot;

        const parent_block_or_null = self.protoArray.getBlock(parent_root);
        if (parent_block_or_null) |parent_block| {
            // we will use parent block later as per the finalization gadget
            _ = parent_block;

            if (slot > self.fcStore.currentSlot) {
                return ForkChoiceError.FutureSlot;
            } else if (slot < self.fcStore.finalizedSlot) {
                return ForkChoiceError.PreFinalizedSlot;
            }

            const is_finalized_descendant = self.isFinalizedDescendant(parent_root);
            if (is_finalized_descendant != true) {
                return ForkChoiceError.NotFinalizedDesendant;
            }

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

            return self.protoArray.onBlock(proto_block, opts.currentSlot);
        } else {
            return ForkChoiceError.UnknownParent;
        }
    }
};

const ForkChoiceError = error{ NotImplemented, UnknownParent, FutureSlot, PreFinalizedSlot, NotFinalizedDesendant };

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

    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.finalizedRoot, &mock_chain.blockRoots[0]));
    try std.testing.expect(fork_choice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &fork_choice.fcStore.finalizedRoot, &fork_choice.protoArray.nodes.items[0].blockRoot));
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
        try fork_choice.onBlock(block.message, beam_state, .{ .currentSlot = block.message.slot, .blockDelayMs = 0 });
        try std.testing.expect(fork_choice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &fork_choice.protoArray.nodes.items[i].blockRoot));

        const searched_idx = fork_choice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);
    }
}
