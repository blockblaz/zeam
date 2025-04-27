const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const utils = @import("@zeam/utils");
const ssz = @import("ssz");

pub const ProtoBlock = struct {
    slot: types.Slot,
    blockRoot: types.RootHex,
    parentRoot: types.RootHex,
    stateRoot: types.RootHex,
    targetRoot: types.RootHex,
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
    indices: std.StringHashMap(usize),

    const Self = @This();
    pub fn init(allocator: Allocator) !Self {
        const nodes = std.ArrayList(ProtoNode).init(allocator);
        const indices = std.StringHashMap(usize).init(allocator);
        return Self{
            .nodes = nodes,
            .indices = indices,
        };
    }

    pub fn onBlock(self: Self, block: ProtoBlock, currentSlot: types.Slot) !void {
        // currentSlot might be needed in future for finding the viable head
        _ = currentSlot;
        const node_or_null = self.indices.get(block.blockRoot);
        if (node_or_null) {
            return;
        }

        const parent = self.indices.get(block.parentRoot);
        const weight = if (block.timeliness) 1 else 0;

        const node = utils.Extend(ProtoNode, block, .{
            .parent = parent,
            .weight = weight,
            // bestChild and bestDescendant are left null
        });
    }

    fn getNode(self: Self, blockRoot: []u8) ?ProtoNode {
        const block_index = self.indices.get(blockRoot);
        if (block_index) |blkidx| {
            const node = self.nodes.get(blkidx);
            return node;
        } else {
            return null;
        }
    }

    pub fn getBlock(self: Self, blockRoot: []u8) ?ProtoBlock {
        const nodeOrNull = self.getNode(blockRoot);
        if (nodeOrNull) |node| {
            const block = utils.Cast(ProtoBlock, node);
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
    finalizedRoot: types.Bytes32,
};

pub const ForkChoice = struct {
    protoArray: ProtoArray,
    anchorState: types.BeamState,
    config: configs.ChainConfig,
    fcStore: ForkChoiceStore,
    allocator: Allocator,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const proto_array = try ProtoArray.init(allocator);
        const fc_store = ForkChoiceStore{
            .currentSlot = anchorState.slot,
            .finalizadSlot = anchorState.slot,
        };

        return Self{
            .allocator = allocator,
            .protoArray = proto_array,
            .anchorState = anchorState,
            .config = config,
            .fcStore = fc_store,
        };
    }

    fn isBlockTimely(self: Self, blockDelayMs: usize) bool {
        _ = self;
        _ = blockDelayMs;
        return true;
    }

    fn isFinalizedDescendant(self: Self, blockRoot: []u8) bool {
        const finalized_slot = self.fcStore.finalizadSlot;
        const finalized_root = self.fcStore.finalizedRoot;

        var searched_idx_or_null = self.indices.get(blockRoot);

        while (searched_idx_or_null) |searched_idx| {
            const searched_node_or_null = self.protoArray[searched_idx];
            if (searched_node_or_null) |searched_node| {
                if (searched_node.slot <= finalized_slot) {
                    if (std.mem.eql(searched_node.blockRoot, finalized_root)) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    searched_idx_or_null = self.indices.get(searched_node.parent);
                }
            } else {
                break;
            }
        }

        return false;
    }

    pub fn onBlock(self: Self, block: types.BeaconBlock, state: types.BeaconState, opts: OnBlockOpts) !void {
        _ = state;

        const parent_root = block.parentRoot;
        const slot = block.slot;

        const parent_block_or_null = self.protoArray.getBlock(parent_root);
        if (parent_block_or_null) |parent_block| {
            // we will use parent block later as per the finalization gadget
            _ = parent_block;

            if (slot > self.fcStore.currentSlot) {
                return ForkChoiceError.FutureSlot;
            } else if (slot < self.fcStore.finalizadSlot) {
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
                .stateRoot = block.stateRoot,
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
