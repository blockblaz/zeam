const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const configs = @import("@zeam/configs");

pub const ProtoNode = struct {
    slot: types.Slot,
    blockRoot: types.RootHex,
    parentRoot: types.RootHex,
    stateRoot: types.RootHex,
    targetRoot: types.RootHex,
    timeliness: bool,

    parent: ?usize,
    weight: ?usize,
    bestChild: ?usize,
    bestDescendant: ?usize,
};

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

    pub fn onBlock(block: ProtoNode, currentSlot: types.Slot) !void {
        _ = block;
        _ = currentSlot;
        return ForkChoiceError.NotImplemented;
    }
};

const OnBlockOpts = struct {
    currentSlot: types.Slot,
};

pub const ForkChoice = struct {
    blockTree: ProtoArray,
    anchorState: types.BeamState,
    config: configs.ChainConfig,

    const Self = @This();
    pub fn init(allocator: Allocator, config: configs.ChainConfig, anchorState: types.BeamState) !Self {
        const block_tree = try ProtoArray.init(allocator);
        return Self{
            .blockTree = block_tree,
            .anchorState = anchorState,
            .config = config,
        };
    }
    pub fn onBlock(block: types.BeaconBlock, state: types.BeaconState, opts: OnBlockOpts) !void {
        _ = block;
        _ = state;
        _ = opts;

        return ForkChoiceError.NotImplemented;
    }
};

const ForkChoiceError = error{NotImplemented};
