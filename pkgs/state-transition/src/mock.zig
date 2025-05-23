const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");

pub const utils = @import("./utils.zig");
const transition = @import("./transition.zig");
const params = @import("@zeam/params");

const MockChainData = struct {
    genesis_config: types.GenesisSpec,
    genesis_state: types.BeamState,
    blocks: []types.SignedBeamBlock,
    blockRoots: []types.Root,
};

pub fn genMockChain(allocator: Allocator, numBlocks: usize, from_genesis: ?types.GenesisSpec) !MockChainData {
    const genesis_config = from_genesis orelse types.GenesisSpec{
        .genesis_time = 1234,
    };

    const genesis_state = try utils.genGenesisState(allocator, genesis_config);
    var blockList = std.ArrayList(types.SignedBeamBlock).init(allocator);
    var blockRootList = std.ArrayList(types.Root).init(allocator);

    // figure out a way to clone genesis_state
    var beam_state = try utils.genGenesisState(allocator, genesis_config);
    const genesis_block = try utils.genGenesisBlock(allocator, beam_state);

    var gen_signature: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(gen_signature[0..], utils.ZERO_HASH_48HEX);
    const gen_signed_block = types.SignedBeamBlock{
        .message = genesis_block,
        .signature = gen_signature,
    };
    var block_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, genesis_block, &block_root, allocator);

    try blockList.append(gen_signed_block);
    try blockRootList.append(block_root);

    var prev_block = genesis_block;
    for (1..numBlocks) |slot| {
        var parent_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, prev_block, &parent_root, allocator);

        var state_root: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(state_root[0..], utils.ZERO_HASH_HEX);
        const timestamp = genesis_config.genesis_time + slot * params.SECONDS_PER_SLOT;

        var block = types.BeamBlock{
            .slot = slot,
            .proposer_index = 1,
            .parent_root = parent_root,
            .state_root = state_root,
            .body = types.BeamBlockBody{ .execution_payload_header = .{ .timestamp = timestamp } },
        };

        // prepare pre state to process block for that slot, may be rename prepare_pre_state
        try transition.process_slots(allocator, &beam_state, block.slot);
        // process block and modify the pre state to post state
        try transition.process_block(allocator, &beam_state, block);

        // extract the post state root
        try ssz.hashTreeRoot(types.BeamState, beam_state, &state_root, allocator);
        block.state_root = state_root;
        try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, allocator);

        // generate the signed beam block and add to block list
        var signature: [48]u8 = undefined;
        _ = try std.fmt.hexToBytes(signature[0..], utils.ZERO_HASH_48HEX);
        const signed_block = types.SignedBeamBlock{
            .message = block,
            .signature = signature,
        };
        try blockList.append(signed_block);
        try blockRootList.append(block_root);

        // now we are ready for next round as the beam_state is not this blocks post state
        prev_block = block;
    }

    return MockChainData{
        .genesis_config = genesis_config,
        .genesis_state = genesis_state,
        .blocks = blockList.items,
        .blockRoots = blockRootList.items,
    };
}
