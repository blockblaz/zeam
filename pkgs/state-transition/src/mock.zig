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
        .num_validators = 4,
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

    // track latest justified and finalized for constructing votes
    var latest_justified: types.Mini3SFCheckpoint = .{ .root = block_root, .slot = genesis_block.slot };
    var latest_finalized = latest_justified;

    for (1..numBlocks) |slot| {
        var parent_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, prev_block, &parent_root, allocator);

        var state_root: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(state_root[0..], utils.ZERO_HASH_HEX);
        const timestamp = genesis_config.genesis_time + slot * params.SECONDS_PER_SLOT;
        var votes = std.ArrayList(types.Mini3SFVote).init(allocator);
        // 4 slot moving scenario can be applied over and over with finalization in 0
        switch (slot % 4) {
            // no votes on the first block of this
            1 => {},
            2 => {
                const slotVotes = [_]types.Mini3SFVote{
                    // val 0
                    .{ .validator_id = 0, .slot = slot - 1, .head = .{ .root = parent_root, .slot = 0 }, .target = .{ .root = parent_root, .slot = 0 }, .source = latest_justified },
                    .{ .validator_id = 2, .slot = slot - 1, .head = .{ .root = parent_root, .slot = 0 }, .target = .{ .root = parent_root, .slot = 0 }, .source = latest_justified },
                    .{ .validator_id = 3, .slot = slot - 1, .head = .{ .root = parent_root, .slot = 0 }, .target = .{ .root = parent_root, .slot = 0 }, .source = latest_justified },
                    // val 1
                };
                for (slotVotes) |slotVote| {
                    try votes.append(slotVote);
                }
            },
            3 => {},
            0 => {
                latest_finalized = latest_justified;
                latest_justified = .{ .root = parent_root, .slot = slot - 1 };
            },
            else => unreachable,
        }

        var block = types.BeamBlock{
            .slot = slot,
            .proposer_index = 1,
            .parent_root = parent_root,
            .state_root = state_root,
            .body = types.BeamBlockBody{
                .execution_payload_header = .{ .timestamp = timestamp },
                .votes = try votes.toOwnedSlice(),
            },
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
