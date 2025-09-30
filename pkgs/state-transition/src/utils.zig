const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const params = @import("@zeam/params");
const ssz = @import("ssz");

pub const ZERO_HASH = [_]u8{0x00} ** 32;
pub const ZERO_HASH_4000 = [_]u8{0} ** types.SIGSIZE;

pub fn blockToHeader(allocator: Allocator, block: types.BeamBlock) types.BeamBlockHeader {
    var body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        types.BeamBlockBody,
        block.body,
        &body_root,
        allocator,
    );

    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .parent_root = block.parent_root,
        .state_root = block.state_root,
        .body_root = body_root,
    };
    return header;
}

// computing latest block header to be assigned to the state for processing the block
pub fn blockToLatestBlockHeader(allocator: Allocator, block: types.BeamBlock) !types.BeamBlockHeader {
    var body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        types.BeamBlockBody,
        block.body,
        &body_root,
        allocator,
    );

    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .parent_root = block.parent_root,
        .state_root = ZERO_HASH,
        .body_root = body_root,
    };
    return header;
}

pub fn genGenesisBlock(allocator: Allocator, genesis_state: types.BeamState) !types.BeamBlock {
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        types.BeamState,
        genesis_state,
        &state_root,
        allocator,
    );

    const genesis_latest_block = types.BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = ZERO_HASH,
        .state_root = state_root,
        .body = types.BeamBlockBody{
            // .execution_payload_header = .{ .timestamp = 0 },
            // 3sf mini
            .attestations = try types.SignedVotes.init(allocator),
        },
    };

    return genesis_latest_block;
}

pub fn genStateBlockHeader(allocator: Allocator, state: types.BeamState) !types.BeamBlockHeader {
    // check does it need cloning?
    var block = state.latest_block_header;
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        types.BeamState,
        state,
        &state_root,
        allocator,
    );
    block.state_root = state_root;

    return block;
}
