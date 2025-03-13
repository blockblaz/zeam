const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const ssz = @import("ssz");

pub const ZERO_HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000";
pub const ZERO_HASH = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

pub const ZERO_HASH_48HEX = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

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
    // zero hash the stateroot for purposes of state's latest block header
    var state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(state_root[0..], ZERO_HASH_HEX);

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
        .state_root = state_root,
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

    var parent_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(parent_root[0..], ZERO_HASH_HEX);

    const genesis_latest_block = types.BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = types.BeamBlockBody{},
    };

    return genesis_latest_block;
}

pub fn genGenesisLatestBlock() !types.BeamBlock {
    var state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(state_root[0..], ZERO_HASH_HEX);

    var parent_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(parent_root[0..], ZERO_HASH_HEX);

    const genesis_latest_block = types.BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = types.BeamBlockBody{},
    };

    return genesis_latest_block;
}

pub fn genGenesisState(allocator: Allocator, genesis: types.GenesisSpec) !types.BeamState {
    const genesis_latest_block = try genGenesisLatestBlock();
    const state = types.BeamState{
        .genesis_time = genesis.genesis_time,
        .slot = 0,
        .latest_block_header = try blockToLatestBlockHeader(allocator, genesis_latest_block),
    };

    return state;
}
