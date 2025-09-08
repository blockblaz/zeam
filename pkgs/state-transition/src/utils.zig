const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const ssz = @import("ssz");

pub const ZERO_HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000";
pub const ZERO_HASH = [_]u8{0x00} ** 32;

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
        .body = types.BeamBlockBody{
            .execution_payload_header = .{ .timestamp = 0 },
            // 3sf mini
            .atttestations = &[_]types.SignedVote{},
        },
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
        .body = types.BeamBlockBody{
            .execution_payload_header = .{ .timestamp = 0 },
            // 3sf mini votes
            .atttestations = &[_]types.SignedVote{},
        },
    };

    return genesis_latest_block;
}

pub fn genGenesisState(allocator: Allocator, genesis: types.GenesisSpec) !types.BeamState {
    const genesis_latest_block = try genGenesisLatestBlock();
    var parent_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(parent_root[0..], ZERO_HASH_HEX);

    // historical hashes and justified slots are slices so we need to alloc them
    // for them to exist outside this fn scope
    var historical_hashes_array = std.ArrayList(types.Root).init(allocator);
    var justified_slots_array = std.ArrayList(u8).init(allocator);

    const state = types.BeamState{
        .config = .{ .num_validators = genesis.num_validators },
        .genesis_time = genesis.genesis_time,
        .slot = 0,
        .latest_block_header = try blockToLatestBlockHeader(allocator, genesis_latest_block),
        // mini3sf
        .latest_justified = .{ .root = [_]u8{0} ** 32, .slot = 0 },
        .latest_finalized = .{ .root = [_]u8{0} ** 32, .slot = 0 },
        .historical_block_hashes = try historical_hashes_array.toOwnedSlice(),
        .justified_slots = try justified_slots_array.toOwnedSlice(),
        // justifications map is empty
        .justifications_roots = &[_]types.Root{},
        .justifications_validators = &[_]u8{},
    };

    return state;
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
