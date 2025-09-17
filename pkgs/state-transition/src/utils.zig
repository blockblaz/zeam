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
            .attestations = try types.SignedVotes.init(0),
        },
    };

    return genesis_latest_block;
}

pub fn genGenesisLatestBlock() !types.BeamBlock {
    const genesis_latest_block = types.BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = ZERO_HASH,
        .state_root = ZERO_HASH,
        .body = types.BeamBlockBody{
            // .execution_payload_header = .{ .timestamp = 0 },
            // 3sf mini votes
            .attestations = try types.SignedVotes.init(0),
        },
    };

    return genesis_latest_block;
}

pub fn genGenesisState(allocator: Allocator, genesis: types.GenesisSpec) !types.BeamState {
    const genesis_latest_block = try genGenesisLatestBlock();

    const state = types.BeamState{
        .config = .{
            .num_validators = genesis.num_validators,
            .genesis_time = genesis.genesis_time,
        },
        .slot = 0,
        .latest_block_header = try blockToLatestBlockHeader(allocator, genesis_latest_block),
        // mini3sf
        .latest_justified = .{ .root = [_]u8{0} ** 32, .slot = 0 },
        .latest_finalized = .{ .root = [_]u8{0} ** 32, .slot = 0 },
        .historical_block_hashes = try types.HistoricalBlockHashes.init(0),
        .justified_slots = try types.JustifiedSlots.init(0),
        // justifications map is empty
        .justifications_roots = try ssz.utils.List(types.Root, params.HISTORICAL_ROOTS_LIMIT).init(0),
        .justifications_validators = try ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT).init(0),
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
