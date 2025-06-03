const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");

const utils = @import("./utils.zig");
pub usingnamespace utils;

const transition = @import("./transition.zig");

pub const process_slots = transition.process_slot;
pub const apply_transition = transition.apply_transition;
pub const StateTransitionError = transition.StateTransitionError;
pub const StateTransitionOpts = transition.StateTransitionOpts;

const mockImport = @import("./mock.zig");
pub const genMockChain = mockImport.genMockChain;

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "apply transition on mocked chain" {
    // 1. setup genesis config
    const test_config = types.GenesisSpec{
        .genesis_time = 1234,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 3, test_config);
    try std.testing.expect(mock_chain.blocks.len == 3);

    // starting beam state
    var beam_state = mock_chain.genesis_state;
    // block 0 is genesis so we have to apply block 1 onwards
    for (1..mock_chain.blocks.len) |i| {
        // this is a signed block
        const block = mock_chain.blocks[i];
        try apply_transition(allocator, &beam_state, block, .{});
    }

    // check the post state root to be equal to block2's stateroot
    // this is reduant though because apply_transition already checks this for each block's state root
    var post_state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, beam_state, &post_state_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &post_state_root, &mock_chain.blocks[mock_chain.blocks.len - 1].message.state_root));
}

test "mock genesis and block production" {
    // 1. setup genesis config
    const test_config = types.GenesisSpec{
        .genesis_time = 1234,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 2, test_config);

    // check genesis state root
    var test_genesis_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, mock_chain.genesis_state, &test_genesis_root, std.testing.allocator);
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_root[0..], "0d2ea8d3f6846e408db07fd6970d131533a7062ed973c8c4d4d64de8adad1bff");
    try std.testing.expect(std.mem.eql(u8, &test_genesis_root, &expected_root));

    // check genesis block root & check genesis root matches to genesis block state root
    var test_genesis_block_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, mock_chain.blocks[0].message, &test_genesis_block_root, std.testing.allocator);
    try std.testing.expect(std.mem.eql(u8, &test_genesis_root, &mock_chain.blocks[0].message.state_root));
    var expected_genesis_block_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_genesis_block_root[0..], "5d476554c248a6f59082aabf1bf9cde041e7f9e0cf43990a22f42246dcfc1007");
    try std.testing.expect(std.mem.eql(u8, &test_genesis_block_root, &expected_genesis_block_root));

    // check produced block 1 state root
    var expected_block1_state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_block1_state_root[0..], "993a459ace700aaeacf2fd3ec20b0f9efd3acae93ff904c5adbc1997b025ea97");
    try std.testing.expect(std.mem.eql(u8, &expected_block1_state_root, &mock_chain.blocks[1].message.state_root));

    // 7. check block 1 root
    var block1_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, mock_chain.blocks[1].message, &block1_root, std.testing.allocator);
    var expected_block1_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_block1_root[0..], "4851312e74b73c99581772286a853ee8fc6a9d2fde00c2bd21e9c7b966a6c238");
    try std.testing.expect(std.mem.eql(u8, &block1_root, &expected_block1_root));

    // 9. run and check state transition
    // TODO: the previous process block should have been run on cloned state so we have the original pre
    // state here to run the state transition. for now regen same genesis state
    var state = try utils.genGenesisState(std.testing.allocator, test_config);
    try apply_transition(std.testing.allocator, &state, mock_chain.blocks[1], .{});
    var post_state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, state, &post_state_root, std.testing.allocator);

    try std.testing.expect(std.mem.eql(u8, &post_state_root, &expected_block1_state_root));
}

test "genStateBlockHeader" {
    // 1. setup genesis config
    const test_config = types.GenesisSpec{
        .genesis_time = 1234,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 2, test_config);

    var beam_state = mock_chain.genesis_state;
    for (0..mock_chain.blocks.len) |i| {
        // get applied block
        const applied_block = mock_chain.blocks[i];
        var applied_block_root: types.Root = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, applied_block.message, &applied_block_root, allocator);

        const state_block_header = try utils.genStateBlockHeader(allocator, beam_state);
        var state_block_header_root: types.Root = undefined;
        try ssz.hashTreeRoot(types.BeamBlockHeader, state_block_header, &state_block_header_root, allocator);

        try std.testing.expect(std.mem.eql(u8, &applied_block_root, &state_block_header_root));

        if (i < mock_chain.blocks.len - 1) {
            // apply the next block
            const block = mock_chain.blocks[i + 1];
            try apply_transition(allocator, &beam_state, block, .{});
        }
    }
}
