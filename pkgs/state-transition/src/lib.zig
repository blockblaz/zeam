const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

const transition = @import("./transition.zig");

pub const apply_transition = transition.apply_transition;
pub const apply_raw_block = transition.apply_raw_block;
pub const StateTransitionError = transition.StateTransitionError;
pub const StateTransitionOpts = transition.StateTransitionOpts;
pub const verifySignatures = transition.verifySignatures;
pub const verifySingleAttestation = transition.verifySingleAttestation;

const mockImport = @import("./mock.zig");
pub const genMockChain = mockImport.genMockChain;
pub const MockChainData = mockImport.MockChainData;

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "apply transition on mocked chain" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 5, null);
    try std.testing.expect(mock_chain.blocks.len == 5);

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.state_transition);

    // starting beam state
    var beam_state = mock_chain.genesis_state;
    // block 0 is genesis so we have to apply block 1 onwards
    for (1..mock_chain.blocks.len) |i| {
        // this is a signed block
        const signed_block = mock_chain.blocks[i];

        // Verify signatures before applying state transition
        try verifySignatures(allocator, &beam_state, &signed_block);

        try apply_transition(allocator, &beam_state, signed_block.message.block, .{ .logger = module_logger });
    }

    // check the post state root to be equal to block2's stateroot
    // this is reduant though because apply_transition already checks this for each block's state root
    var post_state_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamState, beam_state, &post_state_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &post_state_root, &mock_chain.blocks[mock_chain.blocks.len - 1].message.block.state_root));
}

test "genStateBlockHeader" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 2, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.state_transition);

    var beam_state = mock_chain.genesis_state;
    for (0..mock_chain.blocks.len) |i| {
        // get applied block
        const applied_block = mock_chain.blocks[i];
        var applied_block_root: types.Root = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlock, applied_block.message.block, &applied_block_root, allocator);

        const state_block_header = try beam_state.genStateBlockHeader(allocator);
        var state_block_header_root: types.Root = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlockHeader, state_block_header, &state_block_header_root, allocator);

        try std.testing.expect(std.mem.eql(u8, &applied_block_root, &state_block_header_root));

        if (i < mock_chain.blocks.len - 1) {
            // apply the next block
            const signed_block_with_attestation = mock_chain.blocks[i + 1];
            try apply_transition(allocator, &beam_state, signed_block_with_attestation.message.block, .{ .logger = module_logger });
        }
    }
}
