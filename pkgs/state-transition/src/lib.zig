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
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);

    try ssz.serialize(u16, data, &list, std.testing.allocator);
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
        // Pass null for pubkey_cache since tests don't need caching optimization
        try verifySignatures(allocator, &beam_state, &signed_block, null, null);

        try apply_transition(allocator, &beam_state, signed_block.block, .{ .logger = module_logger });
    }

    // check the post state root to be equal to block2's stateroot
    // this is reduant though because apply_transition already checks this for each block's state root
    var post_state_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamState, beam_state, &post_state_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &post_state_root, &mock_chain.blocks[mock_chain.blocks.len - 1].block.state_root));
}

test "verifySignatures: a block with empty aggregation_bits is rejected before verify" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 2, null);
    var signed_block = mock_chain.blocks[1];
    const state = mock_chain.genesis_state;

    // Append an attestation whose aggregation_bits select no validators. In
    // devnet5 a block carries a single merged Type-2 proof (there is no
    // per-attestation signature list), so aggregation_bits is the SOLE binding
    // to pubkeys: an empty set is structurally invalid, and verifySignatures
    // rejects it (InvalidBlockSignatures) before the expensive Type-2 verify.
    const phantom_att = types.AggregatedAttestation{
        .data = .{
            .slot = 1,
            .head = .{ .root = [_]u8{0} ** 32, .slot = 0 },
            .source = .{ .root = [_]u8{0} ** 32, .slot = 0 },
            .target = .{ .root = [_]u8{0} ** 32, .slot = 0 },
        },
        .aggregation_bits = try types.AggregationBits.init(allocator),
    };
    try signed_block.block.body.attestations.append(phantom_att);

    var block_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, allocator);

    try std.testing.expectError(
        types.StateTransitionError.InvalidBlockSignatures,
        verifySignatures(allocator, &state, &signed_block, null, &block_root),
    );
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
        try zeam_utils.hashTreeRoot(types.BeamBlock, applied_block.block, &applied_block_root, allocator);

        const state_block_header = try beam_state.genStateBlockHeader(allocator);
        var state_block_header_root: types.Root = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlockHeader, state_block_header, &state_block_header_root, allocator);

        try std.testing.expect(std.mem.eql(u8, &applied_block_root, &state_block_header_root));

        if (i < mock_chain.blocks.len - 1) {
            // apply the next block
            const signed_block = mock_chain.blocks[i + 1];
            try apply_transition(allocator, &beam_state, signed_block.block, .{ .logger = module_logger });
        }
    }
}
