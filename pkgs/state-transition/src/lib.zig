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
pub const verifySignaturesParallel = transition.verifySignaturesParallel;
pub const verifySignaturesParallelMultiBlock = transition.verifySignaturesParallelMultiBlock;
pub const VerifyMultiBlockTask = transition.VerifyMultiBlockTask;
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
        try verifySignatures(allocator, &beam_state, &signed_block, null);

        try apply_transition(allocator, &beam_state, signed_block.block, .{ .logger = module_logger });
    }

    // check the post state root to be equal to block2's stateroot
    // this is reduant though because apply_transition already checks this for each block's state root
    var post_state_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamState, beam_state, &post_state_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &post_state_root, &mock_chain.blocks[mock_chain.blocks.len - 1].block.state_root));
}

test "verifySignaturesParallelMultiBlock: K=1 delegates to single-block path" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // 2-block mock chain (genesis + slot 1) so we have one real signed block.
    const mock_chain = try genMockChain(allocator, 2, null);
    const signed_block = mock_chain.blocks[1];
    const state = mock_chain.genesis_state;

    var block_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, allocator);

    // Single-element batch must produce the same result as calling
    // verifySignaturesParallel directly. We rely on the K=1 branch in
    // verifySignaturesParallelMultiBlock to forward to the single-block
    // path; if the batch path were taken for K=1 it would still pass
    // here, so this test guards the call shape rather than correctness
    // alone.
    const tasks = [_]VerifyMultiBlockTask{
        .{
            .state = &state,
            .signed_block = &signed_block,
            .precomputed_block_root = &block_root,
        },
    };
    try verifySignaturesParallelMultiBlock(allocator, &tasks, null, {});
}

test "verifySignaturesParallelMultiBlock: K>1 happy path across chain blocks" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // 4-block mock chain — gives us 3 signed blocks (slots 1..3) to batch.
    const mock_chain = try genMockChain(allocator, 4, null);
    try std.testing.expect(mock_chain.blocks.len == 4);

    // For each signed block, the verify input is its PARENT state — i.e.
    // the state right before that block was applied. We need to roll the
    // mock state forward as we go to compute per-block parent states.
    // Use heap allocations because the task slice holds pointers.
    var parent_states = try allocator.alloc(types.BeamState, mock_chain.blocks.len - 1);
    var roots = try allocator.alloc([32]u8, mock_chain.blocks.len - 1);
    var beam_state = mock_chain.genesis_state;

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.state_transition);

    for (1..mock_chain.blocks.len) |i| {
        // parent_states[i-1] is the state BEFORE applying block i.
        parent_states[i - 1] = try zeam_utils.clone(types.BeamState, &beam_state, allocator);
        try zeam_utils.hashTreeRoot(types.BeamBlock, mock_chain.blocks[i].block, &roots[i - 1], allocator);
        // Roll forward for the next iteration's parent_state.
        try apply_transition(allocator, &beam_state, mock_chain.blocks[i].block, .{ .logger = module_logger });
    }

    var tasks: std.ArrayList(VerifyMultiBlockTask) = .empty;
    defer tasks.deinit(allocator);
    for (1..mock_chain.blocks.len) |i| {
        try tasks.append(allocator, .{
            .state = &parent_states[i - 1],
            .signed_block = &mock_chain.blocks[i],
            .precomputed_block_root = &roots[i - 1],
        });
    }

    try verifySignaturesParallelMultiBlock(allocator, tasks.items, null, {});
}

test "verifySignaturesParallelMultiBlock: K=0 is a no-op" {
    const tasks: []const VerifyMultiBlockTask = &.{};
    try verifySignaturesParallelMultiBlock(std.testing.allocator, tasks, null, {});
}

test "verifySignaturesParallelMultiBlock: structural mismatch (attestations.len != signature_proofs.len) errors before any verify" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 2, null);
    var signed_block = mock_chain.blocks[1];
    const state = mock_chain.genesis_state;

    // Force a structural mismatch by adding a phantom attestation without
    // its signature group. The pre-flight check in
    // verifySignaturesParallelMultiBlock should reject this before
    // touching the rayon batch.
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

    const tasks = [_]VerifyMultiBlockTask{
        .{
            .state = &state,
            .signed_block = &signed_block,
            .precomputed_block_root = &block_root,
        },
        // K=2 so we go through the batched path (K=1 would delegate to
        // the single-block function and that has its own coverage).
        .{
            .state = &state,
            .signed_block = &signed_block,
            .precomputed_block_root = &block_root,
        },
    };
    try std.testing.expectError(
        types.StateTransitionError.InvalidBlockSignatures,
        verifySignaturesParallelMultiBlock(allocator, &tasks, null, {}),
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
