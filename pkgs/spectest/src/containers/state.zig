const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

fn sampleConfig() types.BeamStateConfig {
    return .{
        .num_validators = params.VALIDATOR_REGISTRY_LIMIT,
        .genesis_time = 0,
    };
}

fn sampleBlockHeader() types.BeamBlockHeader {
    return .{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .body_root = [_]u8{0} ** 32,
    };
}

fn sampleCheckpoint() types.Mini3SFCheckpoint {
    return .{
        .root = [_]u8{0} ** 32,
        .slot = 0,
    };
}

fn baseState(allocator: Allocator) types.BeamState {
    return .{
        .config = sampleConfig(),
        .slot = 0,
        .latest_block_header = sampleBlockHeader(),
        .latest_justified = sampleCheckpoint(),
        .latest_finalized = sampleCheckpoint(),
        .historical_block_hashes = try types.HistoricalBlockHashes.init(allocator),
        .justified_slots = try types.JustifiedSlots.init(allocator),
        .justifications_roots = try types.JustificationsRoots.init(allocator),
        .justifications_validators = try types.JustificationsValidators.init(allocator),
    };
}

/// Validate hash tree root against expected Python spec test output
/// This ensures SSZ implementation correctness by comparing with reference implementation
fn validateHashTreeRootAgainstSpec(
    allocator: Allocator,
    comptime T: type,
    data: T,
    expected_hex: []const u8,
    description: []const u8,
) !void {
    var computed_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(T, data, &computed_root, allocator);

    var hex_buf: [64]u8 = undefined;
    const computed_hex = try std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&computed_root)});

    if (!std.mem.eql(u8, computed_hex, expected_hex)) {
        std.debug.print("Hash tree root validation failed for {s}:\n", .{description});
        std.debug.print("  Expected: {s}\n", .{expected_hex});
        std.debug.print("  Computed: {s}\n", .{computed_hex});
        return error.HashTreeRootMismatch;
    }
}

test "test_get_justifications_empty" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    // Sanity: State starts with no justifications data.
    try std.testing.expectEqual(@as(usize, 0), base_state.justifications_roots.len());
    try std.testing.expectEqual(@as(usize, 0), base_state.justifications_validators.len());

    // Reconstruct the map; expect an empty map.
    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications.deinit(allocator);
    try base_state.getJustification(allocator, &justifications);

    try std.testing.expectEqual(@as(u32, 0), justifications.count());
}

test "test_get_justifications_single_root" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    // Create a unique root under consideration.
    const root1: types.Root = [_]u8{1} ** 32;

    // Add the root to the state
    try base_state.justifications_roots.append(root1);

    // Prepare a vote bitlist with required length; flip two positions to True.
    const count = base_state.config.num_validators;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const vote = (i == 2 or i == 5); // Validator 2 and 5 voted True
        try base_state.justifications_validators.append(vote);
    }

    // Rebuild the map from the flattened state.
    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer {
        var it = justifications.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        justifications.deinit(allocator);
    }
    try base_state.getJustification(allocator, &justifications);

    // Should have exactly one entry
    try std.testing.expectEqual(@as(u32, 1), justifications.count());

    // Verify the mapping
    const votes_slice = justifications.get(root1).?;
    try std.testing.expectEqual(count, votes_slice.len);

    // Check specific votes: positions 2 and 5 should be True, others False
    for (votes_slice, 0..) |vote_byte, idx| {
        const expected: u8 = if (idx == 2 or idx == 5) 1 else 0;
        try std.testing.expectEqual(expected, vote_byte);
    }
}

test "test_get_justifications_multiple_roots" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    // Three distinct roots to track.
    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;
    const root3: types.Root = [_]u8{3} ** 32;

    // Add roots to the state in order
    try base_state.justifications_roots.append(root1);
    try base_state.justifications_roots.append(root2);
    try base_state.justifications_roots.append(root3);

    // Validator count for each vote slice.
    const count = base_state.config.num_validators;

    // Build per-root vote slices and add to state
    // votes1: Only validator 0 in favor for root1
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try base_state.justifications_validators.append(i == 0);
    }

    // votes2: Validators 1 and 2 in favor for root2
    i = 0;
    while (i < count) : (i += 1) {
        try base_state.justifications_validators.append(i == 1 or i == 2);
    }

    // votes3: Unanimous in favor for root3
    i = 0;
    while (i < count) : (i += 1) {
        try base_state.justifications_validators.append(true);
    }

    // Reconstruct the mapping from the flattened representation.
    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer {
        var it = justifications.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        justifications.deinit(allocator);
    }
    try base_state.getJustification(allocator, &justifications);

    // Confirm we have exactly three entries.
    try std.testing.expectEqual(@as(u32, 3), justifications.count());

    // Validate that each root maps to its intended slice.

    // Check root1: only validator 0 should be True
    const votes1 = justifications.get(root1).?;
    try std.testing.expectEqual(count, votes1.len);
    for (votes1, 0..) |vote_byte, idx| {
        const expected: u8 = if (idx == 0) 1 else 0;
        try std.testing.expectEqual(expected, vote_byte);
    }

    // Check root2: validators 1 and 2 should be True
    const votes2 = justifications.get(root2).?;
    try std.testing.expectEqual(count, votes2.len);
    for (votes2, 0..) |vote_byte, idx| {
        const expected: u8 = if (idx == 1 or idx == 2) 1 else 0;
        try std.testing.expectEqual(expected, vote_byte);
    }

    // Check root3: all validators should be True
    const votes3 = justifications.get(root3).?;
    try std.testing.expectEqual(count, votes3.len);
    for (votes3) |vote_byte| {
        try std.testing.expectEqual(@as(u8, 1), vote_byte);
    }
}

test "test_with_justifications_invalid_length" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    const root1 = [_]u8{1} ** 32;
    const invalid_len = base_state.config.num_validators - 1;
    const invalid_justification = try allocator.alloc(u8, invalid_len);
    defer allocator.free(invalid_justification);
    @memset(invalid_justification, 1); // Set all bytes to 1
    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications.deinit(allocator);
    try justifications.put(allocator, root1, invalid_justification);

    const result = base_state.withJustifications(allocator, &justifications);
    try std.testing.expect(result == error.InvalidJustificationLength);
}

test "test_with_justifications_empty" {
    const allocator = std.testing.allocator;

    var initial_state = baseState(allocator);
    defer initial_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    try initial_state.justifications_roots.append(root1);

    var i: usize = 0;
    while (i < initial_state.config.num_validators) : (i += 1) {
        try initial_state.justifications_validators.append(true);
    }

    try std.testing.expectEqual(@as(usize, 1), initial_state.justifications_roots.len());
    try std.testing.expectEqual(initial_state.config.num_validators, initial_state.justifications_validators.len());

    var empty_justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer empty_justifications.deinit(allocator);

    try initial_state.withJustifications(allocator, &empty_justifications);

    try std.testing.expectEqual(@as(usize, 0), initial_state.justifications_roots.len());
    try std.testing.expectEqual(@as(usize, 0), initial_state.justifications_validators.len());
}

test "test_with_justifications_deterministic_order" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    // Two roots to test ordering
    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;

    // Build two vote slices of proper length
    const count = base_state.config.num_validators;
    const votes1_buf = try allocator.alloc(u8, count);
    defer allocator.free(votes1_buf);
    @memset(votes1_buf, 0); // All False

    const votes2_buf = try allocator.alloc(u8, count);
    defer allocator.free(votes2_buf);
    @memset(votes2_buf, 1); // All True

    // Intentionally supply the map in unsorted key order (root2 first, then root1)
    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications.deinit(allocator);
    try justifications.put(allocator, root2, votes2_buf);
    try justifications.put(allocator, root1, votes1_buf);

    // Flatten into the state; method sorts keys deterministically
    try base_state.withJustifications(allocator, &justifications);

    // The stored roots should be [root1, root2] (sorted ascending)
    try std.testing.expectEqual(@as(usize, 2), base_state.justifications_roots.len());
    try std.testing.expectEqual(root1, base_state.justifications_roots.constSlice()[0]);
    try std.testing.expectEqual(root2, base_state.justifications_roots.constSlice()[1]);

    // The flattened validators list should follow the same order (votes1 + votes2)
    try std.testing.expectEqual(count * 2, base_state.justifications_validators.len());

    // Check first part corresponds to votes1 (all false)
    for (0..count) |i| {
        const vote = try base_state.justifications_validators.get(i);
        try std.testing.expect(!vote);
    }

    // Check second part corresponds to votes2 (all true)
    for (count..base_state.justifications_validators.len()) |i| {
        const vote = try base_state.justifications_validators.get(i);
        try std.testing.expect(vote);
    }
}

// Helper function to create votes array with specific indices set to True
fn createVotes(allocator: Allocator, true_indices: []const usize, total_count: usize) ![]u8 {
    const votes = try allocator.alloc(u8, total_count);
    @memset(votes, 0); // Initialize all to False

    for (true_indices) |idx| {
        if (idx < total_count) {
            votes[idx] = 1; // Set to True
        }
    }

    return votes;
}

// Helper function to verify roundtrip equality
fn verifyRoundtrip(allocator: Allocator, base_state: *types.BeamState, original_justifications: *std.AutoHashMapUnmanaged(types.Root, []u8)) !void {
    // Flatten the provided map into the state
    try base_state.withJustifications(allocator, original_justifications);

    // Reconstruct the map from the flattened representation
    var reconstructed_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer {
        var it = reconstructed_map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        reconstructed_map.deinit(allocator);
    }
    try base_state.getJustification(allocator, &reconstructed_map);

    // Verify the maps have the same number of entries
    try std.testing.expectEqual(original_justifications.count(), reconstructed_map.count());

    // Verify each entry matches (the implementation should handle sorting internally)
    var original_it = original_justifications.iterator();
    while (original_it.next()) |original_entry| {
        const reconstructed_votes = reconstructed_map.get(original_entry.key_ptr.*);
        try std.testing.expect(reconstructed_votes != null);

        const original_votes = original_entry.value_ptr.*;
        const reconstructed_slice = reconstructed_votes.?;

        try std.testing.expectEqual(original_votes.len, reconstructed_slice.len);
        for (original_votes, reconstructed_slice) |orig, recon| {
            try std.testing.expectEqual(orig, recon);
        }
    }
}

test "test_justifications_roundtrip_empty" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    // Empty justifications map
    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_single_root" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const true_indices = [_]usize{0};
    const votes1 = try createVotes(allocator, &true_indices, base_state.config.num_validators);
    defer allocator.free(votes1);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    try justifications_map.put(allocator, root1, votes1);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_multiple_roots_sorted" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;

    const true_indices_1 = [_]usize{0};
    const true_indices_2 = [_]usize{ 1, 2 };
    const votes1 = try createVotes(allocator, &true_indices_1, base_state.config.num_validators);
    defer allocator.free(votes1);
    const votes2 = try createVotes(allocator, &true_indices_2, base_state.config.num_validators);
    defer allocator.free(votes2);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    // Insert in sorted order
    try justifications_map.put(allocator, root1, votes1);
    try justifications_map.put(allocator, root2, votes2);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_multiple_roots_unsorted" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;

    const true_indices_1 = [_]usize{0};
    const true_indices_2 = [_]usize{ 1, 2 };
    const votes1 = try createVotes(allocator, &true_indices_1, base_state.config.num_validators);
    defer allocator.free(votes1);
    const votes2 = try createVotes(allocator, &true_indices_2, base_state.config.num_validators);
    defer allocator.free(votes2);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    // Insert in unsorted order (root2 first, then root1)
    try justifications_map.put(allocator, root2, votes2);
    try justifications_map.put(allocator, root1, votes1);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_complex_unsorted" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;
    const root3: types.Root = [_]u8{3} ** 32;

    const true_indices_1 = [_]usize{0};
    const true_indices_2 = [_]usize{ 1, 2 };
    const votes1 = try createVotes(allocator, &true_indices_1, base_state.config.num_validators);
    defer allocator.free(votes1);
    const votes2 = try createVotes(allocator, &true_indices_2, base_state.config.num_validators);
    defer allocator.free(votes2);

    // votes3: all validators vote True (unanimous)
    const votes3 = try allocator.alloc(u8, base_state.config.num_validators);
    defer allocator.free(votes3);
    @memset(votes3, 1);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    // Insert in unsorted order (root3, root1, root2)
    try justifications_map.put(allocator, root3, votes3);
    try justifications_map.put(allocator, root1, votes1);
    try justifications_map.put(allocator, root2, votes2);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_generate_genesis" {
    const allocator = std.testing.allocator;

    // Create a sample config for testing
    const sample_config = types.BeamStateConfig{
        .num_validators = 64,
        .genesis_time = 1000,
    };

    // Create genesis spec
    const genesis_spec = types.GenesisSpec{
        .num_validators = sample_config.num_validators,
        .genesis_time = sample_config.genesis_time,
    };

    // Produce a genesis state from the sample config
    var state: types.BeamState = undefined;
    try state.genGenesisState(allocator, genesis_spec);
    defer state.deinit();

    // Config in state should match the input
    try std.testing.expectEqual(sample_config.num_validators, state.config.num_validators);
    try std.testing.expectEqual(sample_config.genesis_time, state.config.genesis_time);

    // Slot should start at 0
    try std.testing.expectEqual(@as(u64, 0), state.slot);

    // Body root must commit to an empty body at genesis
    var expected_body = types.BeamBlockBody{
        .attestations = try types.SignedVotes.init(allocator),
    };
    defer expected_body.deinit();

    var expected_body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlockBody, expected_body, &expected_body_root, allocator);

    try std.testing.expectEqual(expected_body_root, state.latest_block_header.body_root);

    var hex_buf: [64]u8 = undefined;
    const hex_string = try std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&state.latest_block_header.body_root)});
    // Check against body root generated by python spec test for empty body root
    try std.testing.expectEqualStrings("dba9671bac9513c9482f1416a53aabd2c6ce90d5a5f865ce5a55c775325c9136", hex_string);

    // History and justifications must be empty initially
    try std.testing.expectEqual(@as(usize, 0), state.historical_block_hashes.len());
    try std.testing.expectEqual(@as(usize, 0), state.justified_slots.len());
    try std.testing.expectEqual(@as(usize, 0), state.justifications_roots.len());
    try std.testing.expectEqual(@as(usize, 0), state.justifications_validators.len());
}
test "test_process_slot" {
    const allocator = std.testing.allocator;

    // Create genesis state
    var genesis_state = baseState(allocator);
    defer genesis_state.deinit();

    // At genesis, latest_block_header.state_root is zero.
    const zero_hash = [_]u8{0} ** 32;
    try std.testing.expect(std.mem.eql(u8, &genesis_state.latest_block_header.state_root, &zero_hash));

    // Clone the state to preserve original for comparison (functional style simulation)
    var state_after_slot = try types.sszClone(allocator, types.BeamState, genesis_state);
    defer state_after_slot.deinit();

    // Process one slot; this should backfill the header's state_root.
    try state_after_slot.process_slot(allocator);

    // The filled root must be the hash of the pre-slot state.
    var expected_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, genesis_state, &expected_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &state_after_slot.latest_block_header.state_root, &expected_root));

    // Validate hash tree root against Python spec test output for SSZ correctness
    var hex_buf: [64]u8 = undefined;
    const hex_string = try std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&expected_root)});
    // This should match the hash tree root generated by Python spec test for genesis state
    // TODO: Replace with actual Python spec test output when available
    // For now, we validate that the hash is consistent and non-zero
    try std.testing.expect(!std.mem.eql(u8, hex_string, "0000000000000000000000000000000000000000000000000000000000000000"));

    // Clone the state again for the second process_slot call
    var state_after_second_slot = try types.sszClone(allocator, types.BeamState, state_after_slot);
    defer state_after_second_slot.deinit();

    // Re-processing the slot should be a no-op for the state_root.
    try state_after_second_slot.process_slot(allocator);
    try std.testing.expect(std.mem.eql(u8, &state_after_second_slot.latest_block_header.state_root, &expected_root));
}

test "test_process_slots" {
    const allocator = std.testing.allocator;

    // Create genesis state
    var genesis_state = baseState(allocator);
    defer genesis_state.deinit();

    // Compute genesis state root for later comparison
    var genesis_state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, genesis_state, &genesis_state_root, allocator);

    // Clone state and advance to slot 5
    var new_state = try types.sszClone(allocator, types.BeamState, genesis_state);
    defer new_state.deinit();

    // Create a test logger config
    var logger_config = zeam_utils.getTestLoggerConfig();
    const test_logger = logger_config.logger(null);

    const target_slot: types.Slot = 5;
    try new_state.process_slots(allocator, target_slot, test_logger);

    // The state's slot should equal the target.
    try std.testing.expectEqual(target_slot, new_state.slot);

    // The header state_root should reflect the genesis state's root.
    try std.testing.expect(std.mem.eql(u8, &new_state.latest_block_header.state_root, &genesis_state_root));

    // Validate hash tree root against Python spec test output for SSZ correctness
    var hex_buf: [64]u8 = undefined;
    const hex_string = try std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&genesis_state_root)});
    // This should match the hash tree root generated by Python spec test for genesis state after process_slots
    // TODO: Replace with actual Python spec test output when available
    // For now, we validate that the hash is consistent and non-zero
    try std.testing.expect(!std.mem.eql(u8, hex_string, "0000000000000000000000000000000000000000000000000000000000000000"));

    // Clone state again for testing backward slot movement
    var state_for_backward_test = try types.sszClone(allocator, types.BeamState, new_state);
    defer state_for_backward_test.deinit();

    // Rewinding is invalid; expect an InvalidPreState error.
    const result = state_for_backward_test.process_slots(allocator, 4, test_logger);
    try std.testing.expectError(error.InvalidPreState, result);
}

test "test_hash_tree_root_validation_against_python_spec" {
    const allocator = std.testing.allocator;

    // Create genesis state for validation
    var genesis_state = baseState(allocator);
    defer genesis_state.deinit();

    // Test 1: Validate genesis state hash tree root
    // This should match the output from Python spec test
    // TODO: Replace with actual Python spec test output when available
    // For now, we validate that the hash is consistent and non-zero
    var genesis_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, genesis_state, &genesis_root, allocator);

    var hex_buf: [64]u8 = undefined;
    const hex_string = try std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&genesis_root)});

    // Validate that the hash is not all zeros (which would indicate a bug)
    try std.testing.expect(!std.mem.eql(u8, hex_string, "0000000000000000000000000000000000000000000000000000000000000000"));

    // Validate that the hash is deterministic (same input produces same output)
    var genesis_root2: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, genesis_state, &genesis_root2, allocator);
    try std.testing.expect(std.mem.eql(u8, &genesis_root, &genesis_root2));

    // Test 2: Validate process_slot hash tree root consistency
    var state_after_slot = try types.sszClone(allocator, types.BeamState, genesis_state);
    defer state_after_slot.deinit();

    try state_after_slot.process_slot(allocator);

    // The state root in the header should match the hash of the pre-slot state
    try std.testing.expect(std.mem.eql(u8, &state_after_slot.latest_block_header.state_root, &genesis_root));

    // Test 3: Validate process_slots hash tree root consistency
    var state_after_slots = try types.sszClone(allocator, types.BeamState, genesis_state);
    defer state_after_slots.deinit();

    // Set logger for process_slots
    var logger_config = zeam_utils.getTestLoggerConfig();
    const test_logger = logger_config.logger(null);

    try state_after_slots.process_slots(allocator, 3, test_logger);

    // The state root in the header should still match the original genesis root
    try std.testing.expect(std.mem.eql(u8, &state_after_slots.latest_block_header.state_root, &genesis_root));

    // Test that our hash matches Python leanSpec reference implementation
    const expected_python_hash = "933fc69092f542e467681ac6cf9dae4a616ba5ea9c3c61f93cbcaf0be3548e01";
    try std.testing.expect(std.mem.eql(u8, hex_string, expected_python_hash));
}
