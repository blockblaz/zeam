const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const params = @import("@zeam/params");

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

fn sampleCheckpoint() types.Checkpoint {
    return .{
        .root = [_]u8{0} ** 32,
        .slot = 0,
    };
}

fn baseState(allocator: Allocator) !types.BeamState {
    return .{
        .config = sampleConfig(),
        .slot = 0,
        .latest_block_header = sampleBlockHeader(),
        .latest_justified = sampleCheckpoint(),
        .latest_finalized = sampleCheckpoint(),
        .historical_block_hashes = try types.HistoricalBlockHashes.init(allocator),
        .justified_slots = try types.JustifiedSlots.init(allocator),
        .validators = try types.Validators.init(allocator),
        .justifications_roots = try types.JustificationRoots.init(allocator),
        .justifications_validators = try types.JustificationValidators.init(allocator),
    };
}

test "test_get_justifications_empty" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
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
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    // Create a unique root under consideration.
    const root1: types.Root = [_]u8{1} ** 32;

    // Add the root to the state
    try base_state.justifications_roots.append(root1);

    const count = base_state.config.num_validators;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const attest = (i == 2 or i == 5); // Validator 2 and 5 attested True
        try base_state.justifications_validators.append(attest);
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
    const attestations_slice = justifications.get(root1).?;
    try std.testing.expectEqual(count, attestations_slice.len);

    // Check specific attestations: positions 2 and 5 should be True, others False
    for (attestations_slice, 0..) |attest_byte, idx| {
        const expected: u8 = if (idx == 2 or idx == 5) 1 else 0;
        try std.testing.expectEqual(expected, attest_byte);
    }
}

test "test_get_justifications_multiple_roots" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    // Three distinct roots to track.
    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;
    const root3: types.Root = [_]u8{3} ** 32;

    // Add roots to the state in order
    try base_state.justifications_roots.append(root1);
    try base_state.justifications_roots.append(root2);
    try base_state.justifications_roots.append(root3);

    // Validator count for each attestation slice.
    const count = base_state.config.num_validators;

    // Build per-root attestation slices and add to state
    // attestations1: Only validator 0 in favor for root1
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try base_state.justifications_validators.append(i == 0);
    }

    // attestations2: Validators 1 and 2 in favor for root2
    i = 0;
    while (i < count) : (i += 1) {
        try base_state.justifications_validators.append(i == 1 or i == 2);
    }

    // attestations3: Unanimous in favor for root3
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
    const attestations1 = justifications.get(root1).?;
    try std.testing.expectEqual(count, attestations1.len);
    for (attestations1, 0..) |attest_byte, idx| {
        const expected: u8 = if (idx == 0) 1 else 0;
        try std.testing.expectEqual(expected, attest_byte);
    }

    // Check root2: validators 1 and 2 should be True
    const attestations2 = justifications.get(root2).?;
    try std.testing.expectEqual(count, attestations2.len);
    for (attestations2, 0..) |attest_byte, idx| {
        const expected: u8 = if (idx == 1 or idx == 2) 1 else 0;
        try std.testing.expectEqual(expected, attest_byte);
    }

    // Check root3: all validators should be True
    const attestations3 = justifications.get(root3).?;
    try std.testing.expectEqual(count, attestations3.len);
    for (attestations3) |attest_byte| {
        try std.testing.expectEqual(@as(u8, 1), attest_byte);
    }
}

test "test_with_justifications_invalid_length" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
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

    var initial_state = try baseState(allocator);
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
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    // Two roots to test ordering
    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;

    // Build two attestation slices of proper length
    const count = base_state.config.num_validators;
    const attestations1_buf = try allocator.alloc(u8, count);
    defer allocator.free(attestations1_buf);
    @memset(attestations1_buf, 0); // All False

    const attestations2_buf = try allocator.alloc(u8, count);
    defer allocator.free(attestations2_buf);
    @memset(attestations2_buf, 1); // All True

    // Intentionally supply the map in unsorted key order (root2 first, then root1)
    var justifications: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications.deinit(allocator);
    try justifications.put(allocator, root2, attestations2_buf);
    try justifications.put(allocator, root1, attestations1_buf);

    // Flatten into the state; method sorts keys deterministically
    try base_state.withJustifications(allocator, &justifications);

    // The stored roots should be [root1, root2] (sorted ascending)
    try std.testing.expectEqual(@as(usize, 2), base_state.justifications_roots.len());
    try std.testing.expectEqual(root1, base_state.justifications_roots.constSlice()[0]);
    try std.testing.expectEqual(root2, base_state.justifications_roots.constSlice()[1]);

    // The flattened validators list should follow the same order (attestations1 + attestations2)
    try std.testing.expectEqual(count * 2, base_state.justifications_validators.len());

    // Check first part corresponds to attestations1 (all false)
    for (0..count) |i| {
        const attest = try base_state.justifications_validators.get(i);
        try std.testing.expect(!attest);
    }

    // Check second part corresponds to attestations2 (all true)
    for (count..base_state.justifications_validators.len()) |i| {
        const attest = try base_state.justifications_validators.get(i);
        try std.testing.expect(attest);
    }
}

// Helper function to create attestations array with specific indices set to True
fn createAttestations(allocator: Allocator, true_indices: []const usize, total_count: usize) ![]u8 {
    const attestations = try allocator.alloc(u8, total_count);
    @memset(attestations, 0); // Initialize all to False

    for (true_indices) |idx| {
        if (idx < total_count) {
            attestations[idx] = 1; // Set to True
        }
    }

    return attestations;
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
        const reconstructed_attestations = reconstructed_map.get(original_entry.key_ptr.*);
        try std.testing.expect(reconstructed_attestations != null);

        const original_attestations = original_entry.value_ptr.*;
        const reconstructed_slice = reconstructed_attestations.?;

        try std.testing.expectEqual(original_attestations.len, reconstructed_slice.len);
        for (original_attestations, reconstructed_slice) |orig, recon| {
            try std.testing.expectEqual(orig, recon);
        }
    }
}

test "test_justifications_roundtrip_empty" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    // Empty justifications map
    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_single_root" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const true_indices = [_]usize{0};
    const attestations1 = try createAttestations(allocator, &true_indices, base_state.config.num_validators);
    defer allocator.free(attestations1);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    try justifications_map.put(allocator, root1, attestations1);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_multiple_roots_sorted" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;

    const true_indices_1 = [_]usize{0};
    const true_indices_2 = [_]usize{ 1, 2 };
    const attestations1 = try createAttestations(allocator, &true_indices_1, base_state.config.num_validators);
    defer allocator.free(attestations1);
    const attestations2 = try createAttestations(allocator, &true_indices_2, base_state.config.num_validators);
    defer allocator.free(attestations2);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    // Insert in sorted order
    try justifications_map.put(allocator, root1, attestations1);
    try justifications_map.put(allocator, root2, attestations2);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_multiple_roots_unsorted" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;

    const true_indices_1 = [_]usize{0};
    const true_indices_2 = [_]usize{ 1, 2 };
    const attestations1 = try createAttestations(allocator, &true_indices_1, base_state.config.num_validators);
    defer allocator.free(attestations1);
    const attestations2 = try createAttestations(allocator, &true_indices_2, base_state.config.num_validators);
    defer allocator.free(attestations2);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    // Insert in unsorted order (root2 first, then root1)
    try justifications_map.put(allocator, root2, attestations2);
    try justifications_map.put(allocator, root1, attestations1);

    try verifyRoundtrip(allocator, &base_state, &justifications_map);
}

test "test_justifications_roundtrip_complex_unsorted" {
    const allocator = std.testing.allocator;
    var base_state = try baseState(allocator);
    defer base_state.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;
    const root3: types.Root = [_]u8{3} ** 32;

    const true_indices_1 = [_]usize{0};
    const true_indices_2 = [_]usize{ 1, 2 };
    const attestations1 = try createAttestations(allocator, &true_indices_1, base_state.config.num_validators);
    defer allocator.free(attestations1);
    const attestations2 = try createAttestations(allocator, &true_indices_2, base_state.config.num_validators);
    defer allocator.free(attestations2);

    // attestations3: all validators attest True (unanimous)
    const attestations3 = try allocator.alloc(u8, base_state.config.num_validators);
    defer allocator.free(attestations3);
    @memset(attestations3, 1);

    var justifications_map: std.AutoHashMapUnmanaged(types.Root, []u8) = .empty;
    defer justifications_map.deinit(allocator);
    // Insert in unsorted order (root3, root1, root2)
    try justifications_map.put(allocator, root3, attestations3);
    try justifications_map.put(allocator, root1, attestations1);
    try justifications_map.put(allocator, root2, attestations2);

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
        .attestations = try types.Attestations.init(allocator),
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
