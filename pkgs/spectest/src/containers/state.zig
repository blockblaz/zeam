const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const params = @import("@zeam/params");
const stf = @import("@zeam/state-transition");
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

test "test_process_attestations_justification_and_finalization" {
    const allocator = std.testing.allocator;

    // Generate genesis state
    const config = types.GenesisSpec{
        .genesis_time = 0,
        .num_validators = 10,
    };
    var state = try stf.genGenesisState(allocator, config);
    defer state.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.state_transition);

    // Move to slot 1 to allow producing a block there
    try stf.process_slots(allocator, &state, 1, logger);

    // Create and process the block at slot 1
    var block1_body = types.BeamBlockBody{
        .attestations = try types.SignedVotes.init(allocator),
    };
    defer block1_body.attestations.deinit();

    var block1_parent_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &block1_parent_root, allocator);

    const block1 = types.BeamBlock{
        .slot = 1,
        .proposer_index = 1 % 10,
        .parent_root = block1_parent_root,
        .state_root = [_]u8{0} ** 32,
        .body = block1_body,
    };

    try stf.process_block(allocator, &state, block1, logger);

    // Move to slot 4 and produce a block
    try stf.process_slots(allocator, &state, 4, logger);

    var block4_body = types.BeamBlockBody{
        .attestations = try types.SignedVotes.init(allocator),
    };
    defer block4_body.attestations.deinit();

    var block4_parent_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &block4_parent_root, allocator);

    const block4 = types.BeamBlock{
        .slot = 4,
        .proposer_index = 4 % 10,
        .parent_root = block4_parent_root,
        .state_root = [_]u8{0} ** 32,
        .body = block4_body,
    };

    try stf.process_block(allocator, &state, block4, logger);

    // Advance to slot 5 so the header at slot 4 caches its state root
    try stf.process_slots(allocator, &state, 5, logger);

    // Define source (genesis) and target (slot 4) checkpoints for voting
    const genesis_checkpoint = types.Mini3SFCheckpoint{
        .root = try state.historical_block_hashes.get(0),
        .slot = 0,
    };

    var checkpoint4_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.latest_block_header, &checkpoint4_root, allocator);
    const checkpoint4 = types.Mini3SFCheckpoint{
        .root = checkpoint4_root,
        .slot = 4,
    };

    // Create 7 votes from distinct validators (indices 0..6) to reach ≥2/3
    var votes_for_4 = try types.SignedVotes.init(allocator);
    defer votes_for_4.deinit();

    var i: u64 = 0;
    while (i < 7) : (i += 1) {
        const vote = types.SignedVote{
            .validator_id = i,
            .message = types.Mini3SFVote{
                .slot = 4,
                .head = checkpoint4,
                .target = checkpoint4,
                .source = genesis_checkpoint,
            },
            .signature = [_]u8{0} ** types.SIGSIZE,
        };
        try votes_for_4.append(vote);
    }

    // Process attestations directly
    try stf.process_attestations(allocator, &state, votes_for_4, logger);

    // The target (slot 4) should now be justified
    try std.testing.expectEqual(checkpoint4, state.latest_justified);

    // The justified bit for slot 4 must be set
    const slot4_justified = try state.justified_slots.get(4);
    try std.testing.expect(slot4_justified);

    // Since no other justifiable slot exists between 0 and 4, genesis is finalized
    try std.testing.expectEqual(genesis_checkpoint, state.latest_finalized);
}
