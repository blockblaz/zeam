const std = @import("std");
const Allocator = std.mem.Allocator;
const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const params = @import("@zeam/params");

fn sampleConfig() types.BeamStateConfig {
    return .{
        .num_validators = 10,
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

fn baseState(allocator:Allocator) types.BeamState {
    return .{
        .config = sampleConfig(),
        .slot = 0,
        .latest_block_header = sampleBlockHeader(),
        .latest_justified = sampleCheckpoint(),
        .latest_finalized = sampleCheckpoint(),
        .historical_block_hashes = try types.HistoricalBlockHashes.init(allocator),
        .justified_slots = try types.JustifiedSlots.init(allocator),
        .justifications_roots = try ssz.utils.List(types.Root, params.HISTORICAL_ROOTS_LIMIT).init(allocator),
        .justifications_validators = try ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT).init(allocator),
    };
}

test "test_with_justifications_invalid_length" {
    const allocator = std.testing.allocator;
    var base_state = baseState(allocator);
    defer base_state.deinit();

    const root1 = [_]u8{1} ** 32;
    var invalid_justification = [_]u8{1} ** (params.VALIDATOR_REGISTRY_LIMIT - 1);
    var justifications:std.AutoHashMapUnmanaged(types.Root, []u8)=.empty;
    defer justifications.deinit(allocator);
    try justifications.put(allocator, root1, &invalid_justification);

    const result = base_state.withJustifications(allocator, &justifications);
    try std.testing.expect(result == error.InvalidJustificationLength);
}