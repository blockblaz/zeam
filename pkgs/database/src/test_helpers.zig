const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");

/// Helper function to create a dummy block for testing. Carries an empty devnet5 Type-2 proof
/// (these DB tests exercise SSZ persistence/round-trip, not signature verification).
pub fn createDummyBlock(allocator: Allocator, slot: u64, proposer_index: u64, parent_root_fill: u8, state_root_fill: u8) !types.SignedBlock {
    const attestations_list = try types.AggregatedAttestations.init(allocator);

    var test_block = types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = undefined,
        .state_root = undefined,
        .body = types.BeamBlockBody{
            .attestations = attestations_list,
        },
    };
    @memset(&test_block.parent_root, parent_root_fill);
    @memset(&test_block.state_root, state_root_fill);

    return types.SignedBlock{
        .block = test_block,
        .proof = try types.ByteList512KiB.init(allocator),
    };
}

/// Helper function to create a dummy state for testing
pub fn createDummyState(allocator: Allocator, slot: u64, num_validators: u64, genesis_time: u64, justified_slot: u64, finalized_slot: u64, justified_root_fill: u8, finalized_root_fill: u8) !types.BeamState {
    var validators = try types.Validators.init(allocator);
    errdefer validators.deinit();
    for (0..num_validators) |index| {
        try validators.append(.{ .attestation_pubkey = [_]u8{0} ** 52, .proposal_pubkey = [_]u8{0} ** 52, .index = @as(types.ValidatorIndex, @intCast(index)) });
    }

    var test_state = types.BeamState{
        .config = types.BeamStateConfig{
            .genesis_time = genesis_time,
        },
        .slot = slot,
        .latest_justified = types.Checkpoint{
            .slot = justified_slot,
            .root = undefined,
        },
        .latest_finalized = types.Checkpoint{
            .slot = finalized_slot,
            .root = undefined,
        },
        .historical_block_hashes = try types.HistoricalBlockHashes.init(allocator),
        .justified_slots = try types.JustifiedSlots.init(allocator),
        .validators = try types.Validators.init(allocator),
        .latest_block_header = types.BeamBlockHeader{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = undefined,
            .state_root = undefined,
            .body_root = undefined,
        },
        .justifications_roots = try types.JustificationRoots.init(allocator),
        .justifications_validators = try types.JustificationValidators.init(allocator),
    };
    @memset(&test_state.latest_justified.root, justified_root_fill);
    @memset(&test_state.latest_finalized.root, finalized_root_fill);

    return test_state;
}

/// Helper function to create a dummy root for testing
pub fn createDummyRoot(fill_byte: u8) types.Root {
    var root: types.Root = undefined;
    @memset(&root, fill_byte);
    return root;
}
