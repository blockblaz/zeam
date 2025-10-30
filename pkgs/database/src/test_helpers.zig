const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");

/// Helper function to create a dummy block for testing
pub fn createDummyBlock(allocator: Allocator, slot: u64, proposer_index: u64, parent_root_fill: u8, state_root_fill: u8, signatures: []const types.Bytes4000) !types.SignedBlockWithAttestation {
    var test_block = types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = undefined,
        .state_root = undefined,
        .body = types.BeamBlockBody{
            .attestations = try types.Attestations.init(allocator),
        },
    };
    @memset(&test_block.parent_root, parent_root_fill);
    @memset(&test_block.state_root, state_root_fill);

    const proposer_attestation = types.Attestation{
        .validator_id = proposer_index,
        .data = types.AttestationData{
            .slot = slot,
            .head = types.Checkpoint{
                .slot = slot,
                .root = undefined,
            },
            .source = types.Checkpoint{
                .slot = 0,
                .root = undefined,
            },
            .target = types.Checkpoint{
                .slot = slot,
                .root = undefined,
            },
        },
    };

    const block_with_attestation = types.BlockWithAttestation{
        .block = test_block,
        .proposer_attestation = proposer_attestation,
    };

    var block_signatures = try types.BlockSignatures.init(allocator);
    errdefer block_signatures.deinit();

    // Add all provided signatures to the list
    for (signatures) |sig| {
        try block_signatures.append(sig);
    }

    const signed_block = types.SignedBlockWithAttestation{
        .message = block_with_attestation,
        .signature = block_signatures,
    };

    return signed_block;
}

/// Helper function to create a dummy state for testing
pub fn createDummyState(allocator: Allocator, slot: u64, num_validators: u64, genesis_time: u64, justified_slot: u64, finalized_slot: u64, justified_root_fill: u8, finalized_root_fill: u8) !types.BeamState {
    var test_state = types.BeamState{
        .config = types.BeamStateConfig{
            .num_validators = num_validators,
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
