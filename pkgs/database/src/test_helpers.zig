const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("@zeam/types");

/// Helper function to create a dummy block for testing
pub fn createDummyBlock(allocator: Allocator, slot: u64, proposer_index: u64, parent_root_fill: u8, state_root_fill: u8, signature_fill: u8) !types.SignedBeamBlock {
    var test_block = types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = undefined,
        .state_root = undefined,
        .body = types.BeamBlockBody{
            .attestations = try types.SignedVotes.init(allocator),
        },
    };
    @memset(&test_block.parent_root, parent_root_fill);
    @memset(&test_block.state_root, state_root_fill);

    var signed_block = types.SignedBeamBlock{
        .message = test_block,
        .signature = undefined,
    };
    @memset(&signed_block.signature, signature_fill);

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
        .latest_justified = types.Mini3SFCheckpoint{
            .slot = justified_slot,
            .root = undefined,
        },
        .latest_finalized = types.Mini3SFCheckpoint{
            .slot = finalized_slot,
            .root = undefined,
        },
        .historical_block_hashes = try types.HistoricalBlockHashes.init(allocator),
        .justified_slots = try types.JustifiedSlots.init(allocator),
        .latest_block_header = types.BeamBlockHeader{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = undefined,
            .state_root = undefined,
            .body_root = undefined,
        },
        .justifications_roots = try types.JustificationsRoots.init(allocator),
        .justifications_validators = try types.JustificationsValidators.init(allocator),
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
