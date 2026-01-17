const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const keymanager = @import("@zeam/key-manager");
const xmss = @import("@zeam/xmss");

const transition = @import("./transition.zig");

pub const MockChainData = struct {
    genesis_config: types.GenesisSpec,
    genesis_state: types.BeamState,
    blocks: []types.SignedBlockWithAttestation,
    blockRoots: []types.Root,
    // what should be justified and finalzied post each of these blocks
    latestJustified: []types.Checkpoint,
    latestFinalized: []types.Checkpoint,
    latestHead: []types.Checkpoint,
    // did justification/finalization happen
    justification: []bool,
    finalization: []bool,

    pub fn deinit(self: *MockChainData, allocator: Allocator) void {
        // NOTE: genesis_state cleanup is handled by the caller who uses it
        // This is necessary because the state may be modified externally,
        // creating new allocations that this struct doesn't know about
        for (self.blocks) |*b| {
            b.deinit();
        }
        allocator.free(self.blocks);
        allocator.free(self.blockRoots);
        allocator.free(self.latestJustified);
        allocator.free(self.latestFinalized);
        allocator.free(self.latestHead);
        allocator.free(self.justification);
        allocator.free(self.finalization);
    }
};

pub fn genMockChain(allocator: Allocator, numBlocks: usize, from_genesis: ?types.GenesisSpec) !MockChainData {
    // Determine num_validators early
    const num_validators: usize = if (from_genesis) |gen| @intCast(gen.numValidators()) else 4;
    std.debug.assert(num_validators > 0); // A chain must have at least one validator.

    // Init key_manager ONCE for entire function (used for genesis AND signing later)
    var key_manager = try keymanager.getTestKeyManager(allocator, num_validators, numBlocks);
    defer key_manager.deinit();

    var genesis_config: types.GenesisSpec = undefined;
    var should_free_genesis = false;

    if (from_genesis) |gen| {
        genesis_config = gen;
    } else {
        // Generate pubkeys from key_manager
        const pubkeys = try key_manager.getAllPubkeys(allocator, num_validators);
        errdefer allocator.free(pubkeys);

        genesis_config = types.GenesisSpec{
            .genesis_time = 1234,
            .validator_pubkeys = pubkeys,
        };
        should_free_genesis = true;
    }
    defer if (should_free_genesis) allocator.free(genesis_config.validator_pubkeys);

    var genesis_state: types.BeamState = undefined;
    try genesis_state.genGenesisState(allocator, genesis_config);
    errdefer genesis_state.deinit();
    var blockList = std.ArrayList(types.SignedBlockWithAttestation).init(allocator);
    var blockRootList = std.ArrayList(types.Root).init(allocator);

    var justificationCPList = std.ArrayList(types.Checkpoint).init(allocator);
    var justificationList = std.ArrayList(bool).init(allocator);

    var finalizationCPList = std.ArrayList(types.Checkpoint).init(allocator);
    var finalizationList = std.ArrayList(bool).init(allocator);

    var headList = std.ArrayList(types.Checkpoint).init(allocator);

    // figure out a way to clone genesis_state
    var beam_state: types.BeamState = undefined;
    try beam_state.genGenesisState(allocator, genesis_config);
    defer beam_state.deinit();

    var genesis_block: types.BeamBlock = undefined;
    try beam_state.genGenesisBlock(allocator, &genesis_block);

    const gen_block_with_attestation = types.BlockWithAttestation{
        .block = genesis_block,
        .proposer_attestation = types.Attestation{
            .validator_id = 0,
            .data = types.AttestationData{
                .slot = 0,
                .head = .{ .root = types.ZERO_HASH, .slot = 0 },
                .target = .{ .root = types.ZERO_HASH, .slot = 0 },
                .source = .{ .root = types.ZERO_HASH, .slot = 0 },
            },
        },
    };

    const gen_signed_block = types.SignedBlockWithAttestation{
        .message = gen_block_with_attestation,
        .signature = blk: {
            var signatures = try types.createBlockSignatures(allocator, gen_block_with_attestation.block.body.attestations.len());
            const proposer_sig = try key_manager.signAttestation(
                &gen_block_with_attestation.proposer_attestation,
                allocator,
            );
            signatures.proposer_signature = proposer_sig;
            break :blk signatures;
        },
    };
    var block_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, genesis_block, &block_root, allocator);

    try blockList.append(gen_signed_block);
    try blockRootList.append(block_root);

    var prev_block = genesis_block;

    // track latest justified and finalized for constructing attestations
    var latest_justified: types.Checkpoint = .{ .root = block_root, .slot = genesis_block.slot };
    var latest_justified_prev = latest_justified;
    var latest_finalized = latest_justified;

    try justificationCPList.append(latest_justified);
    try justificationList.append(true);
    try finalizationCPList.append(latest_finalized);
    try finalizationList.append(true);

    // to easily track new justifications/finalizations for bunding in the response
    var prev_justified_root = latest_justified.root;
    var prev_finalized_root = latest_finalized.root;
    // head is genesis block itself
    var head_idx: usize = 0;
    try headList.append(.{ .root = block_root, .slot = head_idx });

    // TODO: pass logger as genmockchain arg with scope set
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const block_building_logger = zeam_logger_config.logger(.state_transition_mock_block_building);

    for (1..numBlocks) |slot| {
        var parent_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, prev_block, &parent_root, allocator);

        const state_root: [32]u8 = types.ZERO_HASH;
        // const timestamp = genesis_config.genesis_time + slot * params.SECONDS_PER_SLOT;
        var attestations = std.ArrayList(types.Attestation).init(allocator);
        defer attestations.deinit();
        // 4 slot moving scenario can be applied over and over with finalization in 0
        switch (slot % 4) {
            // no attestations on the first block of this
            1 => {
                head_idx = slot;
            },
            2 => {
                const slotAttestations = [_]types.Attestation{
                    // val 0
                    .{
                        .validator_id = 0 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },
                    // skip val1
                    // val2
                    .{
                        .validator_id = 2 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },

                    // val3
                    .{
                        .validator_id = 3 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },
                };

                for (slotAttestations) |slotAttestation| {
                    try attestations.append(slotAttestation);
                }

                head_idx = slot;
                // post these attestations last_justified would be updated
                latest_justified_prev = latest_justified;
                latest_justified = .{ .root = parent_root, .slot = slot - 1 };
            },
            3 => {
                const slotAttestations = [_]types.Attestation{
                    // skip val0

                    // val 1
                    .{
                        .validator_id = 1 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },

                    // val2
                    .{
                        .validator_id = 2 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },

                    // val3
                    .{
                        .validator_id = 3 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },
                };
                for (slotAttestations) |slotAttestation| {
                    try attestations.append(slotAttestation);
                }

                head_idx = slot;
                // post these attestations last justified and finalized would be updated
                latest_finalized = latest_justified;
                latest_justified_prev = latest_justified;
                latest_justified = .{ .root = parent_root, .slot = slot - 1 };
            },
            0 => {
                const slotAttestations = [_]types.Attestation{
                    // val 0
                    .{
                        .validator_id = 0 % num_validators,
                        .data = .{
                            .slot = slot - 1,
                            .head = .{ .root = parent_root, .slot = slot - 1 },
                            .target = .{ .root = parent_root, .slot = slot - 1 },
                            .source = latest_justified,
                        },
                    },

                    // skip val1

                    // skip val2

                    // skip val3
                };

                head_idx = slot;
                for (slotAttestations) |slotAttestation| {
                    try attestations.append(slotAttestation);
                }
            },
            else => unreachable,
        }

        // Build gossip signatures map from attestations
        var signatures_map = types.SignaturesMap.init(allocator);
        defer signatures_map.deinit();

        for (attestations.items) |attestation| {
            // Get the serialized signature bytes
            const sig_buffer = try key_manager.signAttestation(&attestation, allocator);

            // Compute data root for the signature key
            const data_root = try attestation.data.sszRoot(allocator);

            try signatures_map.put(
                .{ .validator_id = attestation.validator_id, .data_root = data_root },
                .{ .slot = attestation.data.slot, .signature = sig_buffer },
            );
        }

        // Compute aggregated signatures using the shared method
        var aggregation = try types.AggregatedAttestationsResult.init(allocator);
        var agg_att_cleanup = true;
        var agg_sig_cleanup = true;
        errdefer if (agg_att_cleanup) {
            for (aggregation.attestations.slice()) |*att| {
                att.deinit();
            }
            aggregation.attestations.deinit();
        };
        errdefer if (agg_sig_cleanup) {
            for (aggregation.attestation_signatures.slice()) |*sig| {
                sig.deinit();
            }
            aggregation.attestation_signatures.deinit();
        };
        try aggregation.computeAggregatedSignatures(
            attestations.items,
            &beam_state.validators,
            &signatures_map,
            null, // no pre-aggregated payloads in mock
        );

        const proposer_index = slot % genesis_config.numValidators();
        var block = types.BeamBlock{
            .slot = slot,
            .proposer_index = proposer_index,
            .parent_root = parent_root,
            .state_root = state_root,
            .body = types.BeamBlockBody{
                .attestations = aggregation.attestations,
            },
        };
        agg_att_cleanup = false;

        // prepare pre state to process block for that slot, may be rename prepare_pre_state
        try transition.apply_raw_block(allocator, &beam_state, &block, block_building_logger);
        try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, allocator);

        // generate the signed beam block and add to block list
        const block_with_attestation = types.BlockWithAttestation{
            .block = block,
            // set the additional proposer attestation to the old with genesis
            // this way it won't get impored in the forkchoice since forkchoice doesn't
            // import old attestations
            // TODO: update with the correct proposer attestation as per the mock sequence
            .proposer_attestation = .{
                .validator_id = proposer_index,
                .data = types.AttestationData{
                    // setting slot=0 helps to ignore this attestation because forkchoice wouldn't import
                    // old attestations
                    .slot = 0,
                    // set all the votes to genesis since this attestation is to be ignored
                    .head = .{ .root = blockRootList.items[0], .slot = 0 },
                    .target = .{ .root = blockRootList.items[0], .slot = 0 },
                    .source = .{ .root = blockRootList.items[0], .slot = 0 },
                },
            },
        };

        const proposer_sig = try key_manager.signAttestation(
            &block_with_attestation.proposer_attestation,
            allocator,
        );

        const block_signatures = types.BlockSignatures{
            .attestation_signatures = aggregation.attestation_signatures,
            .proposer_signature = proposer_sig,
        };
        agg_sig_cleanup = false;

        const signed_block = types.SignedBlockWithAttestation{
            .message = block_with_attestation,
            .signature = block_signatures,
        };
        try blockList.append(signed_block);
        try blockRootList.append(block_root);

        const head = types.Checkpoint{ .root = blockRootList.items[head_idx], .slot = head_idx };
        try headList.append(head);

        try justificationCPList.append(latest_justified);
        const justification = !std.mem.eql(u8, &prev_justified_root, &latest_justified.root);
        try justificationList.append(justification);
        prev_justified_root = latest_justified.root;

        try finalizationCPList.append(latest_finalized);
        const finalization = !std.mem.eql(u8, &prev_finalized_root, &latest_finalized.root);
        try finalizationList.append(finalization);
        prev_finalized_root = latest_finalized.root;

        // now we are ready for next round as the beam_state is not this blocks post state
        prev_block = block;
    }

    return MockChainData{
        .genesis_config = genesis_config,
        .genesis_state = genesis_state,
        .blocks = try blockList.toOwnedSlice(),
        .blockRoots = try blockRootList.toOwnedSlice(),
        .latestJustified = try justificationCPList.toOwnedSlice(),
        .latestFinalized = try finalizationCPList.toOwnedSlice(),
        .latestHead = try headList.toOwnedSlice(),
        .justification = try justificationList.toOwnedSlice(),
        .finalization = try finalizationList.toOwnedSlice(),
    };
}
