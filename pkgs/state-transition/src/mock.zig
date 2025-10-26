const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;

const params = @import("@zeam/params");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

const transition = @import("./transition.zig");

const MockChainData = struct {
    genesis_config: types.GenesisSpec,
    genesis_state: types.BeamState,
    blocks: []types.SignedBlockWithAttestations,
    blockRoots: []types.Root,
    // what should be justified and finalzied post each of these blocks
    latestJustified: []types.Checkpoint,
    latestFinalized: []types.Checkpoint,
    latestHead: []types.Checkpoint,
    // did justification/finalization happen
    justification: []bool,
    finalization: []bool,

    pub fn deinit(self: *MockChainData, allocator: Allocator) void {
        self.genesis_state.deinit(allocator);
        for (self.blocks) |*b| {
            b.deinit(allocator);
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
    const genesis_config = from_genesis orelse types.GenesisSpec{
        .genesis_time = 1234,
        .num_validators = 4,
    };

    var genesis_state: types.BeamState = undefined;
    try genesis_state.genGenesisState(allocator, genesis_config);
    errdefer genesis_state.deinit();
    var blockList = std.ArrayList(types.SignedBlockWithAttestations).init(allocator);
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
        .proposer_attestations = try types.Attestations.init(allocator),
    };
    const gen_signed_block = types.SignedBlockWithAttestations{
        .message = gen_block_with_attestation,
        .signatures = try types.BlockSignatures.init(allocator),
    };
    var block_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, genesis_block, &block_root, allocator);

    try blockList.append(gen_signed_block);
    try blockRootList.append(block_root);

    var prev_block = genesis_block;

    // track latest justified and finalized for constructing votes
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
        var attestations = std.ArrayList(types.SignedAttestation).init(allocator);
        // 4 slot moving scenario can be applied over and over with finalization in 0
        switch (slot % 4) {
            // no votes on the first block of this
            1 => {
                head_idx = slot;
            },
            2 => {
                const slotAttestations = [_]types.SignedAttestation{
                    // val 0
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 0,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
                    },
                    // skip val1
                    // val2
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 2,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
                    },

                    // val3
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 3,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
                    },
                };

                for (slotAttestations) |slotAttestation| {
                    try attestations.append(slotAttestation);
                }

                head_idx = slot;
                // post these votes last_justified would be updated
                latest_justified_prev = latest_justified;
                latest_justified = .{ .root = parent_root, .slot = slot - 1 };
            },
            3 => {
                const slotAttestations = [_]types.SignedAttestation{
                    // skip val0

                    // val 1
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 1,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
                    },

                    // val2
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 2,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
                    },

                    // val3
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 3,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
                    },
                };
                for (slotAttestations) |slotAttestation| {
                    try attestations.append(slotAttestation);
                }

                head_idx = slot;
                // post these votes last justified and finalized would be updated
                latest_finalized = latest_justified;
                latest_justified_prev = latest_justified;
                latest_justified = .{ .root = parent_root, .slot = slot - 1 };
            },
            0 => {
                const slotAttestations = [_]types.SignedAttestation{
                    // val 0
                    types.SignedAttestation{
                        .message = .{
                            .validator_id = 0,
                            .data = .{
                                .slot = slot - 1,
                                .head = .{ .root = parent_root, .slot = slot - 1 },
                                .target = .{ .root = parent_root, .slot = slot - 1 },
                                .source = latest_justified,
                            },
                        },
                        .signature = [_]u8{0} ** types.SIGSIZE,
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

        var block = types.BeamBlock{
            .slot = slot,
            .proposer_index = slot % genesis_config.num_validators,
            .parent_root = parent_root,
            .state_root = state_root,
            .body = types.BeamBlockBody{
                // .execution_payload_header = .{ .timestamp = timestamp },
                .attestations = blk: {
                    var attestations_list = try types.Attestations.init(allocator);
                    for (attestations.items) |attestation| {
                        try attestations_list.append(attestation);
                    }
                    break :blk attestations_list;
                },
            },
        };

        // prepare pre state to process block for that slot, may be rename prepare_pre_state
        try transition.apply_raw_block(allocator, &beam_state, &block, block_building_logger);
        try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, allocator);

        // generate the signed beam block and add to block list
        const block_with_attestation = types.BlockWithAttestation{
            .block = block,
            .proposer_attestations = blk: {
                var attestations_list = try types.Attestations.init(allocator);
                for (attestations.items) |attestation| {
                    try attestations_list.append(attestation);
                }
                break :blk attestations_list;
            },
        };
        const signed_block = types.SignedBlockWithAttestations{
            .message = block_with_attestation,
            .signatures = try types.BlockSignatures.init(allocator),
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
        .blocks = blockList.items,
        .blockRoots = blockRootList.items,
        .latestJustified = justificationCPList.items,
        .latestFinalized = finalizationCPList.items,
        .latestHead = headList.items,
        .justification = justificationList.items,
        .finalization = finalizationList.items,
    };
}
