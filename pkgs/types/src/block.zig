const std = @import("std");
const ssz = @import("ssz");
const params = @import("@zeam/params");

const mini_3sf = @import("./mini_3sf.zig");
const state = @import("./state.zig");
const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;
const Bytes32 = utils.Bytes32;
const Bytes4000 = utils.Bytes4000;
const Root = utils.Root;
const SignedVotes = mini_3sf.SignedVotes;
const ZERO_HASH = utils.ZERO_HASH;

// some p2p containers
pub const BlockByRootRequest = struct {
    roots: ssz.utils.List(utils.Root, params.MAX_REQUEST_BLOCKS),
};

/// Canonical lightweight forkchoice proto block used across modules
pub const ProtoBlock = struct {
    slot: Slot,
    blockRoot: Root,
    parentRoot: Root,
    stateRoot: Root,
    timeliness: bool,
};

pub const BeamBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body: BeamBlockBody,
};

pub const BeamBlockHeader = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,
};

pub const BeamBlockBody = struct {
    // some form of APS - to be activated later - disabled for PQ devnet0
    // execution_payload_header: ExecutionPayloadHeader,

    // mini 3sf simplified votes
    attestations: SignedVotes,
};

pub const SignedBeamBlock = struct {
    message: BeamBlock,
    // winternitz signature might be of different size depending on num chunks and chunk size
    signature: Bytes4000,
    pub fn deinit(self: *SignedBeamBlock) void {
        // Deinit heap allocated ArrayLists
        self.message.body.attestations.deinit();
    }
};

// computing latest block header to be assigned to the state for processing the block
pub fn blockToLatestBlockHeader(allocator: Allocator, test_block: BeamBlock) !BeamBlockHeader {
    var body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        BeamBlockBody,
        test_block.body,
        &body_root,
        allocator,
    );

    const header = BeamBlockHeader{
        .slot = test_block.slot,
        .proposer_index = test_block.proposer_index,
        .parent_root = test_block.parent_root,
        .state_root = utils.ZERO_HASH,
        .body_root = body_root,
    };
    return header;
}

pub fn genGenesisLatestBlock(allocator: Allocator) !BeamBlock {
    const genesis_latest_block = BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = ZERO_HASH,
        .state_root = ZERO_HASH,
        .body = BeamBlockBody{
            // .execution_payload_header = .{ .timestamp = 0 },
            // 3sf mini votes
            .attestations = try SignedVotes.init(allocator),
        },
    };

    return genesis_latest_block;
}

pub fn blockToHeader(allocator: Allocator, beam_block: BeamBlock) !BeamBlockHeader {
    var body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        BeamBlockBody,
        beam_block.body,
        &body_root,
        allocator,
    );

    const header = BeamBlockHeader{
        .slot = beam_block.slot,
        .proposer_index = beam_block.proposer_index,
        .parent_root = beam_block.parent_root,
        .state_root = beam_block.state_root,
        .body_root = body_root,
    };
    return header;
}

pub fn genGenesisBlock(allocator: Allocator, genesis_state: state.BeamState) !BeamBlock {
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        state.BeamState,
        genesis_state,
        &state_root,
        allocator,
    );

    const genesis_latest_block = BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = ZERO_HASH,
        .state_root = state_root,
        .body = BeamBlockBody{
            // .execution_payload_header = .{ .timestamp = 0 },
            // 3sf mini
            .attestations = try mini_3sf.SignedVotes.init(allocator),
        },
    };

    return genesis_latest_block;
}

test "ssz seralize/deserialize signed beam block" {
    var signed_block = SignedBeamBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{
                //
                // .execution_payload_header = ExecutionPayloadHeader{ .timestamp = 23 },
                .attestations = try SignedVotes.init(std.testing.allocator),
            },
        },
        .signature = [_]u8{2} ** utils.SIGSIZE,
    };
    defer signed_block.deinit();

    // check SignedBeamBlock serialization/deserialization
    var serialized_signed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_signed_block.deinit();
    try ssz.serialize(SignedBeamBlock, signed_block, &serialized_signed_block);
    std.debug.print("\n\n\nserialized_signed_block ({d})", .{serialized_signed_block.items.len});

    var deserialized_signed_block: SignedBeamBlock = undefined;
    try ssz.deserialize(SignedBeamBlock, serialized_signed_block.items[0..], &deserialized_signed_block, std.testing.allocator);

    // try std.testing.expect(signed_block.message.body.execution_payload_header.timestamp == deserialized_signed_block.message.body.execution_payload_header.timestamp);
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.state_root, &deserialized_signed_block.message.state_root));
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.parent_root, &deserialized_signed_block.message.parent_root));

    // successful merklization
    var block_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        BeamBlock,
        signed_block.message,
        &block_root,
        std.testing.allocator,
    );
}
