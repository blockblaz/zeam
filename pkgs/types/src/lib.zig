const std = @import("std");
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const params = @import("@zeam/params");

// just dummy type right now to test imports
pub const Bytes32 = [32]u8;
pub const Slot = u64;
pub const Interval = u64;
pub const ValidatorIndex = u64;
pub const Bytes48 = [48]u8;

pub const Root = Bytes32;
// zig treats string as byte sequence so hex is 64 bytes string
pub const RootHex = [64]u8;

pub const BeamBlockHeader = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,
};

// basic payload header for some sort of APS
pub const ExecutionPayloadHeader = struct {
    timestamp: u64,
};

pub const Mini3SFCheckpoint = struct {
    root: Root,
    slot: Slot,
};

pub const Mini3SFVote = struct {
    slot: Slot,
    head: Mini3SFCheckpoint,
    target: Mini3SFCheckpoint,
    source: Mini3SFCheckpoint,
};

// this will be updated to correct impl in the followup PR to reflect latest spec changes
pub const SignedVote = struct {
    validator_id: u64,
    message: Mini3SFVote,
    // TODO signature objects to be updated in a followup PR
    signature: Bytes48,
};
// issue in serialization/deserialization with ssz list, for now use slice
// for which serialization/deserialization is not an issue but hash is not stable/expected
// pub const Mini3SFVotes = ssz.utils.List(Mini3SFVote, MAX_VALIDATORS);
pub const SignedVotes = []SignedVote;

// 3sf mini impl simplified assumptions
pub const MAX_VALIDATORS = 4096;
pub const BeamBlockBody = struct {
    // some form of APS
    execution_payload_header: ExecutionPayloadHeader,
    // mini 3sf simplified votes
    atttestations: SignedVotes,
};

pub const BeamBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body: BeamBlockBody,
};

pub const SignedBeamBlock = struct {
    message: BeamBlock,
    // winternitz signature might be of different size depending on num chunks and chunk size
    signature: Bytes48,
};

// impl 3sf mini, ideally genesis_time can also move into config but we don't know what will
// be the final shape of the state
pub const BeamStateConfig = struct {
    num_validators: u64,
};

// issue with serialize/deserialize list so implement with slices
pub const MAX_HISTORICAL_BLOCK_HASHES = 4096;
// pub const HistoricalBlockHashes = ssz.utils.List(Root, MAX_HISTORICAL_BLOCK_HASHES);
// pub const JustifiedSlots = ssz.utils.Bitlist(bool, MAX_HISTORICAL_BLOCK_HASHES);
// // internal state representation could be a map or we can directly interpret map as list of list
// // for ssz purposes
// pub const Justifications = ssz.utils.List(JustifiedSlots, MAX_HISTORICAL_BLOCK_HASHES);

pub const HistoricalBlockHashes = []Root;
// need to check the integration of bitvector with struct in ssz
// for now use byte list
pub const JustifiedSlots = []u8;
// array of array ssz needs to be also figured out
// implement justification map as flat array of keys, with flatted corresponding
// justifications of num_validators each, which isn't an issue for now because
// we will keep it constant
// pub const Justifications = struct {
//     roots: []Root,
//     voting_validators: []u8,
// };
pub const BeamState = struct {
    config: BeamStateConfig,
    genesis_time: u64,
    slot: u64,
    latest_block_header: BeamBlockHeader,
    latest_justified: Mini3SFCheckpoint,
    latest_finalized: Mini3SFCheckpoint,
    historical_block_hashes: HistoricalBlockHashes,
    justified_slots: JustifiedSlots,

    // a flat representation of the justifications map
    justifications_roots: []Root,
    justifications_validators: []u8,
};

// non ssz types, difference is the variable list doesn't need upper boundaries
pub const ZkVm = enum {
    ceno,
    powdr,
    sp1,
};

pub const BeamSTFProof = struct {
    // zk_vm: ZkVm,
    proof: []const u8,
};

pub const GenesisSpec = struct { genesis_time: u64, num_validators: u64 };
pub const ChainSpec = struct { preset: params.Preset, name: []u8 };

pub const BeamSTFProverInput = struct {
    block: SignedBeamBlock,
    state: BeamState,
};

// some p2p containers
pub const BlockByRootRequest = struct { roots: []Root };

// TODO: a super hacky cloning utility for ssz container structs
// replace by a better mechanisms which could be upstreated into the ssz lib as well
pub fn sszClone(allocator: Allocator, comptime T: type, data: T) !T {
    var bytes = std.ArrayList(u8).init(allocator);
    defer bytes.deinit();

    try ssz.serialize(T, data, &bytes);
    var cloned: T = undefined;
    try ssz.deserialize(T, bytes.items[0..], &cloned, allocator);
    return cloned;
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "ssz seralize/deserialize signed beam block" {
    const signed_block = SignedBeamBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .execution_payload_header = ExecutionPayloadHeader{ .timestamp = 23 }, .atttestations = &[_]SignedVote{} },
        },
        .signature = [_]u8{2} ** 48,
    };

    // check SignedBeamBlock serialization/deserialization
    var serialized_signed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_signed_block.deinit();
    try ssz.serialize(SignedBeamBlock, signed_block, &serialized_signed_block);
    std.debug.print("\n\n\nserialized_signed_block ({d})=\n{any}", .{ serialized_signed_block.items.len, serialized_signed_block.items });

    var deserialized_signed_block: SignedBeamBlock = undefined;
    try ssz.deserialize(SignedBeamBlock, serialized_signed_block.items[0..], &deserialized_signed_block, std.testing.allocator);

    try std.testing.expect(signed_block.message.body.execution_payload_header.timestamp == deserialized_signed_block.message.body.execution_payload_header.timestamp);
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.state_root, &deserialized_signed_block.message.state_root));
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.parent_root, &deserialized_signed_block.message.parent_root));

    // successful merklization
    // var block_root: [32]u8 = undefined;
    // try ssz.hashTreeRoot(
    //     SignedBeamBlock,
    //     signed_block,
    //     &block_root,
    //     std.testing.allocator,
    // );
}

test "ssz seralize/deserialize signed beam state" {
    const config = BeamStateConfig{ .num_validators = 4 };
    const genesis_root = [_]u8{9} ** 32;
    var justifications_roots = [_]Root{genesis_root};
    var justifications_validators = [_]u8{ 0, 1, 1, 1 };

    const state = BeamState{
        .config = config,
        .genesis_time = 93,
        .slot = 99,
        .latest_block_header = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = [_]u8{1} ** 32,
            .state_root = [_]u8{2} ** 32,
            .body_root = [_]u8{3} ** 32,
        },
        // mini3sf
        .latest_justified = .{ .root = [_]u8{5} ** 32, .slot = 0 },
        .latest_finalized = .{ .root = [_]u8{4} ** 32, .slot = 0 },
        .historical_block_hashes = &[_]Root{},
        .justified_slots = &[_]u8{},
        .justifications_roots = &justifications_roots,
        // .justifications_roots = &[_]Root{genesis_root},
        // 3 validators voting for genesis root except first one
        .justifications_validators = &justifications_validators,
        // .justifications = .{
        //     .roots = &[_]Root{},
        //     .voting_validators = &[_]u8{},
        // },
    };

    var serialized_state = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_state.deinit();
    try ssz.serialize(BeamState, state, &serialized_state);
    std.debug.print("\n\n\nserialized_state ({d})=\n{any}", .{ serialized_state.items.len, serialized_state.items });

    // we need to use arena allocator because deserialization allocs without providing for
    // a way to deinit, this needs to be probably addressed in ssz
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var deserialized_state: BeamState = undefined;
    try ssz.deserialize(BeamState, serialized_state.items[0..], &deserialized_state, arena_allocator.allocator());
    try std.testing.expect(std.mem.eql(u8, state.justifications_validators[0..], deserialized_state.justifications_validators[0..]));

    // successful merklization
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        BeamState,
        state,
        &state_root,
        std.testing.allocator,
    );
}

test "ssz seralize/deserialize signed stf prover input" {
    const config = BeamStateConfig{ .num_validators = 4 };
    const genesis_root = [_]u8{9} ** 32;
    var justifications_roots = [_]Root{genesis_root};
    var justifications_validators = [_]u8{ 0, 1, 1, 1 };

    const state = BeamState{
        .config = config,
        .genesis_time = 93,
        .slot = 99,
        .latest_block_header = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = [_]u8{1} ** 32,
            .state_root = [_]u8{2} ** 32,
            .body_root = [_]u8{3} ** 32,
        },
        // mini3sf
        .latest_justified = .{ .root = [_]u8{5} ** 32, .slot = 0 },
        .latest_finalized = .{ .root = [_]u8{4} ** 32, .slot = 0 },
        .historical_block_hashes = &[_]Root{},
        .justified_slots = &[_]u8{},
        .justifications_roots = &justifications_roots,
        // .justifications_roots = &[_]Root{genesis_root},
        // 3 validators voting for genesis root except first one
        .justifications_validators = &justifications_validators,
        // .justifications = .{
        //     .roots = &[_]Root{},
        //     .voting_validators = &[_]u8{},
        // },
    };

    const block = SignedBeamBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .execution_payload_header = ExecutionPayloadHeader{ .timestamp = 23 }, .atttestations = &[_]SignedVote{} },
        },
        .signature = [_]u8{2} ** 48,
    };

    const prover_input = BeamSTFProverInput{
        .state = state,
        .block = block,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var serialized = std.ArrayList(u8).init(arena_allocator.allocator());
    defer serialized.deinit();
    try ssz.serialize(BeamSTFProverInput, prover_input, &serialized);
    std.debug.print("\n\n\nprove transition ----------- serialized({d})=\n{any}\n", .{ serialized.items.len, serialized.items });

    var prover_input_deserialized: BeamSTFProverInput = undefined;
    try ssz.deserialize(BeamSTFProverInput, serialized.items[0..], &prover_input_deserialized, arena_allocator.allocator());
    std.debug.print("should deserialize to={any}", .{prover_input_deserialized});
}
