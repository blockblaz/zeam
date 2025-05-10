const std = @import("std");

const ssz = @import("ssz");
const params = @import("@zeam/params");

// just dummy type right now to test imports
pub const Bytes32 = [32]u8;
pub const Slot = u64;
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

// empty block body
pub const BeamBlockBody = struct {
    // something to avoid having empty body
    slot: Slot,
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

pub const BeamState = struct {
    genesis_time: u64,
    slot: u64,
    latest_block_header: BeamBlockHeader,
};

// non ssz types, difference is the variable list doesn't need upper boundaries
pub const ZkVm = enum {
    ceno,
    powdr,
    sp1,
};

pub const BeamSTFProof = struct {
    // zk_vm: ZkVm,
    // proof: []u8,
};

pub const GenesisSpec = struct { genesis_time: u64 };
pub const ChainSpec = struct { preset: params.Preset, name: []u8 };

pub const BeamSTFProverInput = struct {
    state: BeamState,
    block: SignedBeamBlock,
};

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
            .slot = 0,
            .proposer_index = 0,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{
                .slot = 9,
            },
        },
        .signature = [_]u8{3} ** 48,
    };

    // 1. check BeamBlock serialization/deserialization
    var serialized_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_block.deinit();
    try ssz.serialize(BeamBlock, signed_block.message, &serialized_block);

    var deserialized_block: BeamBlock = undefined;
    std.debug.print("serialized_block({d})={any}\n", .{ serialized_block.items.len, serialized_block.items });
    try ssz.deserialize(BeamBlock, serialized_block.items[0..], &deserialized_block, std.testing.allocator);
    std.debug.print("deserialized_block={any}\n", .{deserialized_block});

    // 2. check SignedBeamBlock serialization/deserialization
    var serialized_signed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_signed_block.deinit();
    try ssz.serialize(SignedBeamBlock, signed_block, &serialized_signed_block);
    std.debug.print("serialized_signed_block({d})={any}\n", .{ serialized_signed_block.items.len, serialized_signed_block.items });

    var deserialized_signed_block: SignedBeamBlock = undefined;
    try ssz.deserialize(SignedBeamBlock, serialized_signed_block.items[0..], &deserialized_signed_block, std.testing.allocator);
    std.debug.print("deserialized_signed_block={any}\n", .{deserialized_signed_block});
}
