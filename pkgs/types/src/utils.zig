const std = @import("std");
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const params = @import("@zeam/params");

const block = @import("./block.zig");
const types = @import("./lib.zig");

// just dummy type right now to test imports
pub const Bytes32 = [32]u8;
pub const Slot = u64;
pub const Interval = u64;
pub const ValidatorIndex = u64;
pub const Bytes48 = [48]u8;

pub const SIGSIZE = 4000;
pub const Bytes4000 = [SIGSIZE]u8;

pub const Root = Bytes32;
// zig treats string as byte sequence so hex is 64 bytes string
pub const RootHex = [64]u8;

pub const ZERO_HASH = [_]u8{0x00} ** 32;
pub const ZERO_HASH_4000 = [_]u8{0} ** SIGSIZE;

pub const StateTransitionError = error{ InvalidParentRoot, InvalidPreState, InvalidPostState, InvalidExecutionPayloadHeaderTimestamp, InvalidJustifiableSlot, InvalidValidatorId, InvalidBlockSignatures, InvalidLatestBlockHeader, InvalidProposer, InvalidJustificationIndex, InvalidSlotIndex };

pub const HistoricalBlockHashes = ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT);
pub const JustifiedSlots = ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT);
pub const JustificationsRoots = ssz.utils.List(Root, params.HISTORICAL_ROOTS_LIMIT);
pub const JustificationsValidators = ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT);

// basic payload header for some sort of APS
pub const ExecutionPayloadHeader = struct {
    timestamp: u64,
};

pub const GenesisSpec = struct { genesis_time: u64, num_validators: u64 };
pub const ChainSpec = struct {
    preset: params.Preset,
    name: []u8,

    pub fn deinit(self: *ChainSpec, allocator: Allocator) void {
        allocator.free(self.name);
    }
};

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
