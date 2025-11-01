const std = @import("std");
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const params = @import("@zeam/params");
const utils = @import("@zeam/utils");

const block = @import("./block.zig");
const types = @import("./lib.zig");
pub const jsonToString = utils.jsonToString;

// just dummy type right now to test imports
pub const Bytes32 = [32]u8;
pub const Slot = u64;
pub const Interval = u64;
pub const ValidatorIndex = u64;
pub const Bytes48 = [48]u8;
pub const Bytes52 = [52]u8;

pub const SIGSIZE = 4000;
pub const Bytes4000 = [SIGSIZE]u8;

pub const Root = Bytes32;
// zig treats string as byte sequence so hex is 64 bytes string
pub const RootHex = [64]u8;

pub const ZERO_HASH = [_]u8{0x00} ** 32;
pub const ZERO_HASH_4000 = [_]u8{0} ** SIGSIZE;

pub const StateTransitionError = error{ InvalidParentRoot, InvalidPreState, InvalidPostState, InvalidExecutionPayloadHeaderTimestamp, InvalidJustifiableSlot, InvalidValidatorId, InvalidBlockSignatures, InvalidLatestBlockHeader, InvalidProposer, InvalidJustificationIndex, InvalidSlotIndex };

const json = std.json;

// prepare the state to be pre state of the slot
pub fn IsJustifiableSlot(finalized: types.Slot, candidate: types.Slot) !bool {
    if (candidate < finalized) {
        return StateTransitionError.InvalidJustifiableSlot;
    }

    const delta: f32 = @floatFromInt(candidate - finalized);
    if (delta <= 5) {
        return true;
    }
    const delta_x2: f32 = @mod(std.math.pow(f32, delta, 0.5), 1);
    if (delta_x2 == 0) {
        return true;
    }
    const delta_x2_x: f32 = @mod(std.math.pow(f32, delta + 0.25, 0.5), 1);
    if (delta_x2_x == 0.5) {
        return true;
    }

    return false;
}

// Helper function to convert bytes to hex string
pub fn BytesToHex(allocator: Allocator, bytes: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(bytes)});
}

pub const GenesisSpec = struct { genesis_time: u64, num_validators: u64 };
pub const ChainSpec = struct {
    preset: params.Preset,
    name: []u8,

    pub fn deinit(self: *ChainSpec, allocator: Allocator) void {
        allocator.free(self.name);
    }

    pub fn toJson(self: *const ChainSpec, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("preset", json.Value{ .string = @tagName(self.preset) });
        try obj.put("name", json.Value{ .string = self.name });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ChainSpec, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return jsonToString(allocator, json_value);
    }
};

// TODO: a super hacky cloning utility for ssz container structs
// replace by a better mechanisms which could be upstreated into the ssz lib as well
// pass a pointer where you want to clone the data
pub fn sszClone(allocator: Allocator, comptime T: type, data: T, cloned: *T) !void {
    var bytes = std.ArrayList(u8).init(allocator);
    defer bytes.deinit();

    try ssz.serialize(T, data, &bytes);
    try ssz.deserialize(T, bytes.items[0..], cloned, allocator);
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}
