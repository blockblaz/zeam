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

pub const SIGSIZE = 3112;
pub const SIGBYTES = [SIGSIZE]u8;

pub const Root = Bytes32;
// zig treats string as byte sequence so hex is 64 bytes string
pub const RootHex = [64]u8;

pub const ZERO_HASH = [_]u8{0x00} ** 32;
pub const ZERO_SIGBYTES = [_]u8{0} ** SIGSIZE;

pub const StateTransitionError = error{ InvalidParentRoot, InvalidPreState, InvalidPostState, InvalidExecutionPayloadHeaderTimestamp, InvalidJustifiableSlot, InvalidValidatorId, InvalidBlockSignatures, InvalidLatestBlockHeader, InvalidProposer, InvalidJustificationIndex, InvalidJustificationCapacity, InvalidJustificationTargetSlot, InvalidJustificationRoot, InvalidSlotIndex, DuplicateAttestationData };

const json = std.json;

pub fn freeJsonValue(val: *json.Value, allocator: Allocator) void {
    switch (val.*) {
        .object => |*o| {
            var it = o.iterator();
            while (it.next()) |entry| {
                freeJsonValue(&entry.value_ptr.*, allocator);
            }
            o.deinit();
        },
        .array => |*a| {
            for (a.items) |*item| {
                freeJsonValue(item, allocator);
            }
            a.deinit();
        },
        .string => |s| allocator.free(s),
        else => {},
    }
}

// prepare the state to be pre state of the slot
pub fn IsJustifiableSlot(finalized: types.Slot, candidate: types.Slot) !bool {
    if (candidate < finalized) {
        return StateTransitionError.InvalidJustifiableSlot;
    }

    const delta: u64 = @intCast(candidate - finalized);
    if (delta <= 5) {
        return true;
    }

    // Rule 2: perfect square delta.
    const delta_u128: u128 = @intCast(delta);
    const delta_root = sqrtFloorU128(delta_u128);
    if (delta_root * delta_root == delta_u128) {
        return true;
    }

    // Rule 3: pronic delta: n(n+1) => 4*delta+1 is an odd perfect square.
    const pronic_disc: u128 = 4 * delta_u128 + 1;
    const pronic_root = sqrtFloorU128(pronic_disc);
    if (pronic_root * pronic_root == pronic_disc and (pronic_root & 1) == 1) {
        return true;
    }

    return false;
}

fn sqrtFloorU128(n: u128) u128 {
    var lo: u128 = 0;
    var hi: u128 = if (n < @as(u128, std.math.maxInt(u64))) n else @as(u128, std.math.maxInt(u64));
    var ans: u128 = 0;

    while (lo <= hi) {
        const mid = (lo + hi) / 2;
        const sq = mid * mid;
        if (sq == n) {
            return mid;
        }
        if (sq < n) {
            ans = mid;
            lo = mid + 1;
        } else {
            if (mid == 0) break;
            hi = mid - 1;
        }
    }

    return ans;
}

pub fn getJustifiedSlotsIndex(finalized_slot: types.Slot, slot: types.Slot) ?usize {
    if (slot <= finalized_slot) {
        return null;
    }
    const base: types.Slot = finalized_slot + 1;
    return @intCast(slot - base);
}

pub fn isSlotJustified(finalized_slot: types.Slot, justified_slots: *const types.JustifiedSlots, slot: types.Slot) !bool {
    const idx_opt = getJustifiedSlotsIndex(finalized_slot, slot);
    if (idx_opt == null) {
        return true;
    }
    const idx = idx_opt.?;
    if (idx >= justified_slots.len()) {
        return StateTransitionError.InvalidJustificationIndex;
    }
    return try justified_slots.get(idx);
}

pub fn setSlotJustified(finalized_slot: types.Slot, justified_slots: *types.JustifiedSlots, slot: types.Slot, value: bool) !void {
    const idx_opt = getJustifiedSlotsIndex(finalized_slot, slot);
    if (idx_opt == null) {
        return;
    }
    const idx = idx_opt.?;
    if (idx >= justified_slots.len()) {
        return StateTransitionError.InvalidJustificationIndex;
    }
    try justified_slots.set(idx, value);
}

// Helper function to convert bytes to hex string
pub fn BytesToHex(allocator: Allocator, bytes: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(bytes)});
}

pub const GenesisSpec = struct {
    genesis_time: u64,
    validator_pubkeys: []const Bytes52,

    pub fn deinit(self: *GenesisSpec, allocator: Allocator) void {
        allocator.free(self.validator_pubkeys);
    }

    pub fn numValidators(self: *const GenesisSpec) u64 {
        return @intCast(self.validator_pubkeys.len);
    }
};
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
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit();
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

test "isSlotJustified treats finalized boundary as implicit" {
    var justified_slots = try types.JustifiedSlots.init(std.testing.allocator);
    defer justified_slots.deinit();

    try justified_slots.append(false);

    try std.testing.expect(try isSlotJustified(0, &justified_slots, 0));
    try std.testing.expectEqual(false, try isSlotJustified(0, &justified_slots, 1));
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}
