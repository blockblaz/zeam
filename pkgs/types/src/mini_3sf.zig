const std = @import("std");
const params = @import("@zeam/params");

const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const Bytes32 = utils.Bytes32;
const Root = utils.Root;
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;

const bytesToHex = utils.BytesToHex;
const json = std.json;

pub const Checkpoint = struct {
    root: Root,
    slot: Slot,

    pub fn toJson(self: *const Checkpoint, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("root", json.Value{ .string = try bytesToHex(allocator, &self.root) });
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Checkpoint, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        allocator.free(val.object.get("root").?.string);
        val.object.deinit();
    }
};

pub const Status = struct {
    finalized_root: Root,
    finalized_slot: Slot,
    head_root: Root,
    head_slot: Slot,

    pub fn toJson(self: *const Status, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("finalized_root", json.Value{ .string = try bytesToHex(allocator, &self.finalized_root) });
        try obj.put("finalized_slot", json.Value{ .integer = @as(i64, @intCast(self.finalized_slot)) });
        try obj.put("head_root", json.Value{ .string = try bytesToHex(allocator, &self.head_root) });
        try obj.put("head_slot", json.Value{ .integer = @as(i64, @intCast(self.head_slot)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Status, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        allocator.free(val.object.get("finalized_root").?.string);
        allocator.free(val.object.get("head_root").?.string);
        val.object.deinit();
    }
};
