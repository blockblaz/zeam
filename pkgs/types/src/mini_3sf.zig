const std = @import("std");

const ssz = @import("ssz");
const params = @import("@zeam/params");

const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;

const bytesToHex = utils.BytesToHex;
const json = std.json;
const Bytes32 = utils.Bytes32;
const Slot = utils.Slot;

pub const Mini3SFCheckpoint = struct {
    root: utils.Root,
    slot: utils.Slot,

    pub fn toJson(self: *const Mini3SFCheckpoint, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("root", json.Value{ .string = try bytesToHex(allocator, &self.root) });
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Mini3SFCheckpoint, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const Mini3SFVote = struct {
    slot: utils.Slot,
    head: Mini3SFCheckpoint,
    target: Mini3SFCheckpoint,
    source: Mini3SFCheckpoint,

    pub fn toJson(self: *const Mini3SFVote, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("head", try self.head.toJson(allocator));
        try obj.put("target", try self.target.toJson(allocator));
        try obj.put("source", try self.source.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Mini3SFVote, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

// this will be updated to correct impl in the followup PR to reflect latest spec changes
pub const SignedVote = struct {
    validator_id: utils.ValidatorIndex,
    message: Mini3SFVote,
    // TODO signature objects to be updated in a followup PR
    signature: utils.Bytes4000,

    pub fn toJson(self: *const SignedVote, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("validator_id", json.Value{ .integer = @as(i64, @intCast(self.validator_id)) });
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", json.Value{ .string = try bytesToHex(allocator, &self.signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedVote, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const Status = struct {
    finalized_root: Bytes32,
    finalized_slot: Slot,
    head_root: Bytes32,
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
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const Mini3SFVotes = ssz.utils.List(Mini3SFVote, params.VALIDATOR_REGISTRY_LIMIT);
pub const SignedVotes = ssz.utils.List(SignedVote, params.VALIDATOR_REGISTRY_LIMIT);
