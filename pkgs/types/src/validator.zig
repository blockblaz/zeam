const std = @import("std");
const ssz = @import("ssz");
const params = @import("@zeam/params");
const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const Bytes52 = utils.Bytes52;

const bytesToHex = utils.BytesToHex;
const json = std.json;

// Types
pub const Validators = ssz.utils.List(Validator, params.VALIDATOR_REGISTRY_LIMIT);

pub const Validator = struct {
    pubkey: Bytes52,

    pub fn toJson(self: *const Validator, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("pubkey", json.Value{ .string = try bytesToHex(allocator, &self.pubkey) });
        return json.Value{ .object = obj };
    }

    pub fn getPubkey(self: *const Validator) []const u8 {
        return &self.pubkey;
    }

    pub fn toJsonString(self: *const Validator, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        allocator.free(val.object.get("pubkey").?.string);
        val.object.deinit();
    }
};
