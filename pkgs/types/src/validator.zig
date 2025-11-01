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

    pub fn toJsonString(self: *const Validator, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};
