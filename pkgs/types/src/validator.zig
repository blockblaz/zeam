const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");

const attestation = @import("./attestation.zig");
const utils = @import("./utils.zig");

const Attestation = attestation.Attestation;
const AttestationData = attestation.AttestationData;
const Allocator = std.mem.Allocator;
const Bytes52 = utils.Bytes52;
const ValidatorIndex = utils.ValidatorIndex;

const bytesToHex = utils.BytesToHex;
const json = std.json;

// Types
pub const Validators = ssz.utils.List(Validator, params.VALIDATOR_REGISTRY_LIMIT);

pub const Validator = struct {
    pubkey: Bytes52,
    index: ValidatorIndex,

    const Self = @This();

    pub fn toJson(self: *const Self, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("pubkey", json.Value{ .string = try bytesToHex(allocator, &self.pubkey) });
        try obj.put("index", json.Value{ .integer = @as(i64, @intCast(self.index)) });
        return json.Value{ .object = obj };
    }

    pub fn getPubkey(self: *const Self) []const u8 {
        return &self.pubkey;
    }

    pub fn produceAttestation(self: *const Self, data: AttestationData) Attestation {
        return Attestation{
            .data = data,
            .validator_id = self.index,
        };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        allocator.free(val.object.get("pubkey").?.string);
        val.object.deinit();
    }
};
