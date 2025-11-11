const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");

const mini_3sf = @import("./mini_3sf.zig");
const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const Bytes4000 = utils.Bytes4000;
const Checkpoint = mini_3sf.Checkpoint;
const Root = utils.Root;
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;

const bytesToHex = utils.BytesToHex;
const json = std.json;

// Types
pub const AggregationBits = ssz.utils.Bitlist(params.VALIDATOR_REGISTRY_LIMIT);
pub const AggregatedSignatures = ssz.utils.List(Bytes4000, params.VALIDATOR_REGISTRY_LIMIT);

pub const AttestationData = struct {
    slot: Slot,
    head: Checkpoint,
    target: Checkpoint,
    source: Checkpoint,

    pub fn toJson(self: *const AttestationData, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("head", try self.head.toJson(allocator));
        try obj.put("target", try self.target.toJson(allocator));
        try obj.put("source", try self.source.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const AttestationData, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const Attestation = struct {
    validator_id: ValidatorIndex,
    data: AttestationData,

    pub fn toJson(self: *const Attestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("validator_id", json.Value{ .integer = @as(i64, @intCast(self.validator_id)) });
        try obj.put("data", try self.data.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Attestation, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const SignedAttestation = struct {
    message: Attestation,
    signature: Bytes4000,

    pub fn toJson(self: *const SignedAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", json.Value{ .string = try bytesToHex(allocator, &self.signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedAttestation, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const AggregatedAttestation = struct {
    attestation_bits: AggregationBits,
    data: AttestationData,

    pub fn toJson(self: *const AggregatedAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);

        // Serialize attestation_bits as array of booleans
        var bits_array = json.Array.init(allocator);
        for (0..self.attestation_bits.len()) |i| {
            try bits_array.append(json.Value{ .bool = try self.attestation_bits.get(i) });
        }
        try obj.put("attestation_bits", json.Value{ .array = bits_array });
        try obj.put("data", try self.data.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const AggregatedAttestation, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const SignedAggregatedAttestation = struct {
    message: AggregatedAttestation,
    signature: AggregatedSignatures,

    pub fn toJson(self: *const SignedAggregatedAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("message", try self.message.toJson(allocator));

        // Serialize signature list as array of hex strings
        var sig_array = json.Array.init(allocator);
        errdefer sig_array.deinit();

        for (self.signature.constSlice()) |sig| {
            try sig_array.append(json.Value{ .string = try bytesToHex(allocator, &sig) });
        }
        try obj.put("signature", json.Value{ .array = sig_array });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedAggregatedAttestation, allocator: Allocator) ![]const u8 {
        const json_value = try self.toJson(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};
