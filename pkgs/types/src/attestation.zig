const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");

const mini_3sf = @import("./mini_3sf.zig");
const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const SIGBYTES = utils.SIGBYTES;
const Checkpoint = mini_3sf.Checkpoint;
const Root = utils.Root;
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;
const ZERO_HASH = utils.ZERO_HASH;
const ZERO_SIGBYTES = utils.ZERO_SIGBYTES;

const bytesToHex = utils.BytesToHex;
const json = std.json;

fn freeJsonValue(val: *json.Value, allocator: Allocator) void {
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

// Types
pub const AggregationBits = ssz.utils.Bitlist(params.VALIDATOR_REGISTRY_LIMIT);
pub const AggregatedSignatures = ssz.utils.List(SIGBYTES, params.VALIDATOR_REGISTRY_LIMIT);

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
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
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
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const SignedAttestation = struct {
    message: Attestation,
    signature: SIGBYTES,

    pub fn toJson(self: *const SignedAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", json.Value{ .string = try bytesToHex(allocator, &self.signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedAttestation, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
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
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
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
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

test "encode decode signed attestation roundtrip" {
    const signed_attestation = SignedAttestation{
        .message = .{
            .validator_id = 0,
            .data = .{
                .slot = 0,
                .head = .{
                    .root = ZERO_HASH,
                    .slot = 0,
                },
                .target = .{
                    .root = ZERO_HASH,
                    .slot = 0,
                },
                .source = .{
                    .root = ZERO_HASH,
                    .slot = 0,
                },
            },
        },
        .signature = ZERO_SIGBYTES,
    };

    // Encode
    var encoded = std.ArrayList(u8).init(std.testing.allocator);
    defer encoded.deinit();
    try ssz.serialize(SignedAttestation, signed_attestation, &encoded);

    // Convert to hex and compare with expected value
    // Expected value is "0" * 6504 (6504 hex characters = 3252 bytes)
    const expected_hex_len = 6504;
    const expected_value = try std.testing.allocator.alloc(u8, expected_hex_len);
    defer std.testing.allocator.free(expected_value);
    @memset(expected_value, '0');

    const encoded_hex = try std.fmt.allocPrint(std.testing.allocator, "{s}", .{std.fmt.fmtSliceHexLower(encoded.items)});
    defer std.testing.allocator.free(encoded_hex);
    try std.testing.expectEqualStrings(expected_value, encoded_hex);

    // Decode
    var decoded: SignedAttestation = undefined;
    try ssz.deserialize(SignedAttestation, encoded.items[0..], &decoded, std.testing.allocator);

    // Verify roundtrip
    try std.testing.expect(decoded.message.validator_id == signed_attestation.message.validator_id);
    try std.testing.expect(decoded.message.data.slot == signed_attestation.message.data.slot);
    try std.testing.expect(decoded.message.data.head.slot == signed_attestation.message.data.head.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.data.head.root, &signed_attestation.message.data.head.root));
    try std.testing.expect(decoded.message.data.target.slot == signed_attestation.message.data.target.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.data.target.root, &signed_attestation.message.data.target.root));
    try std.testing.expect(decoded.message.data.source.slot == signed_attestation.message.data.source.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.data.source.root, &signed_attestation.message.data.source.root));
    try std.testing.expect(std.mem.eql(u8, &decoded.signature, &signed_attestation.signature));
}
