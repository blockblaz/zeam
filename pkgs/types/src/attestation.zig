const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

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

const freeJsonValue = utils.freeJsonValue;

// Types
pub const AggregationBits = ssz.utils.Bitlist(params.VALIDATOR_REGISTRY_LIMIT);

pub const AttestationData = struct {
    slot: Slot,
    head: Checkpoint,
    target: Checkpoint,
    source: Checkpoint,

    pub fn sszRoot(self: *const AttestationData, allocator: Allocator) !Root {
        var root: Root = undefined;
        try zeam_utils.hashTreeRoot(AttestationData, self.*, &root, allocator);
        return root;
    }

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

    pub fn format(self: Attestation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("Attestation{{ validator={d}, slot={d}, source_slot={d}, target_slot={d} }}", .{
            self.validator_id,
            self.data.slot,
            self.data.source.slot,
            self.data.target.slot,
        });
    }

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
    validator_id: ValidatorIndex,
    message: AttestationData,
    signature: SIGBYTES,

    pub fn format(self: SignedAttestation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("SignedAttestation{{ validator={d}, slot={d}, source_slot={d}, target_slot={d} }}", .{
            self.validator_id,
            self.message.slot,
            self.message.source.slot,
            self.message.target.slot,
        });
    }

    pub fn toJson(self: *const SignedAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("validator_id", json.Value{ .integer = @as(i64, @intCast(self.validator_id)) });
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", json.Value{ .string = try bytesToHex(allocator, &self.signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedAttestation, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn toAttestation(self: *const SignedAttestation) Attestation {
        return .{ .validator_id = self.validator_id, .data = self.message };
    }
};

pub const AggregatedAttestation = struct {
    aggregation_bits: AggregationBits,
    data: AttestationData,

    pub fn deinit(self: *AggregatedAttestation) void {
        self.aggregation_bits.deinit();
    }

    pub fn toJson(self: *const AggregatedAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);

        var bits_array = json.Array.init(allocator);
        for (0..self.aggregation_bits.len()) |i| {
            try bits_array.append(json.Value{ .bool = try self.aggregation_bits.get(i) });
        }
        try obj.put("aggregation_bits", json.Value{ .array = bits_array });
        try obj.put("data", try self.data.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const AggregatedAttestation, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub fn aggregationBitsEnsureLength(bits: *AggregationBits, target_len: usize) !void {
    while (bits.len() < target_len) {
        try bits.append(false);
    }
}

pub fn aggregationBitsSet(bits: *AggregationBits, index: usize, value: bool) !void {
    try aggregationBitsEnsureLength(bits, index + 1);
    try bits.set(index, value);
}

pub fn aggregationBitsToValidatorIndices(bits: *const AggregationBits, allocator: Allocator) !std.ArrayList(usize) {
    var indices: std.ArrayList(usize) = .empty;
    errdefer indices.deinit(allocator);

    for (0..bits.len()) |validator_index| {
        if (try bits.get(validator_index)) {
            try indices.append(allocator, validator_index);
        }
    }

    return indices;
}

test "encode decode signed attestation roundtrip" {
    const signed_attestation = SignedAttestation{
        .validator_id = 0,
        .message = .{
            .slot = 0,
            .head = .{ .root = ZERO_HASH, .slot = 0 },
            .target = .{ .root = ZERO_HASH, .slot = 0 },
            .source = .{ .root = ZERO_HASH, .slot = 0 },
        },
        .signature = ZERO_SIGBYTES,
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ssz.serialize(SignedAttestation, signed_attestation, &encoded, std.testing.allocator);
    try std.testing.expect(encoded.items.len > 0);

    // Convert to hex and compare with expected value.
    // Expected value is "0" * 6496 (6496 hex characters = 3248 bytes).
    const expected_hex_len = 6496;
    const expected_value = try std.testing.allocator.alloc(u8, expected_hex_len);
    defer std.testing.allocator.free(expected_value);
    @memset(expected_value, '0');

    const encoded_hex = try std.fmt.allocPrint(std.testing.allocator, "{x}", .{encoded.items});
    defer std.testing.allocator.free(encoded_hex);
    try std.testing.expectEqualStrings(expected_value, encoded_hex);

    var decoded: SignedAttestation = undefined;
    try ssz.deserialize(SignedAttestation, encoded.items[0..], &decoded, std.testing.allocator);

    try std.testing.expect(decoded.validator_id == signed_attestation.validator_id);
    try std.testing.expect(decoded.message.slot == signed_attestation.message.slot);
    try std.testing.expect(decoded.message.head.slot == signed_attestation.message.head.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.head.root, &signed_attestation.message.head.root));
    try std.testing.expect(decoded.message.target.slot == signed_attestation.message.target.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.target.root, &signed_attestation.message.target.root));
    try std.testing.expect(decoded.message.source.slot == signed_attestation.message.source.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.source.root, &signed_attestation.message.source.root));
    try std.testing.expect(std.mem.eql(u8, &decoded.signature, &signed_attestation.signature));
}
