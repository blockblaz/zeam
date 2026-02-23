const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

const mini_3sf = @import("./mini_3sf.zig");
const utils = @import("./utils.zig");
const signature_mod = @import("./signature.zig");

const Allocator = std.mem.Allocator;
const SIGBYTES = utils.SIGBYTES;
const Checkpoint = mini_3sf.Checkpoint;
const Root = utils.Root;
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;
const ZERO_HASH = utils.ZERO_HASH;
const ZERO_SIGBYTES = utils.ZERO_SIGBYTES;
const XmssSignature = signature_mod.Signature;

const bytesToHex = utils.BytesToHex;
const json = std.json;

const freeJsonValue = utils.freeJsonValue;

/// Container type for SignedAttestation with proper XmssSignature (used for HTR computation).
/// Defined at module level to avoid duplicate definitions in sszRoot methods.
const SignedAttestationContainer = struct {
    validator_id: ValidatorIndex,
    message: AttestationData,
    signature: XmssSignature,
};

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

    pub fn format(self: Attestation, writer: anytype) !void {
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

    pub fn format(self: SignedAttestation, writer: anytype) !void {
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

    /// Compute the SSZ hash_tree_root of this SignedAttestation.
    /// This method deserializes the signature bytes to XmssSignature Container
    /// to compute the correct hash_tree_root (as Container, not FixedBytes).
    ///
    /// The hash_tree_root is computed as:
    ///   merkle_root([HTR(validator_id), HTR(message), HTR(signature_as_container)])
    ///
    /// This matches leanSpec's SignedAttestation container structure.
    pub fn sszRoot(self: *const SignedAttestation, allocator: Allocator) !Root {
        // Deserialize signature bytes to XmssSignature Container
        var xmss_sig = try XmssSignature.fromSszBytes(&self.signature, allocator);
        defer xmss_sig.deinit();

        const container = SignedAttestationContainer{
            .validator_id = self.validator_id,
            .message = self.message,
            .signature = xmss_sig,
        };

        var root: Root = undefined;
        try zeam_utils.hashTreeRoot(SignedAttestationContainer, container, &root, allocator);
        return root;
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

test "SignedAttestation sszRoot with real signature" {
    const xmss = @import("@zeam/xmss");
    const allocator = std.testing.allocator;

    // Generate a keypair and sign a message
    var keypair = try xmss.KeyPair.generate(allocator, "test_signed_attestation", 0, 10);
    defer keypair.deinit();

    const attestation_data = AttestationData{
        .slot = 1,
        .head = .{ .root = ZERO_HASH, .slot = 1 },
        .target = .{ .root = ZERO_HASH, .slot = 1 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };

    // Compute attestation data root for signing
    const data_root = try attestation_data.sszRoot(allocator);

    // Sign the attestation
    var opaque_sig = try keypair.sign(&data_root, 0);
    defer opaque_sig.deinit();

    // Get signature bytes (zero-initialize to ensure trailing bytes are defined)
    var sig_bytes: SIGBYTES = std.mem.zeroes(SIGBYTES);
    const sig_len = try opaque_sig.toBytes(&sig_bytes);
    try std.testing.expectEqual(sig_bytes.len, sig_len); // Ensure signature fills entire buffer

    // Create SignedAttestation
    const signed_attestation = SignedAttestation{
        .validator_id = 0,
        .message = attestation_data,
        .signature = sig_bytes,
    };

    // Compute sszRoot - this should use XmssSignature Container internally
    const root = try signed_attestation.sszRoot(allocator);

    // Verify root is non-zero (sanity check)
    var is_zero = true;
    for (root) |byte| {
        if (byte != 0) {
            is_zero = false;
            break;
        }
    }
    try std.testing.expect(!is_zero);

    // The root should be different from a naive hash_tree_root that treats signature as FixedBytes
    var naive_root: Root = undefined;
    try zeam_utils.hashTreeRoot(SignedAttestation, signed_attestation, &naive_root, allocator);

    // These should be different because Container HTR != FixedBytes HTR for signature
    try std.testing.expect(!std.mem.eql(u8, &root, &naive_root));
}
