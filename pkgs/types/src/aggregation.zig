const std = @import("std");
const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");

const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const json = std.json;

const attestation = @import("./attestation.zig");

const AggregationBits = attestation.AggregationBits;
const ByteListMiB = xmss.ByteListMiB;

const freeJsonValue = utils.freeJsonValue;

/// Protocol-level inverse proof size parameter for aggregation (range 1-4).
pub const INVERSE_PROOF_SIZE: usize = 2;

// Types
pub const AggregatedSignatureProof = struct {
    participants: attestation.AggregationBits,
    proof_data: ByteListMiB,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();

        var proof_data = try ByteListMiB.init(allocator);
        errdefer proof_data.deinit();

        return Self{
            .participants = participants,
            .proof_data = proof_data,
        };
    }

    pub fn deinit(self: *Self) void {
        self.participants.deinit();
        self.proof_data.deinit();
    }

    pub fn toJson(self: *const Self, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);

        // Serialize participants as array of booleans
        var participants_array = json.Array.init(allocator);
        errdefer participants_array.deinit();
        for (0..self.participants.len()) |i| {
            try participants_array.append(json.Value{ .bool = try self.participants.get(i) });
        }
        try obj.put("participants", json.Value{ .array = participants_array });

        // Serialize proof_data as hex string
        const proof_bytes = self.proof_data.constSlice();
        const proof_hex = try utils.BytesToHex(allocator, proof_bytes);
        try obj.put("proof_data", json.Value{ .string = proof_hex });

        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    /// Recursively aggregate child proofs and raw XMSS signatures into a single proof.
    ///
    /// - `xmss_participants`: bitfield for validators represented by raw_xmss. null if no raw sigs.
    /// - `children`: already-aggregated child proofs to include.
    /// - `children_pub_keys`: per-child arrays of public key handles (parallel with `children`).
    /// - `raw_xmss_pks`/`raw_xmss_sigs`: raw XMSS public key + signature pairs.
    /// - Validation: at least 1 raw sig or child required; if no raw sigs, need ≥2 children.
    pub fn aggregate(
        allocator: Allocator,
        xmss_participants: ?AggregationBits,
        children: []const AggregatedSignatureProof,
        children_pub_keys: []const []*const xmss.HashSigPublicKey,
        raw_xmss_pks: []*const xmss.HashSigPublicKey,
        raw_xmss_sigs: []*const xmss.HashSigSignature,
        message_hash: *const [32]u8,
        epoch: u64,
        result: *Self,
    ) !void {
        const has_raw = xmss_participants != null;
        const has_children = children.len > 0;

        if (!has_raw and !has_children) return error.AggregationInvalidInput;
        if (!has_raw and children.len < 2) return error.AggregationInvalidInput;

        // Merge participant bitfields
        var merged = try attestation.AggregationBits.init(allocator);
        errdefer merged.deinit();

        // Add gossip participants
        if (xmss_participants) |gp| {
            for (0..gp.len()) |i| {
                if (gp.get(i) catch false) {
                    try attestation.aggregationBitsSet(&merged, i, true);
                }
            }
        }

        // Add all children participants
        for (children) |child| {
            for (0..child.participants.len()) |i| {
                if (child.participants.get(i) catch false) {
                    try attestation.aggregationBitsSet(&merged, i, true);
                }
            }
        }

        // Build per-child proof references for FFI
        const children_proof_refs = try allocator.alloc(*const ByteListMiB, children.len);
        defer allocator.free(children_proof_refs);
        for (children, 0..) |*child, i| {
            children_proof_refs[i] = &child.proof_data;
        }

        // FFI call — passes children proofs + their public keys for true recursive aggregation
        try xmss.aggregateSignatures(
            raw_xmss_pks,
            raw_xmss_sigs,
            children_pub_keys,
            children_proof_refs,
            message_hash,
            @intCast(epoch),
            INVERSE_PROOF_SIZE,
            &result.proof_data,
        );

        // Clean up old result data before overwriting
        result.participants.deinit();

        result.participants = merged;
    }

    /// Verify this aggregated signature proof.
    pub fn verify(self: *const Self, public_keys: []*const xmss.HashSigPublicKey, message_hash: *const [32]u8, epoch: u64) !void {
        try xmss.verifyAggregatedPayload(public_keys, message_hash, @intCast(epoch), &self.proof_data);
    }
};
