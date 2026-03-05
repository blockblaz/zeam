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
pub const INV_PROOF_SIZE: usize = 2;

// Types
pub const AggregatedSignatureProof = struct {
    participants: attestation.AggregationBits,
    proof_data: ByteListMiB,
    bytecode_point: ByteListMiB, // empty = non-recursive, non-empty = recursive

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();

        var proof_data = try ByteListMiB.init(allocator);
        errdefer proof_data.deinit();

        var bytecode_point = try ByteListMiB.init(allocator);
        errdefer bytecode_point.deinit();

        return Self{
            .participants = participants,
            .proof_data = proof_data,
            .bytecode_point = bytecode_point,
        };
    }

    pub fn deinit(self: *Self) void {
        self.participants.deinit();
        self.proof_data.deinit();
        self.bytecode_point.deinit();
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

        // Serialize bytecode_point as hex string
        const bp_bytes = self.bytecode_point.constSlice();
        const bp_hex = try utils.BytesToHex(allocator, bp_bytes);
        try obj.put("bytecode_point", json.Value{ .string = bp_hex });

        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    /// Recursively aggregate child proofs and raw XMSS signatures into a single proof.
    ///
    /// - `gossip_participants`: bitfield for validators represented by raw_xmss. null if no raw sigs.
    /// - `children`: already-aggregated child proofs to include.
    /// - `raw_xmss_pks`/`raw_xmss_sigs`: raw XMSS public key + signature pairs.
    /// - Validation: at least 1 raw sig or child required; if no raw sigs, need ≥2 children.
    ///
    /// Currently uses dummy mode (merges bitfields + placeholder proof bytes).
    pub fn aggregate(
        allocator: Allocator,
        gossip_participants: ?AggregationBits,
        children: []const AggregatedSignatureProof,
        raw_xmss_pks: []*const xmss.HashSigPublicKey,
        raw_xmss_sigs: []*const xmss.HashSigSignature,
        message_hash: *const [32]u8,
        epoch: u64,
        result: *Self,
    ) !void {
        _ = message_hash;
        _ = epoch;
        _ = raw_xmss_pks;
        _ = raw_xmss_sigs;

        const has_raw = gossip_participants != null;
        const has_children = children.len > 0;

        if (!has_raw and !has_children) return error.AggregationInvalidInput;
        if (!has_raw and children.len < 2) return error.AggregationInvalidInput;

        // Dummy mode: merge participant bitfields
        var merged = try attestation.AggregationBits.init(allocator);
        errdefer merged.deinit();

        // Add gossip participants
        if (gossip_participants) |gp| {
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

        // Dummy proof_data: single zero byte
        var proof_data = try ByteListMiB.init(allocator);
        errdefer proof_data.deinit();
        try proof_data.append(0x00);

        // bytecode_point: empty if no children (flat), single zero byte if recursive
        var bytecode_point = try ByteListMiB.init(allocator);
        errdefer bytecode_point.deinit();
        if (has_children) {
            try bytecode_point.append(0x00);
        }

        // Clean up old result data before overwriting
        result.participants.deinit();
        result.proof_data.deinit();
        result.bytecode_point.deinit();

        result.participants = merged;
        result.proof_data = proof_data;
        result.bytecode_point = bytecode_point;
    }

    /// Verify this aggregated signature proof.
    /// Currently uses dummy mode: checks that participant count matches public_keys count.
    pub fn verify(self: *const Self, public_keys: []*const xmss.HashSigPublicKey, message_hash: *const [32]u8, epoch: u64) !void {
        _ = message_hash;
        _ = epoch;

        // Dummy verification: count participants and compare with public_keys
        var count: usize = 0;
        for (0..self.participants.len()) |i| {
            if (self.participants.get(i) catch false) {
                count += 1;
            }
        }
        if (count != public_keys.len) return error.InvalidAggregationSignature;
    }
};
