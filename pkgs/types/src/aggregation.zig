const std = @import("std");
const ssz = @import("ssz");
const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");

const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const json = std.json;

const attestation = @import("./attestation.zig");

const AggregationBits = attestation.AggregationBits;
const ByteListMiB = xmss.ByteListMiB;

const freeJsonValue = utils.freeJsonValue;

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

    pub fn aggregate(
        participants: AggregationBits,
        public_keys: []*const xmss.HashSigPublicKey,
        signatures: []*const xmss.HashSigSignature,
        message_hash: *const [32]u8,
        epoch: u64,
        aggregated_signature_proof: *Self,
    ) !void {
        try xmss.aggregateSignatures(public_keys, signatures, message_hash, @intCast(epoch), &aggregated_signature_proof.proof_data);

        // Transfer ownership only after aggregation succeeds
        aggregated_signature_proof.participants = participants;
    }

    pub fn verify(self: *const Self, public_keys: []*const xmss.HashSigPublicKey, message_hash: *const [32]u8, epoch: u64) !void {
        try xmss.verifyAggregatedPayload(public_keys, message_hash, @intCast(epoch), &self.proof_data);
    }
};
