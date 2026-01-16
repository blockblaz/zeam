const std = @import("std");
const ssz = @import("ssz");
const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");

const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const json = std.json;

const attestation = @import("./attestation.zig");

const AggregationBits = attestation.AggregationBits;
const MultisigAggregatedSignature = xmss.MultisigAggregatedSignature;

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
pub const AttestationSignatures = ssz.utils.List(AggregatedSignatureProof, params.VALIDATOR_REGISTRY_LIMIT);

pub const AggregatedSignatureProof = struct {
    participants: attestation.AggregationBits,
    proof_data: MultisigAggregatedSignature,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();

        var proof_data = try MultisigAggregatedSignature.init(allocator);
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
        try obj.put("participants", try self.participants.toJson(allocator));
        try obj.put("proof_data", try self.proof_data.toJson(allocator));
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
        aggregated_signature_proof.participants = participants;
        try xmss.aggregateSignatures(public_keys, signatures, message_hash, epoch, &aggregated_signature_proof.proof_data);
    }

    pub fn verify(self: *const Self, public_keys: []*const xmss.HashSigPublicKey, message_hash: *const [32]u8, epoch: u64) !void {
        try xmss.verifyAggregatedPayload(public_keys, message_hash, epoch, &self.proof_data);
    }
};
