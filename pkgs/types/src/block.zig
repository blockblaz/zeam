const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");

const attestation = @import("./attestation.zig");
const mini_3sf = @import("./mini_3sf.zig");
const state = @import("./state.zig");
const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const AggregatedAttestation = attestation.AggregatedAttestation;
pub const AggregatedAttestations = ssz.utils.List(AggregatedAttestation, params.VALIDATOR_REGISTRY_LIMIT);
const Attestation = attestation.Attestation;
pub const AttestationSignatures = ssz.utils.List(attestation.NaiveAggregatedSignature, params.VALIDATOR_REGISTRY_LIMIT);
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;
const Bytes32 = utils.Bytes32;
const SIGBYTES = utils.SIGBYTES;
const SIGSIZE = utils.SIGSIZE;
const Root = utils.Root;
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
pub const BeamBlockBody = struct {
    attestations: AggregatedAttestations,

    pub fn deinit(self: *BeamBlockBody) void {
        for (self.attestations.slice()) |*att| {
            att.deinit();
        }
        self.attestations.deinit();
    }

    pub fn toJson(self: *const BeamBlockBody, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);

        var attestations_array = json.Array.init(allocator);
        errdefer attestations_array.deinit();

        for (self.attestations.constSlice()) |att| {
            try attestations_array.append(try att.toJson(allocator));
        }
        try obj.put("attestations", json.Value{ .array = attestations_array });

        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamBlockBody, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamBlockHeader = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,

    pub fn toJson(self: *const BeamBlockHeader, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("proposer_index", json.Value{ .integer = @as(i64, @intCast(self.proposer_index)) });
        try obj.put("parent_root", json.Value{ .string = try bytesToHex(allocator, &self.parent_root) });
        try obj.put("state_root", json.Value{ .string = try bytesToHex(allocator, &self.state_root) });
        try obj.put("body_root", json.Value{ .string = try bytesToHex(allocator, &self.body_root) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamBlockHeader, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer self.freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        if (val.object.get("parent_root")) |*parent_root| {
            allocator.free(parent_root.string);
        }
        if (val.object.get("state_root")) |*state_root| {
            allocator.free(state_root.string);
        }
        if (val.object.get("body_root")) |*body_root| {
            allocator.free(body_root.string);
        }
        val.object.deinit();
    }
};

pub const BeamBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body: BeamBlockBody,

    const Self = @This();

    pub fn setToDefault(self: *Self, allocator: Allocator) !void {
        const attestations = try AggregatedAttestations.init(allocator);
        errdefer attestations.deinit();

        self.* = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .body = BeamBlockBody{
                .attestations = attestations,
            },
        };
    }

    pub fn blockToHeader(self: *const Self, allocator: Allocator) !BeamBlockHeader {
        var body_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamBlockBody,
            self.body,
            &body_root,
            allocator,
        );

        return BeamBlockHeader{
            .slot = self.slot,
            .proposer_index = self.proposer_index,
            .parent_root = self.parent_root,
            .state_root = self.state_root,
            .body_root = body_root,
        };
    }

    pub fn blockToLatestBlockHeader(self: *const Self, allocator: Allocator, header: *BeamBlockHeader) !void {
        var body_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(
            BeamBlockBody,
            self.body,
            &body_root,
            allocator,
        );

        header.* = .{
            .slot = self.slot,
            .proposer_index = self.proposer_index,
            .parent_root = self.parent_root,
            .state_root = ZERO_HASH,
            .body_root = body_root,
        };
    }

    pub fn deinit(self: *Self) void {
        self.body.deinit();
    }

    pub fn toJson(self: *const BeamBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("proposer_index", json.Value{ .integer = @as(i64, @intCast(self.proposer_index)) });
        try obj.put("parent_root", json.Value{ .string = try bytesToHex(allocator, &self.parent_root) });
        try obj.put("state_root", json.Value{ .string = try bytesToHex(allocator, &self.state_root) });
        try obj.put("body", try self.body.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamBlock, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BlockSignatures = struct {
    proposer_signature: SIGBYTES,
    attestation_signatures: AttestationSignatures,

    pub fn deinit(self: *BlockSignatures) void {
        for (self.attestation_signatures.slice()) |*group| {
            group.deinit();
        }
        self.attestation_signatures.deinit();
    }

    pub fn toJson(self: *const BlockSignatures, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);

        var groups_array = json.Array.init(allocator);
        errdefer groups_array.deinit();

        for (self.attestation_signatures.constSlice()) |group| {
            var sig_array = json.Array.init(allocator);
            var success = false;
            defer if (!success) sig_array.deinit();

            for (group.constSlice()) |sig| {
                try sig_array.append(json.Value{ .string = try bytesToHex(allocator, &sig) });
            }

            try groups_array.append(json.Value{ .array = sig_array });
            success = true;
        }

        try obj.put("attestation_signatures", json.Value{ .array = groups_array });
        try obj.put("proposer_signature", json.Value{ .string = try bytesToHex(allocator, &self.proposer_signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlockSignatures, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BlockWithAttestation = struct {
    block: BeamBlock,
    proposer_attestation: Attestation,

    pub fn deinit(self: *BlockWithAttestation) void {
        self.block.deinit();
    }

    pub fn toJson(self: *const BlockWithAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("block", try self.block.toJson(allocator));
        try obj.put("proposer_attestation", try self.proposer_attestation.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlockWithAttestation, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const SignedBlockWithAttestation = struct {
    message: BlockWithAttestation,
    signature: BlockSignatures,

    pub fn deinit(self: *SignedBlockWithAttestation) void {
        self.message.deinit();
        self.signature.deinit();
    }

    pub fn toJson(self: *const SignedBlockWithAttestation, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("message", try self.message.toJson(allocator));
        try obj.put("signature", try self.signature.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedBlockWithAttestation, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub fn createBlockSignatures(allocator: Allocator, num_aggregated_attestations: usize) !BlockSignatures {
    var groups = try AttestationSignatures.init(allocator);
    errdefer groups.deinit();

    for (0..num_aggregated_attestations) |_| {
        const signatures = try attestation.NaiveAggregatedSignature.init(allocator);
        try groups.append(signatures);
    }

    return .{
        .attestation_signatures = groups,
        .proposer_signature = utils.ZERO_SIGBYTES,
    };
}

const AggregationGroup = struct {
    data: attestation.AttestationData,
    bits: attestation.AggregationBits,
    signatures: attestation.NaiveAggregatedSignature,

    fn init(allocator: Allocator, signed_attestation: attestation.SignedAttestation) !AggregationGroup {
        var bits = try attestation.AggregationBits.init(allocator);
        errdefer bits.deinit();

        const validator_index: usize = @intCast(signed_attestation.validator_id);
        try attestation.aggregationBitsSet(&bits, validator_index, true);

        var signatures = try attestation.NaiveAggregatedSignature.init(allocator);
        errdefer signatures.deinit();
        try signatures.append(signed_attestation.signature);

        return AggregationGroup{
            .data = signed_attestation.message,
            .bits = bits,
            .signatures = signatures,
        };
    }
};

pub const AggregatedAttestationsResult = struct {
    attestations: AggregatedAttestations,
    attestation_signatures: AttestationSignatures,

    pub fn deinit(self: *AggregatedAttestationsResult) void {
        for (self.attestations.slice()) |*att| {
            att.deinit();
        }
        self.attestations.deinit();

        for (self.attestation_signatures.slice()) |*sig_group| {
            sig_group.deinit();
        }
        self.attestation_signatures.deinit();
    }
};

pub fn aggregateSignedAttestations(
    allocator: Allocator,
    signed_attestations: []const attestation.SignedAttestation,
) !AggregatedAttestationsResult {
    var aggregated_attestations = try AggregatedAttestations.init(allocator);
    errdefer aggregated_attestations.deinit();

    var attestation_signatures = try AttestationSignatures.init(allocator);
    errdefer attestation_signatures.deinit();

    var groups = std.ArrayList(AggregationGroup).init(allocator);
    defer groups.deinit();
    errdefer for (groups.items) |*group| {
        group.bits.deinit();
        group.signatures.deinit();
    };

    var root_indices = std.AutoHashMap(Root, usize).init(allocator);
    defer root_indices.deinit();

    for (signed_attestations) |signed_attestation| {
        const root = try signed_attestation.message.sszRoot(allocator);
        if (root_indices.get(root)) |group_index| {
            var group = &groups.items[group_index];
            const validator_index: usize = @intCast(signed_attestation.validator_id);
            try attestation.aggregationBitsSet(&group.bits, validator_index, true);
            try group.signatures.append(signed_attestation.signature);
        } else {
            const new_group = try AggregationGroup.init(allocator, signed_attestation);
            try groups.append(new_group);
            const inserted_index = groups.items.len - 1;
            try root_indices.put(root, inserted_index);
        }
    }

    for (groups.items) |group| {
        try aggregated_attestations.append(.{ .aggregation_bits = group.bits, .data = group.data });
        try attestation_signatures.append(group.signatures);
    }

    return .{
        .attestations = aggregated_attestations,
        .attestation_signatures = attestation_signatures,
    };
}

pub const BlockByRootRequest = struct {
    roots: ssz.utils.List(utils.Root, params.MAX_REQUEST_BLOCKS),

    pub fn toJson(self: *const BlockByRootRequest, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        var roots_array = json.Array.init(allocator);
        errdefer roots_array.deinit();
        for (self.roots.constSlice()) |root| {
            try roots_array.append(json.Value{ .string = try bytesToHex(allocator, &root) });
        }
        try obj.put("roots", json.Value{ .array = roots_array });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlockByRootRequest, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

/// Canonical lightweight forkchoice proto block used across modules
pub const ProtoBlock = struct {
    slot: Slot,
    blockRoot: Root,
    parentRoot: Root,
    stateRoot: Root,
    timeliness: bool,
    // the protoblock entry might get added even at produce block even before validator signs it
    // which is when we would not even have persisted the signed block, so we need to track this
    // and make sure we persit the signed block before publishing and voting on it, and especially
    // in voting. also this needs to be handled in pruning
    confirmed: bool,

    pub fn toJson(self: *const ProtoBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put("blockRoot", json.Value{ .string = try bytesToHex(allocator, &self.blockRoot) });
        try obj.put("parentRoot", json.Value{ .string = try bytesToHex(allocator, &self.parentRoot) });
        try obj.put("stateRoot", json.Value{ .string = try bytesToHex(allocator, &self.stateRoot) });
        try obj.put("timeliness", json.Value{ .bool = self.timeliness });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ProtoBlock, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const ExecutionPayloadHeader = struct {
    timestamp: u64,

    pub fn toJson(self: *const ExecutionPayloadHeader, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("timestamp", json.Value{ .integer = @as(i64, @intCast(self.timestamp)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ExecutionPayloadHeader, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit();
        return utils.jsonToString(allocator, json_value);
    }
};

test "ssz seralize/deserialize signed beam block" {
    var attestations = try AggregatedAttestations.init(std.testing.allocator);

    var signatures = try createBlockSignatures(std.testing.allocator, attestations.len());
    errdefer signatures.deinit();

    var signed_block = SignedBlockWithAttestation{
        .message = .{
            .block = .{
                .slot = 9,
                .proposer_index = 3,
                .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
                .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
                .body = .{ .attestations = attestations },
            },
            .proposer_attestation = .{
                .validator_id = 3,
                .data = .{
                    .slot = 9,
                    .head = .{ .slot = 9, .root = [_]u8{1} ** 32 },
                    .source = .{ .slot = 0, .root = ZERO_HASH },
                    .target = .{ .slot = 9, .root = [_]u8{1} ** 32 },
                },
            },
        },
        .signature = signatures,
    };
    defer signed_block.deinit();

    var serialized_signed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_signed_block.deinit();

    try ssz.serialize(SignedBlockWithAttestation, signed_block, &serialized_signed_block);
    try std.testing.expect(serialized_signed_block.items.len > 0);

    var deserialized_signed_block: SignedBlockWithAttestation = undefined;
    try ssz.deserialize(SignedBlockWithAttestation, serialized_signed_block.items[0..], &deserialized_signed_block, std.testing.allocator);
    defer deserialized_signed_block.deinit();

    try std.testing.expect(std.mem.eql(u8, &signed_block.message.block.state_root, &deserialized_signed_block.message.block.state_root));
    try std.testing.expect(std.mem.eql(u8, &signed_block.message.block.parent_root, &deserialized_signed_block.message.block.parent_root));

    var block_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(BeamBlock, signed_block.message.block, &block_root, std.testing.allocator);
}

test "blockToLatestBlockHeader and blockToHeader" {
    var block = BeamBlock{
        .slot = 9,
        .proposer_index = 3,
        .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
        .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
        .body = .{ .attestations = try AggregatedAttestations.init(std.testing.allocator) },
    };
    defer block.deinit();

    var lastest_block_header: BeamBlockHeader = undefined;
    try block.blockToLatestBlockHeader(std.testing.allocator, &lastest_block_header);
    try std.testing.expect(lastest_block_header.proposer_index == block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &block.parent_root, &lastest_block_header.parent_root));
    try std.testing.expect(std.mem.eql(u8, &ZERO_HASH, &lastest_block_header.state_root));

    var block_header: BeamBlockHeader = try block.blockToHeader(std.testing.allocator);
    try std.testing.expect(block_header.proposer_index == block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &block.parent_root, &block_header.parent_root));
    try std.testing.expect(std.mem.eql(u8, &block.state_root, &block_header.state_root));
}

test "encode decode signed block with attestation roundtrip" {
    var attestations = try AggregatedAttestations.init(std.testing.allocator);
    errdefer attestations.deinit();

    var signatures = try createBlockSignatures(std.testing.allocator, attestations.len());
    errdefer signatures.deinit();

    var signed_block_with_attestation = SignedBlockWithAttestation{
        .message = .{
            .block = .{
                .slot = 0,
                .proposer_index = 0,
                .parent_root = ZERO_HASH,
                .state_root = ZERO_HASH,
                .body = .{ .attestations = attestations },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 0,
                    .head = .{ .root = ZERO_HASH, .slot = 0 },
                    .target = .{ .root = ZERO_HASH, .slot = 0 },
                    .source = .{ .root = ZERO_HASH, .slot = 0 },
                },
            },
        },
        .signature = signatures,
    };
    defer signed_block_with_attestation.deinit();

    var encoded = std.ArrayList(u8).init(std.testing.allocator);
    defer encoded.deinit();
    try ssz.serialize(SignedBlockWithAttestation, signed_block_with_attestation, &encoded);

    var decoded: SignedBlockWithAttestation = undefined;
    try ssz.deserialize(SignedBlockWithAttestation, encoded.items[0..], &decoded, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expect(decoded.message.block.slot == signed_block_with_attestation.message.block.slot);
    try std.testing.expect(decoded.message.block.proposer_index == signed_block_with_attestation.message.block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.block.parent_root, &signed_block_with_attestation.message.block.parent_root));
    try std.testing.expect(std.mem.eql(u8, &decoded.message.block.state_root, &signed_block_with_attestation.message.block.state_root));
    try std.testing.expect(decoded.message.proposer_attestation.validator_id == signed_block_with_attestation.message.proposer_attestation.validator_id);
    try std.testing.expect(decoded.message.proposer_attestation.data.slot == signed_block_with_attestation.message.proposer_attestation.data.slot);
    try std.testing.expect(std.mem.eql(u8, &decoded.message.proposer_attestation.data.head.root, &signed_block_with_attestation.message.proposer_attestation.data.head.root));
    try std.testing.expect(decoded.signature.attestation_signatures.len() == signed_block_with_attestation.signature.attestation_signatures.len());
}

test "encode decode signed block with non-empty attestation signatures" {
    var attestations = try AggregatedAttestations.init(std.testing.allocator);
    errdefer attestations.deinit();

    var attestation_signatures = try AttestationSignatures.init(std.testing.allocator);
    errdefer attestation_signatures.deinit();

    var validator_signatures = try attestation.NaiveAggregatedSignature.init(std.testing.allocator);
    errdefer validator_signatures.deinit();

    var test_sig1: SIGBYTES = undefined;
    var test_sig2: SIGBYTES = undefined;
    @memset(&test_sig1, 0x12);
    @memset(&test_sig2, 0x34);

    try validator_signatures.append(test_sig1);
    try validator_signatures.append(test_sig2);

    try attestation_signatures.append(validator_signatures);

    var signed_block_with_attestation = SignedBlockWithAttestation{
        .message = .{
            .block = .{
                .slot = 1,
                .proposer_index = 0,
                .parent_root = ZERO_HASH,
                .state_root = ZERO_HASH,
                .body = .{ .attestations = attestations },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 1,
                    .head = .{ .root = ZERO_HASH, .slot = 1 },
                    .target = .{ .root = ZERO_HASH, .slot = 1 },
                    .source = .{ .root = ZERO_HASH, .slot = 0 },
                },
            },
        },
        .signature = .{
            .attestation_signatures = attestation_signatures,
            .proposer_signature = ZERO_SIGBYTES,
        },
    };
    defer signed_block_with_attestation.deinit();

    var encoded = std.ArrayList(u8).init(std.testing.allocator);
    defer encoded.deinit();
    try ssz.serialize(SignedBlockWithAttestation, signed_block_with_attestation, &encoded);

    var decoded: SignedBlockWithAttestation = undefined;
    try ssz.deserialize(SignedBlockWithAttestation, encoded.items[0..], &decoded, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expect(decoded.message.block.slot == signed_block_with_attestation.message.block.slot);
    try std.testing.expect(decoded.signature.attestation_signatures.len() == 1);
    const decoded_group = try decoded.signature.attestation_signatures.get(0);
    try std.testing.expect(decoded_group.len() == 2);
}
