const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");
const zeam_utils = @import("@zeam/utils");

const aggregation = @import("./aggregation.zig");
const attestation = @import("./attestation.zig");
const mini_3sf = @import("./mini_3sf.zig");
const state = @import("./state.zig");
const utils = @import("./utils.zig");
const validator = @import("./validator.zig");

const Allocator = std.mem.Allocator;
const AggregatedAttestation = attestation.AggregatedAttestation;
pub const AggregatedAttestations = ssz.utils.List(AggregatedAttestation, params.VALIDATOR_REGISTRY_LIMIT);
const Attestation = attestation.Attestation;
pub const AttestationSignatures = ssz.utils.List(aggregation.AggregatedSignatureProof, params.VALIDATOR_REGISTRY_LIMIT);
const Slot = utils.Slot;
const ValidatorIndex = utils.ValidatorIndex;
const Bytes32 = utils.Bytes32;
const SIGBYTES = utils.SIGBYTES;
const SIGSIZE = utils.SIGSIZE;
const Root = utils.Root;
const ZERO_HASH = utils.ZERO_HASH;
const ZERO_SIGBYTES = utils.ZERO_SIGBYTES;
const Validators = validator.Validators;

const bytesToHex = utils.BytesToHex;
const json = std.json;

const freeJsonValue = utils.freeJsonValue;

// signatures_map types for aggregation
/// SignatureKey is used to index signatures by (validator_id, data_root).
pub const SignatureKey = struct {
    validator_id: ValidatorIndex,
    data_root: Root,
};

/// Stored signatures_map entry
pub const StoredSignature = struct {
    slot: Slot,
    signature: SIGBYTES,
};

/// Map type for signatures_map: SignatureKey -> individual XMSS signature bytes + slot metadata
pub const SignaturesMap = std.AutoHashMap(SignatureKey, StoredSignature);

/// Stored aggregated payload entry
pub const StoredAggregatedPayload = struct {
    /// Slot of the attested data (used for pruning).
    attestation_slot: Slot,
    /// Slot when the proof was learned (used for tie-break ordering).
    source_slot: Slot,
    proof: aggregation.AggregatedSignatureProof,
};

/// List of aggregated payloads for a single key
pub const AggregatedPayloadsList = std.ArrayList(StoredAggregatedPayload);

/// Map type for aggregated payloads: SignatureKey -> list of AggregatedSignatureProof
pub const AggregatedPayloadsMap = std.AutoHashMap(SignatureKey, AggregatedPayloadsList);

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
        try zeam_utils.hashTreeRoot(
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
        try zeam_utils.hashTreeRoot(
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
    attestation_signatures: AttestationSignatures,
    proposer_signature: SIGBYTES,

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
            try groups_array.append(try group.toJson(allocator));
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
        const signatures = try aggregation.AggregatedSignatureProof.init(allocator);
        try groups.append(signatures);
    }

    return .{
        .attestation_signatures = groups,
        .proposer_signature = utils.ZERO_SIGBYTES,
    };
}

pub const AggregatedAttestationsResult = struct {
    attestations: AggregatedAttestations,
    attestation_signatures: AttestationSignatures,
    allocator: Allocator,

    const Self = @This();
    const AttestationGroup = struct {
        data: attestation.AttestationData,
        data_root: Root,
        validator_bits: std.DynamicBitSet,

        fn deinit(self: *AttestationGroup) void {
            self.validator_bits.deinit();
        }
    };

    const CollectedGossipSignatures = struct {
        signatures: std.ArrayList(xmss.Signature),
        public_keys: std.ArrayList(xmss.PublicKey),
        participants: attestation.AggregationBits,
        participants_owned: bool,

        fn init(allocator: Allocator) !CollectedGossipSignatures {
            var signatures = std.ArrayList(xmss.Signature).init(allocator);
            errdefer signatures.deinit();
            var public_keys = std.ArrayList(xmss.PublicKey).init(allocator);
            errdefer public_keys.deinit();
            var participants = try attestation.AggregationBits.init(allocator);
            errdefer participants.deinit();

            return .{
                .signatures = signatures,
                .public_keys = public_keys,
                .participants = participants,
                .participants_owned = true,
            };
        }

        fn deinit(self: *CollectedGossipSignatures) void {
            for (self.signatures.items) |*sig| {
                sig.deinit();
            }
            self.signatures.deinit();

            for (self.public_keys.items) |*pk| {
                pk.deinit();
            }
            self.public_keys.deinit();

            if (self.participants_owned) {
                self.participants.deinit();
            }
        }
    };

    pub fn init(allocator: Allocator) !Self {
        var attestations_list = try AggregatedAttestations.init(allocator);
        errdefer attestations_list.deinit();

        var signatures_list = try AttestationSignatures.init(allocator);
        errdefer signatures_list.deinit();

        return .{
            .attestations = attestations_list,
            .attestation_signatures = signatures_list,
            .allocator = allocator,
        };
    }

    fn buildAttestationGroups(
        allocator: Allocator,
        attestations_list: []const Attestation,
    ) !std.ArrayList(AttestationGroup) {
        var groups = std.ArrayList(AttestationGroup).init(allocator);
        errdefer {
            for (groups.items) |*group| {
                group.deinit();
            }
            groups.deinit();
        }

        // Map data_root -> index into groups so we can update existing bitsets in O(1).
        var root_indices = std.AutoHashMap(Root, usize).init(allocator);
        defer root_indices.deinit();

        // Group attestations by data_root and collect validator ids into bitsets.
        for (attestations_list) |att| {
            const data_root = try att.data.sszRoot(allocator);
            const vid: usize = @intCast(att.validator_id);
            if (root_indices.get(data_root)) |group_index| {
                var bits = &groups.items[group_index].validator_bits;
                // Grow the bitset to fit this validator id if needed.
                if (vid >= bits.capacity()) {
                    try bits.resize(vid + 1, false);
                }
                bits.set(vid);
            } else {
                // First time seeing this data_root: seed the bitset with this validator id.
                var new_bits = try std.DynamicBitSet.initEmpty(allocator, vid + 1);
                new_bits.set(vid);
                try groups.append(.{
                    .data = att.data,
                    .data_root = data_root,
                    .validator_bits = new_bits,
                });
                try root_indices.put(data_root, groups.items.len - 1);
            }
        }

        return groups;
    }

    fn collectGossipSignaturesForGroup(
        allocator: Allocator,
        group: *const AttestationGroup,
        validators: *const Validators,
        signatures_map: *const SignaturesMap,
    ) !?CollectedGossipSignatures {
        var collected = try CollectedGossipSignatures.init(allocator);
        errdefer collected.deinit();

        // Collect all available signatures for the group's data_root.
        var validator_it = group.validator_bits.iterator(.{});
        while (validator_it.next()) |validator_id| {
            const vid: ValidatorIndex = @intCast(validator_id);
            // Each validator contributes at most one signature per (validator_id, data_root).
            const sig_entry = signatures_map.get(.{ .validator_id = vid, .data_root = group.data_root }) orelse {
                continue;
            };

            // Skip missing signatures that are explicitly zeroed.
            if (std.mem.eql(u8, &sig_entry.signature, &ZERO_SIGBYTES)) continue;

            // Deserialize signature and fetch the corresponding public key.
            var sig = xmss.Signature.fromBytes(&sig_entry.signature) catch {
                continue;
            };

            if (validator_id >= validators.len()) {
                sig.deinit();
                continue;
            }

            const val = validators.get(validator_id) catch {
                sig.deinit();
                continue;
            };

            // Parse the validator's public key so we can aggregate with XMSS.
            var pk = xmss.PublicKey.fromBytes(&val.pubkey) catch {
                sig.deinit();
                continue;
            };

            collected.signatures.append(sig) catch |e| {
                sig.deinit();
                pk.deinit();
                return e;
            };
            collected.public_keys.append(pk) catch |e| {
                pk.deinit();
                return e;
            };

            // Track participant membership in the aggregated proof.
            try attestation.aggregationBitsSet(&collected.participants, validator_id, true);
        }

        if (collected.signatures.items.len == 0) {
            collected.deinit();
            return null;
        }

        return collected;
    }

    fn appendAggregatedProofForGroup(
        self: *Self,
        group: *const AttestationGroup,
        message_hash: *const [32]u8,
        collected: *CollectedGossipSignatures,
    ) !void {
        const allocator = self.allocator;
        const epoch: u64 = group.data.slot;

        // Convert signatures and public keys into the handle arrays expected by XMSS.
        var pk_handles = try allocator.alloc(*const xmss.HashSigPublicKey, collected.public_keys.items.len);
        defer allocator.free(pk_handles);
        var sig_handles = try allocator.alloc(*const xmss.HashSigSignature, collected.signatures.items.len);
        defer allocator.free(sig_handles);

        // Stable ordering of handles follows the collected lists (validator iteration order).
        for (collected.public_keys.items, 0..) |*pk, i| pk_handles[i] = pk.handle;
        for (collected.signatures.items, 0..) |*sig, i| sig_handles[i] = sig.handle;

        // Aggregate into a single proof. This transfers ownership of participants to the proof.
        var proof = try aggregation.AggregatedSignatureProof.init(allocator);
        errdefer proof.deinit();
        try aggregation.AggregatedSignatureProof.aggregate(
            collected.participants,
            pk_handles,
            sig_handles,
            message_hash,
            epoch,
            &proof,
        );
        collected.participants_owned = false;

        // Clone the participants bitlist for the aggregated attestation record.
        var att_bits = try attestation.AggregationBits.init(allocator);
        errdefer att_bits.deinit();
        // We keep att_bits in the block body while proof keeps its own participants list.
        for (0..proof.participants.len()) |i| {
            if (proof.participants.get(i) catch false) {
                try attestation.aggregationBitsSet(&att_bits, i, true);
            }
        }

        try self.attestations.append(.{ .aggregation_bits = att_bits, .data = group.data });
        try self.attestation_signatures.append(proof);
    }

    /// Aggregate individual gossip signatures into proofs (used by committee aggregators).
    pub fn aggregateGossipSignatures(
        self: *Self,
        attestations_list: []const Attestation,
        validators: *const Validators,
        signatures_map: *const SignaturesMap,
    ) !void {
        const allocator = self.allocator;

        // Algorithm overview (group -> collect -> aggregate):
        // 1) Group attestations by data_root and collect validator ids into a bitset per group.
        // 2) For each group, pull any available per-validator signatures from signatures_map.
        // 3) If we collected at least one signature, aggregate them into a single proof and
        //    emit a matching AggregatedAttestation for block inclusion/gossip.

        var groups = try buildAttestationGroups(allocator, attestations_list);
        defer {
            for (groups.items) |*group| {
                group.deinit();
            }
            groups.deinit();
        }

        for (groups.items) |*group| {
            var message_hash: [32]u8 = undefined;
            try zeam_utils.hashTreeRoot(attestation.AttestationData, group.data, &message_hash, allocator);

            const collected_opt = try collectGossipSignaturesForGroup(
                allocator,
                group,
                validators,
                signatures_map,
            );
            if (collected_opt == null) continue;

            var collected = collected_opt.?;
            defer collected.deinit();
            try self.appendAggregatedProofForGroup(group, &message_hash, &collected);
        }
    }

    fn initRemainingValidators(
        allocator: Allocator,
        group: *const AttestationGroup,
    ) !std.DynamicBitSet {
        const max_validator = group.validator_bits.capacity();
        var remaining = try std.DynamicBitSet.initEmpty(allocator, max_validator);

        var init_it = group.validator_bits.iterator(.{});
        while (init_it.next()) |validator_id| {
            if (validator_id >= remaining.capacity()) {
                try remaining.resize(validator_id + 1, false);
            }
            remaining.set(validator_id);
        }

        // "remaining" starts as the full participant set for this data_root.
        return remaining;
    }

    fn selectBestProofForGroup(
        remaining: *const std.DynamicBitSet,
        candidates: *const AggregatedPayloadsList,
    ) ?*const aggregation.AggregatedSignatureProof {
        var best_proof: ?*const aggregation.AggregatedSignatureProof = null;
        var max_coverage: usize = 0;
        const remaining_count = remaining.count();

        // Choose the proof that covers the most remaining validators.
        for (candidates.items) |*stored| {
            const proof = &stored.proof;
            const participants_len = proof.participants.len();

            var coverage: usize = 0;
            var remaining_it = remaining.iterator(.{});
            while (remaining_it.next()) |i| {
                if (i >= participants_len) continue;
                if (proof.participants.get(i) catch false) {
                    coverage += 1;
                }
            }

            if (coverage == 0) continue;
            // Strictly greater keeps the first max-coverage proof (list order tie-break).
            if (coverage > max_coverage) {
                max_coverage = coverage;
                best_proof = proof;
                if (max_coverage == remaining_count) break;
            }
        }

        return best_proof;
    }

    fn appendSelectedProofForGroup(
        self: *Self,
        group: *const AttestationGroup,
        remaining: *std.DynamicBitSet,
        proof: *const aggregation.AggregatedSignatureProof,
    ) !void {
        const allocator = self.allocator;

        // Clone the stored proof so the block owns its copy.
        var cloned_proof: aggregation.AggregatedSignatureProof = undefined;
        try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, proof.*, &cloned_proof);
        errdefer cloned_proof.deinit();

        var att_bits = try attestation.AggregationBits.init(allocator);
        errdefer att_bits.deinit();

        // Convert proof participants into aggregation bits and remove them from remaining.
        for (0..cloned_proof.participants.len()) |i| {
            if (cloned_proof.participants.get(i) catch false) {
                try attestation.aggregationBitsSet(&att_bits, i, true);
                if (i < remaining.capacity()) {
                    remaining.unset(i);
                }
            }
        }

        try self.attestations.append(.{ .aggregation_bits = att_bits, .data = group.data });
        try self.attestation_signatures.append(cloned_proof);
    }

    /// Select aggregated proofs from stored payloads (used by proposers; no fallback).
    pub fn selectAggregatedProofs(
        self: *Self,
        attestations_list: []const Attestation,
        aggregated_payloads: ?*const AggregatedPayloadsMap,
    ) !void {
        const allocator = self.allocator;

        // Algorithm overview (greedy set cover with deterministic tie-break):
        // 1) Group attestations by data_root and track participating validator ids in a bitset.
        // 2) For each group, keep a "remaining" bitset of validators we still need to cover.
        // 3) Repeatedly:
        //    a) Pick an arbitrary remaining validator (lowest set bit for determinism).
        //    b) Fetch candidate proofs indexed by (validator_id, data_root).
        //    c) Choose the proof that covers the most remaining validators.
        //       If coverage ties, keep the first proof in the list.
        //       The list is pre-ordered by source_slot (most recent first),
        //       so this tie-break is deterministic and prefers newer proofs.
        //    d) If the best proof has zero overlap, stop to avoid inconsistent results.
        //    e) Add the proof and remove its participants from remaining.
        // Note: We do not aggregate fresh gossip signatures here. Only stored proofs are used.

        // Group attestations by data root using bitsets for validator tracking.
        var groups = try buildAttestationGroups(allocator, attestations_list);
        defer {
            for (groups.items) |*group| {
                group.deinit();
            }
            groups.deinit();
        }

        // Process each group
        for (groups.items) |*group| {
            const data_root = group.data_root;
            var remaining = try initRemainingValidators(allocator, group);
            defer remaining.deinit();

            if (aggregated_payloads) |agg_payloads| {
                while (remaining.count() > 0) {
                    // Pick a deterministic target validator to drive lookup.
                    const target_id = remaining.findFirstSet() orelse break;
                    const vid: ValidatorIndex = @intCast(target_id);

                    // Proofs are indexed by participant id and data root.
                    const candidates = agg_payloads.get(.{ .validator_id = vid, .data_root = data_root }) orelse {
                        remaining.unset(target_id);
                        continue;
                    };

                    if (candidates.items.len == 0) {
                        remaining.unset(target_id);
                        continue;
                    }

                    const best_proof = selectBestProofForGroup(&remaining, &candidates) orelse {
                        break;
                    };
                    try self.appendSelectedProofForGroup(group, &remaining, best_proof);
                }
            }
        }
    }

    pub fn deinit(self: *Self) void {
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
    try zeam_utils.hashTreeRoot(BeamBlock, signed_block.message.block, &block_root, std.testing.allocator);
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

    var signature_proof = try aggregation.AggregatedSignatureProof.init(std.testing.allocator);
    errdefer signature_proof.deinit();

    // Set participants for validators 0 and 1
    try attestation.aggregationBitsSet(&signature_proof.participants, 0, true);
    try attestation.aggregationBitsSet(&signature_proof.participants, 1, true);

    try attestation_signatures.append(signature_proof);

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
    try std.testing.expect(decoded_group.participants.len() == 2);
}

test "selectAggregatedProofs: tie-break uses list order" {
    const allocator = std.testing.allocator;

    const att_data = attestation.AttestationData{
        .slot = 5,
        .head = .{ .root = ZERO_HASH, .slot = 5 },
        .target = .{ .root = ZERO_HASH, .slot = 5 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
    const data_root = try att_data.sszRoot(allocator);

    var attestations_list = [_]Attestation{
        .{ .validator_id = 0, .data = att_data },
        .{ .validator_id = 1, .data = att_data },
        .{ .validator_id = 2, .data = att_data },
    };

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer {
        var it = payloads_map.valueIterator();
        while (it.next()) |list| {
            for (list.items) |*item| {
                item.proof.deinit();
            }
            list.deinit();
        }
        payloads_map.deinit();
    }

    var proof_a = try aggregation.AggregatedSignatureProof.init(allocator);
    var proof_a_moved = false;
    errdefer if (!proof_a_moved) proof_a.deinit();
    try attestation.aggregationBitsSet(&proof_a.participants, 0, true);
    try attestation.aggregationBitsSet(&proof_a.participants, 1, true);
    try attestation.aggregationBitsSet(&proof_a.participants, 2, false);

    var proof_b = try aggregation.AggregatedSignatureProof.init(allocator);
    var proof_b_moved = false;
    errdefer if (!proof_b_moved) proof_b.deinit();
    try attestation.aggregationBitsSet(&proof_b.participants, 0, true);
    try attestation.aggregationBitsSet(&proof_b.participants, 1, false);
    try attestation.aggregationBitsSet(&proof_b.participants, 2, true);

    const gop = try payloads_map.getOrPut(.{ .validator_id = 0, .data_root = data_root });
    if (!gop.found_existing) {
        gop.value_ptr.* = AggregatedPayloadsList.init(allocator);
    }
    try gop.value_ptr.append(.{
        .attestation_slot = att_data.slot,
        .source_slot = att_data.slot,
        .proof = proof_a,
    });
    proof_a_moved = true;
    try gop.value_ptr.append(.{
        .attestation_slot = att_data.slot,
        .source_slot = att_data.slot,
        .proof = proof_b,
    });
    proof_b_moved = true;

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();
    try agg_ctx.selectAggregatedProofs(attestations_list[0..], &payloads_map);

    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    const selected = try agg_ctx.attestations.get(0);
    try std.testing.expectEqual(@as(usize, 2), selected.aggregation_bits.len());
    try std.testing.expect(try selected.aggregation_bits.get(0));
    try std.testing.expect(try selected.aggregation_bits.get(1));
}
