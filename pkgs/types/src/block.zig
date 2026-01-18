const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");

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
    slot: Slot,
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

    /// Compute aggregated signatures using three-phase algorithm:
    /// Phase 1: Collect individual signatures from signatures_map (chain: gossip_signatures)
    /// Phase 2: Fallback to aggregated_payloads using greedy set-cover (if provided)
    /// Phase 3: Remove signatures which are already coverd by stored prrofs and aggregate remaining signatures
    pub fn computeAggregatedSignatures(
        self: *Self,
        attestations_list: []const Attestation,
        validators: *const Validators,
        signatures_map: *const SignaturesMap,
        aggregated_payloads: ?*const AggregatedPayloadsMap,
    ) !void {
        const allocator = self.allocator;

        // Group attestations by data root using bitsets for validator tracking
        const AttestationGroup = struct {
            data: attestation.AttestationData,
            data_root: Root,
            validator_bits: std.DynamicBitSet,
        };

        var groups = std.ArrayList(AttestationGroup).init(allocator);
        defer {
            for (groups.items) |*group| {
                group.validator_bits.deinit();
            }
            groups.deinit();
        }

        var root_indices = std.AutoHashMap(Root, usize).init(allocator);
        defer root_indices.deinit();

        // Group attestations by data root
        for (attestations_list) |att| {
            const data_root = try att.data.sszRoot(allocator);
            const vid: usize = @intCast(att.validator_id);
            if (root_indices.get(data_root)) |group_index| {
                var bits = &groups.items[group_index].validator_bits;
                if (vid >= bits.capacity()) {
                    try bits.resize(vid + 1, false);
                }
                bits.set(vid);
            } else {
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

        // Process each group
        for (groups.items) |*group| {
            const data_root = group.data_root;
            const epoch: u64 = group.data.slot;
            var message_hash: [32]u8 = undefined;
            try ssz.hashTreeRoot(attestation.AttestationData, group.data, &message_hash, allocator);

            // Phase 1: Collect signatures from signatures_map
            const max_validator = group.validator_bits.capacity();

            var sigmap_sigs = std.ArrayList(xmss.Signature).init(allocator);
            defer {
                for (sigmap_sigs.items) |*sig| {
                    sig.deinit();
                }
                sigmap_sigs.deinit();
            }

            var sigmap_pks = std.ArrayList(xmss.PublicKey).init(allocator);
            defer {
                for (sigmap_pks.items) |*pk| {
                    pk.deinit();
                }
                sigmap_pks.deinit();
            }

            // Map from validator_id to index in signatures_map arrays
            // Used to remove signatures from sigmap_sigs while aggregating which are already covered by stored proofs
            var vid_to_sigmap_idx = try allocator.alloc(?usize, max_validator);
            defer allocator.free(vid_to_sigmap_idx);
            @memset(vid_to_sigmap_idx, null);

            // Bitsets for tracking validator states
            var remaining = try std.DynamicBitSet.initEmpty(allocator, max_validator);
            defer remaining.deinit();

            var sigmap_available = try std.DynamicBitSet.initEmpty(allocator, max_validator);
            defer sigmap_available.deinit();

            // Track validators covered by stored proofs (to avoid redundancy with signatures_map)
            var covered_by_stored = try std.DynamicBitSet.initEmpty(allocator, max_validator);
            defer covered_by_stored.deinit();

            // Attempt to collect each validator's signature from signatures_map
            var validator_it = group.validator_bits.iterator(.{});
            while (validator_it.next()) |validator_id| {
                const vid: ValidatorIndex = @intCast(validator_id);
                if (signatures_map.get(.{ .validator_id = vid, .data_root = data_root })) |sig_entry| {
                    // Check if it's not a zero signature
                    if (!std.mem.eql(u8, &sig_entry.signature, &ZERO_SIGBYTES)) {
                        // Deserialize signature
                        var sig = xmss.Signature.fromBytes(&sig_entry.signature) catch {
                            remaining.set(validator_id);
                            continue;
                        };
                        errdefer sig.deinit();

                        // Get public key from validator
                        if (validator_id >= validators.len()) {
                            sig.deinit();
                            remaining.set(validator_id);
                            continue;
                        }

                        const val = validators.get(validator_id) catch {
                            sig.deinit();
                            remaining.set(validator_id);
                            continue;
                        };
                        const pk = xmss.PublicKey.fromBytes(&val.pubkey) catch {
                            sig.deinit();
                            remaining.set(validator_id);
                            continue;
                        };

                        vid_to_sigmap_idx[validator_id] = sigmap_sigs.items.len;
                        try sigmap_sigs.append(sig);
                        try sigmap_pks.append(pk);
                        sigmap_available.set(validator_id);
                    } else {
                        remaining.set(validator_id);
                    }
                } else {
                    remaining.set(validator_id);
                }
            }

            // Phase 2: Fallback to aggregated_payloads using greedy set-cover
            if (aggregated_payloads) |agg_payloads| {
                // Temporary bitset for computing coverage
                var proof_bits = try std.DynamicBitSet.initEmpty(allocator, max_validator);
                defer proof_bits.deinit();

                while (remaining.count() > 0) {
                    // Pick any remaining validator to look up proofs
                    const target_id = remaining.findFirstSet() orelse break;
                    const vid: ValidatorIndex = @intCast(target_id);

                    // Remove the target_id from remaining if not covered by stored proofs
                    const candidates = agg_payloads.get(.{ .validator_id = vid, .data_root = data_root }) orelse {
                        remaining.unset(target_id);
                        continue;
                    };

                    if (candidates.items.len == 0) {
                        remaining.unset(target_id);
                        continue;
                    }

                    // Find the proof covering the most remaining validators (greedy set-cover)
                    var best_proof: ?*const aggregation.AggregatedSignatureProof = null;
                    var max_coverage: usize = 0;

                    for (candidates.items) |*stored| {
                        const proof = &stored.proof;
                        const max_participants = proof.participants.len();

                        // Reset and populate proof_bits from participants
                        proof_bits.setRangeValue(.{ .start = 0, .end = proof_bits.capacity() }, false);
                        if (max_participants > proof_bits.capacity()) {
                            try proof_bits.resize(max_participants, false);
                        }

                        var coverage: usize = 0;

                        for (0..max_participants) |i| {
                            if (proof.participants.get(i) catch false) {
                                // Count coverage of validators still in remaining (not yet covered by stored proofs)
                                if (i < remaining.capacity() and remaining.isSet(i)) {
                                    proof_bits.set(i);
                                    coverage += 1;
                                }
                            }
                        }

                        if (coverage == 0) {
                            continue;
                        }

                        if (coverage > max_coverage) {
                            max_coverage = coverage;
                            best_proof = proof;
                        }
                    }

                    if (best_proof == null or max_coverage == 0) {
                        remaining.unset(target_id);
                        continue;
                    }

                    // Clone and add the proof
                    var cloned_proof: aggregation.AggregatedSignatureProof = undefined;
                    try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, best_proof.?.*, &cloned_proof);
                    errdefer cloned_proof.deinit();

                    // Create aggregated attestation matching the proof's participants
                    // and update tracking bitsets in a single pass
                    var att_bits = try attestation.AggregationBits.init(allocator);
                    errdefer att_bits.deinit();

                    for (0..cloned_proof.participants.len()) |i| {
                        if (cloned_proof.participants.get(i) catch false) {
                            try attestation.aggregationBitsSet(&att_bits, i, true);
                            if (i < remaining.capacity()) {
                                remaining.unset(i);
                            }
                            // Track ALL validators covered by stored proofs to remove from signatures_map later
                            if (i >= covered_by_stored.capacity()) {
                                try covered_by_stored.resize(i + 1, false);
                            }
                            covered_by_stored.set(i);
                        }
                    }

                    try self.attestations.append(.{ .aggregation_bits = att_bits, .data = group.data });
                    try self.attestation_signatures.append(cloned_proof);
                }
            }

            // Finally, aggregate signatures_map for validators NOT covered by stored proofs
            // This avoids redundancy: if a validator is in a stored proof, don't include them in signatures_map aggregation
            var usable_count: usize = 0;
            var git = sigmap_available.iterator(.{});
            while (git.next()) |vid| {
                if (vid >= covered_by_stored.capacity() or !covered_by_stored.isSet(vid)) {
                    usable_count += 1;
                }
            }

            if (usable_count > 0) {
                var participants = try attestation.AggregationBits.init(allocator);
                var participants_cleanup = true;
                errdefer if (participants_cleanup) participants.deinit();

                var pk_handles = try allocator.alloc(*const xmss.HashSigPublicKey, usable_count);
                defer allocator.free(pk_handles);
                var sig_handles = try allocator.alloc(*const xmss.HashSigSignature, usable_count);
                defer allocator.free(sig_handles);

                // Iterate sigmap_available in order, skipping validators already in stored proofs
                var handle_idx: usize = 0;
                var git2 = sigmap_available.iterator(.{});
                while (git2.next()) |vid| {
                    // Skip if already covered by a stored proof
                    if (vid < covered_by_stored.capacity() and covered_by_stored.isSet(vid)) continue;

                    try attestation.aggregationBitsSet(&participants, vid, true);
                    const sigmap_idx = vid_to_sigmap_idx[vid].?;
                    pk_handles[handle_idx] = sigmap_pks.items[sigmap_idx].handle;
                    sig_handles[handle_idx] = sigmap_sigs.items[sigmap_idx].handle;
                    handle_idx += 1;
                }

                var proof = try aggregation.AggregatedSignatureProof.init(allocator);
                errdefer proof.deinit();

                try aggregation.AggregatedSignatureProof.aggregate(
                    participants,
                    pk_handles[0..handle_idx],
                    sig_handles[0..handle_idx],
                    &message_hash,
                    epoch,
                    &proof,
                );
                participants_cleanup = false; // proof now owns participants buffer

                // Create aggregated attestation using proof's participants (which now owns the bits)
                // We need to clone it since we're moving it into the attestation
                var att_bits = try attestation.AggregationBits.init(allocator);
                errdefer att_bits.deinit();

                // Clone from proof.participants
                const proof_participants_len = proof.participants.len();
                for (0..proof_participants_len) |i| {
                    if (proof.participants.get(i) catch false) {
                        try attestation.aggregationBitsSet(&att_bits, i, true);
                    }
                }

                try self.attestations.append(.{ .aggregation_bits = att_bits, .data = group.data });
                try self.attestation_signatures.append(proof);
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

// ============================================================================
// Test helpers for computeAggregatedSignatures
// ============================================================================

const keymanager = @import("@zeam/key-manager");

const TestContext = struct {
    allocator: std.mem.Allocator,
    key_manager: keymanager.KeyManager,
    validators: validator.Validators,
    data_root: Root,
    attestation_data: attestation.AttestationData,

    pub fn init(allocator: std.mem.Allocator, num_validators: usize) !TestContext {
        var key_manager = try keymanager.getTestKeyManager(allocator, num_validators, 10);
        errdefer key_manager.deinit();

        // Create validators with proper pubkeys
        var validators_list = try validator.Validators.init(allocator);
        errdefer validators_list.deinit();

        for (0..num_validators) |i| {
            var pubkey: utils.Bytes52 = undefined;
            _ = try key_manager.getPublicKeyBytes(@intCast(i), &pubkey);
            try validators_list.append(.{
                .pubkey = pubkey,
                .index = @intCast(i),
            });
        }

        // Create common attestation data
        const att_data = attestation.AttestationData{
            .slot = 5,
            .head = .{ .root = [_]u8{1} ** 32, .slot = 5 },
            .target = .{ .root = [_]u8{1} ** 32, .slot = 5 },
            .source = .{ .root = ZERO_HASH, .slot = 0 },
        };

        const data_root = try att_data.sszRoot(allocator);

        return TestContext{
            .allocator = allocator,
            .key_manager = key_manager,
            .validators = validators_list,
            .data_root = data_root,
            .attestation_data = att_data,
        };
    }

    pub fn deinit(self: *TestContext) void {
        self.validators.deinit();
        self.key_manager.deinit();
    }

    /// Create an attestation for a given validator
    pub fn createAttestation(self: *const TestContext, validator_id: ValidatorIndex) attestation.Attestation {
        return attestation.Attestation{
            .validator_id = validator_id,
            .data = self.attestation_data,
        };
    }

    /// Create attestation with custom data (for different groups)
    pub fn createAttestationWithData(self: *const TestContext, validator_id: ValidatorIndex, data: attestation.AttestationData) attestation.Attestation {
        _ = self;
        return attestation.Attestation{
            .validator_id = validator_id,
            .data = data,
        };
    }

    /// Sign an attestation and add to signatures map
    pub fn addToSignatureMap(
        self: *TestContext,
        signatures_map: *SignaturesMap,
        validator_id: ValidatorIndex,
    ) !void {
        const att = self.createAttestation(validator_id);
        const sig_bytes = try self.key_manager.signAttestation(&att, self.allocator);
        try signatures_map.put(
            .{ .validator_id = validator_id, .data_root = self.data_root },
            .{ .slot = self.attestation_data.slot, .signature = sig_bytes },
        );
    }

    /// Create an aggregated proof covering specified validators
    pub fn createAggregatedProof(
        self: *TestContext,
        validator_ids: []const ValidatorIndex,
    ) !aggregation.AggregatedSignatureProof {
        // Create attestations and collect signatures
        var sigs = std.ArrayList(xmss.Signature).init(self.allocator);
        defer {
            for (sigs.items) |*sig| sig.deinit();
            sigs.deinit();
        }

        var pks = std.ArrayList(xmss.PublicKey).init(self.allocator);
        defer {
            for (pks.items) |*pk| pk.deinit();
            pks.deinit();
        }

        for (validator_ids) |vid| {
            const att = self.createAttestation(vid);
            const sig_bytes = try self.key_manager.signAttestation(&att, self.allocator);
            var sig = try xmss.Signature.fromBytes(&sig_bytes);
            errdefer sig.deinit();

            const val = try self.validators.get(@intCast(vid));
            var pk = try xmss.PublicKey.fromBytes(&val.pubkey);
            errdefer pk.deinit();

            try sigs.append(sig);
            try pks.append(pk);
        }

        // Build handle arrays
        var pk_handles = try self.allocator.alloc(*const xmss.HashSigPublicKey, pks.items.len);
        defer self.allocator.free(pk_handles);
        var sig_handles = try self.allocator.alloc(*const xmss.HashSigSignature, sigs.items.len);
        defer self.allocator.free(sig_handles);

        for (pks.items, 0..) |*pk, i| {
            pk_handles[i] = pk.handle;
        }
        for (sigs.items, 0..) |*sig, i| {
            sig_handles[i] = sig.handle;
        }

        // Build participants bitset
        var participants = try attestation.AggregationBits.init(self.allocator);
        errdefer participants.deinit();
        for (validator_ids) |vid| {
            try attestation.aggregationBitsSet(&participants, @intCast(vid), true);
        }

        // Compute message hash
        var message_hash: [32]u8 = undefined;
        try ssz.hashTreeRoot(attestation.AttestationData, self.attestation_data, &message_hash, self.allocator);

        // Aggregate
        var proof = try aggregation.AggregatedSignatureProof.init(self.allocator);
        errdefer proof.deinit();

        try aggregation.AggregatedSignatureProof.aggregate(
            participants,
            pk_handles,
            sig_handles,
            &message_hash,
            self.attestation_data.slot,
            &proof,
        );

        return proof;
    }

    /// Add an aggregated proof to the payloads map for a specific validator
    pub fn addAggregatedPayload(
        self: *TestContext,
        payloads_map: *AggregatedPayloadsMap,
        lookup_validator_id: ValidatorIndex,
        proof: aggregation.AggregatedSignatureProof,
    ) !void {
        const key = SignatureKey{ .validator_id = lookup_validator_id, .data_root = self.data_root };
        const gop = try payloads_map.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = AggregatedPayloadsList.init(self.allocator);
        }
        try gop.value_ptr.append(.{
            .slot = self.attestation_data.slot,
            .proof = proof,
        });
    }

    /// Helper to check if a bitset contains exactly the specified validators
    pub fn checkParticipants(bits: *const attestation.AggregationBits, expected_validators: []const ValidatorIndex) !bool {
        var count: usize = 0;
        for (0..bits.len()) |i| {
            if (try bits.get(i)) {
                count += 1;
                var found = false;
                for (expected_validators) |vid| {
                    if (i == vid) {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            }
        }
        return count == expected_validators.len;
    }
};

fn deinitSignaturesMap(map: *SignaturesMap) void {
    map.deinit();
}

fn deinitPayloadsMap(map: *AggregatedPayloadsMap) void {
    var it = map.valueIterator();
    while (it.next()) |list| {
        for (list.items) |*item| {
            item.proof.deinit();
        }
        list.deinit();
    }
    map.deinit();
}

// ============================================================================
// Test 1: All 4 signatures in signatures_map (pure signatures_map)
// ============================================================================
test "computeAggregatedSignatures: all 4 in signatures_map" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    // Create attestations for all 4 validators
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    // Add all 4 signatures to signatures_map
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);
    try ctx.addToSignatureMap(&signatures_map, 2);
    try ctx.addToSignatureMap(&signatures_map, 3);

    // No aggregated payloads
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 1 aggregated attestation covering all 4 validators
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 0, 1, 2, 3 }));
}

// ============================================================================
// Test 2: 2 in signatures_map, 2 in aggregated_proof (clean split)
// ============================================================================
test "computeAggregatedSignatures: 2 signatures_map, 2 in aggregated proof" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    // Create attestations for all 4 validators
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    // Add signatures for validators 0, 1 only
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);

    // Create aggregated proof for validators 2, 3
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_2_3 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 2, 3 });
    // Add to both validator 2 and 3's lookup
    try ctx.addAggregatedPayload(&payloads_map, 2, proof_2_3);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 2 aggregated attestations
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

    // Verify one covers 2,3 and one covers 0,1
    var found_0_1 = false;
    var found_2_3 = false;

    for (0..agg_ctx.attestations.len()) |i| {
        const att_bits = &(try agg_ctx.attestations.get(i)).aggregation_bits;
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 0, 1 })) {
            found_0_1 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 2, 3 })) {
            found_2_3 = true;
        }
    }

    try std.testing.expect(found_0_1);
    try std.testing.expect(found_2_3);
}

// ============================================================================
// Test 3: 2 in signatures_map, all 4 in aggregated_proof (full overlap - no redundancy)
// When stored proof covers ALL validators, signatures_map aggregation is skipped
// ============================================================================
test "computeAggregatedSignatures: full overlap uses stored only" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    // Create attestations for all 4 validators
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    // Add signatures for validators 0, 1 only
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);

    // Create aggregated proof for ALL 4 validators (fully covers 0,1)
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_all = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 0, 1, 2, 3 });
    try ctx.addAggregatedPayload(&payloads_map, 2, proof_all);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have only 1 aggregated attestation:
    // - Stored proof covering {0,1,2,3}
    // - signatures_map {0,1} is NOT included because all validators are covered by stored proof
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 0, 1, 2, 3 }));
}

// ============================================================================
// Test 4: Greedy set-cover with competing proofs
// ============================================================================
test "computeAggregatedSignatures: greedy set-cover" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    // Create attestations for all 4 validators
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    // Add signature only for validator 0
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);

    // Create competing aggregated proofs:
    // Proof A: covers 1,2,3 (optimal)
    // Proof B: covers 1,2 (suboptimal)
    // Proof C: covers 2,3 (suboptimal)
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_a = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 1, 2, 3 });
    const proof_b = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 1, 2 });

    // Add proof A and B for validator 1 lookup
    try ctx.addAggregatedPayload(&payloads_map, 1, proof_a);
    try ctx.addAggregatedPayload(&payloads_map, 1, proof_b);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 2 aggregated attestations:
    // 1. signatures_map for validator 0
    // 2. Aggregated proof A for validators 1,2,3
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

    // Verify one covers 0 and one covers 1,2,3
    var found_0 = false;
    var found_1_2_3 = false;

    for (0..agg_ctx.attestations.len()) |i| {
        const att_bits = &(try agg_ctx.attestations.get(i)).aggregation_bits;
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{0})) {
            found_0 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 1, 2, 3 })) {
            found_1_2_3 = true;
        }
    }

    try std.testing.expect(found_0);
    try std.testing.expect(found_1_2_3);
}

// ============================================================================
// Test 5: Partial signatures_map overlap with stored proof (maximize coverage)
// signatures_map {1,2} + Stored {2,3,4} = Both included for maximum coverage {1,2,3,4}
// ============================================================================
test "computeAggregatedSignatures: partial signatures_map overlap maximizes coverage" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 5);
    defer ctx.deinit();

    // Create attestations for validators 1,2,3,4
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
        ctx.createAttestation(4),
    };

    // Add signatures_map for validators 1, 2 only
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 1);
    try ctx.addToSignatureMap(&signatures_map, 2);

    // Create aggregated proof for validators 2, 3, 4 (overlaps with signatures_map on 2)
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_2_3_4 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 2, 3, 4 });
    try ctx.addAggregatedPayload(&payloads_map, 3, proof_2_3_4);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have 2 aggregated attestations:
    // 1. Stored proof covering {2,3,4}
    // 2. signatures_map aggregation covering {1} only (validator 2 excluded - already in stored proof)
    // Together they cover {1,2,3,4} without redundancy
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

    // Verify both aggregations exist
    var found_1 = false;
    var found_2_3_4 = false;

    for (0..agg_ctx.attestations.len()) |i| {
        const att_bits = &(try agg_ctx.attestations.get(i)).aggregation_bits;
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{1})) {
            found_1 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 2, 3, 4 })) {
            found_2_3_4 = true;
        }
    }

    try std.testing.expect(found_1);
    try std.testing.expect(found_2_3_4);
}

// ============================================================================
// Test 6: Empty attestations list
// ============================================================================
test "computeAggregatedSignatures: empty attestations" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{};

    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have no attestations
    try std.testing.expectEqual(@as(usize, 0), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 0), agg_ctx.attestation_signatures.len());
}

// ============================================================================
// Test 7: No signatures available
// ============================================================================
test "computeAggregatedSignatures: no signatures available" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    // Create attestations for all 4 validators
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    // No signatures_map signatures
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    // No aggregated payloads
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have no attestations (all validators uncovered)
    try std.testing.expectEqual(@as(usize, 0), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 0), agg_ctx.attestation_signatures.len());
}

// ============================================================================
// Test 8: Multiple data roots (separate groups)
// ============================================================================
test "computeAggregatedSignatures: multiple data roots" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    // Create second attestation data with different slot
    const att_data_2 = attestation.AttestationData{
        .slot = 10,
        .head = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .target = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
    const data_root_2 = try att_data_2.sszRoot(allocator);

    // Create attestations: 0,1 with data_root_1, 2,3 with data_root_2
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0), // data_root_1
        ctx.createAttestation(1), // data_root_1
        ctx.createAttestationWithData(2, att_data_2), // data_root_2
        ctx.createAttestationWithData(3, att_data_2), // data_root_2
    };

    // Add signatures_map signatures for all
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    // Signatures for group 1 (data_root_1)
    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);

    // Signatures for group 2 (data_root_2) - need to sign with different data
    const att_2 = attestations_list[2];
    const sig_bytes_2 = try ctx.key_manager.signAttestation(&att_2, allocator);
    try signatures_map.put(
        .{ .validator_id = 2, .data_root = data_root_2 },
        .{ .slot = att_data_2.slot, .signature = sig_bytes_2 },
    );

    const att_3 = attestations_list[3];
    const sig_bytes_3 = try ctx.key_manager.signAttestation(&att_3, allocator);
    try signatures_map.put(
        .{ .validator_id = 3, .data_root = data_root_2 },
        .{ .slot = att_data_2.slot, .signature = sig_bytes_3 },
    );

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 2 aggregated attestations (one per data root)
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

    // Verify one covers 0,1 and one covers 2,3
    var found_0_1 = false;
    var found_2_3 = false;

    for (0..agg_ctx.attestations.len()) |i| {
        const att_bits = &(try agg_ctx.attestations.get(i)).aggregation_bits;
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 0, 1 })) {
            found_0_1 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 2, 3 })) {
            found_2_3 = true;
        }
    }

    try std.testing.expect(found_0_1);
    try std.testing.expect(found_2_3);
}

// ============================================================================
// Test 9: Single validator attestation
// ============================================================================
test "computeAggregatedSignatures: single validator" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 1);
    defer ctx.deinit();

    // Create attestation for single validator
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
    };

    // Add signatures_map signature
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 1 aggregated attestation with 1 validator
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{0}));
}

// ============================================================================
// Test 10: Complex scenario with 3 attestation_data types
// - Group 1: All validators have signatures_map signatures (pure signatures_map)
// - Group 2: All validators covered by aggregated_payload only (pure stored)
// - Group 3: Overlap - some signatures_map + stored proof covering some signatures_map validators
// ============================================================================
test "computeAggregatedSignatures: complex 3 groups" {
    const allocator = std.testing.allocator;

    // Need 10 validators for this test
    var ctx = try TestContext.init(allocator, 10);
    defer ctx.deinit();

    // Create 3 different attestation data types
    const att_data_1 = ctx.attestation_data; // slot 5 (uses ctx.data_root for signatures_map)

    const att_data_2 = attestation.AttestationData{
        .slot = 10,
        .head = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .target = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
    const data_root_2 = try att_data_2.sszRoot(allocator);

    const att_data_3 = attestation.AttestationData{
        .slot = 15,
        .head = .{ .root = [_]u8{3} ** 32, .slot = 15 },
        .target = .{ .root = [_]u8{3} ** 32, .slot = 15 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
    const data_root_3 = try att_data_3.sszRoot(allocator);

    // Create attestations for all groups:
    // Group 1 (data_root_1): validators 0,1,2 - pure signatures_map
    // Group 2 (data_root_2): validators 3,4,5 - pure stored
    // Group 3 (data_root_3): validators 6,7,8,9 - overlap (signatures_map 6,7 + stored 7,8,9)
    var attestations_list = [_]attestation.Attestation{
        // Group 1
        ctx.createAttestationWithData(0, att_data_1),
        ctx.createAttestationWithData(1, att_data_1),
        ctx.createAttestationWithData(2, att_data_1),
        // Group 2
        ctx.createAttestationWithData(3, att_data_2),
        ctx.createAttestationWithData(4, att_data_2),
        ctx.createAttestationWithData(5, att_data_2),
        // Group 3
        ctx.createAttestationWithData(6, att_data_3),
        ctx.createAttestationWithData(7, att_data_3),
        ctx.createAttestationWithData(8, att_data_3),
        ctx.createAttestationWithData(9, att_data_3),
    };

    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    // Group 1: Add signatures_map signatures for validators 0,1,2
    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);
    try ctx.addToSignatureMap(&signatures_map, 2);

    // Group 2: No signatures_map signatures (all from stored)

    // Group 3: Add signatures_map signatures for validators 6,7 only
    const att_6 = attestations_list[6];
    const sig_bytes_6 = try ctx.key_manager.signAttestation(&att_6, allocator);
    try signatures_map.put(
        .{ .validator_id = 6, .data_root = data_root_3 },
        .{ .slot = att_data_3.slot, .signature = sig_bytes_6 },
    );

    const att_7 = attestations_list[7];
    const sig_bytes_7 = try ctx.key_manager.signAttestation(&att_7, allocator);
    try signatures_map.put(
        .{ .validator_id = 7, .data_root = data_root_3 },
        .{ .slot = att_data_3.slot, .signature = sig_bytes_7 },
    );

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    // Group 2: Create aggregated proof for validators 3,4,5
    {
        // Need to create proof with att_data_2
        var sigs = std.ArrayList(xmss.Signature).init(allocator);
        defer {
            for (sigs.items) |*sig| sig.deinit();
            sigs.deinit();
        }
        var pks = std.ArrayList(xmss.PublicKey).init(allocator);
        defer {
            for (pks.items) |*pk| pk.deinit();
            pks.deinit();
        }

        for ([_]ValidatorIndex{ 3, 4, 5 }) |vid| {
            const att = attestations_list[vid];
            const sig_bytes = try ctx.key_manager.signAttestation(&att, allocator);
            var sig = try xmss.Signature.fromBytes(&sig_bytes);
            errdefer sig.deinit();
            const val = try ctx.validators.get(@intCast(vid));
            var pk = try xmss.PublicKey.fromBytes(&val.pubkey);
            errdefer pk.deinit();
            try sigs.append(sig);
            try pks.append(pk);
        }

        var pk_handles = try allocator.alloc(*const xmss.HashSigPublicKey, 3);
        defer allocator.free(pk_handles);
        var sig_handles = try allocator.alloc(*const xmss.HashSigSignature, 3);
        defer allocator.free(sig_handles);

        for (pks.items, 0..) |*pk, i| pk_handles[i] = pk.handle;
        for (sigs.items, 0..) |*sig, i| sig_handles[i] = sig.handle;

        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();
        for ([_]ValidatorIndex{ 3, 4, 5 }) |vid| {
            try attestation.aggregationBitsSet(&participants, @intCast(vid), true);
        }

        var message_hash: [32]u8 = undefined;
        try ssz.hashTreeRoot(attestation.AttestationData, att_data_2, &message_hash, allocator);

        var proof = try aggregation.AggregatedSignatureProof.init(allocator);
        errdefer proof.deinit();

        try aggregation.AggregatedSignatureProof.aggregate(
            participants,
            pk_handles,
            sig_handles,
            &message_hash,
            att_data_2.slot,
            &proof,
        );

        // Add to payloads_map for validator 3
        const key = SignatureKey{ .validator_id = 3, .data_root = data_root_2 };
        const gop = try payloads_map.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = AggregatedPayloadsList.init(allocator);
        }
        try gop.value_ptr.append(.{ .slot = att_data_2.slot, .proof = proof });
    }

    // Group 3: Create aggregated proof for validators 7,8,9 (overlaps with signatures_map on 7)
    {
        var sigs = std.ArrayList(xmss.Signature).init(allocator);
        defer {
            for (sigs.items) |*sig| sig.deinit();
            sigs.deinit();
        }
        var pks = std.ArrayList(xmss.PublicKey).init(allocator);
        defer {
            for (pks.items) |*pk| pk.deinit();
            pks.deinit();
        }

        for ([_]ValidatorIndex{ 7, 8, 9 }) |vid| {
            const att = attestations_list[vid];
            const sig_bytes = try ctx.key_manager.signAttestation(&att, allocator);
            var sig = try xmss.Signature.fromBytes(&sig_bytes);
            errdefer sig.deinit();
            const val = try ctx.validators.get(@intCast(vid));
            var pk = try xmss.PublicKey.fromBytes(&val.pubkey);
            errdefer pk.deinit();
            try sigs.append(sig);
            try pks.append(pk);
        }

        var pk_handles = try allocator.alloc(*const xmss.HashSigPublicKey, 3);
        defer allocator.free(pk_handles);
        var sig_handles = try allocator.alloc(*const xmss.HashSigSignature, 3);
        defer allocator.free(sig_handles);

        for (pks.items, 0..) |*pk, i| pk_handles[i] = pk.handle;
        for (sigs.items, 0..) |*sig, i| sig_handles[i] = sig.handle;

        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();
        for ([_]ValidatorIndex{ 7, 8, 9 }) |vid| {
            try attestation.aggregationBitsSet(&participants, @intCast(vid), true);
        }

        var message_hash: [32]u8 = undefined;
        try ssz.hashTreeRoot(attestation.AttestationData, att_data_3, &message_hash, allocator);

        var proof = try aggregation.AggregatedSignatureProof.init(allocator);
        errdefer proof.deinit();

        try aggregation.AggregatedSignatureProof.aggregate(
            participants,
            pk_handles,
            sig_handles,
            &message_hash,
            att_data_3.slot,
            &proof,
        );

        // Add to payloads_map for validator 8 (one of the remaining signatures_map validators)
        const key = SignatureKey{ .validator_id = 8, .data_root = data_root_3 };
        const gop = try payloads_map.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = AggregatedPayloadsList.init(allocator);
        }
        try gop.value_ptr.append(.{ .slot = att_data_3.slot, .proof = proof });
    }

    // Execute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Expected results:
    // - Group 1: 1 attestation from signatures_map {0,1,2}
    // - Group 2: 1 attestation from stored {3,4,5}
    // - Group 3: 2 attestations - stored {7,8,9} + signatures_map {6} (7 excluded from signatures_map)
    // Total: 4 attestations
    try std.testing.expectEqual(@as(usize, 4), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 4), agg_ctx.attestation_signatures.len());

    // Verify each group
    var found_0_1_2 = false;
    var found_3_4_5 = false;
    var found_7_8_9 = false;
    var found_6 = false;

    for (0..agg_ctx.attestations.len()) |i| {
        const att_bits = &(try agg_ctx.attestations.get(i)).aggregation_bits;
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 0, 1, 2 })) {
            found_0_1_2 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 3, 4, 5 })) {
            found_3_4_5 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 7, 8, 9 })) {
            found_7_8_9 = true;
        }
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{6})) {
            found_6 = true;
        }
    }

    try std.testing.expect(found_0_1_2); // Group 1: pure signatures_map
    try std.testing.expect(found_3_4_5); // Group 2: pure stored
    try std.testing.expect(found_7_8_9); // Group 3: stored proof
    try std.testing.expect(found_6); // Group 3: remaining signatures_map (7 excluded)
}

// ============================================================================
// Test 11: Validator without signature is excluded
// signatures_map {1} + aggregated_payload {2,3} = attestations {1} + {2,3}, validator 4 excluded
// ============================================================================
test "computeAggregatedSignatures: validator without signature excluded" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 5);
    defer ctx.deinit();

    // Create attestations for validators 1, 2, 3, 4
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
        ctx.createAttestation(4),
    };

    // Add signature only for validator 1 to signatures_map
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 1);

    // Create aggregated proof for validators 2, 3 only
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_2_3 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 2, 3 });
    try ctx.addAggregatedPayload(&payloads_map, 2, proof_2_3);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 2 aggregated attestations:
    // 1. signatures_map for validator 1
    // 2. Aggregated proof for validators 2, 3
    // Validator 4 should be excluded (no signature available)
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

    // Verify one covers {1} and one covers {2, 3}
    var found_1 = false;
    var found_2_3 = false;

    for (0..agg_ctx.attestations.len()) |i| {
        const att_bits = &(try agg_ctx.attestations.get(i)).aggregation_bits;

        // Check for validator 1 only
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{1})) {
            found_1 = true;
        }
        // Check for validators 2, 3
        if (try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 2, 3 })) {
            found_2_3 = true;
        }

        // Verify validator 4 is NOT included in any attestation
        // If the bitlist has fewer than 5 elements, validator 4 can't be included
        if (att_bits.len() > 4) {
            try std.testing.expect(!(try att_bits.get(4)));
        }
    }

    try std.testing.expect(found_1);
    try std.testing.expect(found_2_3);
}

// ============================================================================
// Test 12: Single attestation lookup key with all validators in aggregated payload
// Attestations for validators 1,2 nothing in signatures_map,
// aggregated_payload {1,2,3,4} indexed by validator 1 => all bits set
// Validators 3 and 4 are included although not covered  by attestations_list
// ============================================================================
test "computeAggregatedSignatures: empty signatures_map with full aggregated payload" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 5);
    defer ctx.deinit();

    // Create attestations for validators 1, 2
    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
    };

    // Empty signatures_map - nothing found while iterating
    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    // Create aggregated proof for validators 1, 2, 3, 4 indexed by validator 1
    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_1_2_3_4 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 1, 2, 3, 4 });
    try ctx.addAggregatedPayload(&payloads_map, 1, proof_1_2_3_4);

    // Create aggregation context and compute
    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.computeAggregatedSignatures(
        &attestations_list,
        &ctx.validators,
        &signatures_map,
        &payloads_map,
    );

    // Should have exactly 1 aggregated attestation covering all 4 validators
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    // Verify attestation_bits are set for validators 1, 2, 3, 4
    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 1, 2, 3, 4 }));
}
