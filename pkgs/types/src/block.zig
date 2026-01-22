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
