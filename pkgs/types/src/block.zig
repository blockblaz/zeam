const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_metrics = @import("@zeam/metrics");
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

/// Stored signatures_map entry: per-validator signature + slot metadata.
pub const StoredSignature = struct {
    slot: Slot,
    signature: SIGBYTES,
};

/// Map type for gossip signatures: AttestationData -> per-validator signatures.
/// Wraps AutoHashMap to manage the lifecycle of inner maps and provide
/// convenience helpers for common operations.
pub const SignaturesMap = struct {
    pub const InnerMap = std.AutoHashMap(ValidatorIndex, StoredSignature);

    const InnerHashMap = std.AutoHashMap(attestation.AttestationData, InnerMap);

    inner: InnerHashMap,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SignaturesMap {
        return .{
            .inner = InnerHashMap.init(allocator),
            .allocator = allocator,
        };
    }

    /// Deinit all inner maps, then the outer map itself.
    pub fn deinit(self: *SignaturesMap) void {
        var it = self.inner.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit();
        self.inner.deinit();
    }

    /// Look up (or create) the inner map for `att_data` and insert the signature.
    pub fn addSignature(
        self: *SignaturesMap,
        att_data: attestation.AttestationData,
        validator_id: utils.ValidatorIndex,
        sig: StoredSignature,
    ) !void {
        const gop = try self.inner.getOrPut(att_data);
        if (!gop.found_existing) {
            gop.value_ptr.* = InnerMap.init(self.allocator);
        }
        try gop.value_ptr.put(validator_id, sig);
    }

    pub fn getOrPut(self: *SignaturesMap, key: attestation.AttestationData) !InnerHashMap.GetOrPutResult {
        return self.inner.getOrPut(key);
    }

    pub fn getPtr(self: *const SignaturesMap, key: attestation.AttestationData) ?*InnerMap {
        return self.inner.getPtr(key);
    }

    pub fn get(self: *const SignaturesMap, key: attestation.AttestationData) ?InnerMap {
        return self.inner.get(key);
    }

    pub fn fetchRemove(self: *SignaturesMap, key: attestation.AttestationData) ?InnerHashMap.KV {
        return self.inner.fetchRemove(key);
    }

    /// Remove an entry and deinit its inner map. No-op if key not present.
    pub fn removeAndDeinit(self: *SignaturesMap, key: attestation.AttestationData) void {
        if (self.inner.fetchRemove(key)) |kv| {
            var inner = kv.value;
            inner.deinit();
        }
    }

    pub fn put(self: *SignaturesMap, key: attestation.AttestationData, value: InnerMap) !void {
        return self.inner.put(key, value);
    }

    pub fn iterator(self: *const SignaturesMap) InnerHashMap.Iterator {
        return self.inner.iterator();
    }

    pub fn count(self: *const SignaturesMap) InnerHashMap.Size {
        return self.inner.count();
    }
};

/// Stored aggregated payload entry
pub const StoredAggregatedPayload = struct {
    slot: Slot,
    proof: aggregation.AggregatedSignatureProof,
};

/// List of aggregated payloads for a single key
pub const AggregatedPayloadsList = std.ArrayList(StoredAggregatedPayload);

/// Map type for aggregated payloads: AttestationData -> list of AggregatedSignatureProof.
pub const AggregatedPayloadsMap = std.AutoHashMap(attestation.AttestationData, AggregatedPayloadsList);

/// Aggregate all individual gossip signatures in an inner map into a single proof.
/// The caller owns the returned proof and must call `deinit` on it.
pub fn AggregateInnerMap(
    allocator: Allocator,
    inner_map: *const SignaturesMap.InnerMap,
    att_data: attestation.AttestationData,
    validators: *const Validators,
) !aggregation.AggregatedSignatureProof {
    var message_hash: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(attestation.AttestationData, att_data, &message_hash, allocator);

    var sigs: std.ArrayList(xmss.Signature) = .empty;
    defer {
        for (sigs.items) |*sig| sig.deinit();
        sigs.deinit(allocator);
    }

    var pks: std.ArrayList(xmss.PublicKey) = .empty;
    defer {
        for (pks.items) |*pk| pk.deinit();
        pks.deinit(allocator);
    }

    var participants = try attestation.AggregationBits.init(allocator);
    defer participants.deinit();

    const ValidatorEntry = struct {
        validator_id: utils.ValidatorIndex,
        stored_sig: *const StoredSignature,
    };
    var validator_entries: std.ArrayList(ValidatorEntry) = .empty;
    defer validator_entries.deinit(allocator);

    var it = inner_map.iterator();
    while (it.next()) |entry| {
        try validator_entries.append(allocator, .{
            .validator_id = entry.key_ptr.*,
            .stored_sig = entry.value_ptr,
        });
    }

    std.mem.sort(ValidatorEntry, validator_entries.items, {}, struct {
        fn lessThan(_: void, a: ValidatorEntry, b: ValidatorEntry) bool {
            return a.validator_id < b.validator_id;
        }
    }.lessThan);

    for (validator_entries.items) |ve| {
        const validator_idx: usize = @intCast(ve.validator_id);

        var sig = try xmss.Signature.fromBytes(ve.stored_sig.signature[0..]);
        errdefer sig.deinit();

        const val = try validators.get(ve.validator_id);
        var pk = try xmss.PublicKey.fromBytes(&val.attestation_pubkey);
        errdefer pk.deinit();

        try attestation.aggregationBitsSet(&participants, validator_idx, true);
        try sigs.append(allocator, sig);
        try pks.append(allocator, pk);
    }

    const num_sigs = sigs.items.len;
    const sig_handles = try allocator.alloc(*const xmss.HashSigSignature, num_sigs);
    defer allocator.free(sig_handles);
    const pk_handles = try allocator.alloc(*const xmss.HashSigPublicKey, num_sigs);
    defer allocator.free(pk_handles);

    for (sigs.items, 0..) |*sig, i| sig_handles[i] = sig.handle;
    for (pks.items, 0..) |*pk, i| pk_handles[i] = pk.handle;

    var proof = try aggregation.AggregatedSignatureProof.init(allocator);
    errdefer proof.deinit();

    try aggregation.AggregatedSignatureProof.aggregate(
        allocator,
        participants,
        &.{},
        &.{},
        pk_handles,
        sig_handles,
        &message_hash,
        @intCast(att_data.slot),
        &proof,
    );

    return proof;
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
        var obj = json.ObjectMap.empty;

        var attestations_array = json.Array.init(allocator);
        errdefer attestations_array.deinit();

        for (self.attestations.constSlice()) |att| {
            try attestations_array.append(try att.toJson(allocator));
        }
        try obj.put(allocator, "attestations", json.Value{ .array = attestations_array });

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
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put(allocator, "proposer_index", json.Value{ .integer = @as(i64, @intCast(self.proposer_index)) });
        try obj.put(allocator, "parent_root", json.Value{ .string = try bytesToHex(allocator, &self.parent_root) });
        try obj.put(allocator, "state_root", json.Value{ .string = try bytesToHex(allocator, &self.state_root) });
        try obj.put(allocator, "body_root", json.Value{ .string = try bytesToHex(allocator, &self.body_root) });
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
        val.object.deinit(allocator);
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
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put(allocator, "proposer_index", json.Value{ .integer = @as(i64, @intCast(self.proposer_index)) });
        try obj.put(allocator, "parent_root", json.Value{ .string = try bytesToHex(allocator, &self.parent_root) });
        try obj.put(allocator, "state_root", json.Value{ .string = try bytesToHex(allocator, &self.state_root) });
        try obj.put(allocator, "body", try self.body.toJson(allocator));
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
        var obj = json.ObjectMap.empty;

        var groups_array = json.Array.init(allocator);
        errdefer groups_array.deinit();

        for (self.attestation_signatures.constSlice()) |group| {
            try groups_array.append(try group.toJson(allocator));
        }

        try obj.put(allocator, "attestation_signatures", json.Value{ .array = groups_array });
        try obj.put(allocator, "proposer_signature", json.Value{ .string = try bytesToHex(allocator, &self.proposer_signature) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlockSignatures, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const SignedBlock = struct {
    block: BeamBlock,
    signature: BlockSignatures,

    pub fn deinit(self: *SignedBlock) void {
        self.block.deinit();
        self.signature.deinit();
    }

    pub fn toJson(self: *const SignedBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "block", try self.block.toJson(allocator));
        try obj.put(allocator, "signature", try self.signature.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedBlock, allocator: Allocator) ![]const u8 {
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

    /// Compute aggregated signatures using recursive aggregation:
    /// Step 1: Derive AttestationData keys from signatures_map ∪ new_payloads
    /// Step 2: Greedy child proof selection — new_payloads first, then known_payloads as helpers
    /// Step 3: Collect individual gossip signatures not covered by children
    /// Step 4: Recursive aggregate — combine selected children + remaining gossip sigs
    pub fn computeAggregatedSignatures(
        self: *Self,
        validators: *const Validators,
        signatures_map: *const SignaturesMap,
        new_payloads: ?*const AggregatedPayloadsMap,
        known_payloads: ?*const AggregatedPayloadsMap,
    ) !void {
        const allocator = self.allocator;

        // Step 1: Derive unique AttestationData keys from signatures_map ∪ new_payloads
        var att_data_set = std.AutoHashMap(attestation.AttestationData, void).init(allocator);
        defer att_data_set.deinit();

        {
            var it = signatures_map.iterator();
            while (it.next()) |entry| {
                try att_data_set.put(entry.key_ptr.*, {});
            }
        }
        if (new_payloads) |np| {
            var it = np.iterator();
            while (it.next()) |entry| {
                try att_data_set.put(entry.key_ptr.*, {});
            }
        }

        // Process each AttestationData
        var data_it = att_data_set.iterator();
        while (data_it.next()) |data_entry| {
            const data = data_entry.key_ptr.*;
            const epoch: u64 = data.slot;
            var message_hash: [32]u8 = undefined;
            try zeam_utils.hashTreeRoot(attestation.AttestationData, data, &message_hash, allocator);

            // Step 2: Greedy child proof selection — new_payloads first, then known_payloads as helpers
            var selected_children: std.ArrayList(aggregation.AggregatedSignatureProof) = .empty;
            defer {
                for (selected_children.items) |*child| {
                    child.deinit();
                }
                selected_children.deinit(allocator);
            }

            // We need to know max_validator for bitset sizing — derive from validators count
            const max_validator = validators.len();

            var covered_by_children = try std.DynamicBitSet.initEmpty(allocator, max_validator);
            defer covered_by_children.deinit();

            // Dummy empty bitset for gossip_available (not known yet)
            var empty_available = try std.DynamicBitSet.initEmpty(allocator, max_validator);
            defer empty_available.deinit();

            try extendProofsGreedily(
                allocator,
                new_payloads,
                data,
                &selected_children,
                &covered_by_children,
                &empty_available,
            );
            try extendProofsGreedily(
                allocator,
                known_payloads,
                data,
                &selected_children,
                &covered_by_children,
                &empty_available,
            );

            // Step 3: Collect individual gossip signatures not covered by selected children
            var sigmap_sigs: std.ArrayList(xmss.Signature) = .empty;
            defer {
                for (sigmap_sigs.items) |*sig| {
                    sig.deinit();
                }
                sigmap_sigs.deinit(allocator);
            }

            var sigmap_pks: std.ArrayList(xmss.PublicKey) = .empty;
            defer {
                for (sigmap_pks.items) |*pk| {
                    pk.deinit();
                }
                sigmap_pks.deinit(allocator);
            }

            var sigmap_vids: std.ArrayList(usize) = .empty;
            defer sigmap_vids.deinit(allocator);

            const inner_map = signatures_map.get(data);
            if (inner_map) |im| {
                var vid_it = im.iterator();
                while (vid_it.next()) |entry| {
                    const vid: usize = @intCast(entry.key_ptr.*);
                    const sig_entry = entry.value_ptr.*;

                    // Skip if already covered by children
                    if (vid < covered_by_children.capacity() and covered_by_children.isSet(vid)) continue;

                    if (std.mem.eql(u8, &sig_entry.signature, &ZERO_SIGBYTES)) continue;

                    var sig = xmss.Signature.fromBytes(&sig_entry.signature) catch continue;
                    errdefer sig.deinit();

                    if (vid >= validators.len()) {
                        sig.deinit();
                        continue;
                    }

                    const val = validators.get(vid) catch {
                        sig.deinit();
                        continue;
                    };
                    const pk = xmss.PublicKey.fromBytes(&val.attestation_pubkey) catch {
                        sig.deinit();
                        continue;
                    };

                    try sigmap_sigs.append(allocator, sig);
                    try sigmap_pks.append(allocator, pk);
                    try sigmap_vids.append(allocator, vid);
                }
            }

            const has_gossip = sigmap_sigs.items.len > 0;
            const has_children = selected_children.items.len > 0;

            if (!has_gossip and !has_children) continue;

            // Build gossip participants bitfield and handle arrays
            var xmss_participants: ?attestation.AggregationBits = null;
            defer if (xmss_participants) |*gp| gp.deinit();

            var pk_handles_buf: ?[]*const xmss.HashSigPublicKey = null;
            defer if (pk_handles_buf) |buf| allocator.free(buf);
            var sig_handles_buf: ?[]*const xmss.HashSigSignature = null;
            defer if (sig_handles_buf) |buf| allocator.free(buf);

            var pk_handles: []*const xmss.HashSigPublicKey = &.{};
            var sig_handles: []*const xmss.HashSigSignature = &.{};

            if (has_gossip) {
                var gp = try attestation.AggregationBits.init(allocator);
                errdefer gp.deinit();

                const pks = try allocator.alloc(*const xmss.HashSigPublicKey, sigmap_sigs.items.len);
                errdefer allocator.free(pks);
                const sigs = try allocator.alloc(*const xmss.HashSigSignature, sigmap_sigs.items.len);
                errdefer allocator.free(sigs);

                for (sigmap_vids.items, 0..) |vid, idx| {
                    try attestation.aggregationBitsSet(&gp, vid, true);
                    pks[idx] = sigmap_pks.items[idx].handle;
                    sigs[idx] = sigmap_sigs.items[idx].handle;
                }

                xmss_participants = gp;
                pk_handles_buf = pks;
                sig_handles_buf = sigs;
                pk_handles = pks[0..sigmap_sigs.items.len];
                sig_handles = sigs[0..sigmap_sigs.items.len];
            }

            // If only 1 child and no gossip, pass through the child directly
            if (!has_gossip and selected_children.items.len == 1) {
                const child = &selected_children.items[0];

                // Create attestation bits from the child's participants
                var att_bits: ?attestation.AggregationBits = try attestation.AggregationBits.init(allocator);
                defer if (att_bits) |*ab| ab.deinit();
                for (0..child.participants.len()) |i| {
                    if (child.participants.get(i) catch false) {
                        try attestation.aggregationBitsSet(&att_bits.?, i, true);
                    }
                }

                // Clone the child proof for the result (original will be freed by deferred cleanup)
                var cloned_child: aggregation.AggregatedSignatureProof = undefined;
                try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, child.*, &cloned_child);
                errdefer cloned_child.deinit();

                try self.attestations.append(.{ .aggregation_bits = att_bits.?, .data = data });
                att_bits = null; // ownership transferred to self.attestations
                try self.attestation_signatures.append(cloned_child);
                continue;
            }

            // Recursive aggregation: children + gossip
            var proof = try aggregation.AggregatedSignatureProof.init(allocator);
            errdefer proof.deinit();

            // Build per-child pub key arrays for recursive aggregation
            var child_pk_allocs: std.ArrayList([]*const xmss.HashSigPublicKey) = .empty;
            defer {
                for (child_pk_allocs.items) |arr| allocator.free(arr);
                child_pk_allocs.deinit(allocator);
            }
            var child_pk_slices: std.ArrayList([]*const xmss.HashSigPublicKey) = .empty;
            defer child_pk_slices.deinit(allocator);

            var child_pk_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
            defer {
                for (child_pk_wrappers.items) |*pw| pw.deinit();
                child_pk_wrappers.deinit(allocator);
            }

            for (selected_children.items) |*child| {
                var n_participants: usize = 0;
                for (0..child.participants.len()) |i| {
                    if (child.participants.get(i) catch false) {
                        n_participants += 1;
                    }
                }

                const cpks = try allocator.alloc(*const xmss.HashSigPublicKey, n_participants);
                errdefer allocator.free(cpks);

                var cpk_idx: usize = 0;
                for (0..child.participants.len()) |i| {
                    if (child.participants.get(i) catch false) {
                        if (i >= validators.len()) continue;
                        const val = validators.get(@intCast(i)) catch continue;
                        const pk = xmss.PublicKey.fromBytes(&val.attestation_pubkey) catch continue;
                        try child_pk_wrappers.append(allocator, pk);
                        cpks[cpk_idx] = pk.handle;
                        cpk_idx += 1;
                    }
                }

                try child_pk_allocs.append(allocator, cpks);
                try child_pk_slices.append(allocator, cpks[0..cpk_idx]);
            }

            const pq_sig_timer = zeam_metrics.lean_pq_sig_aggregated_signatures_building_time_seconds.start();
            try aggregation.AggregatedSignatureProof.aggregate(
                allocator,
                xmss_participants,
                selected_children.items,
                child_pk_slices.items,
                pk_handles,
                sig_handles,
                &message_hash,
                epoch,
                &proof,
            );
            _ = pq_sig_timer.observe();
            if (xmss_participants) |*gp| gp.deinit();
            xmss_participants = null;

            // Create attestation from the proof's merged participants
            var att_bits: ?attestation.AggregationBits = try attestation.AggregationBits.init(allocator);
            defer if (att_bits) |*ab| ab.deinit();
            for (0..proof.participants.len()) |i| {
                if (proof.participants.get(i) catch false) {
                    try attestation.aggregationBitsSet(&att_bits.?, i, true);
                }
            }

            try self.attestations.append(.{ .aggregation_bits = att_bits.?, .data = data });
            att_bits = null; // ownership transferred to self.attestations
            try self.attestation_signatures.append(proof);
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

/// Greedy proof selection: pick proofs from `payloads_map` for `att_data` that cover
/// the most uncovered validators. Appends selected proofs to `selected` and marks
/// covered validators in `covered`. Skips validators already in `gossip_available`.
fn extendProofsGreedily(
    allocator: Allocator,
    payloads_map: ?*const AggregatedPayloadsMap,
    att_data: attestation.AttestationData,
    selected: *std.ArrayList(aggregation.AggregatedSignatureProof),
    covered: *std.DynamicBitSet,
    gossip_available: *const std.DynamicBitSet,
) !void {
    const pm = payloads_map orelse return;
    const candidates = pm.get(att_data) orelse return;
    if (candidates.items.len == 0) return;

    // Track which candidate proofs we've already selected (by index)
    var used = try allocator.alloc(bool, candidates.items.len);
    defer allocator.free(used);
    @memset(used, false);

    while (true) {
        // Find candidate proof with maximum coverage of uncovered, non-gossip validators
        var best_idx: ?usize = null;
        var max_coverage: usize = 0;

        for (candidates.items, 0..) |*stored, idx| {
            if (used[idx]) continue;
            const proof = &stored.proof;
            var coverage: usize = 0;

            for (0..proof.participants.len()) |i| {
                if (proof.participants.get(i) catch false) {
                    // Count this validator if not already covered by children or gossip
                    const already_covered = (i < covered.capacity() and covered.isSet(i));
                    const has_gossip = (i < gossip_available.capacity() and gossip_available.isSet(i));
                    if (!already_covered and !has_gossip) {
                        coverage += 1;
                    }
                }
            }

            if (coverage > max_coverage) {
                max_coverage = coverage;
                best_idx = idx;
            }
        }

        if (best_idx == null or max_coverage == 0) break;

        // Clone and select the best proof
        used[best_idx.?] = true;
        var cloned: aggregation.AggregatedSignatureProof = undefined;
        try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, candidates.items[best_idx.?].proof, &cloned);
        errdefer cloned.deinit();
        try selected.append(allocator, cloned);

        // Mark covered validators
        for (0..cloned.participants.len()) |i| {
            if (cloned.participants.get(i) catch false) {
                if (i >= covered.capacity()) {
                    try covered.resize(i + 1, false);
                }
                covered.set(i);
            }
        }
    }
}

/// Compact multiple proofs sharing the same AttestationData into single entries
/// using recursive children aggregation. After greedy selection, multiple proofs
/// may exist for the same AttestationData. This merges them so each AttestationData
/// appears at most once with a single combined proof.
///
/// Takes ownership of the input lists and returns new compacted lists.
/// The caller must deinit the returned lists.
const CompactGroupEntry = struct {
    att_data: attestation.AttestationData,
    indices: []const usize,
};

const CompactGroupResult = struct {
    attestation: AggregatedAttestation,
    signature: aggregation.AggregatedSignatureProof,
};

const CompactGroupSlot = struct {
    result: ?CompactGroupResult = null,
    err: ?anyerror = null,
};

/// Per-entry preparation built serially before any worker thread runs.
///
/// Holds the per-child `*const HashSigPublicKey` slices that the multi-proof
/// aggregate path needs. Building these slices requires `xmss.PublicKey.fromBytes`,
/// which is a Rust FFI call whose thread-safety we do not control. By
/// constructing every prep on the main thread we keep `fromBytes` out of the
/// parallel worker entirely; worker code only invokes the Rust `aggregate`
/// entry point on already-deserialized handles.
const CompactGroupPrep = struct {
    entry: CompactGroupEntry,
    /// Empty for single-proof groups (no aggregation needed). For multi-proof
    /// groups, one `[]*const HashSigPublicKey` per child, in `entry.indices`
    /// order.
    child_pk_slices: []const []*const xmss.HashSigPublicKey,
};

/// Single-proof passthrough — clone proof, derive aggregation bits.
fn compactSingleProof(
    allocator: Allocator,
    att_data: attestation.AttestationData,
    sig: *const aggregation.AggregatedSignatureProof,
) !CompactGroupResult {
    var cloned_proof: aggregation.AggregatedSignatureProof = undefined;
    try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, sig.*, &cloned_proof);
    errdefer cloned_proof.deinit();

    var att_bits = try attestation.AggregationBits.init(allocator);
    errdefer att_bits.deinit();
    for (0..cloned_proof.participants.len()) |i| {
        if (cloned_proof.participants.get(i) catch false) {
            try attestation.aggregationBitsSet(&att_bits, i, true);
        }
    }

    return .{
        .attestation = .{ .aggregation_bits = att_bits, .data = att_data },
        .signature = cloned_proof,
    };
}

/// Multi-proof aggregation using pre-built per-child pubkey slices. Safe to
/// run from a worker thread: no FFI deserialization, only `aggregate()` which
/// receives const handles.
fn compactMultiProofWithPrep(
    allocator: Allocator,
    att_data: attestation.AttestationData,
    indices: []const usize,
    sig_slice: []const aggregation.AggregatedSignatureProof,
    child_pk_slices: []const []*const xmss.HashSigPublicKey,
) !CompactGroupResult {
    const epoch: u64 = att_data.slot;
    var message_hash: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(attestation.AttestationData, att_data, &message_hash, allocator);

    const children = try allocator.alloc(aggregation.AggregatedSignatureProof, indices.len);
    defer allocator.free(children);
    for (indices, 0..) |idx, i| {
        children[i] = sig_slice[idx];
    }

    var proof = try aggregation.AggregatedSignatureProof.init(allocator);
    errdefer proof.deinit();

    const empty_pks: []*const xmss.HashSigPublicKey = &.{};
    const empty_sigs: []*const xmss.HashSigSignature = &.{};

    try aggregation.AggregatedSignatureProof.aggregate(
        allocator,
        null, // no raw XMSS participants
        children,
        child_pk_slices,
        empty_pks,
        empty_sigs,
        &message_hash,
        epoch,
        &proof,
    );

    var att_bits = try attestation.AggregationBits.init(allocator);
    errdefer att_bits.deinit();
    for (0..proof.participants.len()) |i| {
        if (proof.participants.get(i) catch false) {
            try attestation.aggregationBitsSet(&att_bits, i, true);
        }
    }

    return .{
        .attestation = .{ .aggregation_bits = att_bits, .data = att_data },
        .signature = proof,
    };
}

fn runCompactGroupPrep(
    allocator: Allocator,
    prep: CompactGroupPrep,
    sig_slice: []const aggregation.AggregatedSignatureProof,
) !CompactGroupResult {
    if (prep.entry.indices.len == 1) {
        return compactSingleProof(allocator, prep.entry.att_data, &sig_slice[prep.entry.indices[0]]);
    }
    return compactMultiProofWithPrep(
        allocator,
        prep.entry.att_data,
        prep.entry.indices,
        sig_slice,
        prep.child_pk_slices,
    );
}

pub fn compactAttestations(
    allocator: Allocator,
    attestations: *AggregatedAttestations,
    signatures: *AttestationSignatures,
    validators: *const Validators,
    thread_pool: anytype,
) !struct { attestations: AggregatedAttestations, signatures: AttestationSignatures } {
    const att_slice = attestations.constSlice();
    const sig_slice = signatures.constSlice();

    // Group indices by AttestationData
    var groups = std.AutoHashMap(attestation.AttestationData, std.ArrayList(usize)).init(allocator);
    defer {
        var it = groups.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        groups.deinit();
    }

    for (att_slice, 0..) |att, idx| {
        const gop = try groups.getOrPut(att.data);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(allocator, idx);
    }

    // If every group has exactly 1 entry, no compaction needed
    var needs_compaction = false;
    {
        var it = groups.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.items.len > 1) {
                needs_compaction = true;
                break;
            }
        }
    }

    if (!needs_compaction) {
        // Return inputs as-is (transfer ownership).
        // Caller will overwrite its locals with the returned values.
        return .{ .attestations = attestations.*, .signatures = signatures.* };
    }

    // Build compacted output
    var out_atts = try AggregatedAttestations.init(allocator);
    errdefer {
        for (out_atts.slice()) |*att| att.deinit();
        out_atts.deinit();
    }
    var out_sigs = try AttestationSignatures.init(allocator);
    errdefer {
        for (out_sigs.slice()) |*sig| sig.deinit();
        out_sigs.deinit();
    }

    // Snapshot groups and sort deterministically. `std.AutoHashMap.iterator()`
    // order is not stable across runs (insertion order is preserved only until
    // the next rehash), so two validators producing the same attestation set
    // could otherwise emit byte-different blocks. Sort by AttestationData
    // (slot, head.root, target.root, source.root) — totally ordered, cheap on
    // small block counts (≤ MAX_ATTESTATIONS).
    var group_entries: std.ArrayList(CompactGroupEntry) = .empty;
    defer group_entries.deinit(allocator);
    {
        var group_it = groups.iterator();
        while (group_it.next()) |group_entry| {
            try group_entries.append(allocator, .{
                .att_data = group_entry.key_ptr.*,
                .indices = group_entry.value_ptr.items,
            });
        }
    }

    const SortCtx = struct {
        fn lessThan(_: void, a: CompactGroupEntry, b: CompactGroupEntry) bool {
            if (a.att_data.slot != b.att_data.slot) return a.att_data.slot < b.att_data.slot;
            const head_cmp = std.mem.order(u8, &a.att_data.head.root, &b.att_data.head.root);
            if (head_cmp != .eq) return head_cmp == .lt;
            const target_cmp = std.mem.order(u8, &a.att_data.target.root, &b.att_data.target.root);
            if (target_cmp != .eq) return target_cmp == .lt;
            const source_cmp = std.mem.order(u8, &a.att_data.source.root, &b.att_data.source.root);
            if (source_cmp != .eq) return source_cmp == .lt;
            // Slot ties on each checkpoint resolved by checkpoint slot.
            if (a.att_data.head.slot != b.att_data.head.slot) return a.att_data.head.slot < b.att_data.head.slot;
            if (a.att_data.target.slot != b.att_data.target.slot) return a.att_data.target.slot < b.att_data.target.slot;
            return a.att_data.source.slot < b.att_data.source.slot;
        }
    };
    std.mem.sort(CompactGroupEntry, group_entries.items, {}, SortCtx.lessThan);

    // -------- Serial pre-phase: build CompactGroupPrep for every entry --------
    //
    // All `xmss.PublicKey.fromBytes` calls happen on this thread. The Rust FFI
    // for pubkey deserialization is not documented as `Send`, and `setupVerifier`
    // (called transitively) carries first-time-init races. By doing every FFI
    // construction here we ensure the parallel worker only invokes
    // `aggregate()` on already-deserialized handles.
    //
    // All wrapper handles are owned by `pubkey_wrappers`; we deinit each at the
    // end so Rust handles do not leak. The slice arrays themselves live in a
    // single `prep_slice_arena` to keep cleanup branch-free.
    var pubkey_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
    defer {
        for (pubkey_wrappers.items) |*pw| pw.deinit();
        pubkey_wrappers.deinit(allocator);
    }

    var prep_slice_arena = std.heap.ArenaAllocator.init(allocator);
    defer prep_slice_arena.deinit();
    const prep_alloc = prep_slice_arena.allocator();

    const preps = try allocator.alloc(CompactGroupPrep, group_entries.items.len);
    defer allocator.free(preps);

    for (group_entries.items, 0..) |entry, ei| {
        if (entry.indices.len == 1) {
            preps[ei] = .{ .entry = entry, .child_pk_slices = &.{} };
            continue;
        }

        const child_arr = try prep_alloc.alloc([]*const xmss.HashSigPublicKey, entry.indices.len);

        for (entry.indices, 0..) |sig_idx, child_i| {
            const child = &sig_slice[sig_idx];
            var n_participants: usize = 0;
            for (0..child.participants.len()) |i| {
                if (child.participants.get(i) catch false) n_participants += 1;
            }

            const cpks = try prep_alloc.alloc(*const xmss.HashSigPublicKey, n_participants);

            var cpk_idx: usize = 0;
            for (0..child.participants.len()) |i| {
                if (child.participants.get(i) catch false) {
                    if (i >= validators.len()) continue;
                    const val = validators.get(@intCast(i)) catch continue;
                    const pk = xmss.PublicKey.fromBytes(&val.attestation_pubkey) catch continue;
                    try pubkey_wrappers.append(allocator, pk);
                    cpks[cpk_idx] = pk.handle;
                    cpk_idx += 1;
                }
            }
            child_arr[child_i] = cpks[0..cpk_idx];
        }

        preps[ei] = .{ .entry = entry, .child_pk_slices = child_arr };
    }

    if (thread_pool) |pool| {
        // Parallel path: per-AttestationData aggregation across the shared
        // worker pool. Workers receive prebuilt `CompactGroupPrep` and never
        // touch FFI deserialization themselves.
        const slots = try allocator.alloc(CompactGroupSlot, preps.len);
        defer allocator.free(slots);
        for (slots) |*slot| slot.* = .{};
        errdefer {
            for (slots) |*slot| {
                if (slot.result) |*r| {
                    r.attestation.deinit();
                    r.signature.deinit();
                }
            }
        }

        const Runner = struct {
            fn runScope(
                scope: anytype,
                preps_in: []const CompactGroupPrep,
                sigs: []const aggregation.AggregatedSignatureProof,
                alloc: Allocator,
                out_slots: []CompactGroupSlot,
                any_err: *std.atomic.Value(bool),
            ) Allocator.Error!void {
                for (preps_in, 0..) |prep, i| {
                    try scope.spawn(runOne, .{ alloc, prep, sigs, &out_slots[i], any_err });
                }
            }

            fn runOne(
                alloc: Allocator,
                prep: CompactGroupPrep,
                sigs: []const aggregation.AggregatedSignatureProof,
                out_slot: *CompactGroupSlot,
                any_err: *std.atomic.Value(bool),
            ) void {
                if (any_err.load(.acquire)) return;
                const result = runCompactGroupPrep(alloc, prep, sigs) catch |err| {
                    out_slot.err = err;
                    any_err.store(true, .release);
                    return;
                };
                out_slot.result = result;
            }
        };

        var any_err = std.atomic.Value(bool).init(false);
        try pool.scope(Runner.runScope, .{
            preps,
            sig_slice,
            allocator,
            slots,
            &any_err,
        });

        for (slots) |*slot| {
            if (slot.err) |err| return err;
        }

        for (slots) |*slot| {
            var result = slot.result orelse continue;
            slot.result = null;

            var att_moved = false;
            var sig_moved = false;
            defer {
                if (!att_moved) result.attestation.deinit();
                if (!sig_moved) result.signature.deinit();
            }

            try out_atts.append(result.attestation);
            att_moved = true;
            try out_sigs.append(result.signature);
            sig_moved = true;
        }
    } else {
        for (preps) |prep| {
            var result = try runCompactGroupPrep(allocator, prep, sig_slice);

            var att_moved = false;
            var sig_moved = false;
            defer {
                if (!att_moved) result.attestation.deinit();
                if (!sig_moved) result.signature.deinit();
            }

            try out_atts.append(result.attestation);
            att_moved = true;
            try out_sigs.append(result.signature);
            sig_moved = true;
        }
    }

    // Free old input entries
    for (attestations.slice()) |*att| att.deinit();
    attestations.deinit();
    for (signatures.slice()) |*sig| sig.deinit();
    signatures.deinit();

    return .{ .attestations = out_atts, .signatures = out_sigs };
}

pub const BlockByRootRequest = struct {
    roots: ssz.utils.List(utils.Root, params.MAX_REQUEST_BLOCKS),

    pub fn toJson(self: *const BlockByRootRequest, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.empty;
        var roots_array = json.Array.init(allocator);
        errdefer roots_array.deinit();
        for (self.roots.constSlice()) |root| {
            try roots_array.append(json.Value{ .string = try bytesToHex(allocator, &root) });
        }
        try obj.put(allocator, "roots", json.Value{ .array = roots_array });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlockByRootRequest, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BlocksByRangeRequest = struct {
    start_slot: Slot,
    count: u64,

    pub fn toJson(self: *const BlocksByRangeRequest, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "start_slot", json.Value{ .integer = @as(i64, @intCast(self.start_slot)) });
        try obj.put(allocator, "count", json.Value{ .integer = @as(i64, @intCast(self.count)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BlocksByRangeRequest, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

/// Canonical lightweight forkchoice proto block used across modules
pub const ProtoBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
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
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "slot", json.Value{ .integer = @as(i64, @intCast(self.slot)) });
        try obj.put(allocator, "blockRoot", json.Value{ .string = try bytesToHex(allocator, &self.blockRoot) });
        try obj.put(allocator, "parentRoot", json.Value{ .string = try bytesToHex(allocator, &self.parentRoot) });
        try obj.put(allocator, "stateRoot", json.Value{ .string = try bytesToHex(allocator, &self.stateRoot) });
        try obj.put(allocator, "timeliness", json.Value{ .bool = self.timeliness });
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
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "timestamp", json.Value{ .integer = @as(i64, @intCast(self.timestamp)) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const ExecutionPayloadHeader, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.object.deinit(allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

test "ssz seralize/deserialize signed beam block" {
    var attestations = try AggregatedAttestations.init(std.testing.allocator);

    var signatures = try createBlockSignatures(std.testing.allocator, attestations.len());
    errdefer signatures.deinit();

    var signed_block = SignedBlock{
        .block = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .attestations = attestations },
        },
        .signature = signatures,
    };
    defer signed_block.deinit();

    var serialized_signed_block: std.ArrayList(u8) = .empty;
    defer serialized_signed_block.deinit(std.testing.allocator);

    try ssz.serialize(SignedBlock, signed_block, &serialized_signed_block, std.testing.allocator);
    try std.testing.expect(serialized_signed_block.items.len > 0);

    var deserialized_signed_block: SignedBlock = undefined;
    try ssz.deserialize(SignedBlock, serialized_signed_block.items[0..], &deserialized_signed_block, std.testing.allocator);
    defer deserialized_signed_block.deinit();

    try std.testing.expect(std.mem.eql(u8, &signed_block.block.state_root, &deserialized_signed_block.block.state_root));
    try std.testing.expect(std.mem.eql(u8, &signed_block.block.parent_root, &deserialized_signed_block.block.parent_root));

    var block_root: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(BeamBlock, signed_block.block, &block_root, std.testing.allocator);
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

test "encode decode signed block roundtrip" {
    var attestations = try AggregatedAttestations.init(std.testing.allocator);
    errdefer attestations.deinit();

    var signatures = try createBlockSignatures(std.testing.allocator, attestations.len());
    errdefer signatures.deinit();

    var signed_block = SignedBlock{
        .block = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .body = .{ .attestations = attestations },
        },
        .signature = signatures,
    };
    defer signed_block.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ssz.serialize(SignedBlock, signed_block, &encoded, std.testing.allocator);

    var decoded: SignedBlock = undefined;
    try ssz.deserialize(SignedBlock, encoded.items[0..], &decoded, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expect(decoded.block.slot == signed_block.block.slot);
    try std.testing.expect(decoded.block.proposer_index == signed_block.block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &decoded.block.parent_root, &signed_block.block.parent_root));
    try std.testing.expect(std.mem.eql(u8, &decoded.block.state_root, &signed_block.block.state_root));
    try std.testing.expect(decoded.signature.attestation_signatures.len() == signed_block.signature.attestation_signatures.len());
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

    var signed_block = SignedBlock{
        .block = .{
            .slot = 1,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .body = .{ .attestations = attestations },
        },
        .signature = .{
            .attestation_signatures = attestation_signatures,
            .proposer_signature = ZERO_SIGBYTES,
        },
    };
    defer signed_block.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ssz.serialize(SignedBlock, signed_block, &encoded, std.testing.allocator);

    var decoded: SignedBlock = undefined;
    try ssz.deserialize(SignedBlock, encoded.items[0..], &decoded, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expect(decoded.block.slot == signed_block.block.slot);
    try std.testing.expect(decoded.signature.attestation_signatures.len() == 1);
    const decoded_group = try decoded.signature.attestation_signatures.get(0);
    try std.testing.expect(decoded_group.participants.len() == 2);
}
