const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");
const zeam_metrics = @import("@zeam/metrics");
const xmss = @import("@zeam/xmss");
const zeam_utils = @import("@zeam/utils");
const ThreadPool = @import("@zeam/thread-pool").ThreadPool;

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
// devnet5: a proposer assembles one Type-1 proof per body attestation (produced by the parallel
// per-att_data aggregation), then merges them with the proposer's own Type-1 into the single
// Type-2 SignedBlock.proof. This list is the intermediate per-attestation Type-1 collection.
pub const Type1ProofList = ssz.utils.List(aggregation.TypeOneMultiSignature, params.VALIDATOR_REGISTRY_LIMIT);
pub const ByteList512KiB = xmss.ByteList512KiB;
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

/// Default `min_aggregation_inputs` for the aggregator-role pre-filter.
///
/// Surfaced on the CLI as `--min-aggregation-inputs` (see
/// `pkgs/cli/src/main.zig`) and consumed by the aggregator wrapper in
/// `pkgs/node/src/forkchoice.zig` (NOT by `computeAggregatedSignatures`,
/// which is spec-pure and aggregates whatever it is given). Default
/// `2`: aggregator skips publishing when an `att_data` has only a
/// single local gossip sig and no peer payload, since the raw sig is
/// already on the gossip topic and a 1-validator "aggregate" carries
/// no consensus signal (#907 finding 4). `1` reverts to pre-#908
/// behavior (always aggregate ≥1 sig). Higher values trade slot
/// latency for fewer sub-threshold aggregates on chatty subnets.
pub const default_min_aggregation_inputs: u32 = 2;

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
    /// Validators in `proof` that entered this aggregate through child payloads.
    /// Null for externally supplied/legacy payloads where source attribution is unknown.
    source_payload_participants: ?attestation.AggregationBits = null,
    /// Validators in `proof` that entered this aggregate as raw gossiped signatures.
    /// Null for externally supplied/legacy payloads where source attribution is unknown.
    source_gossip_participants: ?attestation.AggregationBits = null,
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

pub const SignedBlock = struct {
    block: BeamBlock,
    // devnet5 / leanSpec #717: the single merged Type-2 proof over all attestation Type-1s + the
    // proposer's Type-1, SSZ-encoded into this byte list (replaces devnet4's BlockSignatures).
    proof: xmss.ByteList512KiB,

    pub fn deinit(self: *SignedBlock) void {
        self.block.deinit();
        self.proof.deinit();
    }

    pub fn toJson(self: *const SignedBlock, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.empty;
        try obj.put(allocator, "block", try self.block.toJson(allocator));
        const proof_hex = try utils.BytesToHex(allocator, self.proof.constSlice());
        try obj.put(allocator, "proof", json.Value{ .string = proof_hex });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const SignedBlock, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

/// Build the single Type-2 block proof carried by `SignedBlock.proof` (leanSpec #717).
///
/// Inputs: one per-attestation Type-1 proof per body attestation (in body order, produced by the
/// parallel per-att_data aggregation), plus the proposer's raw signature over the block root. We
/// derive the proposer's singleton Type-1, then merge attestations-then-proposer into one Type-2
/// and SSZ-encode it into `out_proof`.
///
/// `attestation_type1s` must be parallel with `agg_attestations` (same length, same order).
pub fn buildType2BlockProof(
    allocator: Allocator,
    validators: *const Validators,
    agg_attestations: *const AggregatedAttestations,
    attestation_type1s: []const aggregation.TypeOneMultiSignature,
    proposer_index: usize,
    block_root: *const [32]u8,
    slot: u64,
    proposer_sig_bytes: *const SIGBYTES,
    out_proof: *xmss.ByteList512KiB,
) !void {
    const atts = agg_attestations.constSlice();
    if (atts.len != attestation_type1s.len) return error.AggregationInvalidInput;

    // All PublicKey wrappers — free their Rust handles exactly once at the end.
    var pk_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
    defer {
        for (pk_wrappers.items) |*w| w.deinit();
        pk_wrappers.deinit(allocator);
    }

    // Per-component participant pubkey handles: one slice per body attestation, then the proposer.
    const pks_per_part = try allocator.alloc([]*const xmss.HashSigPublicKey, atts.len + 1);
    defer {
        for (pks_per_part) |slice| {
            if (slice.len > 0) allocator.free(slice);
        }
        allocator.free(pks_per_part);
    }
    for (pks_per_part) |*s| s.* = &.{};

    for (atts, 0..) |agg_att, i| {
        var vids = try attestation.aggregationBitsToValidatorIndices(&agg_att.aggregation_bits, allocator);
        defer vids.deinit(allocator);
        const handles = try allocator.alloc(*const xmss.HashSigPublicKey, vids.items.len);
        for (vids.items, 0..) |vid, j| {
            const val = try validators.get(@intCast(vid));
            const pk = try xmss.PublicKey.fromBytes(&val.attestation_pubkey);
            try pk_wrappers.append(allocator, pk);
            handles[j] = pk.handle;
        }
        pks_per_part[i] = handles;
    }

    // Proposer pubkey (proposal key) + raw signature handle.
    const proposer_val = try validators.get(@intCast(proposer_index));
    const proposer_pk = try xmss.PublicKey.fromBytes(&proposer_val.proposal_pubkey);
    try pk_wrappers.append(allocator, proposer_pk);
    {
        const handles = try allocator.alloc(*const xmss.HashSigPublicKey, 1);
        handles[0] = proposer_pk.handle;
        pks_per_part[atts.len] = handles;
    }

    var proposer_sig = try xmss.Signature.fromBytes(proposer_sig_bytes[0..]);
    defer proposer_sig.deinit();

    // Proposer singleton Type-1 over the block root.
    var proposer_participants = try attestation.AggregationBits.init(allocator);
    defer proposer_participants.deinit();
    try attestation.aggregationBitsSet(&proposer_participants, proposer_index, true);

    var proposer_t1 = try aggregation.TypeOneMultiSignature.init(allocator);
    defer proposer_t1.deinit();
    {
        var raw_pks = [_]*const xmss.HashSigPublicKey{proposer_pk.handle};
        var raw_sigs = [_]*const xmss.HashSigSignature{proposer_sig.handle};
        const no_children: []const aggregation.TypeOneMultiSignature = &.{};
        const no_child_pks: []const []*const xmss.HashSigPublicKey = &.{};
        try aggregation.TypeOneMultiSignature.aggregate(
            allocator,
            proposer_participants,
            no_children,
            no_child_pks,
            raw_pks[0..],
            raw_sigs[0..],
            block_root,
            slot,
            &proposer_t1,
        );
    }

    // parts = attestation_type1s ++ [proposer_t1]
    const parts = try allocator.alloc(aggregation.TypeOneMultiSignature, atts.len + 1);
    defer allocator.free(parts);
    for (attestation_type1s, 0..) |t1, i| parts[i] = t1;
    parts[atts.len] = proposer_t1;

    // Merge into Type-2.
    var t2 = try aggregation.TypeTwoMultiSignature.init(allocator);
    defer t2.deinit();
    try aggregation.TypeTwoMultiSignature.aggregate(allocator, parts, pks_per_part, &t2);

    // SSZ-encode the Type-2 container into out_proof (the on-wire form of SignedBlock.proof).
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try ssz.serialize(aggregation.TypeTwoMultiSignature, t2, &encoded, allocator);
    for (encoded.items) |b| try out_proof.append(b);
}

fn slotAllowed(slot: Slot, slot_filter: ?[]const Slot) bool {
    const slots = slot_filter orelse return true;
    for (slots) |allowed| {
        if (slot == allowed) return true;
    }
    return false;
}

pub const AggregatedAttestationsResult = struct {
    attestations: AggregatedAttestations,
    attestation_signatures: Type1ProofList,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var attestations_list = try AggregatedAttestations.init(allocator);
        errdefer attestations_list.deinit();

        var signatures_list = try Type1ProofList.init(allocator);
        errdefer signatures_list.deinit();

        return .{
            .attestations = attestations_list,
            .attestation_signatures = signatures_list,
            .allocator = allocator,
        };
    }

    /// Compute aggregated signatures using recursive aggregation:
    /// Step 1: Derive AttestationData keys from signatures_map ∪ new_payloads,
    ///         optionally restricted to the supplied attestation slots.
    /// Step 2: Greedy child proof selection — new_payloads first, then known_payloads as helpers
    /// Step 3: Collect individual gossip signatures not covered by children
    /// Step 4: Single-source fast path without child payloads:
    ///         `0 gossip + 1 child` clones the lone child.
    /// Step 5: Recursive aggregate — combine selected children + remaining gossip sigs.
    ///
    /// Spec-pure: this function aggregates whatever it is given. Callers
    /// that want to skip trivially-shaped inputs (e.g. the aggregator
    /// role wanting to avoid spending the full STARK prover budget on a
    /// single-validator "aggregate" that carries no consensus signal —
    /// see issue #907 finding 4) must filter the inputs they pass in.
    /// Block proposers, by contrast, MUST aggregate every `att_data`
    /// they choose to include in a block, even if its only input is a
    /// single gossip signature.
    /// Aggregator batch entry: serial prep then sequential XMSS proves (ethlambda
    /// worker loop). Parallel ThreadPool scope was removed — nested Rayon inside
    /// each prove oversubscribed CPU and inflated p50/p95 on devnet (#925).
    pub fn computeAggregatedSignatures(
        self: *Self,
        validators: *const Validators,
        signatures_map: *const SignaturesMap,
        new_payloads: ?*const AggregatedPayloadsMap,
        known_payloads: ?*const AggregatedPayloadsMap,
        slot_filter: ?[]const Slot,
        thread_pool: *ThreadPool,
    ) !void {
        const allocator = self.allocator;

        // Step 1: Derive unique AttestationData keys from signatures_map ∪ new_payloads
        var att_data_set = std.AutoHashMap(attestation.AttestationData, void).init(allocator);
        defer att_data_set.deinit();

        {
            var it = signatures_map.iterator();
            while (it.next()) |entry| {
                if (!slotAllowed(entry.key_ptr.slot, slot_filter)) continue;
                try att_data_set.put(entry.key_ptr.*, {});
            }
        }
        if (new_payloads) |np| {
            var it = np.iterator();
            while (it.next()) |entry| {
                if (!slotAllowed(entry.key_ptr.slot, slot_filter)) continue;
                try att_data_set.put(entry.key_ptr.*, {});
            }
        }

        if (att_data_set.count() == 0) return;

        var att_data_keys = try allocator.alloc(attestation.AttestationData, att_data_set.count());
        defer allocator.free(att_data_keys);
        var key_idx: usize = 0;
        var data_it = att_data_set.keyIterator();
        while (data_it.next()) |key| {
            att_data_keys[key_idx] = key.*;
            key_idx += 1;
        }
        std.mem.sort(attestation.AttestationData, att_data_keys, {}, attestationDataLessThan);

        var preps = try allocator.alloc(AggregateAttDataPrep, att_data_keys.len);
        defer {
            for (preps) |*prep| prep.deinit(allocator);
            allocator.free(preps);
        }

        const prep_start_ns = zeam_utils.monotonicTimestampNs();
        for (att_data_keys, 0..) |data, i| {
            preps[i] = try prepareAggregateAttData(
                allocator,
                validators,
                signatures_map,
                new_payloads,
                known_payloads,
                data,
            );
        }
        observeAggregateAttDataPrepPhase(prep_start_ns);

        try runAggregateAttDataPreps(
            allocator,
            preps,
            thread_pool,
        );

        for (preps) |*prep| {
            if (prep.outcome != .done) continue;
            const result = prep.outcome.done;
            prep.outcome = .skip;
            try self.attestations.append(result.attestation);
            try self.attestation_signatures.append(result.signature);
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

pub fn attestationDataLessThan(_: void, a: attestation.AttestationData, b: attestation.AttestationData) bool {
    if (a.slot != b.slot) return a.slot < b.slot;
    const head_cmp = std.mem.order(u8, &a.head.root, &b.head.root);
    if (head_cmp != .eq) return head_cmp == .lt;
    const target_cmp = std.mem.order(u8, &a.target.root, &b.target.root);
    if (target_cmp != .eq) return target_cmp == .lt;
    const source_cmp = std.mem.order(u8, &a.source.root, &b.source.root);
    if (source_cmp != .eq) return source_cmp == .lt;
    if (a.head.slot != b.head.slot) return a.head.slot < b.head.slot;
    if (a.target.slot != b.target.slot) return a.target.slot < b.target.slot;
    return a.source.slot < b.source.slot;
}

fn observeAggregateAttDataPrepPhase(start_ns: i128) void {
    const end_ns = zeam_utils.monotonicTimestampNs();
    const elapsed_ns: i128 = if (end_ns >= start_ns) end_ns - start_ns else 0;
    const elapsed_s = @as(f32, @floatFromInt(elapsed_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
    zeam_metrics.observeAggregateAttestationBuildPhase("att_data_prep", elapsed_s);
}

pub const SingleAggregatedSignature = CompactGroupResult;

/// Single `att_data` aggregation: serial prep then one XMSS prove (ethlambda
/// `aggregate_job` shape). Used by the aggregator per-job loop.
pub fn computeSingleAggregatedSignature(
    allocator: Allocator,
    validators: *const Validators,
    signatures_map: *const SignaturesMap,
    new_payloads: ?*const AggregatedPayloadsMap,
    known_payloads: ?*const AggregatedPayloadsMap,
    data: attestation.AttestationData,
) !?SingleAggregatedSignature {
    var prep = try prepareAggregateAttData(
        allocator,
        validators,
        signatures_map,
        new_payloads,
        known_payloads,
        data,
    );
    defer prep.deinit(allocator);

    return switch (prep.outcome) {
        .skip => null,
        .done => |result| blk: {
            prep.outcome = .skip;
            break :blk result;
        },
        .ffi => |*args| blk: {
            const result = try runAggregateAttDataFfi(allocator, prep.data, args);
            args.deinit(allocator);
            prep.outcome = .skip;
            break :blk result;
        },
    };
}

const AggregateAttDataOutcome = union(enum) {
    skip,
    ffi: AggregateAttDataFfiArgs,
    done: CompactGroupResult,
};

const AggregateAttDataPrep = struct {
    data: attestation.AttestationData,
    outcome: AggregateAttDataOutcome,

    fn deinit(self: *AggregateAttDataPrep, allocator: Allocator) void {
        switch (self.outcome) {
            .skip => {},
            .ffi => |*args| args.deinit(allocator),
            .done => |*result| {
                result.attestation.deinit();
                result.signature.deinit();
            },
        }
    }
};

const AggregateAttDataFfiArgs = struct {
    message_hash: [32]u8,
    epoch: u64,
    xmss_participants: ?attestation.AggregationBits,
    selected_children: []aggregation.AggregatedSignatureProof,
    child_pk_slices: []const []*const xmss.HashSigPublicKey,
    pk_handles: []*const xmss.HashSigPublicKey,
    sig_handles: []*const xmss.HashSigSignature,
    child_pk_allocs: [][]*const xmss.HashSigPublicKey,
    child_pk_wrappers: []xmss.PublicKey,
    gossip_sig_wrappers: []xmss.Signature,
    gossip_pk_wrappers: []xmss.PublicKey,
    pk_handles_buf: ?[]*const xmss.HashSigPublicKey,
    sig_handles_buf: ?[]*const xmss.HashSigSignature,

    fn deinit(self: *AggregateAttDataFfiArgs, allocator: Allocator) void {
        for (self.selected_children) |*child| child.deinit();
        allocator.free(self.selected_children);
        for (self.child_pk_allocs) |arr| allocator.free(arr);
        allocator.free(self.child_pk_allocs);
        for (self.child_pk_wrappers) |*pw| pw.deinit();
        allocator.free(self.child_pk_wrappers);
        for (self.gossip_sig_wrappers) |*sig| sig.deinit();
        allocator.free(self.gossip_sig_wrappers);
        for (self.gossip_pk_wrappers) |*pk| pk.deinit();
        allocator.free(self.gossip_pk_wrappers);
        if (self.pk_handles_buf) |buf| allocator.free(buf);
        if (self.sig_handles_buf) |buf| allocator.free(buf);
        if (self.xmss_participants) |*gp| gp.deinit();
    }
};

fn prepareAggregateAttData(
    allocator: Allocator,
    validators: *const Validators,
    signatures_map: *const SignaturesMap,
    new_payloads: ?*const AggregatedPayloadsMap,
    known_payloads: ?*const AggregatedPayloadsMap,
    data: attestation.AttestationData,
) !AggregateAttDataPrep {
    const epoch: u64 = data.slot;
    var message_hash: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(attestation.AttestationData, data, &message_hash, allocator);

    var selected_children: std.ArrayList(aggregation.AggregatedSignatureProof) = .empty;
    errdefer {
        for (selected_children.items) |*child| child.deinit();
        selected_children.deinit(allocator);
    }

    const max_validator = validators.len();

    var covered_by_children = try std.DynamicBitSet.initEmpty(allocator, max_validator);
    defer covered_by_children.deinit();

    var empty_available = try std.DynamicBitSet.initEmpty(allocator, max_validator);
    defer empty_available.deinit();

    try extendProofsGreedily(allocator, new_payloads, data, &selected_children, &covered_by_children, &empty_available);
    try extendProofsGreedily(allocator, known_payloads, data, &selected_children, &covered_by_children, &empty_available);

    var sigmap_sigs: std.ArrayList(xmss.Signature) = .empty;
    errdefer {
        for (sigmap_sigs.items) |*sig| sig.deinit();
        sigmap_sigs.deinit(allocator);
    }

    var sigmap_pks: std.ArrayList(xmss.PublicKey) = .empty;
    errdefer {
        for (sigmap_pks.items) |*pk| pk.deinit();
        sigmap_pks.deinit(allocator);
    }

    var sigmap_vids: std.ArrayList(usize) = .empty;
    errdefer sigmap_vids.deinit(allocator);

    if (signatures_map.get(data)) |im| {
        var vid_it = im.iterator();
        while (vid_it.next()) |entry| {
            const vid: usize = @intCast(entry.key_ptr.*);
            const sig_entry = entry.value_ptr.*;

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

    if (!has_gossip and !has_children) {
        return .{ .data = data, .outcome = .skip };
    }

    if (!has_gossip and selected_children.items.len == 1) {
        const child = &selected_children.items[0];

        var att_bits: attestation.AggregationBits = undefined;
        try utils.sszClone(allocator, attestation.AggregationBits, child.participants, &att_bits);
        errdefer att_bits.deinit();

        var cloned_child: aggregation.AggregatedSignatureProof = undefined;
        try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, child.*, &cloned_child);
        errdefer cloned_child.deinit();

        selected_children.items[0].deinit();
        selected_children.deinit(allocator);

        return .{
            .data = data,
            .outcome = .{
                .done = .{
                    .attestation = .{ .aggregation_bits = att_bits, .data = data },
                    .signature = cloned_child,
                },
            },
        };
    }

    var xmss_participants: ?attestation.AggregationBits = null;
    var pk_handles_buf: ?[]*const xmss.HashSigPublicKey = null;
    var sig_handles_buf: ?[]*const xmss.HashSigSignature = null;
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
        pk_handles = pks;
        sig_handles = sigs;
    }

    var child_pk_allocs_list: std.ArrayList([]*const xmss.HashSigPublicKey) = .empty;
    errdefer {
        for (child_pk_allocs_list.items) |arr| allocator.free(arr);
        child_pk_allocs_list.deinit(allocator);
    }
    var child_pk_slices_list: std.ArrayList([]*const xmss.HashSigPublicKey) = .empty;
    errdefer child_pk_slices_list.deinit(allocator);

    var child_pk_wrappers_list: std.ArrayList(xmss.PublicKey) = .empty;
    errdefer {
        for (child_pk_wrappers_list.items) |*pw| pw.deinit();
        child_pk_wrappers_list.deinit(allocator);
    }

    for (selected_children.items) |*child| {
        var n_participants: usize = 0;
        for (0..child.participants.len()) |i| {
            if (child.participants.get(i) catch false) n_participants += 1;
        }

        const cpks = try allocator.alloc(*const xmss.HashSigPublicKey, n_participants);
        errdefer allocator.free(cpks);

        var cpk_idx: usize = 0;
        for (0..child.participants.len()) |i| {
            if (child.participants.get(i) catch false) {
                if (i >= validators.len()) continue;
                const val = validators.get(@intCast(i)) catch continue;
                const pk = xmss.PublicKey.fromBytes(&val.attestation_pubkey) catch continue;
                try child_pk_wrappers_list.append(allocator, pk);
                cpks[cpk_idx] = pk.handle;
                cpk_idx += 1;
            }
        }

        try child_pk_allocs_list.append(allocator, cpks);
        try child_pk_slices_list.append(allocator, cpks[0..cpk_idx]);
    }

    const gossip_sigs = try sigmap_sigs.toOwnedSlice(allocator);
    errdefer {
        for (gossip_sigs) |*sig| sig.deinit();
        allocator.free(gossip_sigs);
    }
    sigmap_sigs = .empty;

    const gossip_pks = try sigmap_pks.toOwnedSlice(allocator);
    errdefer {
        for (gossip_pks) |*pk| pk.deinit();
        allocator.free(gossip_pks);
    }
    sigmap_pks = .empty;
    sigmap_vids.deinit(allocator);

    const children = try selected_children.toOwnedSlice(allocator);
    selected_children = .empty;

    const child_pk_allocs = try child_pk_allocs_list.toOwnedSlice(allocator);
    child_pk_allocs_list = .empty;

    const child_pk_slices = try child_pk_slices_list.toOwnedSlice(allocator);
    child_pk_slices_list = .empty;

    const child_pk_wrappers = try child_pk_wrappers_list.toOwnedSlice(allocator);
    child_pk_wrappers_list = .empty;

    return .{
        .data = data,
        .outcome = .{
            .ffi = .{
                .message_hash = message_hash,
                .epoch = epoch,
                .xmss_participants = xmss_participants,
                .selected_children = children,
                .child_pk_slices = child_pk_slices,
                .pk_handles = pk_handles,
                .sig_handles = sig_handles,
                .child_pk_allocs = child_pk_allocs,
                .child_pk_wrappers = child_pk_wrappers,
                .gossip_sig_wrappers = gossip_sigs,
                .gossip_pk_wrappers = gossip_pks,
                .pk_handles_buf = pk_handles_buf,
                .sig_handles_buf = sig_handles_buf,
            },
        },
    };
}

fn runAggregateAttDataFfi(
    allocator: Allocator,
    data: attestation.AttestationData,
    args: *AggregateAttDataFfiArgs,
) !CompactGroupResult {
    var proof = try aggregation.AggregatedSignatureProof.init(allocator);
    errdefer proof.deinit();

    const pq_sig_timer = zeam_metrics.lean_pq_sig_aggregated_signatures_building_time_seconds.start();
    try aggregation.AggregatedSignatureProof.aggregate(
        allocator,
        args.xmss_participants,
        args.selected_children,
        args.child_pk_slices,
        args.pk_handles,
        args.sig_handles,
        &args.message_hash,
        args.epoch,
        &proof,
    );
    _ = pq_sig_timer.observe();

    var att_bits: attestation.AggregationBits = undefined;
    try utils.sszClone(allocator, attestation.AggregationBits, proof.participants, &att_bits);
    errdefer att_bits.deinit();

    return .{
        .attestation = .{ .aggregation_bits = att_bits, .data = data },
        .signature = proof,
    };
}

fn runAggregateAttDataPreps(allocator: Allocator, preps: []AggregateAttDataPrep, thread_pool: *ThreadPool) !void {
    _ = thread_pool;
    // Ethlambda runs aggregation jobs sequentially on one blocking worker so
    // Rayon gets the full CPU budget per prove. Parallel scope here nested
    // ThreadPool workers each calling xmss_aggregate (Rayon inside) and hurt
    // devnet aggregator p50 (#925).
    for (preps) |*prep| {
        if (prep.outcome != .ffi) continue;
        const result = try runAggregateAttDataFfi(allocator, prep.data, &prep.outcome.ffi);
        prep.outcome.ffi.deinit(allocator);
        prep.outcome = .{ .done = result };
    }
}

const AggregateAttDataSlot = struct {
    result: ?CompactGroupResult = null,
    err: ?anyerror = null,
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

    var att_bits: attestation.AggregationBits = undefined;
    try utils.sszClone(allocator, attestation.AggregationBits, cloned_proof.participants, &att_bits);
    errdefer att_bits.deinit();

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

    var att_bits: attestation.AggregationBits = undefined;
    try utils.sszClone(allocator, attestation.AggregationBits, proof.participants, &att_bits);
    errdefer att_bits.deinit();

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
    signatures: *Type1ProofList,
    validators: *const Validators,
    thread_pool: anytype,
) !struct { attestations: AggregatedAttestations, signatures: Type1ProofList } {
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
    var out_sigs = try Type1ProofList.init(allocator);
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
    // for pubkey deserialization is not documented as `Send`.
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
    try thread_pool.scope(Runner.runScope, .{
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

fn testAttestationData(slot: Slot) attestation.AttestationData {
    return .{
        .slot = slot,
        .head = .{ .root = ZERO_HASH, .slot = slot },
        .target = .{ .root = ZERO_HASH, .slot = slot },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
}

fn testDeinitPayloadsMap(allocator: Allocator, payloads: *AggregatedPayloadsMap) void {
    var it = payloads.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |*stored| {
            stored.proof.deinit();
            if (stored.source_payload_participants) |*bits| bits.deinit();
            if (stored.source_gossip_participants) |*bits| bits.deinit();
        }
        entry.value_ptr.deinit(allocator);
    }
    payloads.deinit();
}

fn testPutSingleChildPayload(allocator: Allocator, payloads: *AggregatedPayloadsMap, data: attestation.AttestationData, validator_index: usize) !void {
    var proof = try aggregation.AggregatedSignatureProof.init(allocator);
    errdefer proof.deinit();
    try attestation.aggregationBitsSet(&proof.participants, validator_index, true);

    const gop = try payloads.getOrPut(data);
    if (!gop.found_existing) gop.value_ptr.* = .empty;
    try gop.value_ptr.append(allocator, .{
        .slot = data.slot,
        .proof = proof,
    });
}

fn setupTestPrimitives(allocator: Allocator) !*ThreadPool {
    // Initialise XMSS aggregation FFI for tests that call
    // `computeAggregatedSignatures` through this pool. Both calls are
    // process-idempotent (`OnceLock` on the Rust side; rayon ignores repeats).
    xmss.setRayonThreads(1);
    try xmss.setupXmssAggregation();
    return ThreadPool.init(.{
        .allocator = allocator,
        .io = std.Io.Threaded.global_single_threaded.io(),
        .thread_count = 4,
    });
}

test "computeAggregatedSignatures filters attestation data by slot list" {
    const allocator = std.testing.allocator;

    var validators = try Validators.init(allocator);
    defer validators.deinit();

    var signatures = SignaturesMap.init(allocator);
    defer signatures.deinit();

    var payloads = AggregatedPayloadsMap.init(allocator);
    defer testDeinitPayloadsMap(allocator, &payloads);

    const slot_10 = testAttestationData(10);
    const slot_11 = testAttestationData(11);
    try testPutSingleChildPayload(allocator, &payloads, slot_10, 0);
    try testPutSingleChildPayload(allocator, &payloads, slot_11, 1);

    var result = try AggregatedAttestationsResult.init(allocator);
    defer result.deinit();

    const thread_pool = try setupTestPrimitives(allocator);
    defer thread_pool.deinit();

    const allowed_slots = [_]Slot{10};
    try result.computeAggregatedSignatures(&validators, &signatures, &payloads, null, allowed_slots[0..], thread_pool);

    try std.testing.expectEqual(@as(usize, 1), result.attestations.len());
    const aggregated = try result.attestations.get(0);
    try std.testing.expectEqual(@as(Slot, 10), aggregated.data.slot);
}

test "computeAggregatedSignatures slot filter matches unfiltered for same-slot input" {
    const allocator = std.testing.allocator;

    var validators = try Validators.init(allocator);
    defer validators.deinit();

    var signatures_a = SignaturesMap.init(allocator);
    defer signatures_a.deinit();
    var payloads_a = AggregatedPayloadsMap.init(allocator);
    defer testDeinitPayloadsMap(allocator, &payloads_a);

    var signatures_b = SignaturesMap.init(allocator);
    defer signatures_b.deinit();
    var payloads_b = AggregatedPayloadsMap.init(allocator);
    defer testDeinitPayloadsMap(allocator, &payloads_b);

    const data = testAttestationData(12);
    try testPutSingleChildPayload(allocator, &payloads_a, data, 0);
    try testPutSingleChildPayload(allocator, &payloads_b, data, 0);

    var unfiltered = try AggregatedAttestationsResult.init(allocator);
    defer unfiltered.deinit();

    const thread_pool = try setupTestPrimitives(allocator);
    defer thread_pool.deinit();
    try unfiltered.computeAggregatedSignatures(&validators, &signatures_a, &payloads_a, null, null, thread_pool);

    var filtered = try AggregatedAttestationsResult.init(allocator);
    defer filtered.deinit();
    const allowed_slots = [_]Slot{12};
    try filtered.computeAggregatedSignatures(&validators, &signatures_b, &payloads_b, null, allowed_slots[0..], thread_pool);

    try std.testing.expectEqual(unfiltered.attestations.len(), filtered.attestations.len());
    try std.testing.expectEqual(unfiltered.attestation_signatures.len(), filtered.attestation_signatures.len());
    try std.testing.expectEqual(@as(usize, 1), filtered.attestations.len());
    const filtered_att = try filtered.attestations.get(0);
    try std.testing.expectEqual(@as(Slot, 12), filtered_att.data.slot);
}

test "computeAggregatedSignatures empty slot filter result is clean" {
    const allocator = std.testing.allocator;

    var validators = try Validators.init(allocator);
    defer validators.deinit();

    var signatures = SignaturesMap.init(allocator);
    defer signatures.deinit();

    var payloads = AggregatedPayloadsMap.init(allocator);
    defer testDeinitPayloadsMap(allocator, &payloads);

    try testPutSingleChildPayload(allocator, &payloads, testAttestationData(13), 0);

    var result = try AggregatedAttestationsResult.init(allocator);
    defer result.deinit();

    const allowed_slots = [_]Slot{14};
    const thread_pool = try setupTestPrimitives(allocator);
    defer thread_pool.deinit();
    try result.computeAggregatedSignatures(&validators, &signatures, &payloads, null, allowed_slots[0..], thread_pool);

    try std.testing.expectEqual(@as(usize, 0), result.attestations.len());
    try std.testing.expectEqual(@as(usize, 0), result.attestation_signatures.len());
}

test "ssz seralize/deserialize signed beam block" {
    const attestations = try AggregatedAttestations.init(std.testing.allocator);

    var signed_block = SignedBlock{
        .block = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .attestations = attestations },
        },
        .proof = try xmss.ByteList512KiB.init(std.testing.allocator),
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

    var signed_block = SignedBlock{
        .block = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .body = .{ .attestations = attestations },
        },
        .proof = try xmss.ByteList512KiB.init(std.testing.allocator),
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
    try std.testing.expect(decoded.proof.len() == signed_block.proof.len());
}

test "encode decode signed block with non-empty proof" {
    var attestations = try AggregatedAttestations.init(std.testing.allocator);
    errdefer attestations.deinit();

    // devnet5: SignedBlock.proof is the opaque SSZ-encoded Type-2 proof blob. Round-trip a
    // non-empty payload and assert it survives byte-for-byte.
    var proof = try xmss.ByteList512KiB.init(std.testing.allocator);
    errdefer proof.deinit();
    const proof_payload = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    for (proof_payload) |b| try proof.append(b);

    var signed_block = SignedBlock{
        .block = .{
            .slot = 1,
            .proposer_index = 0,
            .parent_root = ZERO_HASH,
            .state_root = ZERO_HASH,
            .body = .{ .attestations = attestations },
        },
        .proof = proof,
    };
    defer signed_block.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ssz.serialize(SignedBlock, signed_block, &encoded, std.testing.allocator);

    var decoded: SignedBlock = undefined;
    try ssz.deserialize(SignedBlock, encoded.items[0..], &decoded, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expect(decoded.block.slot == signed_block.block.slot);
    try std.testing.expect(decoded.proof.len() == proof_payload.len);
    try std.testing.expect(std.mem.eql(u8, decoded.proof.constSlice(), &proof_payload));
}

// Regression: an AggregatedSignatureProof whose `participants` bitlist
// has trailing zero bits (i.e., len() > highest_set_bit + 1) must still
// produce an `aggregation_bits` that is byte-for-byte identical to
// `participants`. Rebuilding `aggregation_bits` by re-setting only the
// TRUE indices would shrink it to highest_set_bit + 1, changing its SSZ
// encoding and causing other clients (e.g. ethlambda) to reject the
// block with a ParticipantsMismatch error.
test "compactSingleProof: aggregation_bits matches participants when participants has trailing zeros" {
    const allocator = std.testing.allocator;

    var proof = try aggregation.AggregatedSignatureProof.init(allocator);
    defer proof.deinit();

    // Force participants.len() == 6 with bits set only at {0, 2}.
    // aggregationBitsSet(.., 5, false) extends to length 6 and leaves bit 5 clear.
    try attestation.aggregationBitsSet(&proof.participants, 5, false);
    try attestation.aggregationBitsSet(&proof.participants, 0, true);
    try attestation.aggregationBitsSet(&proof.participants, 2, true);

    try std.testing.expectEqual(@as(usize, 6), proof.participants.len());

    const att_data = attestation.AttestationData{
        .slot = 1,
        .head = .{ .root = ZERO_HASH, .slot = 0 },
        .target = .{ .root = ZERO_HASH, .slot = 0 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };

    var result = try compactSingleProof(allocator, att_data, &proof);
    defer {
        result.attestation.deinit();
        result.signature.deinit();
    }

    try std.testing.expectEqual(
        result.signature.participants.len(),
        result.attestation.aggregation_bits.len(),
    );
    for (0..result.signature.participants.len()) |i| {
        try std.testing.expectEqual(
            try result.signature.participants.get(i),
            try result.attestation.aggregation_bits.get(i),
        );
    }

    // SSZ-encoded forms must also be identical so cross-client strict
    // equality checks pass.
    var participants_bytes: std.ArrayList(u8) = .empty;
    defer participants_bytes.deinit(allocator);
    try ssz.serialize(
        attestation.AggregationBits,
        result.signature.participants,
        &participants_bytes,
        allocator,
    );

    var bits_bytes: std.ArrayList(u8) = .empty;
    defer bits_bytes.deinit(allocator);
    try ssz.serialize(
        attestation.AggregationBits,
        result.attestation.aggregation_bits,
        &bits_bytes,
        allocator,
    );

    try std.testing.expectEqualSlices(u8, participants_bytes.items, bits_bytes.items);
}

// Regression (#929): single-child passthrough (.done) must not double-free when
// computeSingleAggregatedSignature returns and prep.deinit runs.
test "computeSingleAggregatedSignature: single-child passthrough survives prep deinit" {
    const allocator = std.testing.allocator;

    var validators = try Validators.init(allocator);
    defer validators.deinit();

    var signatures = SignaturesMap.init(allocator);
    defer signatures.deinit();

    var payloads = AggregatedPayloadsMap.init(allocator);
    defer testDeinitPayloadsMap(allocator, &payloads);

    const att_data = testAttestationData(7);
    try testPutSingleChildPayload(allocator, &payloads, att_data, 0);

    const maybe_result = try computeSingleAggregatedSignature(
        allocator,
        &validators,
        &signatures,
        &payloads,
        null,
        att_data,
    );
    var result = maybe_result orelse return error.TestExpectedSome;
    defer {
        result.attestation.deinit();
        result.signature.deinit();
    }

    var cloned: aggregation.AggregatedSignatureProof = undefined;
    try utils.sszClone(allocator, aggregation.AggregatedSignatureProof, result.signature, &cloned);
    defer cloned.deinit();

    try std.testing.expect(cloned.participants.len() > 0);
}
