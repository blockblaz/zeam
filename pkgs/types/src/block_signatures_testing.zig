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

const block = @import("./block.zig");
const Allocator = std.mem.Allocator;
const SignaturesMap = block.SignaturesMap;
const AggregatedPayloadsMap = block.AggregatedPayloadsMap;
const ValidatorIndex = utils.ValidatorIndex;
const Root = utils.Root;
const ZERO_HASH = utils.ZERO_HASH;

const SignatureKey = block.SignatureKey;
const AggregatedAttestationsResult = block.AggregatedAttestationsResult;
const AggregatedPayloadsList = block.AggregatedPayloadsList;

// ============================================================================
// Test helpers for aggregation helpers
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
        try zeam_utils.hashTreeRoot(attestation.AttestationData, self.attestation_data, &message_hash, self.allocator);

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
            .attestation_slot = self.attestation_data.slot,
            .source_slot = self.attestation_data.slot,
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
// aggregateGossipSignatures tests
// ============================================================================
test "aggregateGossipSignatures: all 4 in signatures_map" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);
    try ctx.addToSignatureMap(&signatures_map, 2);
    try ctx.addToSignatureMap(&signatures_map, 3);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.aggregateGossipSignatures(
        attestations_list[0..],
        &ctx.validators,
        &signatures_map,
    );

    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 0, 1, 2, 3 }));
}

// ============================================================================
// aggregateGossipSignatures: missing signatures excluded
// ============================================================================
test "aggregateGossipSignatures: missing signatures excluded" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 5);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
        ctx.createAttestation(4),
    };

    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 1);
    try ctx.addToSignatureMap(&signatures_map, 3);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.aggregateGossipSignatures(
        attestations_list[0..],
        &ctx.validators,
        &signatures_map,
    );

    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 1, 3 }));
}

// ============================================================================
// aggregateGossipSignatures: multiple data roots
// ============================================================================
test "aggregateGossipSignatures: multiple data roots" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    const att_data_2 = attestation.AttestationData{
        .slot = 10,
        .head = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .target = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
    const data_root_2 = try att_data_2.sszRoot(allocator);

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestationWithData(2, att_data_2),
        ctx.createAttestationWithData(3, att_data_2),
    };

    var signatures_map = SignaturesMap.init(allocator);
    defer deinitSignaturesMap(&signatures_map);

    try ctx.addToSignatureMap(&signatures_map, 0);
    try ctx.addToSignatureMap(&signatures_map, 1);

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

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.aggregateGossipSignatures(
        attestations_list[0..],
        &ctx.validators,
        &signatures_map,
    );

    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

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
// selectAggregatedProofs tests
// ============================================================================
test "selectAggregatedProofs: greedy set-cover" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
    };

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_a = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 1, 2, 3 });
    const proof_b = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 1, 2 });

    try ctx.addAggregatedPayload(&payloads_map, 1, proof_a);
    try ctx.addAggregatedPayload(&payloads_map, 1, proof_b);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.selectAggregatedProofs(
        attestations_list[0..],
        &payloads_map,
    );

    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 1, 2, 3 }));
}

// ============================================================================
// selectAggregatedProofs: partial coverage excludes missing
// ============================================================================
test "selectAggregatedProofs: partial coverage excludes missing" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 5);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
        ctx.createAttestation(3),
        ctx.createAttestation(4),
    };

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_2_3 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 2, 3 });
    try ctx.addAggregatedPayload(&payloads_map, 2, proof_2_3);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.selectAggregatedProofs(
        attestations_list[0..],
        &payloads_map,
    );

    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 2, 3 }));
}

// ============================================================================
// selectAggregatedProofs: multiple data roots
// ============================================================================
test "selectAggregatedProofs: multiple data roots" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 4);
    defer ctx.deinit();

    const att_data_2 = attestation.AttestationData{
        .slot = 10,
        .head = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .target = .{ .root = [_]u8{2} ** 32, .slot = 10 },
        .source = .{ .root = ZERO_HASH, .slot = 0 },
    };
    const data_root_2 = try att_data_2.sszRoot(allocator);

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
        ctx.createAttestationWithData(2, att_data_2),
        ctx.createAttestationWithData(3, att_data_2),
    };

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_0_1 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 0, 1 });
    try ctx.addAggregatedPayload(&payloads_map, 0, proof_0_1);

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

        for ([_]ValidatorIndex{ 2, 3 }) |vid| {
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

        var pk_handles = try allocator.alloc(*const xmss.HashSigPublicKey, 2);
        defer allocator.free(pk_handles);
        var sig_handles = try allocator.alloc(*const xmss.HashSigSignature, 2);
        defer allocator.free(sig_handles);

        for (pks.items, 0..) |*pk, i| pk_handles[i] = pk.handle;
        for (sigs.items, 0..) |*sig, i| sig_handles[i] = sig.handle;

        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();
        for ([_]ValidatorIndex{ 2, 3 }) |vid| {
            try attestation.aggregationBitsSet(&participants, @intCast(vid), true);
        }

        var message_hash: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(attestation.AttestationData, att_data_2, &message_hash, allocator);

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

        const key = SignatureKey{ .validator_id = 2, .data_root = data_root_2 };
        const gop = try payloads_map.getOrPut(key);
        if (!gop.found_existing) {
            gop.value_ptr.* = AggregatedPayloadsList.init(allocator);
        }
        try gop.value_ptr.append(.{ .slot = att_data_2.slot, .proof = proof });
    }

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.selectAggregatedProofs(
        attestations_list[0..],
        &payloads_map,
    );

    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 2), agg_ctx.attestation_signatures.len());

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
// selectAggregatedProofs: proof can include extra participants
// ============================================================================
test "selectAggregatedProofs: proof can include extra participants" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 5);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(1),
        ctx.createAttestation(2),
    };

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    const proof_1_2_3_4 = try ctx.createAggregatedProof(&[_]ValidatorIndex{ 1, 2, 3, 4 });
    try ctx.addAggregatedPayload(&payloads_map, 1, proof_1_2_3_4);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.selectAggregatedProofs(
        attestations_list[0..],
        &payloads_map,
    );

    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 1), agg_ctx.attestation_signatures.len());

    const att_bits = &(try agg_ctx.attestations.get(0)).aggregation_bits;
    try std.testing.expect(try TestContext.checkParticipants(att_bits, &[_]ValidatorIndex{ 1, 2, 3, 4 }));
}

// ============================================================================
// selectAggregatedProofs: empty payloads yields empty
// ============================================================================
test "selectAggregatedProofs: empty payloads yields empty" {
    const allocator = std.testing.allocator;

    var ctx = try TestContext.init(allocator, 2);
    defer ctx.deinit();

    var attestations_list = [_]attestation.Attestation{
        ctx.createAttestation(0),
        ctx.createAttestation(1),
    };

    var payloads_map = AggregatedPayloadsMap.init(allocator);
    defer deinitPayloadsMap(&payloads_map);

    var agg_ctx = try AggregatedAttestationsResult.init(allocator);
    defer agg_ctx.deinit();

    try agg_ctx.selectAggregatedProofs(
        attestations_list[0..],
        &payloads_map,
    );

    try std.testing.expectEqual(@as(usize, 0), agg_ctx.attestations.len());
    try std.testing.expectEqual(@as(usize, 0), agg_ctx.attestation_signatures.len());
}
