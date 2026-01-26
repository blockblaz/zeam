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
        try zeam_utils.hashTreeRoot(attestation.AttestationData, att_data_3, &message_hash, allocator);

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
