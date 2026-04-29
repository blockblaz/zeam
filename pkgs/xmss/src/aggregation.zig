const std = @import("std");
const hashsig = @import("hashsig.zig");
const ssz = @import("ssz");

pub const AggregationError = error{ SerializationFailed, DeserializationFailed, PublicKeysSignatureLengthMismatch, AggregationFailed, InvalidAggregateSignature };

/// Maximum buffer size for serialized aggregate signatures (1 MiB)
pub const MAX_AGGREGATE_SIGNATURE_SIZE: usize = 1 << 20;

// Variable-length byte list for multisig aggregated signatures.
pub const ByteListMiB = ssz.utils.List(u8, MAX_AGGREGATE_SIGNATURE_SIZE);

pub const AggregatedXMSS = opaque {};

// External C functions from multisig-glue (uses leanMultisig devnet4 with recursive aggregation)
/// Returns 0 on success, -1 if the prover bytecode file is missing or initialisation failed.
/// Never panics — the Rust side wraps the body in catch_unwind (fix for #722).
extern fn xmss_setup_prover() callconv(.c) c_int;
/// Returns 0 on success, -1 on failure.
extern fn xmss_setup_verifier() callconv(.c) c_int;

extern fn xmss_aggregate(
    // Raw XMSS signatures
    raw_pub_keys: [*]const *const hashsig.HashSigPublicKey,
    raw_signatures: [*]const *const hashsig.HashSigSignature,
    num_raw: usize,
    // Children
    num_children: usize,
    child_all_pub_keys: [*]const *const hashsig.HashSigPublicKey,
    child_num_keys: [*]const usize,
    child_proof_ptrs: [*]const [*]const u8,
    child_proof_lens: [*]const usize,
    // Common parameters
    message_hash_ptr: [*]const u8,
    slot: u32,
    log_inv_rate: usize,
) callconv(.c) ?*AggregatedXMSS;

extern fn xmss_verify_aggregated(
    public_keys: [*]const *const hashsig.HashSigPublicKey,
    num_keys: usize,
    message_hash_ptr: [*]const u8,
    agg_sig_bytes: [*]const u8,
    agg_sig_len: usize,
    slot: u32,
) callconv(.c) bool;

extern fn xmss_free_aggregate_signature(agg_sig: *AggregatedXMSS) callconv(.c) void;

// Serialization FFI functions
extern fn xmss_aggregate_signature_to_bytes(
    agg_sig: *const AggregatedXMSS,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.c) usize;

extern fn xmss_aggregate_signature_from_bytes(
    bytes: [*]const u8,
    bytes_len: usize,
) callconv(.c) ?*AggregatedXMSS;

/// Initialize the XMSS prover (idempotent — only runs once).
/// Returns error.ProverSetupFailed when the prover bytecode file is missing or the
/// underlying Rust initialisation failed. Callers should log a warning and skip
/// aggregation rather than propagating the error as a fatal failure.
pub fn setupProver() error{ProverSetupFailed}!void {
    if (xmss_setup_prover() != 0) return error.ProverSetupFailed;
}

/// Initialize the XMSS verifier (idempotent — only runs once).
pub fn setupVerifier() error{VerifierSetupFailed}!void {
    if (xmss_setup_verifier() != 0) return error.VerifierSetupFailed;
}

/// Aggregate raw XMSS signatures with optional recursive children.
///
/// - `public_keys`/`signatures`: raw XMSS public key and signature handles.
/// - `children_pub_keys`: per-child arrays of public key handles (parallel with `children_proofs`).
/// - `children_proofs`: per-child serialized proof data (parallel with `children_pub_keys`).
/// - `log_inv_rate`: inverse proof size exponent (1-4).
pub fn aggregateSignatures(
    public_keys: []*const hashsig.HashSigPublicKey,
    signatures: []*const hashsig.HashSigSignature,
    children_pub_keys: []const []*const hashsig.HashSigPublicKey,
    children_proofs: []const ByteListMiB,
    message_hash: *const [32]u8,
    epoch: u32,
    log_inv_rate: usize,
    multisig_aggregated_signature: *ByteListMiB,
) !void {
    if (public_keys.len != signatures.len) {
        return AggregationError.PublicKeysSignatureLengthMismatch;
    }
    if (children_pub_keys.len != children_proofs.len) {
        return AggregationError.AggregationFailed;
    }

    try setupProver();

    const num_children = children_pub_keys.len;
    const allocator = std.heap.c_allocator;

    // Build flat child pub key array and per-child key counts
    var total_child_pks: usize = 0;
    for (children_pub_keys) |cpks| {
        total_child_pks += cpks.len;
    }

    const child_all_pks = allocator.alloc(*const hashsig.HashSigPublicKey, total_child_pks) catch
        return AggregationError.AggregationFailed;
    defer allocator.free(child_all_pks);

    const child_num_keys = allocator.alloc(usize, num_children) catch
        return AggregationError.AggregationFailed;
    defer allocator.free(child_num_keys);

    const child_proof_ptrs = allocator.alloc([*]const u8, num_children) catch
        return AggregationError.AggregationFailed;
    defer allocator.free(child_proof_ptrs);

    const child_proof_lens = allocator.alloc(usize, num_children) catch
        return AggregationError.AggregationFailed;
    defer allocator.free(child_proof_lens);

    var pk_offset: usize = 0;
    for (0..num_children) |i| {
        const cpks = children_pub_keys[i];
        child_num_keys[i] = cpks.len;
        for (cpks, 0..) |pk, j| {
            child_all_pks[pk_offset + j] = pk;
        }
        pk_offset += cpks.len;

        const proof_slice = children_proofs[i].constSlice();
        child_proof_ptrs[i] = proof_slice.ptr;
        child_proof_lens[i] = proof_slice.len;
    }

    const agg_sig = xmss_aggregate(
        public_keys.ptr,
        signatures.ptr,
        public_keys.len,
        num_children,
        child_all_pks.ptr,
        child_num_keys.ptr,
        child_proof_ptrs.ptr,
        child_proof_lens.ptr,
        message_hash,
        epoch,
        log_inv_rate,
    ) orelse return AggregationError.AggregationFailed;

    // Serialize the aggregate signature to bytes
    var buffer: [MAX_AGGREGATE_SIGNATURE_SIZE]u8 = undefined;
    const bytes_written = xmss_aggregate_signature_to_bytes(agg_sig, &buffer, buffer.len);
    if (bytes_written == 0) {
        xmss_free_aggregate_signature(@constCast(agg_sig));
        return AggregationError.SerializationFailed;
    }

    // Free the aggregate signature
    xmss_free_aggregate_signature(@constCast(agg_sig));

    // Copy the bytes to the output
    for (buffer[0..bytes_written]) |byte| {
        try multisig_aggregated_signature.append(byte);
    }
}

pub fn verifyAggregatedPayload(public_keys: []*const hashsig.HashSigPublicKey, message_hash: *const [32]u8, epoch: u32, agg_sig: *const ByteListMiB) !void {
    // Get bytes from aggregated signature
    const sig_bytes = agg_sig.constSlice();

    try setupVerifier();

    // Verify directly from bytes (Rust deserializes internally)
    const result = xmss_verify_aggregated(
        public_keys.ptr,
        public_keys.len,
        message_hash,
        sig_bytes.ptr,
        sig_bytes.len,
        epoch,
    );

    if (!result) return AggregationError.InvalidAggregateSignature;
}

// Tests

test "aggregateSignatures returns PublicKeysSignatureLengthMismatch for mismatched lengths" {
    var public_keys = [_]*const hashsig.HashSigPublicKey{undefined};
    var signatures = [_]*const hashsig.HashSigSignature{};
    const message_hash = [_]u8{0} ** 32;

    var multisig_aggregated_signature = try ByteListMiB.init(std.testing.allocator);
    defer multisig_aggregated_signature.deinit();
    const empty_children_pks: [][]*const hashsig.HashSigPublicKey = &.{};
    const empty_children_proofs: []const ByteListMiB = &.{};
    const result = aggregateSignatures(&public_keys, &signatures, empty_children_pks, empty_children_proofs, &message_hash, 0, 2, &multisig_aggregated_signature);
    try std.testing.expectError(AggregationError.PublicKeysSignatureLengthMismatch, result);
}

test "aggregateSignatures and verifyAggregatedPayload with valid and invalid public_key/ message/ epoch" {
    const allocator = std.testing.allocator;

    var keypair = try hashsig.KeyPair.generate(allocator, "test_keypair", 0, 10);
    defer keypair.deinit();

    const message_hash = [_]u8{42} ** 32;
    const epoch: u32 = 0;

    var signature = try keypair.sign(&message_hash, epoch);
    defer signature.deinit();

    try setupProver();

    var public_keys = [_]*const hashsig.HashSigPublicKey{keypair.public_key};
    var signatures = [_]*const hashsig.HashSigSignature{signature.handle};

    // Aggregate (no children)
    var multisig_aggregated_signature = try ByteListMiB.init(allocator);
    defer multisig_aggregated_signature.deinit();
    const empty_children_pks: [][]*const hashsig.HashSigPublicKey = &.{};
    const empty_children_proofs: []const ByteListMiB = &.{};
    try aggregateSignatures(&public_keys, &signatures, empty_children_pks, empty_children_proofs, &message_hash, epoch, 2, &multisig_aggregated_signature);

    // Verify
    try verifyAggregatedPayload(&public_keys, &message_hash, epoch, &multisig_aggregated_signature);

    // Verification with wrong public key should fail
    var wrong_keypair = try hashsig.KeyPair.generate(allocator, "test_wrong_keypair", 0, 10);
    defer wrong_keypair.deinit();
    var wrong_public_keys = [_]*const hashsig.HashSigPublicKey{wrong_keypair.public_key};
    var result = verifyAggregatedPayload(&wrong_public_keys, &message_hash, epoch, &multisig_aggregated_signature);
    try std.testing.expectError(AggregationError.InvalidAggregateSignature, result);

    // Verification with wrong message should fail
    const wrong_message = [_]u8{99} ** 32;
    result = verifyAggregatedPayload(&public_keys, &wrong_message, epoch, &multisig_aggregated_signature);
    try std.testing.expectError(AggregationError.InvalidAggregateSignature, result);

    // Verification with wrong epoch should fail
    const wrong_epoch = epoch + 1;
    result = verifyAggregatedPayload(&public_keys, &message_hash, wrong_epoch, &multisig_aggregated_signature);
    try std.testing.expectError(AggregationError.InvalidAggregateSignature, result);
}

test "aggregateSignatures recursively aggregates child payloads and verifies with combined public keys" {
    const allocator = std.testing.allocator;
    const message_hash = [_]u8{7} ** 32;
    const epoch: u32 = 3;

    // Build two independent child proofs (each child has one raw signer).
    var child1_kp = try hashsig.KeyPair.generate(allocator, "child1_keypair", 0, 10);
    defer child1_kp.deinit();
    var child1_sig = try child1_kp.sign(&message_hash, epoch);
    defer child1_sig.deinit();

    var child2_kp = try hashsig.KeyPair.generate(allocator, "child2_keypair", 0, 10);
    defer child2_kp.deinit();
    var child2_sig = try child2_kp.sign(&message_hash, epoch);
    defer child2_sig.deinit();

    var child1_proof = try ByteListMiB.init(allocator);
    defer child1_proof.deinit();
    var child2_proof = try ByteListMiB.init(allocator);
    defer child2_proof.deinit();

    var child1_pks = [_]*const hashsig.HashSigPublicKey{child1_kp.public_key};
    var child1_sigs = [_]*const hashsig.HashSigSignature{child1_sig.handle};
    const no_children_pks: [][]*const hashsig.HashSigPublicKey = &.{};
    const no_children_proofs: []const ByteListMiB = &.{};
    try aggregateSignatures(&child1_pks, &child1_sigs, no_children_pks, no_children_proofs, &message_hash, epoch, 2, &child1_proof);

    var child2_pks = [_]*const hashsig.HashSigPublicKey{child2_kp.public_key};
    var child2_sigs = [_]*const hashsig.HashSigSignature{child2_sig.handle};
    try aggregateSignatures(&child2_pks, &child2_sigs, no_children_pks, no_children_proofs, &message_hash, epoch, 2, &child2_proof);

    // Parent proof aggregates children only (no direct raw signatures).
    var parent_proof = try ByteListMiB.init(allocator);
    defer parent_proof.deinit();
    const parent_raw_pks: []*const hashsig.HashSigPublicKey = &.{};
    const parent_raw_sigs: []*const hashsig.HashSigSignature = &.{};
    var children_pub_keys = [_][]*const hashsig.HashSigPublicKey{
        &child1_pks,
        &child2_pks,
    };
    const children_proofs = [_]ByteListMiB{ child1_proof, child2_proof };
    try aggregateSignatures(
        parent_raw_pks,
        parent_raw_sigs,
        &children_pub_keys,
        &children_proofs,
        &message_hash,
        epoch,
        2,
        &parent_proof,
    );

    var combined_public_keys = [_]*const hashsig.HashSigPublicKey{
        child1_kp.public_key,
        child2_kp.public_key,
    };
    try verifyAggregatedPayload(&combined_public_keys, &message_hash, epoch, &parent_proof);
}

test "aggregateSignatures returns AggregationFailed when child payload arrays are mismatched" {
    const message_hash = [_]u8{1} ** 32;
    var output = try ByteListMiB.init(std.testing.allocator);
    defer output.deinit();

    const raw_pks: []*const hashsig.HashSigPublicKey = &.{};
    const raw_sigs: []*const hashsig.HashSigSignature = &.{};
    const empty_child_pks = [_][]*const hashsig.HashSigPublicKey{};
    var one_child_proof = try ByteListMiB.init(std.testing.allocator);
    defer one_child_proof.deinit();
    const one_child_proofs = [_]ByteListMiB{one_child_proof};

    const result = aggregateSignatures(
        raw_pks,
        raw_sigs,
        &empty_child_pks,
        &one_child_proofs,
        &message_hash,
        0,
        2,
        &output,
    );
    try std.testing.expectError(AggregationError.AggregationFailed, result);
}

test "verifyAggregatedPayload fails for recursively aggregated payload with missing child key" {
    const allocator = std.testing.allocator;
    const message_hash = [_]u8{11} ** 32;
    const epoch: u32 = 5;

    var child1_kp = try hashsig.KeyPair.generate(allocator, "verify_child1_keypair", 0, 10);
    defer child1_kp.deinit();
    var child1_sig = try child1_kp.sign(&message_hash, epoch);
    defer child1_sig.deinit();

    var child2_kp = try hashsig.KeyPair.generate(allocator, "verify_child2_keypair", 0, 10);
    defer child2_kp.deinit();
    var child2_sig = try child2_kp.sign(&message_hash, epoch);
    defer child2_sig.deinit();

    var child1_proof = try ByteListMiB.init(allocator);
    defer child1_proof.deinit();
    var child2_proof = try ByteListMiB.init(allocator);
    defer child2_proof.deinit();

    var child1_pks = [_]*const hashsig.HashSigPublicKey{child1_kp.public_key};
    var child1_sigs = [_]*const hashsig.HashSigSignature{child1_sig.handle};
    const no_children_pks: [][]*const hashsig.HashSigPublicKey = &.{};
    const no_children_proofs: []const ByteListMiB = &.{};
    try aggregateSignatures(&child1_pks, &child1_sigs, no_children_pks, no_children_proofs, &message_hash, epoch, 2, &child1_proof);

    var child2_pks = [_]*const hashsig.HashSigPublicKey{child2_kp.public_key};
    var child2_sigs = [_]*const hashsig.HashSigSignature{child2_sig.handle};
    try aggregateSignatures(&child2_pks, &child2_sigs, no_children_pks, no_children_proofs, &message_hash, epoch, 2, &child2_proof);

    var parent_proof = try ByteListMiB.init(allocator);
    defer parent_proof.deinit();
    const parent_raw_pks: []*const hashsig.HashSigPublicKey = &.{};
    const parent_raw_sigs: []*const hashsig.HashSigSignature = &.{};
    var children_pub_keys = [_][]*const hashsig.HashSigPublicKey{
        &child1_pks,
        &child2_pks,
    };
    const children_proofs = [_]ByteListMiB{ child1_proof, child2_proof };
    try aggregateSignatures(
        parent_raw_pks,
        parent_raw_sigs,
        &children_pub_keys,
        &children_proofs,
        &message_hash,
        epoch,
        2,
        &parent_proof,
    );

    var incomplete_public_keys = [_]*const hashsig.HashSigPublicKey{
        child1_kp.public_key,
    };
    const result = verifyAggregatedPayload(&incomplete_public_keys, &message_hash, epoch, &parent_proof);
    try std.testing.expectError(AggregationError.InvalidAggregateSignature, result);
}
