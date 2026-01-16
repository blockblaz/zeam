const std = @import("std");
const hashsig = @import("hashsig.zig");
const ssz = @import("ssz");

pub const AggregationError = error{ SerializationFailed, DeserializationFailed, PublicKeysSignatureLengthMismatch, AggregationFailed, InvalidAggregateSignature };

/// Maximum buffer size for serialized aggregate signatures (1 MiB)
pub const MAX_AGGREGATE_SIGNATURE_SIZE: usize = 1 << 20;

// Variable-length byte list for multisig aggregated signatures.
pub const ByteListMiB = ssz.utils.List(u8, MAX_AGGREGATE_SIGNATURE_SIZE);

pub const Devnet2XmssAggregateSignature = opaque {};

// External C functions from multisig-glue (uses leanMultisig devnet2)
extern fn xmss_setup_prover() void;
extern fn xmss_setup_verifier() void;

extern fn xmss_aggregate(
    public_keys: [*]const *const hashsig.HashSigPublicKey,
    num_keys: usize,
    signatures: [*]const *const hashsig.HashSigSignature,
    num_sigs: usize,
    message_hash_ptr: [*]const u8,
    epoch: u32,
) ?*Devnet2XmssAggregateSignature;

extern fn xmss_verify_aggregated(
    public_keys: [*]const *const hashsig.HashSigPublicKey,
    num_keys: usize,
    message_hash_ptr: [*]const u8,
    agg_sig: *const Devnet2XmssAggregateSignature,
    epoch: u32,
) bool;

extern fn xmss_free_aggregate_signature(agg_sig: *Devnet2XmssAggregateSignature) void;

// SSZ serialization/deserialization FFI functions
extern fn xmss_aggregate_signature_to_bytes(
    agg_sig: *const Devnet2XmssAggregateSignature,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

extern fn xmss_aggregate_signature_from_bytes(
    bytes: [*]const u8,
    bytes_len: usize,
) ?*Devnet2XmssAggregateSignature;

pub fn setupProver() void {
    xmss_setup_prover();
}

pub fn setupVerifier() void {
    xmss_setup_verifier();
}

pub fn aggregateSignatures(public_keys: []*const hashsig.HashSigPublicKey, signatures: []*const hashsig.HashSigSignature, message_hash: *const [32]u8, epoch: u32, multisig_aggregated_signature: *ByteListMiB) !void {
    if (public_keys.len != signatures.len) {
        return AggregationError.PublicKeysSignatureLengthMismatch;
    }

    setupProver();

    const agg_sig = xmss_aggregate(
        public_keys.ptr,
        public_keys.len,
        signatures.ptr,
        signatures.len,
        message_hash,
        epoch,
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

    // Copy the bytes to the MultisigAggregatedSignature
    // Clear existing content by deinit and reinit, or append each byte
    // Since we don't have access to allocator here, we'll append bytes one by one
    // The caller should ensure the list is empty or we append to existing content
    for (buffer[0..bytes_written]) |byte| {
        try multisig_aggregated_signature.append(byte);
    }
}

pub fn verifyAggregatedPayload(public_keys: []*const hashsig.HashSigPublicKey, message_hash: *const [32]u8, epoch: u32, agg_sig: *const ByteListMiB) !void {
    // Get bytes from MultisigAggregatedSignature
    const sig_bytes = agg_sig.constSlice();

    setupVerifier();

    // Deserialize to Devnet2XmssAggregateSignature
    const devnet_sig = xmss_aggregate_signature_from_bytes(sig_bytes.ptr, sig_bytes.len) orelse {
        return AggregationError.DeserializationFailed;
    };
    defer xmss_free_aggregate_signature(devnet_sig);

    // Verify
    const result = xmss_verify_aggregated(
        public_keys.ptr,
        public_keys.len,
        message_hash,
        devnet_sig,
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
    const result = aggregateSignatures(&public_keys, &signatures, &message_hash, 0, &multisig_aggregated_signature);
    try std.testing.expectError(AggregationError.PublicKeysSignatureLengthMismatch, result);
}

// leanMultisig panics when invalid public key/signature pairs are used
// test "aggregateSignatures returns AggregationFailed for invalid public key/signature pairs" {
//     const epoch: u32 = 0;
//     var kp = try hashsig.KeyPair.generate(std.testing.allocator, "test_keypair", 0, epoch);
//     defer kp.deinit();

//     const message_hash = [_]u8{0} ** 32;

//     var signature = try kp.sign(&message_hash, epoch);
//     defer signature.deinit();
//     var signatures = [_]*const hashsig.HashSigSignature{signature.handle};

//     var wrong_kp = try hashsig.KeyPair.generate(std.testing.allocator, "test_wrong_keypair", 0, epoch);
//     defer wrong_kp.deinit();

//     var multisig_aggregated_signature = try MultisigAggregatedSignature.init(std.testing.allocator);
//     defer multisig_aggregated_signature.deinit();
//     var wrong_public_keys = [_]*const hashsig.HashSigPublicKey{wrong_kp.public_key};
//     const result = aggregateSignatures(&wrong_public_keys, &signatures, &message_hash, epoch, &multisig_aggregated_signature);
//     try std.testing.expectError(AggregationError.AggregationFailed, result);
// }

test "aggregateSignatures and verifyAggregatedPayload with valid and invalid public_key/ message/ epoch" {
    const allocator = std.testing.allocator;

    var keypair = try hashsig.KeyPair.generate(allocator, "test_keypair", 0, 10);
    defer keypair.deinit();

    const message_hash = [_]u8{42} ** 32;
    const epoch: u32 = 0;

    var signature = try keypair.sign(&message_hash, epoch);
    defer signature.deinit();

    setupProver();

    var public_keys = [_]*const hashsig.HashSigPublicKey{keypair.public_key};
    var signatures = [_]*const hashsig.HashSigSignature{signature.handle};

    // Aggregate
    var multisig_aggregated_signature = try ByteListMiB.init(allocator);
    defer multisig_aggregated_signature.deinit();
    try aggregateSignatures(&public_keys, &signatures, &message_hash, epoch, &multisig_aggregated_signature);

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
