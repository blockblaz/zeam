const std = @import("std");
const hashsig = @import("hashsig.zig");

pub const AggregationError = error{ SerializationFailed, ZeroByte, DeserializationFailed, KeypairsSignatureLengthMismatch, AggregationFailed, InvalidAggregateSignature };

/// Maximum buffer size for serialized aggregate signatures (1 MiB)
pub const MAX_AGGREGATE_SIGNATURE_SIZE: usize = 1 << 20;

/// Opaque handle to aggregated signature allocated in Rust
pub const AggregateSignature = opaque {
    /// Free the aggregate signature
    pub fn deinit(self: *AggregateSignature) void {
        xmss_free_aggregate_signature(self);
    }

    /// Serialize the aggregate signature to bytes.
    /// Returns an allocated byte slice that the caller owns and must free.
    pub fn toBytes(self: *const AggregateSignature, allocator: std.mem.Allocator) ![]u8 {
        // First, try with a stack buffer to get the size
        var size_buffer: [MAX_AGGREGATE_SIGNATURE_SIZE]u8 = undefined;
        const bytes_written = xmss_aggregate_signature_to_bytes(
            self,
            &size_buffer,
            size_buffer.len,
        );

        if (bytes_written == 0) {
            return AggregationError.SerializationFailed;
        }

        // Allocate and copy the result
        const result = try allocator.alloc(u8, bytes_written);
        @memcpy(result, size_buffer[0..bytes_written]);
        return result;
    }

    /// Deserialize an aggregate signature from bytes.
    /// Returns an owned AggregateSignature that the caller must deinit().
    pub fn fromBytes(bytes: []const u8) !*AggregateSignature {
        if (bytes.len == 0) {
            return AggregationError.ZeroByte;
        }

        const agg_sig = xmss_aggregate_signature_from_bytes(
            bytes.ptr,
            bytes.len,
        );

        if (agg_sig == null) {
            return AggregationError.DeserializationFailed;
        }

        return agg_sig.?;
    }
};

// External C functions from multisig-glue (uses leanMultisig devnet2)
extern fn xmss_setup_prover() void;
extern fn xmss_setup_verifier() void;

extern fn xmss_aggregate(
    public_keys: [*]const *const anyopaque,
    num_keys: usize,
    signatures: [*]const *const anyopaque,
    num_sigs: usize,
    message_hash_ptr: [*]const u8,
    epoch: u32,
) ?*AggregateSignature;

extern fn xmss_verify_aggregated(
    public_keys: [*]const *const anyopaque,
    num_keys: usize,
    message_hash_ptr: [*]const u8,
    agg_sig: *const AggregateSignature,
    epoch: u32,
) bool;

extern fn xmss_free_aggregate_signature(agg_sig: *AggregateSignature) void;

// SSZ serialization/deserialization FFI functions
extern fn xmss_aggregate_signature_to_bytes(
    agg_sig: *const AggregateSignature,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

extern fn xmss_aggregate_signature_from_bytes(
    bytes: [*]const u8,
    bytes_len: usize,
) ?*AggregateSignature;

pub fn setupProver() void {
    xmss_setup_prover();
}

pub fn setupVerifier() void {
    xmss_setup_verifier();
}

/// Aggregate signatures from hashsig-glue handles
/// Returns opaque handle to Devnet2XmssAggregateSignature
/// Caller must call deinit() on the returned signature
pub fn aggregate(
    keypairs: []*const anyopaque,
    signatures: []*const anyopaque,
    message_hash: *const [32]u8,
    epoch: u32,
    allocator: std.mem.Allocator,
) AggregationError!*AggregateSignature {
    _ = allocator; // No longer needed - we're not allocating or copying anything!

    if (keypairs.len != signatures.len) {
        return AggregationError.KeypairsSignatureLengthMismatch;
    }

    const agg_sig = xmss_aggregate(
        keypairs.ptr,
        keypairs.len,
        signatures.ptr,
        signatures.len,
        message_hash,
        epoch,
    );

    if (agg_sig == null) return AggregationError.AggregationFailed;

    // Return the opaque pointer directly
    return @ptrCast(agg_sig.?);
}

/// Verify aggregated signatures using hashsig-glue keypair handles
/// Takes aggregate signature handle directly
pub fn verifyAggregated(
    keypairs: []*const anyopaque,
    message_hash: *const [32]u8,
    agg_sig: *const AggregateSignature,
    epoch: u32,
) AggregationError!void {
    const is_valid = xmss_verify_aggregated(
        keypairs.ptr,
        keypairs.len,
        message_hash,
        @ptrCast(agg_sig),
        epoch,
    );

    if (!is_valid) return AggregationError.InvalidAggregateSignature;
}

// Tests
test "AggregateSignature.fromBytes returns ZeroByte for empty input" {
    const result = AggregateSignature.fromBytes(&[_]u8{});
    try std.testing.expectError(AggregationError.ZeroByte, result);
}

test "AggregateSignature.fromBytes returns DeserializationFailed for invalid input" {
    const invalid_bytes = [_]u8{ 1, 2, 3, 4, 5 };
    const result = AggregateSignature.fromBytes(&invalid_bytes);
    try std.testing.expectError(AggregationError.DeserializationFailed, result);
}

test "aggregate returns KeypairsSignatureLengthMismatch for mismatched lengths" {
    const allocator = std.testing.allocator;

    var keypairs = [_]*const anyopaque{undefined};
    var signatures = [_]*const anyopaque{};
    const message_hash = [_]u8{0} ** 32;

    const result = aggregate(&keypairs, &signatures, &message_hash, 0, allocator);
    try std.testing.expectError(AggregationError.KeypairsSignatureLengthMismatch, result);
}

test "AggregateSignature SSZ roundtrip" {
    const allocator = std.testing.allocator;

    // Generate a keypair
    var keypair = try hashsig.KeyPair.generate(allocator, "test_aggregate_ssz", 0, 10);
    defer keypair.deinit();

    const message_hash = [_]u8{42} ** 32;
    const epoch: u32 = 0;

    // Sign the message
    var signature = try keypair.sign(&message_hash, epoch);
    defer signature.deinit();

    // Setup prover for aggregation
    setupProver();

    // Prepare arrays for aggregation (cast to anyopaque pointers)
    var keypairs = [_]*const anyopaque{@ptrCast(keypair.handle)};
    var signatures = [_]*const anyopaque{@ptrCast(signature.handle)};

    // Aggregate
    const agg_sig = try aggregate(&keypairs, &signatures, &message_hash, epoch, allocator);
    defer agg_sig.deinit();

    // Serialize to SSZ bytes
    const ssz_bytes = try agg_sig.toBytes(allocator);
    defer allocator.free(ssz_bytes);

    std.debug.print("\nAggregate signature SSZ size: {d} bytes\n", .{ssz_bytes.len});

    // Deserialize from SSZ bytes
    const restored_agg_sig = try AggregateSignature.fromBytes(ssz_bytes);
    defer restored_agg_sig.deinit();

    // Verify the restored signature works
    try verifyAggregated(&keypairs, &message_hash, restored_agg_sig, epoch);

    // Re-serialize and compare bytes
    const re_encoded = try restored_agg_sig.toBytes(allocator);
    defer allocator.free(re_encoded);

    try std.testing.expectEqualSlices(u8, ssz_bytes, re_encoded);

    std.debug.print("SSZ roundtrip successful!\n", .{});
}

test "verifyAggregated fails with wrong message/ epoch" {
    const allocator = std.testing.allocator;

    var keypair = try hashsig.KeyPair.generate(allocator, "test_wrong_msg", 0, 10);
    defer keypair.deinit();

    const message_hash = [_]u8{42} ** 32;
    const wrong_message = [_]u8{99} ** 32;
    const epoch: u32 = 0;

    var signature = try keypair.sign(&message_hash, epoch);
    defer signature.deinit();

    setupProver();

    var keypairs = [_]*const anyopaque{@ptrCast(keypair.handle)};
    var signatures = [_]*const anyopaque{@ptrCast(signature.handle)};

    const agg_sig = try aggregate(&keypairs, &signatures, &message_hash, epoch, allocator);
    defer agg_sig.deinit();

    // Verification with wrong message should fail
    var result = verifyAggregated(&keypairs, &wrong_message, agg_sig, epoch);
    try std.testing.expectError(AggregationError.InvalidAggregateSignature, result);

    // Verification with wrong epoch should fail
    result = verifyAggregated(&keypairs, &message_hash, agg_sig, epoch + 1);
    try std.testing.expectError(AggregationError.InvalidAggregateSignature, result);
}
