const std = @import("std");

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
) ?*anyopaque;

extern fn xmss_verify_aggregated(
    public_keys: [*]const *const anyopaque,
    num_keys: usize,
    message_hash_ptr: [*]const u8,
    agg_sig: *const anyopaque,
    epoch: u32,
) bool;

extern fn xmss_free_aggregate_signature(agg_sig: *anyopaque) void;

pub const AggregationError = error{
    GenerationFailed,
    AggregationFailed,
    InvalidSignature,
    VerificationFailed,
};

pub fn setupProver() void {
    xmss_setup_prover();
}

pub fn setupVerifier() void {
    xmss_setup_verifier();
}

/// Opaque handle to aggregated signature allocated in Rust
pub const AggregateSignature = opaque {
    /// Free the aggregate signature
    pub fn deinit(self: *AggregateSignature) void {
        xmss_free_aggregate_signature(@ptrCast(self));
    }
};

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
        return AggregationError.AggregationFailed;
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

    if (!is_valid) return AggregationError.InvalidSignature;
}
