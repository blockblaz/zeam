const std = @import("std");
const hashsig = @import("hashsig.zig");
const ssz = @import("ssz");
const zeam_metrics = @import("@zeam/metrics");
const zeam_utils = @import("@zeam/utils");

pub const AggregationError = error{ SerializationFailed, DeserializationFailed, PublicKeysSignatureLengthMismatch, AggregationFailed, InvalidAggregateSignature };

/// Maximum buffer size for serialized aggregate signatures (1 MiB)
pub const MAX_AGGREGATE_SIGNATURE_SIZE: usize = 1 << 20;

// Variable-length byte list for multisig aggregated signatures.
pub const ByteListMiB = ssz.utils.List(u8, MAX_AGGREGATE_SIGNATURE_SIZE);

pub const AggregatedXMSS = opaque {};

// External C functions from multisig-glue (uses leanMultisig devnet4 with recursive aggregation)
/// Returns 0 on success, -1 if the prover bytecode file is missing or initialisation failed.
/// Never panics — the Rust side wraps the body in catch_unwind (fix for #722).
extern fn setup_xmss_aggregation() callconv(.c) c_int;
/// Configure the global rayon thread pool. Must be called before setup_xmss_aggregation.
/// num_threads=0 means use rayon default (one per logical CPU).
/// Returns 0 always (errors from an already-initialized pool are silently ignored).
extern fn xmss_set_rayon_threads(num_threads: usize) callconv(.c) c_int;

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
    // Phase timing out-params (#940). See multisig-glue/src/lib.rs for the
    // exact phase definitions. Nullable.
    out_marshal_ns: ?*u64,
    out_stark_ns: ?*u64,
    out_post_ns: ?*u64,
) callconv(.c) ?*AggregatedXMSS;

extern fn xmss_verify_aggregated(
    public_keys: [*]const *const hashsig.HashSigPublicKey,
    num_keys: usize,
    message_hash_ptr: [*]const u8,
    agg_sig_bytes: [*]const u8,
    agg_sig_len: usize,
    slot: u32,
) callconv(.c) bool;

extern fn xmss_verify_aggregated_batch(
    public_key_offsets: [*]const usize,
    public_key_counts: [*]const usize,
    num_tasks: usize,
    public_keys: [*]const *const hashsig.HashSigPublicKey,
    message_hashes: [*]const u8,
    agg_sig_ptrs: [*]const [*]const u8,
    agg_sig_lens: [*]const usize,
    slots: [*]const u32,
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

/// Configure the global rayon thread pool used by the XMSS aggregate prover.
/// Must be called before `setupXmssAggregation` and before any aggregation work begins.
/// `num_threads = 0` means "use rayon's default" (one thread per logical CPU).
/// Typical usage: pass `cpu_count - 3` to reserve cores for libxev, the chain
/// worker, and the rust-libp2p network thread (see issue #873).
/// Silently no-ops if the pool is already initialized.
pub fn setRayonThreads(num_threads: usize) void {
    _ = xmss_set_rayon_threads(num_threads);
}

/// Initialize XMSS aggregation (both prove and verify state). Must be called
/// exactly once at node startup, before any aggregation or verification work
/// begins.
pub fn setupXmssAggregation() error{XmssAggregationSetupFailed}!void {
    if (setup_xmss_aggregation() != 0) return error.XmssAggregationSetupFailed;
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

    // Phase-timing buckets filled by the Rust FFI (#940). Zero-initialized so
    // an early-return inside xmss_aggregate that skips the writes still leaves
    // a defined state; the success path below overwrites all three before we
    // observe them.
    var ffi_marshal_ns: u64 = 0;
    var ffi_stark_ns: u64 = 0;
    var ffi_post_ns: u64 = 0;

    const prove_start_ns = zeam_utils.monotonicTimestampNs();
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
        &ffi_marshal_ns,
        &ffi_stark_ns,
        &ffi_post_ns,
    ) orelse return AggregationError.AggregationFailed;
    recordXmssProveDuration(prove_start_ns, public_keys.len, num_children);
    zeam_metrics.observeXmssRecAggregatePhase("marshal", ffi_marshal_ns);
    zeam_metrics.observeXmssRecAggregatePhase("stark", ffi_stark_ns);
    zeam_metrics.observeXmssRecAggregatePhase("post", ffi_post_ns);

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

fn recordXmssProveDuration(start_ns: i128, num_raw: usize, num_children: usize) void {
    const end_ns = zeam_utils.monotonicTimestampNs();
    const elapsed_ns: i128 = if (end_ns >= start_ns) end_ns - start_ns else 0;
    const elapsed_s = @as(f32, @floatFromInt(elapsed_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
    zeam_metrics.observeXmssRecAggregateProve(elapsed_s, num_raw, num_children);
}

/// Precondition: `setupXmssAggregation` must have been called once in this process.
pub fn verifyAggregatedPayload(public_keys: []*const hashsig.HashSigPublicKey, message_hash: *const [32]u8, epoch: u32, agg_sig: *const ByteListMiB) !void {
    // Get bytes from aggregated signature
    const sig_bytes = agg_sig.constSlice();

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

pub const AggregatedPayloadVerifyBatch = struct {
    public_keys: []*const hashsig.HashSigPublicKey,
    message_hash: [32]u8,
    epoch: u32,
    agg_sig: *const ByteListMiB,
};

/// Precondition: `setupXmssAggregation` must have been called once in this process.
pub fn verifyAggregatedPayloadBatch(allocator: std.mem.Allocator, tasks: []const AggregatedPayloadVerifyBatch) !void {
    if (tasks.len == 0) return;

    var total_keys: usize = 0;
    for (tasks) |task| total_keys += task.public_keys.len;

    const offsets = try allocator.alloc(usize, tasks.len);
    defer allocator.free(offsets);
    const counts = try allocator.alloc(usize, tasks.len);
    defer allocator.free(counts);
    const all_public_keys = try allocator.alloc(*const hashsig.HashSigPublicKey, total_keys);
    defer allocator.free(all_public_keys);
    const message_hashes = try allocator.alloc(u8, tasks.len * 32);
    defer allocator.free(message_hashes);
    const sig_ptrs = try allocator.alloc([*]const u8, tasks.len);
    defer allocator.free(sig_ptrs);
    const sig_lens = try allocator.alloc(usize, tasks.len);
    defer allocator.free(sig_lens);
    const slots = try allocator.alloc(u32, tasks.len);
    defer allocator.free(slots);

    var key_offset: usize = 0;
    for (tasks, 0..) |task, i| {
        offsets[i] = key_offset;
        counts[i] = task.public_keys.len;
        for (task.public_keys, 0..) |public_key, j| {
            all_public_keys[key_offset + j] = public_key;
        }
        key_offset += task.public_keys.len;
        @memcpy(message_hashes[i * 32 .. (i + 1) * 32], &task.message_hash);
        const sig_bytes = task.agg_sig.constSlice();
        sig_ptrs[i] = sig_bytes.ptr;
        sig_lens[i] = sig_bytes.len;
        slots[i] = task.epoch;
    }

    const result = xmss_verify_aggregated_batch(
        offsets.ptr,
        counts.ptr,
        tasks.len,
        all_public_keys.ptr,
        message_hashes.ptr,
        sig_ptrs.ptr,
        sig_lens.ptr,
        slots.ptr,
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

    setRayonThreads(1);
    try setupXmssAggregation();

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

    setRayonThreads(1);
    try setupXmssAggregation();

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

    setRayonThreads(1);
    try setupXmssAggregation();

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
