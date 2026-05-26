const std = @import("std");
const hashsig = @import("hashsig.zig");
const ssz = @import("ssz");
const zeam_metrics = @import("@zeam/metrics");
const zeam_utils = @import("@zeam/utils");

pub const AggregationError = error{
    PublicKeysSignatureLengthMismatch,
    ProofTooLarge,
    ProverSetupFailed,
    VerifierSetupFailed,
    Type1AggregateFailed,
    Type1VerifyFailed,
    Type2MergeFailed,
    Type2SplitFailed,
    Type2VerifyFailed,
};

/// Maximum size of a compact (no-pubkeys) Type-1/Type-2 proof on the wire (512 KiB).
/// Matches the leanSpec `ByteList512KiB` cap for `SignedBlock.proof` and proof payloads.
pub const MAX_AGGREGATE_PROOF_SIZE: usize = 512 * 1024;

/// Variable-length byte list for compact Type-1/Type-2 proofs.
pub const ByteList512KiB = ssz.utils.List(u8, MAX_AGGREGATE_PROOF_SIZE);

/// Per-component (message hash, slot) binding used when verifying a Type-2 proof.
pub const MessageBinding = struct {
    hash: [32]u8,
    slot: u32,
};

// --- multisig-glue FFI (leanMultisig devnet5 Type-1/Type-2 surface) ---
//
// All wrappers are pure Zig + extern calls and are safe to call from any thread, BUT each one
// drives the leanMultisig zk prover/verifier — they are heavy and MUST NOT be called from the
// libxev thread. Run them on the chain worker / Io.Threaded pool (see issue #873).

/// Returns 0 on success, -1 if the prover bytecode is missing or init failed (never panics).
extern fn xmss_setup_prover() callconv(.c) c_int;
/// Returns 0 on success, -1 on failure.
extern fn xmss_setup_verifier() callconv(.c) c_int;
/// Configure the global rayon pool. Must be called before xmss_setup_prover. Returns 0.
extern fn xmss_set_rayon_threads(num_threads: usize) callconv(.c) c_int;

/// Aggregate raw XMSS sigs + child Type-1 proofs into one Type-1. Output via the
/// (out_buf, out_cap, out_written) protocol: 0 = ok, -1 = error, -2 = buffer too small
/// (out_written set to required size).
extern fn xmss_aggregate_type_1(
    raw_pub_keys: [*]const *const hashsig.HashSigPublicKey,
    raw_signatures: [*]const *const hashsig.HashSigSignature,
    num_raw: usize,
    num_children: usize,
    child_all_pub_keys: [*]const *const hashsig.HashSigPublicKey,
    child_num_keys: [*]const usize,
    child_proof_ptrs: [*]const [*]const u8,
    child_proof_lens: [*]const usize,
    message_hash_ptr: [*]const u8,
    slot: u32,
    log_inv_rate: usize,
    out_buf: [*]u8,
    out_cap: usize,
    out_written: *usize,
) callconv(.c) c_int;

/// Verify a Type-1 proof against (pubkeys, message, slot). The (message, slot) binding is
/// enforced inside the FFI. Returns true iff valid.
extern fn xmss_verify_type_1(
    public_keys: [*]const *const hashsig.HashSigPublicKey,
    num_keys: usize,
    message_hash_ptr: [*]const u8,
    slot: u32,
    type_1_bytes: [*]const u8,
    type_1_len: usize,
) callconv(.c) bool;

/// Merge N Type-1 proofs (distinct messages) into one Type-2. Output via the protocol above.
extern fn xmss_merge_type_1_to_type_2(
    num_parts: usize,
    type_1_proof_ptrs: [*]const [*]const u8,
    type_1_proof_lens: [*]const usize,
    pks_flat: [*]const *const hashsig.HashSigPublicKey,
    pks_per_part_counts: [*]const usize,
    log_inv_rate: usize,
    out_buf: [*]u8,
    out_cap: usize,
    out_written: *usize,
) callconv(.c) c_int;

/// Recover the Type-1 component bound to `target_message_hash` from a Type-2. Output via protocol.
extern fn xmss_split_type_2_by_msg(
    type_2_bytes: [*]const u8,
    type_2_len: usize,
    pks_flat: [*]const *const hashsig.HashSigPublicKey,
    pks_per_message_counts: [*]const usize,
    num_messages: usize,
    target_message_hash: [*]const u8,
    log_inv_rate: usize,
    out_buf: [*]u8,
    out_cap: usize,
    out_written: *usize,
) callconv(.c) c_int;

/// Verify a Type-2 proof against per-component pubkeys + (message, slot) bindings (parallel,
/// in component order). Returns true iff the SNARK verifies AND every binding matches.
extern fn xmss_verify_type_2(
    type_2_bytes: [*]const u8,
    type_2_len: usize,
    pks_flat: [*]const *const hashsig.HashSigPublicKey,
    pks_per_message_counts: [*]const usize,
    num_messages: usize,
    message_hashes: [*]const u8,
    message_slots: [*]const u32,
) callconv(.c) bool;

/// Cached after first successful init; Rust side uses OnceLock as well.
var prover_ready = std.atomic.Value(bool).init(false);

/// Idempotent prover init for aggregators. Calls `setupProver` once and sets
/// `prover_ready` so the first `aggregateSignatures` does not pay setup on the
/// hot path. Safe to call at startup before the first slot trigger.
pub fn ensureProverReady() !void {
    if (prover_ready.load(.acquire)) return;
    try setupProver();
    prover_ready.store(true, .release);
}

/// Configure the global rayon thread pool used by the XMSS aggregate prover.
/// `num_threads = 0` means rayon default. Silently no-ops if the pool is already initialized.
pub fn setRayonThreads(num_threads: usize) void {
    _ = xmss_set_rayon_threads(num_threads);
}

/// Initialize the XMSS prover (idempotent). Hard error on failure — the caller (block production
/// / aggregation) must surface this, not silently skip (devnet5 no-fallback policy).
pub fn setupProver() AggregationError!void {
    if (xmss_setup_prover() != 0) return AggregationError.ProverSetupFailed;
}

/// Initialize the XMSS verifier (idempotent). Hard error on failure — a node that cannot verify
/// cannot safely import blocks.
pub fn setupVerifier() AggregationError!void {
    if (xmss_setup_verifier() != 0) return AggregationError.VerifierSetupFailed;
}

/// Copy `buf` into the (init'd, empty) `out` ByteList512KiB.
fn appendAll(out: *ByteList512KiB, buf: []const u8) AggregationError!void {
    for (buf) |b| out.append(b) catch return AggregationError.ProofTooLarge;
}

/// Aggregate raw XMSS signatures and child Type-1 proofs into a single Type-1 proof.
///
/// - `raw_pks`/`raw_sigs`: parallel raw public-key + signature handles (must be equal length).
/// - `children_pks`/`children_proofs`: parallel per-child pubkey handles + compact Type-1 wire.
/// - `out` must be an init'd, empty `ByteList512KiB`; the compact Type-1 wire is appended to it.
///
/// MUST be called on a worker thread (drives the prover).
pub fn aggregateType1(
    raw_pks: []*const hashsig.HashSigPublicKey,
    raw_sigs: []*const hashsig.HashSigSignature,
    children_pks: []const []*const hashsig.HashSigPublicKey,
    children_proofs: []const ByteList512KiB,
    message_hash: *const [32]u8,
    slot: u32,
    log_inv_rate: usize,
    out: *ByteList512KiB,
) AggregationError!void {
    if (raw_pks.len != raw_sigs.len) return AggregationError.PublicKeysSignatureLengthMismatch;
    if (children_pks.len != children_proofs.len) return AggregationError.Type1AggregateFailed;

    try ensureProverReady();

    const allocator = std.heap.c_allocator;
    const num_children = children_pks.len;

    var total_child_pks: usize = 0;
    for (children_pks) |c| total_child_pks += c.len;

    const child_all_pks = allocator.alloc(*const hashsig.HashSigPublicKey, total_child_pks) catch
        return AggregationError.Type1AggregateFailed;
    defer allocator.free(child_all_pks);
    const child_num_keys = allocator.alloc(usize, num_children) catch
        return AggregationError.Type1AggregateFailed;
    defer allocator.free(child_num_keys);
    const child_proof_ptrs = allocator.alloc([*]const u8, num_children) catch
        return AggregationError.Type1AggregateFailed;
    defer allocator.free(child_proof_ptrs);
    const child_proof_lens = allocator.alloc(usize, num_children) catch
        return AggregationError.Type1AggregateFailed;
    defer allocator.free(child_proof_lens);

    var off: usize = 0;
    for (0..num_children) |i| {
        const cpks = children_pks[i];
        child_num_keys[i] = cpks.len;
        for (cpks, 0..) |pk, j| child_all_pks[off + j] = pk;
        off += cpks.len;
        const ps = children_proofs[i].constSlice();
        child_proof_ptrs[i] = ps.ptr;
        child_proof_lens[i] = ps.len;
    }

    // 512 KiB scratch on the heap: these wrappers nest on worker threads, so stack frames could
    // overflow a small worker stack.
    const buf = allocator.alloc(u8, MAX_AGGREGATE_PROOF_SIZE) catch return AggregationError.Type1AggregateFailed;
    defer allocator.free(buf);
    var written: usize = 0;
    const prove_start_ns = zeam_utils.monotonicTimestampNs();
    const rc = xmss_aggregate_type_1(
        raw_pks.ptr,
        raw_sigs.ptr,
        raw_pks.len,
        num_children,
        child_all_pks.ptr,
        child_num_keys.ptr,
        child_proof_ptrs.ptr,
        child_proof_lens.ptr,
        message_hash,
        slot,
        log_inv_rate,
        buf.ptr,
        buf.len,
        &written,
    );
    if (rc == -2) return AggregationError.ProofTooLarge;
    if (rc != 0) return AggregationError.Type1AggregateFailed;
    recordXmssProveDuration(prove_start_ns);
    try appendAll(out, buf[0..written]);
}

fn recordXmssProveDuration(start_ns: i128) void {
    const end_ns = zeam_utils.monotonicTimestampNs();
    const elapsed_ns: i128 = if (end_ns >= start_ns) end_ns - start_ns else 0;
    const elapsed_s = @as(f32, @floatFromInt(elapsed_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
    zeam_metrics.observeXmssRecAggregateProve(elapsed_s);
}

/// Verify a Type-1 proof. `pks` are the participants' public-key handles; the (message, slot)
/// binding is checked inside the FFI. MUST be called on a worker thread.
pub fn verifyType1(
    pks: []*const hashsig.HashSigPublicKey,
    message_hash: *const [32]u8,
    slot: u32,
    proof: *const ByteList512KiB,
) AggregationError!void {
    try setupVerifier();
    const wire = proof.constSlice();
    const ok = xmss_verify_type_1(pks.ptr, pks.len, message_hash, slot, wire.ptr, wire.len);
    if (!ok) return AggregationError.Type1VerifyFailed;
}

/// Merge N Type-1 proofs (each over a distinct message) into one Type-2 proof.
///
/// - `parts`/`pks_per_part`: parallel arrays — the compact Type-1 wire and the participant
///   pubkey handles for each part, in canonical component order (caller's responsibility).
/// - `out` must be an init'd, empty `ByteList512KiB`; the compact Type-2 wire is appended.
///
/// MUST be called on a worker thread.
pub fn mergeType1ToType2(
    parts: []const ByteList512KiB,
    pks_per_part: []const []*const hashsig.HashSigPublicKey,
    log_inv_rate: usize,
    out: *ByteList512KiB,
) AggregationError!void {
    if (parts.len != pks_per_part.len) return AggregationError.Type2MergeFailed;
    if (parts.len == 0) return AggregationError.Type2MergeFailed;

    try ensureProverReady();

    const allocator = std.heap.c_allocator;
    const num_parts = parts.len;

    var total_pks: usize = 0;
    for (pks_per_part) |p| total_pks += p.len;

    const proof_ptrs = allocator.alloc([*]const u8, num_parts) catch return AggregationError.Type2MergeFailed;
    defer allocator.free(proof_ptrs);
    const proof_lens = allocator.alloc(usize, num_parts) catch return AggregationError.Type2MergeFailed;
    defer allocator.free(proof_lens);
    const pks_flat = allocator.alloc(*const hashsig.HashSigPublicKey, total_pks) catch return AggregationError.Type2MergeFailed;
    defer allocator.free(pks_flat);
    const pks_counts = allocator.alloc(usize, num_parts) catch return AggregationError.Type2MergeFailed;
    defer allocator.free(pks_counts);

    var off: usize = 0;
    for (0..num_parts) |i| {
        const ps = parts[i].constSlice();
        proof_ptrs[i] = ps.ptr;
        proof_lens[i] = ps.len;
        const pp = pks_per_part[i];
        pks_counts[i] = pp.len;
        for (pp, 0..) |pk, j| pks_flat[off + j] = pk;
        off += pp.len;
    }

    // 512 KiB scratch on the heap, not the stack (see aggregateType1).
    const buf = allocator.alloc(u8, MAX_AGGREGATE_PROOF_SIZE) catch return AggregationError.Type2MergeFailed;
    defer allocator.free(buf);
    var written: usize = 0;
    const rc = xmss_merge_type_1_to_type_2(
        num_parts,
        proof_ptrs.ptr,
        proof_lens.ptr,
        pks_flat.ptr,
        pks_counts.ptr,
        log_inv_rate,
        buf.ptr,
        buf.len,
        &written,
    );
    if (rc == -2) return AggregationError.ProofTooLarge;
    if (rc != 0) return AggregationError.Type2MergeFailed;
    try appendAll(out, buf[0..written]);
}

/// Recover the Type-1 component bound to `target_message_hash` out of a Type-2 proof.
///
/// - `pks_per_message`: the per-component pubkey layout the Type-2 was built with, in component
///   order (caller's responsibility — must match the merge layout).
/// - `out` must be an init'd, empty `ByteList512KiB`; the recovered compact Type-1 wire is appended.
///   The recovered Type-1 has an EMPTY participant set — the caller restores it from the matching
///   attestation's aggregation bits.
///
/// MUST be called on a worker thread.
pub fn splitType2ByMessage(
    type_2_proof: *const ByteList512KiB,
    pks_per_message: []const []*const hashsig.HashSigPublicKey,
    target_message_hash: *const [32]u8,
    log_inv_rate: usize,
    out: *ByteList512KiB,
) AggregationError!void {
    try ensureProverReady();

    const allocator = std.heap.c_allocator;
    const num_messages = pks_per_message.len;

    var total_pks: usize = 0;
    for (pks_per_message) |p| total_pks += p.len;

    const pks_flat = allocator.alloc(*const hashsig.HashSigPublicKey, total_pks) catch return AggregationError.Type2SplitFailed;
    defer allocator.free(pks_flat);
    const pks_counts = allocator.alloc(usize, num_messages) catch return AggregationError.Type2SplitFailed;
    defer allocator.free(pks_counts);

    var off: usize = 0;
    for (0..num_messages) |i| {
        const pp = pks_per_message[i];
        pks_counts[i] = pp.len;
        for (pp, 0..) |pk, j| pks_flat[off + j] = pk;
        off += pp.len;
    }

    const wire = type_2_proof.constSlice();
    // 512 KiB scratch on the heap, not the stack (see aggregateType1).
    const buf = allocator.alloc(u8, MAX_AGGREGATE_PROOF_SIZE) catch return AggregationError.Type2SplitFailed;
    defer allocator.free(buf);
    var written: usize = 0;
    const rc = xmss_split_type_2_by_msg(
        wire.ptr,
        wire.len,
        pks_flat.ptr,
        pks_counts.ptr,
        num_messages,
        target_message_hash,
        log_inv_rate,
        buf.ptr,
        buf.len,
        &written,
    );
    if (rc == -2) return AggregationError.ProofTooLarge;
    if (rc != 0) return AggregationError.Type2SplitFailed;
    try appendAll(out, buf[0..written]);
}

/// Verify a Type-2 multi-message proof against per-component pubkeys + (message, slot) bindings.
///
/// - `pks_per_message` and `messages` are parallel, in component order (attestations in body
///   order, then the proposer entry last).
///
/// MUST be called on a worker thread.
pub fn verifyType2(
    type_2_proof: *const ByteList512KiB,
    pks_per_message: []const []*const hashsig.HashSigPublicKey,
    messages: []const MessageBinding,
) AggregationError!void {
    if (pks_per_message.len != messages.len) return AggregationError.Type2VerifyFailed;
    if (messages.len == 0) return AggregationError.Type2VerifyFailed;

    try setupVerifier();

    const allocator = std.heap.c_allocator;
    const num_messages = messages.len;

    var total_pks: usize = 0;
    for (pks_per_message) |p| total_pks += p.len;

    const pks_flat = allocator.alloc(*const hashsig.HashSigPublicKey, total_pks) catch return AggregationError.Type2VerifyFailed;
    defer allocator.free(pks_flat);
    const pks_counts = allocator.alloc(usize, num_messages) catch return AggregationError.Type2VerifyFailed;
    defer allocator.free(pks_counts);
    const hashes = allocator.alloc(u8, num_messages * 32) catch return AggregationError.Type2VerifyFailed;
    defer allocator.free(hashes);
    const slots = allocator.alloc(u32, num_messages) catch return AggregationError.Type2VerifyFailed;
    defer allocator.free(slots);

    var off: usize = 0;
    for (0..num_messages) |i| {
        const pp = pks_per_message[i];
        pks_counts[i] = pp.len;
        for (pp, 0..) |pk, j| pks_flat[off + j] = pk;
        off += pp.len;
        @memcpy(hashes[i * 32 .. (i + 1) * 32], &messages[i].hash);
        slots[i] = messages[i].slot;
    }

    const wire = type_2_proof.constSlice();
    const ok = xmss_verify_type_2(
        wire.ptr,
        wire.len,
        pks_flat.ptr,
        pks_counts.ptr,
        num_messages,
        hashes.ptr,
        slots.ptr,
    );
    if (!ok) return AggregationError.Type2VerifyFailed;
}

// --- Tests (prod scheme; require the prover bytecode) ---

test "Type-1 aggregate then verify round-trips; wrong key/message/slot rejected" {
    const allocator = std.testing.allocator;

    var keypair = try hashsig.KeyPair.generate(allocator, "t1_keypair", 0, 10);
    defer keypair.deinit();

    const message_hash = [_]u8{42} ** 32;
    const slot: u32 = 0;

    var signature = try keypair.sign(&message_hash, slot);
    defer signature.deinit();

    var raw_pks = [_]*const hashsig.HashSigPublicKey{keypair.public_key};
    var raw_sigs = [_]*const hashsig.HashSigSignature{signature.handle};
    const no_children_pks: []const []*const hashsig.HashSigPublicKey = &.{};
    const no_children_proofs: []const ByteList512KiB = &.{};

    var proof = try ByteList512KiB.init(allocator);
    defer proof.deinit();
    try aggregateType1(&raw_pks, &raw_sigs, no_children_pks, no_children_proofs, &message_hash, slot, 2, &proof);

    // Valid verify.
    try verifyType1(&raw_pks, &message_hash, slot, &proof);

    // Wrong key.
    var wrong_kp = try hashsig.KeyPair.generate(allocator, "t1_wrong", 0, 10);
    defer wrong_kp.deinit();
    var wrong_pks = [_]*const hashsig.HashSigPublicKey{wrong_kp.public_key};
    try std.testing.expectError(AggregationError.Type1VerifyFailed, verifyType1(&wrong_pks, &message_hash, slot, &proof));

    // Wrong message.
    const wrong_msg = [_]u8{99} ** 32;
    try std.testing.expectError(AggregationError.Type1VerifyFailed, verifyType1(&raw_pks, &wrong_msg, slot, &proof));

    // Wrong slot.
    try std.testing.expectError(AggregationError.Type1VerifyFailed, verifyType1(&raw_pks, &message_hash, slot + 1, &proof));
}

test "Type-1 children-only aggregation verifies with combined keys" {
    const allocator = std.testing.allocator;
    const message_hash = [_]u8{7} ** 32;
    const slot: u32 = 3;

    var c1 = try hashsig.KeyPair.generate(allocator, "t1c1", 0, 10);
    defer c1.deinit();
    var s1 = try c1.sign(&message_hash, slot);
    defer s1.deinit();
    var c2 = try hashsig.KeyPair.generate(allocator, "t1c2", 0, 10);
    defer c2.deinit();
    var s2 = try c2.sign(&message_hash, slot);
    defer s2.deinit();

    var c1_pks = [_]*const hashsig.HashSigPublicKey{c1.public_key};
    var c1_sigs = [_]*const hashsig.HashSigSignature{s1.handle};
    var c2_pks = [_]*const hashsig.HashSigPublicKey{c2.public_key};
    var c2_sigs = [_]*const hashsig.HashSigSignature{s2.handle};
    const none_pks: []const []*const hashsig.HashSigPublicKey = &.{};
    const none_proofs: []const ByteList512KiB = &.{};

    var p1 = try ByteList512KiB.init(allocator);
    defer p1.deinit();
    var p2 = try ByteList512KiB.init(allocator);
    defer p2.deinit();
    try aggregateType1(&c1_pks, &c1_sigs, none_pks, none_proofs, &message_hash, slot, 2, &p1);
    try aggregateType1(&c2_pks, &c2_sigs, none_pks, none_proofs, &message_hash, slot, 2, &p2);

    var parent = try ByteList512KiB.init(allocator);
    defer parent.deinit();
    const no_raw_pks: []*const hashsig.HashSigPublicKey = &.{};
    const no_raw_sigs: []*const hashsig.HashSigSignature = &.{};
    var children_pks = [_][]*const hashsig.HashSigPublicKey{ &c1_pks, &c2_pks };
    const children_proofs = [_]ByteList512KiB{ p1, p2 };
    try aggregateType1(no_raw_pks, no_raw_sigs, &children_pks, &children_proofs, &message_hash, slot, 2, &parent);

    var combined = [_]*const hashsig.HashSigPublicKey{ c1.public_key, c2.public_key };
    try verifyType1(&combined, &message_hash, slot, &parent);
}

test "Type-2 merge of two Type-1s verifies with both message bindings; split recovers a component" {
    const allocator = std.testing.allocator;
    const slot: u32 = 5;
    const msg_a = [_]u8{0xAA} ** 32;
    const msg_b = [_]u8{0xBB} ** 32;

    var ka = try hashsig.KeyPair.generate(allocator, "t2a", 0, 10);
    defer ka.deinit();
    var sa = try ka.sign(&msg_a, slot);
    defer sa.deinit();
    var kb = try hashsig.KeyPair.generate(allocator, "t2b", 0, 10);
    defer kb.deinit();
    var sb = try kb.sign(&msg_b, slot);
    defer sb.deinit();

    var a_pks = [_]*const hashsig.HashSigPublicKey{ka.public_key};
    var a_sigs = [_]*const hashsig.HashSigSignature{sa.handle};
    var b_pks = [_]*const hashsig.HashSigPublicKey{kb.public_key};
    var b_sigs = [_]*const hashsig.HashSigSignature{sb.handle};
    const none_pks: []const []*const hashsig.HashSigPublicKey = &.{};
    const none_proofs: []const ByteList512KiB = &.{};

    var t1a = try ByteList512KiB.init(allocator);
    defer t1a.deinit();
    var t1b = try ByteList512KiB.init(allocator);
    defer t1b.deinit();
    try aggregateType1(&a_pks, &a_sigs, none_pks, none_proofs, &msg_a, slot, 2, &t1a);
    try aggregateType1(&b_pks, &b_sigs, none_pks, none_proofs, &msg_b, slot, 2, &t1b);

    const parts = [_]ByteList512KiB{ t1a, t1b };
    var pkpa = [_]*const hashsig.HashSigPublicKey{ka.public_key};
    var pkpb = [_]*const hashsig.HashSigPublicKey{kb.public_key};
    const pks_per_part = [_][]*const hashsig.HashSigPublicKey{ &pkpa, &pkpb };

    var t2 = try ByteList512KiB.init(allocator);
    defer t2.deinit();
    try mergeType1ToType2(&parts, &pks_per_part, 2, &t2);

    const bindings = [_]MessageBinding{
        .{ .hash = msg_a, .slot = slot },
        .{ .hash = msg_b, .slot = slot },
    };
    try verifyType2(&t2, &pks_per_part, &bindings);

    // Wrong binding (swapped slot) must be rejected.
    const bad_bindings = [_]MessageBinding{
        .{ .hash = msg_a, .slot = slot + 1 },
        .{ .hash = msg_b, .slot = slot },
    };
    try std.testing.expectError(AggregationError.Type2VerifyFailed, verifyType2(&t2, &pks_per_part, &bad_bindings));

    // Split recovers the component bound to msg_a, verifiable as a Type-1.
    var recovered = try ByteList512KiB.init(allocator);
    defer recovered.deinit();
    try splitType2ByMessage(&t2, &pks_per_part, &msg_a, 2, &recovered);
    try verifyType1(&a_pks, &msg_a, slot, &recovered);
}

test "aggregateType1 rejects mismatched raw pk/sig lengths" {
    var pks = [_]*const hashsig.HashSigPublicKey{undefined};
    var sigs = [_]*const hashsig.HashSigSignature{};
    const message_hash = [_]u8{0} ** 32;
    const none_pks: []const []*const hashsig.HashSigPublicKey = &.{};
    const none_proofs: []const ByteList512KiB = &.{};
    var out = try ByteList512KiB.init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(
        AggregationError.PublicKeysSignatureLengthMismatch,
        aggregateType1(&pks, &sigs, none_pks, none_proofs, &message_hash, 0, 2, &out),
    );
}
