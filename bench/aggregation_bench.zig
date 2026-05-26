const std = @import("std");
const zbench = @import("zbench");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");

const AggregatedSignatureProof = types.AggregatedSignatureProof;
const AggregationBits = types.AggregationBits;
const aggregationBitsSet = types.aggregationBitsSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of gossip participants for the `proof_aggregate_only` bench.
const NUM_GOSSIP_SIGNERS: usize = 8;

/// Epoch used in all bench iterations (slot 0, epoch 0 is fine for perf work).
const BENCH_EPOCH: u64 = 0;

/// Fixed 32-byte message hash used across all iterations.
var g_message: [32]u8 = undefined;

// ---------------------------------------------------------------------------
// Global state for `proof_aggregate_only`
// ---------------------------------------------------------------------------

/// Keypairs kept alive for the duration of the bench.
var g_keypairs: [NUM_GOSSIP_SIGNERS]xmss.KeyPair = undefined;

/// Raw public key handles — parallel with g_keypairs.
var g_pks: [NUM_GOSSIP_SIGNERS]*const xmss.HashSigPublicKey = undefined;

/// Raw signature handles produced during setup — parallel with g_keypairs.
var g_sigs: [NUM_GOSSIP_SIGNERS]*xmss.HashSigSignature = undefined;

/// AggregationBits with all NUM_GOSSIP_SIGNERS bits set.
var g_participants: AggregationBits = undefined;

// ---------------------------------------------------------------------------
// Global state for `proof_aggregate_with_2_children`
// (only used when both child proofs are successfully pre-built during setup)
// ---------------------------------------------------------------------------

/// Pre-built child proofs (gossip-only, 4 signers each).
var g_child_proofs: [2]AggregatedSignatureProof = undefined;

/// Per-child public key slices passed to aggregate().
///
/// children_pub_keys: []const []*const xmss.HashSigPublicKey
/// We represent this as two fixed arrays + a slice-of-slices built in main.
var g_child0_pks: [NUM_GOSSIP_SIGNERS / 2]*const xmss.HashSigPublicKey = undefined;
var g_child1_pks: [NUM_GOSSIP_SIGNERS / 2]*const xmss.HashSigPublicKey = undefined;
var g_children_pub_key_slices: [2][]*const xmss.HashSigPublicKey = undefined;

/// Set to true if children were built successfully — guards the bench body.
var g_children_ready: bool = false;

// ---------------------------------------------------------------------------
// Benchmark bodies
// ---------------------------------------------------------------------------

/// Bench: `proof_aggregate_only`
///
/// Calls AggregatedSignatureProof.aggregate() with 8 raw XMSS signers and
/// no children.  Uses LOG_INV_RATE_PROD (= 2) matching production code.
fn benchAggregateOnly(allocator: std.mem.Allocator) void {
    var result = AggregatedSignatureProof.init(allocator) catch unreachable;
    defer result.deinit();

    // Cast: bench body cannot return error, so we unwrap.
    var pk_ptrs: [NUM_GOSSIP_SIGNERS]*const xmss.HashSigPublicKey = g_pks;
    var sig_ptrs: [NUM_GOSSIP_SIGNERS]*const xmss.HashSigSignature = undefined;
    for (g_sigs, 0..) |s, i| sig_ptrs[i] = s;

    AggregatedSignatureProof.aggregate(
        allocator,
        g_participants,
        &.{},
        &.{},
        &pk_ptrs,
        &sig_ptrs,
        &g_message,
        BENCH_EPOCH,
        &result,
    ) catch |err| {
        std.debug.panic("proof_aggregate_only: aggregate failed: {}", .{err});
    };
}

/// Bench: `proof_aggregate_with_2_children`
///
/// Calls AggregatedSignatureProof.aggregate() with xmss_participants=null and
/// 2 pre-built child proofs (the minimum to satisfy the >=2 children constraint).
fn benchAggregateWith2Children(allocator: std.mem.Allocator) void {
    if (!g_children_ready) return;

    var result = AggregatedSignatureProof.init(allocator) catch unreachable;
    defer result.deinit();

    AggregatedSignatureProof.aggregate(
        allocator,
        null,
        &g_child_proofs,
        &g_children_pub_key_slices,
        &.{},
        &.{},
        &g_message,
        BENCH_EPOCH,
        &result,
    ) catch |err| {
        std.debug.panic("proof_aggregate_with_2_children: aggregate failed: {}", .{err});
    };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    _ = init;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Fixed message hash.
    @memset(&g_message, 0xCD);

    // -----------------------------------------------------------------------
    // Setup: generate NUM_GOSSIP_SIGNERS keypairs and sign the message.
    // -----------------------------------------------------------------------
    for (0..NUM_GOSSIP_SIGNERS) |i| {
        // Use distinct seed per signer so we get independent keys.
        var seed_buf: [32]u8 = undefined;
        const seed = std.fmt.bufPrint(&seed_buf, "aggregation_bench_signer_{d}", .{i}) catch unreachable;
        g_keypairs[i] = try xmss.KeyPair.generate(allocator, seed, 0, 4);
        g_pks[i] = g_keypairs[i].public_key;
        const sig = try g_keypairs[i].sign(&g_message, @intCast(BENCH_EPOCH));
        g_sigs[i] = sig.handle;
    }
    defer {
        // Free signatures (handles owned by us).
        for (g_sigs) |sh| {
            var s = xmss.Signature{ .handle = sh };
            s.deinit();
        }
        // Free keypairs.
        for (&g_keypairs) |*kp| kp.deinit();
    }

    // Build participants AggregationBits with all NUM_GOSSIP_SIGNERS set.
    g_participants = try AggregationBits.init(allocator);
    defer g_participants.deinit();
    for (0..NUM_GOSSIP_SIGNERS) |i| {
        try aggregationBitsSet(&g_participants, i, true);
    }

    // Sanity-check: run aggregate_only once before handing to zbench.
    {
        var pk_ptrs: [NUM_GOSSIP_SIGNERS]*const xmss.HashSigPublicKey = g_pks;
        var sig_ptrs: [NUM_GOSSIP_SIGNERS]*const xmss.HashSigSignature = undefined;
        for (g_sigs, 0..) |s, i| sig_ptrs[i] = s;

        var sanity = try AggregatedSignatureProof.init(allocator);
        defer sanity.deinit();
        try AggregatedSignatureProof.aggregate(
            allocator,
            g_participants,
            &.{},
            &.{},
            &pk_ptrs,
            &sig_ptrs,
            &g_message,
            BENCH_EPOCH,
            &sanity,
        );
        std.log.info("sanity proof_aggregate_only OK, proof_data len={d}", .{sanity.proof_data.len()});
    }

    // -----------------------------------------------------------------------
    // Setup: build 2 child proofs for proof_aggregate_with_2_children.
    // Each child uses NUM_GOSSIP_SIGNERS/2 = 4 of the already-generated keys.
    // -----------------------------------------------------------------------
    build_children: {
        // Child 0: signers 0..3
        for (0..NUM_GOSSIP_SIGNERS / 2) |i| {
            g_child0_pks[i] = g_pks[i];
        }
        var child0_participants = AggregationBits.init(allocator) catch break :build_children;
        defer child0_participants.deinit();
        for (0..NUM_GOSSIP_SIGNERS / 2) |i| {
            aggregationBitsSet(&child0_participants, i, true) catch break :build_children;
        }

        var child0_sig_ptrs: [NUM_GOSSIP_SIGNERS / 2]*const xmss.HashSigSignature = undefined;
        for (0..NUM_GOSSIP_SIGNERS / 2) |i| child0_sig_ptrs[i] = g_sigs[i];

        g_child_proofs[0] = AggregatedSignatureProof.init(allocator) catch break :build_children;
        AggregatedSignatureProof.aggregate(
            allocator,
            child0_participants,
            &.{},
            &.{},
            &g_child0_pks,
            &child0_sig_ptrs,
            &g_message,
            BENCH_EPOCH,
            &g_child_proofs[0],
        ) catch {
            g_child_proofs[0].deinit();
            break :build_children;
        };

        // Child 1: signers 4..7
        for (0..NUM_GOSSIP_SIGNERS / 2) |i| {
            g_child1_pks[i] = g_pks[NUM_GOSSIP_SIGNERS / 2 + i];
        }
        var child1_participants = AggregationBits.init(allocator) catch {
            g_child_proofs[0].deinit();
            break :build_children;
        };
        defer child1_participants.deinit();
        for (0..NUM_GOSSIP_SIGNERS / 2) |i| {
            aggregationBitsSet(&child1_participants, NUM_GOSSIP_SIGNERS / 2 + i, true) catch {
                g_child_proofs[0].deinit();
                break :build_children;
            };
        }

        var child1_sig_ptrs: [NUM_GOSSIP_SIGNERS / 2]*const xmss.HashSigSignature = undefined;
        for (0..NUM_GOSSIP_SIGNERS / 2) |i| child1_sig_ptrs[i] = g_sigs[NUM_GOSSIP_SIGNERS / 2 + i];

        g_child_proofs[1] = AggregatedSignatureProof.init(allocator) catch {
            g_child_proofs[0].deinit();
            break :build_children;
        };
        AggregatedSignatureProof.aggregate(
            allocator,
            child1_participants,
            &.{},
            &.{},
            &g_child1_pks,
            &child1_sig_ptrs,
            &g_message,
            BENCH_EPOCH,
            &g_child_proofs[1],
        ) catch {
            g_child_proofs[0].deinit();
            g_child_proofs[1].deinit();
            break :build_children;
        };

        // Populate children_pub_key_slices.
        g_children_pub_key_slices[0] = &g_child0_pks;
        g_children_pub_key_slices[1] = &g_child1_pks;
        g_children_ready = true;

        std.log.info("sanity proof_aggregate_with_2_children setup OK, child0_proof_data len={d}, child1_proof_data len={d}", .{
            g_child_proofs[0].proof_data.len(),
            g_child_proofs[1].proof_data.len(),
        });
    }

    defer if (g_children_ready) {
        g_child_proofs[0].deinit();
        g_child_proofs[1].deinit();
    };

    // -----------------------------------------------------------------------
    // zbench runner
    // -----------------------------------------------------------------------
    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    // Aggregation is slow (seconds range), so cap iterations low.
    try bench.add("proof_aggregate_only", benchAggregateOnly, .{ .iterations = 5 });

    if (g_children_ready) {
        try bench.add("proof_aggregate_with_2_children", benchAggregateWith2Children, .{ .iterations = 5 });
    } else {
        std.log.warn("proof_aggregate_with_2_children: skipped (child setup failed)", .{});
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const stdout = std.Io.File.stdout();
    try bench.run(io, stdout);
}
