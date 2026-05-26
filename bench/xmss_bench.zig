const std = @import("std");
const zbench = @import("zbench");
const xmss = @import("@zeam/xmss");

// ---------------------------------------------------------------------------
// Module-level state shared across all benchmark iterations.
//
// Serialised to SSZ bytes once in `main` so that per-iteration bodies only
// exercise the verify / sign paths, not key-generation or serialisation.
// ---------------------------------------------------------------------------

/// SSZ-encoded public key bytes (stack-allocated; 256 B is more than enough).
var g_pubkey_buf: [256]u8 = undefined;
var g_pubkey_len: usize = 0;

/// SSZ-encoded signature bytes (stack-allocated; 4000 B matches test usage).
var g_sig_buf: [4000]u8 = undefined;
var g_sig_len: usize = 0;

/// Fixed 32-byte message used for all iterations.
var g_message: [32]u8 = undefined;

/// Epoch used when signing/verifying — slot 0 is fine for benchmarks.
const BENCH_EPOCH: u32 = 0;

// ---------------------------------------------------------------------------
// Benchmark bodies
// ---------------------------------------------------------------------------

fn benchVerifySingle(_: std.mem.Allocator) void {
    xmss.verifySsz(
        g_pubkey_buf[0..g_pubkey_len],
        &g_message,
        BENCH_EPOCH,
        g_sig_buf[0..g_sig_len],
    ) catch unreachable;
}

fn benchVerifyBatch32(_: std.mem.Allocator) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        xmss.verifySsz(
            g_pubkey_buf[0..g_pubkey_len],
            &g_message,
            BENCH_EPOCH,
            g_sig_buf[0..g_sig_len],
        ) catch unreachable;
    }
}

fn benchSignSingle(_: std.mem.Allocator) void {
    // We need a live KeyPair to sign; reconstruct from the serialised pubkey
    // bytes that are already in globals.  The KeyPair handle itself is the
    // only way to call sign(), and we cannot cheaply clone it, so we use
    // a module-level handle below.
    var sig = g_keypair.sign(&g_message, BENCH_EPOCH) catch unreachable;
    defer sig.deinit();
    std.mem.doNotOptimizeAway(sig.handle);
}

// We also keep the live KeyPair handle alive for the sign bench.
var g_keypair: xmss.KeyPair = undefined;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    _ = init;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate keypair (seed / epochs chosen to be fast; PROD key depth is
    // the default in the Rust library — activation_epoch=0, num_active=2).
    g_keypair = try xmss.KeyPair.generate(allocator, "bench_seed", 0, 2);
    defer g_keypair.deinit();

    // Fill message with a recognisable pattern.
    @memset(&g_message, 0xAB);

    // Serialise public key to bytes (for verifySsz).
    g_pubkey_len = try g_keypair.pubkeyToBytes(&g_pubkey_buf);

    // Sign the message once and serialise the signature to bytes.
    var sig = try g_keypair.sign(&g_message, BENCH_EPOCH);
    defer sig.deinit();
    g_sig_len = try sig.toBytes(&g_sig_buf);

    // Sanity-check the verify path before handing control to zbench.
    try xmss.verifySsz(
        g_pubkey_buf[0..g_pubkey_len],
        &g_message,
        BENCH_EPOCH,
        g_sig_buf[0..g_sig_len],
    );

    // ---------------------------------------------------------------------------
    // zbench runner
    // ---------------------------------------------------------------------------
    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    try bench.add("xmss_verify_single", benchVerifySingle, .{ .iterations = 200 });
    try bench.add("xmss_verify_batch_32", benchVerifyBatch32, .{ .iterations = 50 });
    try bench.add("xmss_sign_single", benchSignSingle, .{ .iterations = 50 });

    const io = std.Io.Threaded.global_single_threaded.io();
    const stdout = std.Io.File.stdout();
    try bench.run(io, stdout);
}
