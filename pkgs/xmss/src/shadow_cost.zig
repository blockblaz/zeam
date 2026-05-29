const std = @import("std");

/// Pure: nanoseconds to sleep to model processing `n` signatures at `rate`
/// signatures/second. Returns 0 when `rate` is null, <= 0, or non-finite (feature off).
pub fn computeDelayNs(rate: ?f64, n: usize) u64 {
    const r = rate orelse return 0;
    if (!std.math.isFinite(r) or r <= 0) return 0;
    const ns = (@as(f64, @floatFromInt(n)) / r) * @as(f64, std.time.ns_per_s);
    if (!std.math.isFinite(ns) or ns <= 0) return 0;
    const max_u64: f64 = @floatFromInt(std.math.maxInt(u64));
    if (ns >= max_u64) return std.math.maxInt(u64);
    return @intFromFloat(ns);
}

// Sim-cost rates, set once at startup; null means off. Read lock-free: init runs before
// any worker thread, and the values are read-only after.
var agg_rate: ?f64 = null;
var verify_rate: ?f64 = null;
// merge rate is components per second, not signatures per second.
var merge_rate: ?f64 = null;

const ENV_AGG = "ZEAM_SHADOW_XMSS_AGGREGATE_SIGNATURES_RATE";
const ENV_VERIFY = "ZEAM_SHADOW_XMSS_VERIFY_AGGREGATED_SIGNATURES_RATE";
const ENV_MERGE = "ZEAM_SHADOW_XMSS_MERGE_RATE";

// Zig 0.16 removed `std.process.getEnvVarOwned`; use libc `getenv` for a simple
// process-env read (no allocation, no free). Returns null when unset/unparseable.
fn readEnvRate(key: [*:0]const u8) ?f64 {
    const raw = std.c.getenv(key) orelse return null;
    return std.fmt.parseFloat(f64, std.mem.span(raw)) catch null;
}

/// Resolve the shadow sim-cost rates. Precedence: CLI flag (non-null) > env var > off.
/// Call exactly once at node startup, before aggregation begins.
pub fn init(cli_agg: ?f64, cli_verify: ?f64, cli_merge: ?f64) void {
    agg_rate = cli_agg orelse readEnvRate(ENV_AGG);
    verify_rate = cli_verify orelse readEnvRate(ENV_VERIFY);
    merge_rate = cli_merge orelse readEnvRate(ENV_MERGE);
}

/// Nanoseconds to sleep to model aggregating `n` raw signatures.
pub fn aggregateDelayNs(n: usize) u64 {
    return computeDelayNs(agg_rate, n);
}

/// Nanoseconds to sleep to model verifying an aggregate over `n` public keys.
pub fn verifyDelayNs(n: usize) u64 {
    return computeDelayNs(verify_rate, n);
}

/// Nanoseconds to sleep to model merging `n` components into one proof.
pub fn mergeDelayNs(n: usize) u64 {
    return computeDelayNs(merge_rate, n);
}

// --- Mock block proof (honest-sim integration tests) ------------------------------------------
//
// DISTINCT from the ZEAM_SHADOW_XMSS_*_RATE knobs above: those run the REAL prover and ADD a
// modeled sleep to SIMULATE prod CPU cost (used by the shadow network simulator). This one does
// the opposite — it REPLACES the XMSS recursive-STARK prove/verify FFI (Type-1 aggregate/verify,
// Type-2 merge/verify/split) with fast placeholders + a fixed merge delay, so the validator
// proposal block-building time is bounded well under the slot regardless of CPU.
//
// Purpose: let an ALL-HONEST-ZEAM integration test (simtest) exercise CONSENSUS (fork choice,
// justification, finalization — all driven by AttestationData + AggregationBits, NEVER the proof
// bytes) without the real multi-second merge blowing the slot budget on weak CI hardware. Real
// proving is covered by the unit tests, build-all-provers, and spectest. ALL-honest-zeam ONLY:
// the mock verify accepts ANY bytes (skips signature authentication), which is observably
// equivalent to real proving only when every participant is honest — so it must NEVER be enabled
// in mixed-client interop or production.

const ENV_MOCK_BLOCK_PROOF = "ZEAM_MOCK_BLOCK_PROOF";
const ENV_MOCK_BLOCK_PROOF_DELAY_MS = "ZEAM_MOCK_BLOCK_PROOF_DELAY_MS";
const DEFAULT_MOCK_BLOCK_PROOF_DELAY_MS: u64 = 400;

/// True when the mock-block-proof feature is enabled via env. Read lazily (no init dependency) so
/// it works for any launch path (simtest spawns inherit the env; lean-quickstart exports it).
pub fn mockBlockProofEnabled() bool {
    const raw = std.c.getenv(ENV_MOCK_BLOCK_PROOF) orelse return false;
    const v = std.mem.span(raw);
    return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true");
}

/// Nanoseconds to sleep inside the mocked Type-2 merge to model a realistic but under-slot
/// proposal block-building time. Default 400ms; override via ZEAM_MOCK_BLOCK_PROOF_DELAY_MS.
pub fn mockBlockProofDelayNs() u64 {
    const raw = std.c.getenv(ENV_MOCK_BLOCK_PROOF_DELAY_MS) orelse
        return DEFAULT_MOCK_BLOCK_PROOF_DELAY_MS * std.time.ns_per_ms;
    const ms = std.fmt.parseInt(u64, std.mem.span(raw), 10) catch DEFAULT_MOCK_BLOCK_PROOF_DELAY_MS;
    return ms * std.time.ns_per_ms;
}

test "computeDelayNs: off when rate missing or non-positive" {
    try std.testing.expectEqual(@as(u64, 0), computeDelayNs(null, 100));
    try std.testing.expectEqual(@as(u64, 0), computeDelayNs(0, 100));
    try std.testing.expectEqual(@as(u64, 0), computeDelayNs(-5.0, 100));
}

test "computeDelayNs: zero signatures means no delay" {
    try std.testing.expectEqual(@as(u64, 0), computeDelayNs(22.704, 0));
}

test "computeDelayNs: proportional to n / rate (qlean default rate)" {
    // 100 sigs / 22.704 sig-per-sec = 4.40451... s ~= 4_404_510_000 ns
    const ns = computeDelayNs(22.704, 100);
    try std.testing.expect(ns > 4_400_000_000);
    try std.testing.expect(ns < 4_410_000_000);
}

test "mergeDelayNs: reads merge_rate set by init; proportional to n / rate" {
    // A non-null CLI arg wins over the env var, so this stays deterministic.
    init(null, null, 22.704);
    // 100 components / 22.704 per-sec = 4.40451... s ~= 4_404_510_000 ns
    const ns = mergeDelayNs(100);
    try std.testing.expect(ns > 4_400_000_000);
    try std.testing.expect(ns < 4_410_000_000);
}

test "mergeDelayNs: off when merge_rate <= 0; zero when n == 0" {
    init(null, null, 0);
    try std.testing.expectEqual(@as(u64, 0), mergeDelayNs(100));
    init(null, null, -5.0);
    try std.testing.expectEqual(@as(u64, 0), mergeDelayNs(100));
    init(null, null, 22.704);
    try std.testing.expectEqual(@as(u64, 0), mergeDelayNs(0));
}
