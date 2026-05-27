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

// Resolved shadow sim-cost rates (signatures/second). null = feature off (no sleep).
// Set once at node startup by `init`; reads are lock-free because `init` runs before
// any aggregation worker thread is spawned and the values are read-only thereafter.
var agg_rate: ?f64 = null;
var verify_rate: ?f64 = null;

const ENV_AGG = "ZEAM_SHADOW_XMSS_AGGREGATE_SIGNATURES_RATE";
const ENV_VERIFY = "ZEAM_SHADOW_XMSS_VERIFY_AGGREGATED_SIGNATURES_RATE";

// Zig 0.16 removed `std.process.getEnvVarOwned`; use libc `getenv` for a simple
// process-env read (no allocation, no free). Returns null when unset/unparseable.
fn readEnvRate(key: [*:0]const u8) ?f64 {
    const raw = std.c.getenv(key) orelse return null;
    return std.fmt.parseFloat(f64, std.mem.span(raw)) catch null;
}

/// Resolve the shadow sim-cost rates. Precedence: CLI flag (non-null) > env var > off.
/// Call exactly once at node startup, before aggregation begins.
pub fn init(cli_agg: ?f64, cli_verify: ?f64) void {
    agg_rate = cli_agg orelse readEnvRate(ENV_AGG);
    verify_rate = cli_verify orelse readEnvRate(ENV_VERIFY);
}

/// Nanoseconds to sleep to model aggregating `n` raw signatures.
pub fn aggregateDelayNs(n: usize) u64 {
    return computeDelayNs(agg_rate, n);
}

/// Nanoseconds to sleep to model verifying an aggregate over `n` public keys.
pub fn verifyDelayNs(n: usize) u64 {
    return computeDelayNs(verify_rate, n);
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
