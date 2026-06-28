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

// Fake-XMSS replaces real STARK prove/verify with a deterministic stub (see aggregation.zig).
// Set from the ZEAM_SHADOW_XMSS_FAKE env var in init() (no CLI flag — adding a CLI field overruns
// the zigcli parser's comptime quota).
// INVARIANT: ONE process-global bool, NOT a per-op flag — "fake" must be uniform across all 5
// FFI wrappers in one process; a fake aggregate/split feeding a real merge/verify would mix
// incompatible byte formats and corrupt. Set once in init() before any worker thread reads it.
var fake_enabled: bool = false;
const ENV_FAKE = "ZEAM_SHADOW_XMSS_FAKE";

// Mirrors readEnvRate: a simple libc env read, no allocation. True iff the value is "1"/"true".
fn readEnvFake() bool {
    const raw = std.c.getenv(ENV_FAKE) orelse return false;
    const value = std.mem.span(raw);
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "true")) return true;
    return false;
}

// Zig 0.16 removed `std.process.getEnvVarOwned`; use libc `getenv` for a simple
// process-env read (no allocation, no free). Returns null when unset/unparseable.
fn readEnvRate(key: [*:0]const u8) ?f64 {
    const raw = std.c.getenv(key) orelse return null;
    return std.fmt.parseFloat(f64, std.mem.span(raw)) catch null;
}

/// Resolve the shadow sim-cost rates and the fake-XMSS toggle. Rates: CLI flag (non-null) >
/// env var > off. Fake: env var only. Call exactly once at node startup, before aggregation begins.
pub fn init(cli_agg: ?f64, cli_verify: ?f64, cli_merge: ?f64) void {
    agg_rate = cli_agg orelse readEnvRate(ENV_AGG);
    verify_rate = cli_verify orelse readEnvRate(ENV_VERIFY);
    merge_rate = cli_merge orelse readEnvRate(ENV_MERGE);
    fake_enabled = readEnvFake();
}

/// Whether the XMSS prove/verify FFI is replaced by the deterministic stub. Read lock-free on
/// workers: set once in init() before any worker thread runs, read-only after.
pub fn fakeXmss() bool {
    return fake_enabled;
}

/// Test-only. Every test that flips a global MUST `defer shadow_cost.resetForTest()`. INVARIANT:
/// no real-crypto test may run with fake_enabled=true — an always-accept fake verify would green
/// a broken real verify.
pub fn resetForTest() void {
    agg_rate = null;
    verify_rate = null;
    merge_rate = null;
    fake_enabled = false;
}

/// Test-only: enable/disable the fake path; pair with `defer resetForTest()`.
pub fn setFakeForTest(v: bool) void {
    fake_enabled = v;
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
    defer resetForTest();
    // A non-null CLI arg wins over the env var, so this stays deterministic.
    init(null, null, 22.704);
    // 100 components / 22.704 per-sec = 4.40451... s ~= 4_404_510_000 ns
    const ns = mergeDelayNs(100);
    try std.testing.expect(ns > 4_400_000_000);
    try std.testing.expect(ns < 4_410_000_000);
}

test "mergeDelayNs: off when merge_rate <= 0; zero when n == 0" {
    defer resetForTest();
    init(null, null, 0);
    try std.testing.expectEqual(@as(u64, 0), mergeDelayNs(100));
    init(null, null, -5.0);
    try std.testing.expectEqual(@as(u64, 0), mergeDelayNs(100));
    init(null, null, 22.704);
    try std.testing.expectEqual(@as(u64, 0), mergeDelayNs(0));
}

test "fakeXmss: off by default, setFakeForTest toggles" {
    defer resetForTest();
    resetForTest();
    try std.testing.expect(!fakeXmss());
    setFakeForTest(true);
    try std.testing.expect(fakeXmss());
    setFakeForTest(false);
    try std.testing.expect(!fakeXmss());
}
