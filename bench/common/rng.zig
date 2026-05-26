const std = @import("std");

/// Deterministic PRNG used across bench fixtures.
///
/// Every bench that needs random-looking input MUST go through this so the
/// numbers in `docs/perf/baselines/*.txt` are reproducible across machines.
/// Seed values are constants declared per-bench file, not derived from time.
pub fn fixedRng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

/// Fill a `[]u8` slice with deterministic pseudo-random bytes from `prng`.
pub fn fillBytes(prng: *std.Random.DefaultPrng, dst: []u8) void {
    prng.random().bytes(dst);
}

test "fixedRng is reproducible" {
    var a = fixedRng(0xDEADBEEF);
    var b = fixedRng(0xDEADBEEF);
    var ba: [16]u8 = undefined;
    var bb: [16]u8 = undefined;
    fillBytes(&a, &ba);
    fillBytes(&b, &bb);
    try std.testing.expectEqualSlices(u8, &ba, &bb);
}
