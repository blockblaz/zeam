const std = @import("std");
const build_options = @import("build_options");
const params = @import("@zeam/params");
const time = @import("time.zig");

/// Per-interval wall-time budget in ns. Derived from
///   SECONDS_PER_SLOT / INTERVALS_PER_SLOT
/// where INTERVALS_PER_SLOT = 5 (see pkgs/node/src/constants.zig).
///
/// Held here, not imported from node-constants, to avoid a utils → node
/// dependency cycle. If INTERVALS_PER_SLOT changes there, change it here.
const INTERVALS_PER_SLOT: u64 = 5;
pub const INTERVAL_BUDGET_NS: u64 = (params.SECONDS_PER_SLOT * std.time.ns_per_s) / INTERVALS_PER_SLOT;
pub const HALF_INTERVAL_BUDGET_NS: u64 = INTERVAL_BUDGET_NS / 2;

/// Tagged based on the `-Dslot-probes=true` build option. `RealProbe` and `NoopProbe`
/// must have the same public method names; users call `Probe.begin(name, budget)`
/// / `probe.end()` regardless of which variant is selected.
pub const Probe = if (build_options.slot_probes) RealProbe else NoopProbe;

const RealProbe = struct {
    name: []const u8,
    start_ns: i128,
    budget_ns: u64,

    pub fn begin(name: []const u8, budget_ns: u64) RealProbe {
        return .{
            .name = name,
            .start_ns = time.monotonicTimestampNs(),
            .budget_ns = budget_ns,
        };
    }

    pub fn end(self: RealProbe) void {
        const now_ns = time.monotonicTimestampNs();
        const diff = now_ns - self.start_ns;
        const elapsed: u64 = if (diff > 0) @intCast(diff) else 0;
        // Design originally had a `std.log.debug` always-emit line here for log
        // scraping. Removed: per-call formatting cost is non-trivial in hot paths
        // and we have no scraper today. Re-add if/when a scraper materialises.
        if (elapsed > self.budget_ns) {
            std.log.warn(
                "slot_probe over budget: {s} took {d}ns (budget {d}ns)",
                .{ self.name, elapsed, self.budget_ns },
            );
        }
    }
};

const NoopProbe = struct {
    pub fn begin(_: []const u8, _: u64) NoopProbe {
        return .{};
    }
    pub fn end(_: NoopProbe) void {}
};

test "NoopProbe begin/end compiles and is zero-cost" {
    const p = NoopProbe.begin("test", 1000);
    p.end();
}

test "RealProbe begin/end emits no warning under budget" {
    const p = RealProbe.begin("test_under_budget", std.time.ns_per_s);
    p.end();
}
