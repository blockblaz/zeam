const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const params = @import("@zeam/params");
const constants = @import("@zeam/node").constants;
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

pub const name = "slot_clock";

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 64 * 1024;

const SECONDS_PER_SLOT: i128 = params.SECONDS_PER_SLOT;
const INTERVALS_PER_SLOT: i128 = constants.INTERVALS_PER_SLOT;
const MS_PER_INTERVAL: i128 = (SECONDS_PER_SLOT * 1000) / INTERVALS_PER_SLOT;
const MS_PER_SLOT: i128 = SECONDS_PER_SLOT * 1000;

pub fn TestCase(
    comptime spec_fork: Fork,
    comptime rel_path: []const u8,
) type {
    return struct {
        payload: []u8,

        const Self = @This();

        pub fn execute(allocator: Allocator, dir: std.Io.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            try tc.run(allocator);
        }

        pub fn init(allocator: Allocator, dir: std.Io.Dir) RunnerError!Self {
            const payload = dir.readFileAlloc(std.testing.io, rel_path, allocator, std.Io.Limit.limited(read_max_bytes)) catch |err| {
                std.debug.print(
                    "spectest: failed to read {s}: {s}\n",
                    .{ rel_path, @errorName(err) },
                );
                return RunnerError.IoFailure;
            };
            return Self{ .payload = payload };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.payload);
        }

        pub fn run(self: *Self, allocator: Allocator) RunnerError!void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            try runFixturePayload(spec_fork, arena_allocator, rel_path, self.payload);
        }
    };
}

pub fn runFixturePayload(
    comptime spec_fork: Fork,
    allocator: Allocator,
    fixture_label: []const u8,
    payload: []const u8,
) FixtureError!void {
    _ = spec_fork;
    var parsed = std.json.parseFromSlice(JsonValue, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| {
        std.debug.print("spectest: fixture {s} not valid JSON: {s}\n", .{ fixture_label, @errorName(err) });
        return FixtureError.InvalidFixture;
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |map| map,
        else => {
            std.debug.print("spectest: fixture {s} must be JSON object\n", .{fixture_label});
            return FixtureError.InvalidFixture;
        },
    };

    var it = obj.iterator();
    while (it.next()) |entry| {
        try runCase(.{
            .fixture_label = fixture_label,
            .case_name = entry.key_ptr.*,
        }, entry.value_ptr.*);
    }
}

fn runCase(ctx: Context, value: JsonValue) FixtureError!void {
    const case_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: expected object\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const operation = try expect_mod.expectStringField(FixtureError, case_obj, &.{"operation"}, ctx, "operation");
    const input_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"input"}, ctx, "input");
    const output_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"output"}, ctx, "output");

    // Verify the embedded clock config matches zeam's compile-time constants.
    if (output_obj.get("config")) |cfg_val| {
        const cfg = try expect_mod.expectObjectValue(FixtureError, cfg_val, ctx, "output.config");
        try checkConfigU64(ctx, cfg, &.{ "secondsPerSlot", "seconds_per_slot" }, params.SECONDS_PER_SLOT, "secondsPerSlot");
        try checkConfigU64(ctx, cfg, &.{ "intervalsPerSlot", "intervals_per_slot" }, constants.INTERVALS_PER_SLOT, "intervalsPerSlot");
        try checkConfigU64(ctx, cfg, &.{ "millisecondsPerInterval", "milliseconds_per_interval" }, @as(u64, @intCast(MS_PER_INTERVAL)), "millisecondsPerInterval");
    }

    if (std.mem.eql(u8, operation, "current_slot")) {
        const genesis_s = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "genesisTime", "genesis_time" }, ctx, "input.genesisTime");
        const current_ms = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "currentTimeMs", "current_time_ms" }, ctx, "input.currentTimeMs");
        const expected = try expect_mod.expectU64Field(FixtureError, output_obj, &.{"slot"}, ctx, "output.slot");
        const actual = currentSlot(genesis_s, current_ms);
        try expectEq(ctx, "current_slot", actual, expected);
    } else if (std.mem.eql(u8, operation, "current_interval")) {
        const genesis_s = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "genesisTime", "genesis_time" }, ctx, "input.genesisTime");
        const current_ms = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "currentTimeMs", "current_time_ms" }, ctx, "input.currentTimeMs");
        const expected = try expect_mod.expectU64Field(FixtureError, output_obj, &.{"interval"}, ctx, "output.interval");
        const actual = currentInterval(genesis_s, current_ms);
        try expectEq(ctx, "current_interval", actual, expected);
    } else if (std.mem.eql(u8, operation, "total_intervals")) {
        const genesis_s = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "genesisTime", "genesis_time" }, ctx, "input.genesisTime");
        const current_ms = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "currentTimeMs", "current_time_ms" }, ctx, "input.currentTimeMs");
        const expected = try expect_mod.expectU64Field(FixtureError, output_obj, &.{ "totalIntervals", "total_intervals" }, ctx, "output.totalIntervals");
        const actual = totalIntervals(genesis_s, current_ms);
        try expectEq(ctx, "total_intervals", actual, expected);
    } else if (std.mem.eql(u8, operation, "from_slot")) {
        const slot = try expect_mod.expectU64Field(FixtureError, input_obj, &.{"slot"}, ctx, "input.slot");
        const expected = try expect_mod.expectU64Field(FixtureError, output_obj, &.{"interval"}, ctx, "output.interval");
        const actual = slot * @as(u64, @intCast(INTERVALS_PER_SLOT));
        try expectEq(ctx, "from_slot", actual, expected);
    } else if (std.mem.eql(u8, operation, "from_unix_time")) {
        const unix_s = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "unixSeconds", "unix_seconds" }, ctx, "input.unixSeconds");
        const genesis_s = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "genesisTime", "genesis_time" }, ctx, "input.genesisTime");
        const expected = try expect_mod.expectU64Field(FixtureError, output_obj, &.{"interval"}, ctx, "output.interval");
        const actual = fromUnixTime(unix_s, genesis_s);
        try expectEq(ctx, "from_unix_time", actual, expected);
    } else {
        std.debug.print(
            "fixture {s} case {s}: unknown slot_clock operation {s}\n",
            .{ ctx.fixture_label, ctx.case_name, operation },
        );
        return FixtureError.UnsupportedFixture;
    }
}

fn currentSlot(genesis_s: u64, current_ms: u64) u64 {
    const genesis_ms: i128 = @as(i128, genesis_s) * 1000;
    const elapsed: i128 = @as(i128, current_ms) - genesis_ms;
    if (elapsed < 0) return 0;
    return @intCast(@divFloor(elapsed, MS_PER_SLOT));
}

fn currentInterval(genesis_s: u64, current_ms: u64) u64 {
    const genesis_ms: i128 = @as(i128, genesis_s) * 1000;
    const elapsed: i128 = @as(i128, current_ms) - genesis_ms;
    if (elapsed < 0) return 0;
    const total = @divFloor(elapsed, MS_PER_INTERVAL);
    return @intCast(@mod(total, INTERVALS_PER_SLOT));
}

fn totalIntervals(genesis_s: u64, current_ms: u64) u64 {
    const genesis_ms: i128 = @as(i128, genesis_s) * 1000;
    const elapsed: i128 = @as(i128, current_ms) - genesis_ms;
    if (elapsed < 0) return 0;
    return @intCast(@divFloor(elapsed, MS_PER_INTERVAL));
}

fn fromUnixTime(unix_s: u64, genesis_s: u64) u64 {
    if (unix_s < genesis_s) return 0;
    const elapsed_s: i128 = @as(i128, unix_s) - @as(i128, genesis_s);
    return @intCast(@divFloor(elapsed_s * 1000, MS_PER_INTERVAL));
}

fn expectEq(ctx: Context, op: []const u8, actual: u64, expected: u64) FixtureError!void {
    if (actual != expected) {
        std.debug.print(
            "fixture {s} case {s}: {s} mismatch (expected {d}, got {d})\n",
            .{ ctx.fixture_label, ctx.case_name, op, expected, actual },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn checkConfigU64(
    ctx: Context,
    cfg: std.json.ObjectMap,
    field_names: []const []const u8,
    expected: u64,
    label: []const u8,
) FixtureError!void {
    for (field_names) |fname| {
        if (cfg.get(fname)) |val| {
            const actual = try expect_mod.expectU64Value(FixtureError, val, ctx, label);
            if (actual != expected) {
                std.debug.print(
                    "fixture {s} case {s}: config.{s} mismatch (expected {d}, got {d})\n",
                    .{ ctx.fixture_label, ctx.case_name, label, expected, actual },
                );
                return FixtureError.FixtureMismatch;
            }
            return;
        }
    }
    // Missing config field is non-fatal — leanSpec versions vary on which
    // are emitted. Only mismatched values are an error.
}
