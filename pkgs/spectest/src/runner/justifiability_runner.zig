const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const types = @import("@zeam/types");
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

pub const name = "justifiability";

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

    const slot = try expect_mod.expectU64Field(FixtureError, case_obj, &.{"slot"}, ctx, "slot");
    const finalized_slot = try expect_mod.expectU64Field(FixtureError, case_obj, &.{ "finalizedSlot", "finalized_slot" }, ctx, "finalizedSlot");

    const output_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"output"}, ctx, "output");
    const expected_delta = try expect_mod.expectU64Field(FixtureError, output_obj, &.{"delta"}, ctx, "output.delta");
    const expected_is_justifiable = try expectBoolField(output_obj, &.{ "isJustifiable", "is_justifiable" }, ctx, "output.isJustifiable");

    if (slot < finalized_slot) {
        std.debug.print(
            "fixture {s} case {s}: slot {d} < finalizedSlot {d}\n",
            .{ ctx.fixture_label, ctx.case_name, slot, finalized_slot },
        );
        return FixtureError.InvalidFixture;
    }
    const actual_delta: u64 = slot - finalized_slot;
    if (actual_delta != expected_delta) {
        std.debug.print(
            "fixture {s} case {s}: delta mismatch (expected {d}, got {d})\n",
            .{ ctx.fixture_label, ctx.case_name, expected_delta, actual_delta },
        );
        return FixtureError.FixtureMismatch;
    }

    const actual_is_justifiable = types.IsJustifiableSlot(finalized_slot, slot) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: IsJustifiableSlot failed: {s}\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.FixtureMismatch;
    };

    if (actual_is_justifiable != expected_is_justifiable) {
        std.debug.print(
            "fixture {s} case {s}: isJustifiable mismatch slot={d} finalized={d} (expected {}, got {})\n",
            .{ ctx.fixture_label, ctx.case_name, slot, finalized_slot, expected_is_justifiable, actual_is_justifiable },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn expectBoolField(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    ctx: Context,
    label: []const u8,
) FixtureError!bool {
    for (field_names) |fname| {
        if (obj.get(fname)) |value| {
            return switch (value) {
                .bool => |b| b,
                else => {
                    std.debug.print(
                        "fixture {s} case {s}: field {s} must be bool\n",
                        .{ ctx.fixture_label, ctx.case_name, label },
                    );
                    return FixtureError.InvalidFixture;
                },
            };
        }
    }
    std.debug.print(
        "fixture {s} case {s}: missing field {s}\n",
        .{ ctx.fixture_label, ctx.case_name, label },
    );
    return FixtureError.InvalidFixture;
}
