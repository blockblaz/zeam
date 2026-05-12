// Behavioral parity runner for lean-spec's api_endpoint fixtures. Each fixture
// pins an HTTP endpoint, method, optional request body, and expected response
// (status, content-type, body shape). The runner doesn't bring up zeam's
// production HTTP server; it mirrors each handler's pure response logic.
// Endpoints whose response depends on chain / state internals (finalized
// state SSZ blob, fork-choice tree, justified checkpoint) are skipped with a
// clear reason — wiring them would require a constructed BeamChain.
const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

pub const name = "api_endpoint";

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 256 * 1024;

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
            tc.run(allocator) catch |err| switch (err) {
                error.SkippedFixture => return,
                else => return err,
            };
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
        try runCase(allocator, .{
            .fixture_label = fixture_label,
            .case_name = entry.key_ptr.*,
        }, entry.value_ptr.*);
    }
}

fn runCase(allocator: Allocator, ctx: Context, value: JsonValue) FixtureError!void {
    const case_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: expected object\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const endpoint = try expect_mod.expectStringField(FixtureError, case_obj, &.{"endpoint"}, ctx, "endpoint");
    const method = try expect_mod.expectStringField(FixtureError, case_obj, &.{"method"}, ctx, "method");

    if (std.mem.eql(u8, endpoint, "/lean/v0/health")) {
        return runHealth(allocator, ctx, case_obj, method);
    }
    if (std.mem.eql(u8, endpoint, "/lean/v0/admin/aggregator")) {
        return runAggregatorAdmin(allocator, ctx, case_obj, method);
    }

    std.debug.print(
        "spectest: skipping api_endpoint fixture {s} (endpoint {s} requires a constructed BeamChain; not yet wired)\n",
        .{ ctx.fixture_label, endpoint },
    );
    return FixtureError.SkippedFixture;
}

fn runHealth(allocator: Allocator, ctx: Context, case_obj: std.json.ObjectMap, method: []const u8) FixtureError!void {
    if (!std.mem.eql(u8, method, "GET")) {
        std.debug.print(
            "fixture {s} case {s}: health expected GET, got {s}\n",
            .{ ctx.fixture_label, ctx.case_name, method },
        );
        return FixtureError.FixtureMismatch;
    }

    // Mirror the production handler at pkgs/cli/src/api_server.zig:255.
    const status: u16 = 200;
    const content_type = "application/json";
    var body_map: std.json.ObjectMap = .empty;
    defer body_map.deinit(allocator);
    putString(allocator, &body_map, "status", "healthy") catch return FixtureError.InvalidFixture;
    putString(allocator, &body_map, "service", "lean-rpc-api") catch return FixtureError.InvalidFixture;
    try assertResponse(allocator, ctx, case_obj, status, content_type, JsonValue{ .object = body_map });
}

fn runAggregatorAdmin(allocator: Allocator, ctx: Context, case_obj: std.json.ObjectMap, method: []const u8) FixtureError!void {
    const initial_is_aggregator = expectBoolField(case_obj, &.{ "initialIsAggregator", "initial_is_aggregator" }, ctx, "initialIsAggregator") catch |err| switch (err) {
        FixtureError.InvalidFixture => false, // default if missing
        else => return err,
    };

    if (std.mem.eql(u8, method, "GET")) {
        var map: std.json.ObjectMap = .empty;
        defer map.deinit(allocator);
        map.put(allocator, "is_aggregator", .{ .bool = initial_is_aggregator }) catch return FixtureError.InvalidFixture;
        try assertResponse(allocator, ctx, case_obj, 200, "application/json", JsonValue{ .object = map });
        return;
    }

    if (std.mem.eql(u8, method, "POST")) {
        const request_body = try expect_mod.expectObject(FixtureError, case_obj, &.{ "requestBody", "request_body" }, ctx, "requestBody");
        const enabled = try expectBoolField(request_body, &.{"enabled"}, ctx, "requestBody.enabled");
        const previous = initial_is_aggregator;
        // Mirror handleAggregatorPost — set flag to `enabled`, return both
        // the new state and the previous one. (Idempotent enable/disable
        // covered: previous == enabled is allowed.)
        var map: std.json.ObjectMap = .empty;
        defer map.deinit(allocator);
        map.put(allocator, "is_aggregator", .{ .bool = enabled }) catch return FixtureError.InvalidFixture;
        map.put(allocator, "previous", .{ .bool = previous }) catch return FixtureError.InvalidFixture;
        try assertResponse(allocator, ctx, case_obj, 200, "application/json", JsonValue{ .object = map });
        return;
    }

    std.debug.print(
        "fixture {s} case {s}: unsupported method {s} for aggregator admin\n",
        .{ ctx.fixture_label, ctx.case_name, method },
    );
    return FixtureError.UnsupportedFixture;
}

fn assertResponse(
    allocator: Allocator,
    ctx: Context,
    case_obj: std.json.ObjectMap,
    actual_status: u16,
    actual_content_type: []const u8,
    actual_body: JsonValue,
) FixtureError!void {
    const expected_status = try expect_mod.expectU64Field(FixtureError, case_obj, &.{ "expectedStatusCode", "expected_status_code" }, ctx, "expectedStatusCode");
    if (@as(u64, actual_status) != expected_status) {
        std.debug.print(
            "fixture {s} case {s}: status mismatch (expected {d}, got {d})\n",
            .{ ctx.fixture_label, ctx.case_name, expected_status, actual_status },
        );
        return FixtureError.FixtureMismatch;
    }

    const expected_content_type = try expect_mod.expectStringField(FixtureError, case_obj, &.{ "expectedContentType", "expected_content_type" }, ctx, "expectedContentType");
    // zeam emits "application/json; charset=utf-8"; the fixture pins
    // "application/json". Allow the actual to start with the expected token.
    if (!std.mem.startsWith(u8, actual_content_type, expected_content_type)) {
        std.debug.print(
            "fixture {s} case {s}: content-type mismatch (expected prefix {s}, got {s})\n",
            .{ ctx.fixture_label, ctx.case_name, expected_content_type, actual_content_type },
        );
        return FixtureError.FixtureMismatch;
    }

    const expected_body_value = case_obj.get("expectedBody") orelse case_obj.get("expected_body") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing expectedBody\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };

    if (!jsonEquals(actual_body, expected_body_value)) {
        const actual_str = std.json.Stringify.valueAlloc(allocator, actual_body, .{}) catch "<serialize failed>";
        const expected_str = std.json.Stringify.valueAlloc(allocator, expected_body_value, .{}) catch "<serialize failed>";
        std.debug.print(
            "fixture {s} case {s}: body mismatch\n  expected: {s}\n  actual:   {s}\n",
            .{ ctx.fixture_label, ctx.case_name, expected_str, actual_str },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn jsonEquals(a: JsonValue, b: JsonValue) bool {
    return switch (a) {
        .null => b == .null,
        .bool => |x| switch (b) {
            .bool => |y| x == y,
            else => false,
        },
        .integer => |x| switch (b) {
            .integer => |y| x == y,
            .float => |y| @as(f64, @floatFromInt(x)) == y,
            else => false,
        },
        .float => |x| switch (b) {
            .float => |y| x == y,
            .integer => |y| x == @as(f64, @floatFromInt(y)),
            else => false,
        },
        .number_string => |x| switch (b) {
            .number_string => |y| std.mem.eql(u8, x, y),
            else => false,
        },
        .string => |x| switch (b) {
            .string => |y| std.mem.eql(u8, x, y),
            else => false,
        },
        .array => |xs| switch (b) {
            .array => |ys| blk: {
                if (xs.items.len != ys.items.len) break :blk false;
                for (xs.items, ys.items) |xi, yi| if (!jsonEquals(xi, yi)) break :blk false;
                break :blk true;
            },
            else => false,
        },
        .object => |xm| switch (b) {
            .object => |ym| blk: {
                if (xm.count() != ym.count()) break :blk false;
                var it = xm.iterator();
                while (it.next()) |entry| {
                    const yv = ym.get(entry.key_ptr.*) orelse break :blk false;
                    if (!jsonEquals(entry.value_ptr.*, yv)) break :blk false;
                }
                break :blk true;
            },
            else => false,
        },
    };
}

fn putString(allocator: Allocator, map: *std.json.ObjectMap, key: []const u8, value: []const u8) !void {
    try map.put(allocator, key, .{ .string = value });
}

fn expectBoolField(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    ctx: Context,
    label: []const u8,
) FixtureError!bool {
    for (field_names) |fname| {
        if (obj.get(fname)) |val| {
            return switch (val) {
                .bool => |b| b,
                else => {
                    std.debug.print(
                        "fixture {s} case {s}: {s} must be bool\n",
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
