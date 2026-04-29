const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const types = @import("@zeam/types");
const xmss = @import("@zeam/xmss");
const stf = @import("@zeam/state-transition");
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

pub const name = "verify_signatures";

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 16 * 1024 * 1024;

pub fn TestCase(
    comptime spec_fork: Fork,
    comptime rel_path: []const u8,
) type {
    return struct {
        payload: []u8,

        const Self = @This();

        pub fn execute(allocator: Allocator, dir: std.fs.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            tc.run(allocator) catch |err| switch (err) {
                error.SkippedFixture => return, // treat skip as pass
                else => return err,
            };
        }

        pub fn init(allocator: Allocator, dir: std.fs.Dir) RunnerError!Self {
            const payload = dir.readFileAlloc(allocator, rel_path, read_max_bytes) catch |err| {
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

    // verify_signatures fixtures are generated against the test signature scheme
    // (leanEnv=test → SIGNATURE_LEN_BYTES ~ 700). zeam runs against the production
    // scheme (SIGSIZE=2536), so these fixtures cannot be deserialized into the
    // production SignedBlock layout. The hex sizes simply do not match.
    //
    // Skip with a clear marker. To exercise these end-to-end, zeam would need a
    // test-mode XMSS path (parallel public-key + signature types and a
    // verifySignatures variant) that is wired through the runner.
    const lean_env = expect_mod.expectStringField(FixtureError, case_obj, &.{"leanEnv"}, ctx, "leanEnv") catch |err| switch (err) {
        FixtureError.InvalidFixture => null,
        else => return err,
    };

    if (lean_env) |env| {
        if (!std.mem.eql(u8, env, "prod")) {
            // Make sure the fixture is well-formed enough that this is a
            // genuine scheme mismatch and not a structural error.
            try ensureWellFormed(ctx, case_obj);
            std.debug.print(
                "spectest: skipping verify_signatures fixture {s} (leanEnv={s}; zeam prod scheme requires SIGSIZE=2536)\n",
                .{ ctx.fixture_label, env },
            );
            return FixtureError.SkippedFixture;
        }
    }

    // Production-scheme path. Deserialize the anchor state and signed block,
    // run zeam's verifySignatures, and check the result against expectException.
    const anchor_value = case_obj.get("anchorState") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing anchorState\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };
    var state = try buildBeamState(allocator, ctx, anchor_value);
    defer state.deinit();

    const signed_block_value = case_obj.get("signedBlock") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing signedBlock\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };
    var signed_block = try buildSignedBlock(allocator, ctx, signed_block_value);
    defer signed_block.deinit();

    const expect_exception = case_obj.get("expectException");

    const result = stf.verifySignatures(allocator, &state, &signed_block, null);
    if (expect_exception != null) {
        if (result) |_| {
            std.debug.print(
                "fixture {s} case {s}: expected exception but verifySignatures succeeded\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        } else |_| {
            return; // expected failure
        }
    } else {
        result catch |err| {
            std.debug.print(
                "fixture {s} case {s}: unexpected verifySignatures error: {s}\n",
                .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
            );
            return FixtureError.FixtureMismatch;
        };
    }
}

/// Sanity-check the structural fields the production runner would otherwise
/// require, so a leanEnv=test skip cannot mask a malformed fixture.
fn ensureWellFormed(ctx: Context, case_obj: std.json.ObjectMap) FixtureError!void {
    _ = try expect_mod.expectObject(FixtureError, case_obj, &.{"anchorState"}, ctx, "anchorState");
    _ = try expect_mod.expectObject(FixtureError, case_obj, &.{"signedBlock"}, ctx, "signedBlock");
}

fn buildBeamState(
    allocator: Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!types.BeamState {
    _ = allocator;
    _ = ctx;
    _ = value;
    // Production-scheme deserialization is not yet wired here — current
    // fixtures are all leanEnv=test and short-circuit above. When a
    // production fixture appears, port the helpers from
    // state_transition_runner.zig (parseValidators, parseBlockHeader, ...).
    return FixtureError.UnsupportedFixture;
}

fn buildSignedBlock(
    allocator: Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!types.SignedBlock {
    _ = allocator;
    _ = ctx;
    _ = value;
    return FixtureError.UnsupportedFixture;
}
