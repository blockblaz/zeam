const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");
const stf_runner = @import("state_transition_runner.zig");
const state_transition = @import("@zeam/state-transition");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const types = @import("@zeam/types");
const xmss = @import("@zeam/xmss");
const zeam_utils = @import("@zeam/utils");
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

        pub fn execute(allocator: Allocator, dir: std.Io.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            tc.run(allocator) catch |err| switch (err) {
                error.SkippedFixture => return, // treat skip as pass
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

    const lean_env = expect_mod.expectStringField(FixtureError, case_obj, &.{"leanEnv"}, ctx, "leanEnv") catch "prod";

    const signed_block_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"signedBlock"}, ctx, "signedBlock");
    const block_obj = try expect_mod.expectObject(FixtureError, signed_block_obj, &.{"block"}, ctx, "signedBlock.block");
    const expect_exception = case_obj.get("expectException");

    // Devnet5 collapses every body attestation AND the proposer signature into a single Type-2
    // proof verified through leanMultisig, which is hardcoded to the production scheme. So the
    // ENTIRE verify path is prod-only now — skip all leanEnv=test fixtures (a parallel test-scheme
    // leanMultisig FFI is the right fix; tracked separately, A-fallback).
    if (std.mem.eql(u8, lean_env, "test")) {
        std.debug.print(
            "spectest: skipping verify_signatures fixture {s} (leanEnv=test; devnet5 Type-2 proof needs test-scheme leanMultisig FFI)\n",
            .{ctx.fixture_label},
        );
        return FixtureError.SkippedFixture;
    }

    const anchor_value = case_obj.get("anchorState") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing anchorState\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };
    var state = try stf_runner.buildState(allocator, ctx, anchor_value);
    defer state.deinit();

    var block = try stf_runner.buildBlock(allocator, ctx, 0, block_obj);
    defer block.deinit();

    // Devnet5: SignedBlock carries one SSZ-encoded Type-2 proof covering every body attestation
    // plus the proposer signature. Build the SignedBlock and run the unified verifier, then
    // compare its outcome to the fixture's expectException.
    const proof_hex = try expect_mod.expectStringField(
        FixtureError,
        signed_block_obj,
        &.{"proof"},
        ctx,
        "signedBlock.proof",
    );
    const proof_bytes = try parseHexBytes(allocator, ctx, proof_hex, "signedBlock.proof");

    var proof_list = try xmss.ByteList512KiB.init(allocator);
    defer proof_list.deinit();
    for (proof_bytes) |b| proof_list.append(b) catch return FixtureError.InvalidFixture;

    // signed_block aliases `block` (freed by its own defer); only proof_list needs cleanup.
    const signed_block = types.SignedBlock{ .block = block, .proof = proof_list };
    const verify_failed = if (state_transition.verifySignatures(allocator, &state, &signed_block, null)) |_| false else |_| true;

    if (expect_exception != null) {
        if (verify_failed) return; // expected — the proof was rejected
        std.debug.print(
            "fixture {s} case {s}: expected exception but the block proof verified\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }

    if (verify_failed) {
        std.debug.print(
            "fixture {s} case {s}: unexpected block proof verification failure\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn parseHexBytes(
    allocator: Allocator,
    ctx: Context,
    hex: []const u8,
    label: []const u8,
) FixtureError![]u8 {
    if (hex.len < 2 or !std.mem.eql(u8, hex[0..2], "0x")) {
        std.debug.print(
            "fixture {s} case {s}: {s} missing 0x prefix\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    }
    const hex_body = hex[2..];
    if (hex_body.len % 2 != 0) {
        std.debug.print(
            "fixture {s} case {s}: {s} hex length not even\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    }
    const byte_len = hex_body.len / 2;
    const out = allocator.alloc(u8, byte_len) catch return FixtureError.InvalidFixture;
    _ = std.fmt.hexToBytes(out, hex_body) catch {
        std.debug.print(
            "fixture {s} case {s}: {s} hex decode failed\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    };
    return out;
}
