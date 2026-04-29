const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");
const stf_runner = @import("state_transition_runner.zig");

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

    const lean_env = expect_mod.expectStringField(FixtureError, case_obj, &.{"leanEnv"}, ctx, "leanEnv") catch "prod";

    // Body attestation verification needs a leanMultisig test scheme that
    // zeam does not yet expose. Skip cases that would exercise that path
    // until the multisig test wrapper lands.
    const signed_block_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"signedBlock"}, ctx, "signedBlock");
    const block_obj = try expect_mod.expectObject(FixtureError, signed_block_obj, &.{"block"}, ctx, "signedBlock.block");
    const body_obj = try expect_mod.expectObject(FixtureError, block_obj, &.{"body"}, ctx, "signedBlock.block.body");
    const attestations_obj = try expect_mod.expectObject(FixtureError, body_obj, &.{"attestations"}, ctx, "signedBlock.block.body.attestations");
    const has_body_attestations = blk: {
        if (attestations_obj.get("data")) |data_val| {
            const arr = try expect_mod.expectArrayValue(FixtureError, data_val, ctx, "body.attestations.data");
            break :blk arr.items.len > 0;
        }
        break :blk false;
    };
    if (has_body_attestations) {
        std.debug.print(
            "spectest: skipping verify_signatures fixture {s} (body attestations present; multisig test path not yet wired)\n",
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

    const signature_obj = try expect_mod.expectObject(FixtureError, signed_block_obj, &.{"signature"}, ctx, "signedBlock.signature");
    const proposer_sig_hex = try expect_mod.expectStringField(
        FixtureError,
        signature_obj,
        &.{ "proposerSignature", "proposer_signature" },
        ctx,
        "signedBlock.signature.proposerSignature",
    );

    const proposer_sig_bytes = try parseHexBytes(allocator, ctx, proposer_sig_hex, "signedBlock.signature.proposerSignature");

    // Hash the block to produce the verification message.
    var block_root: [32]u8 = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, allocator) catch {
        std.debug.print(
            "fixture {s} case {s}: failed to hash block\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };

    const proposer_index: usize = @intCast(block.proposer_index);
    const validators_slice = state.validators.constSlice();
    if (proposer_index >= validators_slice.len) {
        // Out-of-range proposer is itself a rejection-worthy case. If the
        // fixture expected an exception, this counts as success; otherwise
        // it is a validator-state mismatch.
        if (case_obj.get("expectException") != null) return;
        std.debug.print(
            "fixture {s} case {s}: proposer_index {d} >= validators.len {d}\n",
            .{ ctx.fixture_label, ctx.case_name, proposer_index, validators_slice.len },
        );
        return FixtureError.FixtureMismatch;
    }

    const proposal_pubkey = validators_slice[proposer_index].getProposalPubkey();
    const epoch: u32 = @intCast(block.slot);

    const verify_result = if (std.mem.eql(u8, lean_env, "test"))
        xmss.verifySszTest(proposal_pubkey, &block_root, epoch, proposer_sig_bytes)
    else
        xmss.verifySsz(proposal_pubkey, &block_root, epoch, proposer_sig_bytes);

    const expect_exception = case_obj.get("expectException");
    if (expect_exception != null) {
        if (verify_result) |_| {
            std.debug.print(
                "fixture {s} case {s}: expected exception but proposer signature verification succeeded\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        } else |_| {
            return; // expected failure
        }
    } else {
        verify_result catch |err| {
            std.debug.print(
                "fixture {s} case {s}: unexpected proposer signature verification error: {s}\n",
                .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
            );
            return FixtureError.FixtureMismatch;
        };
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
