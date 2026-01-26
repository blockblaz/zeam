const std = @import("std");

const expect = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;

pub const name = "state_transition";

pub const Handler = enum {
    test_block_processing,
};

pub const handlers = std.enums.values(Handler);

pub fn handlerLabel(comptime handler: Handler) []const u8 {
    return switch (handler) {
        .test_block_processing => "test_block_processing",
    };
}

pub fn handlerPath(comptime handler: Handler) []const u8 {
    return handlerLabel(handler);
}

pub fn includeFixtureFile(file_name: []const u8) bool {
    return std.mem.endsWith(u8, file_name, ".json");
}

pub fn baseRelRoot(comptime spec_fork: Fork) []const u8 {
    const kind = FixtureKind.state_transition;
    return std.fmt.comptimePrint(
        "consensus/{s}/{s}/{s}",
        .{ kind.runnerModule(), spec_fork.path, kind.handlerSubdir() },
    );
}

const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const zeam_utils = @import("@zeam/utils");
const JsonValue = std.json.Value;
const Context = expect.Context;

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 16 * 1024 * 1024; // 16 MiB upper bound per fixture file.

pub fn TestCase(
    comptime spec_fork: Fork,
    comptime rel_path: []const u8,
) type {
    return struct {
        payload: []u8,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            try tc.run(allocator);
        }

        pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir) RunnerError!Self {
            const payload = try loadFixturePayload(allocator, dir, rel_path);
            return Self{ .payload = payload };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.payload);
        }

        pub fn run(self: *Self, allocator: std.mem.Allocator) RunnerError!void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            try runFixturePayload(spec_fork, arena_allocator, rel_path, self.payload);
        }
    };
}

fn loadFixturePayload(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    rel_path: []const u8,
) RunnerError![]u8 {
    const payload = dir.readFileAlloc(allocator, rel_path, read_max_bytes) catch |err| switch (err) {
        error.FileTooBig => {
            std.debug.print("spectest: fixture {s} exceeds allowed size\n", .{rel_path});
            return RunnerError.IoFailure;
        },
        else => {
            std.debug.print("spectest: failed to read {s}: {s}\n", .{ rel_path, @errorName(err) });
            return RunnerError.IoFailure;
        },
    };
    return payload;
}

pub fn runFixturePayload(
    comptime spec_fork: Fork,
    allocator: std.mem.Allocator,
    fixture_label: []const u8,
    payload: []const u8,
) FixtureError!void {
    _ = spec_fork;
    var parsed = std.json.parseFromSlice(JsonValue, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| {
        std.debug.print("spectest: fixture {s} not valid JSON: {s}\n", .{ fixture_label, @errorName(err) });
        return FixtureError.InvalidFixture;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |map| map,
        else => {
            std.debug.print("spectest: fixture {s} must be JSON object\n", .{fixture_label});
            return FixtureError.InvalidFixture;
        },
    };

    var skipped_cases: usize = 0;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const case_name = entry.key_ptr.*;
        const case_value = entry.value_ptr.*;
        const ctx = Context{ .fixture_label = fixture_label, .case_name = case_name };
        runCase(allocator, ctx, case_value) catch |err| switch (err) {
            FixtureError.SkippedFixture => skipped_cases += 1,
            FixtureError.UnsupportedFixture => {
                std.debug.print(
                    "spectest: skipping unsupported case {s} in {s}\n",
                    .{ case_name, fixture_label },
                );
            },
            else => return err,
        };
    }

    if (skipped_cases > 0) {
        std.debug.print(
            "spectest: skipped {d} expectException case(s) in fixture {s}\n",
            .{ skipped_cases, fixture_label },
        );
    }
}

fn runCase(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!void {
    const case_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: expected object\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const pre_value = case_obj.get("pre") orelse {
        std.debug.print("fixture {s} case {s}: missing pre state\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    };

    var pre_state = try buildState(allocator, ctx, pre_value);
    defer pre_state.deinit();

    const blocks_array = switch (case_obj.get("blocks") orelse {
        std.debug.print("fixture {s} case {s}: missing blocks array\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    }) {
        .array => |arr| arr,
        else => {
            std.debug.print("fixture {s} case {s}: blocks must be array\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const expect_exception = switch (case_obj.get("expectException") orelse JsonValue{ .null = {} }) {
        .string => |text| text,
        .null => null,
        else => {
            std.debug.print("fixture {s} case {s}: expectException must be string or null\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    if (blocks_array.items.len == 0 and expect_exception != null) {
        if (skipExpectExceptionIfEnabled(ctx)) {
            return FixtureError.SkippedFixture;
        }

        std.debug.print(
            "fixture {s} case {s}: expectException present but no blocks supplied\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }

    const post_obj = switch (case_obj.get("post") orelse JsonValue{ .null = {} }) {
        .null => null,
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: post must be object or null\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    var logger_config = zeam_utils.getTestLoggerConfig();
    defer logger_config.deinit();
    const logger = logger_config.logger(.state_transition);

    var encountered_error = false;
    for (blocks_array.items, 0..) |block_value, block_index| {
        const block_obj = switch (block_value) {
            .object => |map| map,
            else => {
                std.debug.print(
                    "fixture {s} case {s}: block #{} is not object\n",
                    .{ ctx.fixture_label, ctx.case_name, block_index },
                );
                return FixtureError.InvalidFixture;
            },
        };

        var block = try buildBlock(allocator, ctx, block_index, block_obj);
        defer block.deinit();

        if (block_index == 0 and expect_exception == null) {
            var header_for_check = pre_state.latest_block_header;
            if (std.mem.eql(u8, &header_for_check.state_root, &types.ZERO_HASH)) {
                var pre_state_root: types.Root = undefined;
                zeam_utils.hashTreeRoot(types.BeamState, pre_state, &pre_state_root, allocator) catch |err| {
                    std.debug.print(
                        "fixture {s} case {s}: unable to hash pre-state ({s})\n",
                        .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
                    );
                    return FixtureError.UnsupportedFixture;
                };
                header_for_check.state_root = pre_state_root;
            }

            var header_root: types.Root = undefined;
            zeam_utils.hashTreeRoot(types.BeamBlockHeader, header_for_check, &header_root, allocator) catch |err| {
                std.debug.print(
                    "fixture {s} case {s}: unable to hash latest block header ({s})\n",
                    .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
                );
                return FixtureError.UnsupportedFixture;
            };
            if (!std.mem.eql(u8, &header_root, &block.parent_root)) {
                std.debug.print(
                    "fixture {s} case {s}: parent root mismatch (expected=0x{s} got=0x{s})\n",
                    .{
                        ctx.fixture_label,
                        ctx.case_name,
                        std.fmt.fmtSliceHexLower(&header_root),
                        std.fmt.fmtSliceHexLower(&block.parent_root),
                    },
                );
                return FixtureError.UnsupportedFixture;
            }
        }

        state_transition.apply_transition(allocator, &pre_state, block, .{ .logger = logger }) catch |err| {
            encountered_error = true;
            if (expect_exception == null) {
                std.debug.print(
                    "fixture {s} case {s}: unexpected error {s} at block #{}\n",
                    .{ ctx.fixture_label, ctx.case_name, @errorName(err), block_index },
                );
                return FixtureError.FixtureMismatch;
            }
            break;
        };
    }

    if (expect_exception) |_| {
        if (skipExpectExceptionIfEnabled(ctx)) {
            return FixtureError.SkippedFixture;
        }

        if (!encountered_error) {
            std.debug.print(
                "fixture {s} case {s}: expected exception but transition succeeded\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        }
        return;
    }

    if (encountered_error) {
        std.debug.print("fixture {s} case {s}: transition failed unexpectedly\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.FixtureMismatch;
    }

    if (post_obj) |post| {
        try verifyPost(ctx, &pre_state, post);
    }
}

pub fn setSkipExpectedErrorFixtures(flag: bool) void {
    skip.set(flag);
}

pub fn configureSkipExpectedErrorFixturesFromEnv() void {
    _ = skip.configured();
}

pub fn skipExpectedErrorFixturesEnabled() bool {
    return skip.configured();
}

fn skipExpectExceptionIfEnabled(ctx: Context) bool {
    if (!skipExpectedErrorFixturesEnabled()) {
        return false;
    }

    std.debug.print(
        "spectest: skipping expectException case {s} in {s} due to configured skip\n",
        .{ ctx.case_name, ctx.fixture_label },
    );
    return true;
}

fn buildState(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!types.BeamState {
    const pre_obj = try expect.expectObjectValue(FixtureError, value, ctx, "pre");

    const config_obj = try expect.expectObject(FixtureError, pre_obj, &.{"config"}, ctx, "config");
    const genesis_time = try expect.expectU64Field(FixtureError, config_obj, &.{"genesisTime"}, ctx, "config.genesisTime");

    const slot = try expect.expectU64Field(FixtureError, pre_obj, &.{"slot"}, ctx, "slot");

    const header_obj = try expect.expectObject(FixtureError, pre_obj, &.{"latestBlockHeader"}, ctx, "latestBlockHeader");
    const latest_block_header = try parseBlockHeader(ctx, header_obj);

    const latest_justified = try parseCheckpoint(ctx, pre_obj, "latestJustified");
    const latest_finalized = try parseCheckpoint(ctx, pre_obj, "latestFinalized");

    var historical = try types.HistoricalBlockHashes.init(allocator);
    errdefer historical.deinit();
    if (pre_obj.get("historicalBlockHashes")) |val| {
        try expect.appendBytesDataField(FixtureError, types.Root, &historical, ctx, val, "historicalBlockHashes");
    }

    var justified_slots = try types.JustifiedSlots.init(allocator);
    errdefer justified_slots.deinit();
    if (pre_obj.get("justifiedSlots")) |val| {
        try expect.appendBoolDataField(FixtureError, &justified_slots, ctx, val, "justifiedSlots");
    }

    var validators = try parseValidators(allocator, ctx, pre_obj);
    errdefer validators.deinit();

    var just_roots = try types.JustificationRoots.init(allocator);
    errdefer just_roots.deinit();
    if (pre_obj.get("justificationsRoots")) |val| {
        try expect.appendBytesDataField(FixtureError, types.Root, &just_roots, ctx, val, "justificationsRoots");
    }

    var just_validators = try types.JustificationValidators.init(allocator);
    errdefer just_validators.deinit();
    if (pre_obj.get("justificationsValidators")) |val| {
        try expect.appendBoolDataField(FixtureError, &just_validators, ctx, val, "justificationsValidators");
    }

    return types.BeamState{
        .config = .{ .genesis_time = genesis_time },
        .slot = slot,
        .latest_block_header = latest_block_header,
        .latest_justified = latest_justified,
        .latest_finalized = latest_finalized,
        .historical_block_hashes = historical,
        .justified_slots = justified_slots,
        .validators = validators,
        .justifications_roots = just_roots,
        .justifications_validators = just_validators,
    };
}

fn parseValidators(
    allocator: std.mem.Allocator,
    ctx: Context,
    pre_obj: std.json.ObjectMap,
) FixtureError!types.Validators {
    var validators = try types.Validators.init(allocator);
    errdefer validators.deinit();

    if (pre_obj.get("validators")) |val| {
        const validators_obj = try expect.expectObjectValue(FixtureError, val, ctx, "validators");
        if (validators_obj.get("data")) |data_val| {
            const arr = try expect.expectArrayValue(FixtureError, data_val, ctx, "validators.data");
            for (arr.items, 0..) |item, idx| {
                var base_label_buf: [64]u8 = undefined;
                const base_label = std.fmt.bufPrint(&base_label_buf, "validators[{d}]", .{idx}) catch "validators";
                const validator_obj = try expect.expectObjectValue(FixtureError, item, ctx, base_label);

                var label_buf: [96]u8 = undefined;
                const pubkey_label = std.fmt.bufPrint(&label_buf, "{s}.pubkey", .{base_label}) catch "validator.pubkey";
                const pubkey = try expect.expectBytesField(FixtureError, types.Bytes52, validator_obj, &.{"pubkey"}, ctx, pubkey_label);

                const validator_index: u64 = blk: {
                    if (validator_obj.get("index")) |index_value| {
                        var index_label_buf: [96]u8 = undefined;
                        const index_label = std.fmt.bufPrint(&index_label_buf, "{s}.index", .{base_label}) catch "validator.index";
                        break :blk try expect.expectU64Value(FixtureError, index_value, ctx, index_label);
                    }
                    break :blk @as(u64, @intCast(idx));
                };

                validators.append(.{ .pubkey = pubkey, .index = validator_index }) catch |err| {
                    std.debug.print(
                        "fixture {s} case {s}: validator #{} append failed: {s}\n",
                        .{ ctx.fixture_label, ctx.case_name, idx, @errorName(err) },
                    );
                    return FixtureError.InvalidFixture;
                };
            }
        }
    }

    return validators;
}

fn buildBlock(
    allocator: std.mem.Allocator,
    ctx: Context,
    index: usize,
    obj: std.json.ObjectMap,
) FixtureError!types.BeamBlock {
    const slot = try expect.expectU64Field(FixtureError, obj, &.{"slot"}, ctx, "slot");
    const proposer_index = try expect.expectU64Field(FixtureError, obj, &.{ "proposer_index", "proposerIndex" }, ctx, "proposer_index");
    const parent_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "parent_root", "parentRoot" }, ctx, "parent_root");
    const state_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "state_root", "stateRoot" }, ctx, "state_root");

    const body_obj = try expect.expectObject(FixtureError, obj, &.{"body"}, ctx, "body");
    const attestations_obj = try expect.expectObject(FixtureError, body_obj, &.{"attestations"}, ctx, "body.attestations");
    if (attestations_obj.get("data")) |data_val| {
        const arr = try expect.expectArrayValue(FixtureError, data_val, ctx, "body.attestations.data");
        if (arr.items.len != 0) {
            std.debug.print(
                "fixture {s} case {s}: attestations unsupported (block #{})\n",
                .{ ctx.fixture_label, ctx.case_name, index },
            );
            return FixtureError.UnsupportedFixture;
        }
    }

    const attestations = try types.AggregatedAttestations.init(allocator);
    return types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = .{ .attestations = attestations },
    };
}

fn verifyPost(
    ctx: Context,
    state: *types.BeamState,
    post_obj: std.json.ObjectMap,
) FixtureError!void {
    if (post_obj.get("slot")) |val| {
        const expected = try expect.expectU64Value(FixtureError, val, ctx, "post.slot");
        if (state.slot != expected) {
            std.debug.print(
                "fixture {s} case {s}: slot mismatch, got {d}, expected {d}\n",
                .{ ctx.fixture_label, ctx.case_name, state.slot, expected },
            );
            return FixtureError.FixtureMismatch;
        }
    }

    if (post_obj.get("latestBlockHeaderSlot")) |val| {
        const expected = try expect.expectU64Value(FixtureError, val, ctx, "post.latestBlockHeaderSlot");
        if (state.latest_block_header.slot != expected) {
            std.debug.print(
                "fixture {s} case {s}: latest block header slot mismatch (got {d}, want {d})\n",
                .{ ctx.fixture_label, ctx.case_name, state.latest_block_header.slot, expected },
            );
            return FixtureError.FixtureMismatch;
        }
    }

    if (post_obj.get("latestBlockHeaderStateRoot")) |val| {
        const expected = try expect.expectBytesValue(FixtureError, types.Root, val, ctx, "post.latestBlockHeaderStateRoot");
        if (!std.mem.eql(u8, &state.latest_block_header.state_root, &expected)) {
            std.debug.print(
                "fixture {s} case {s}: latest block header state root mismatch\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        }
    }

    if (post_obj.get("latestJustifiedRoot")) |val| {
        const expected = try expect.expectBytesValue(FixtureError, types.Root, val, ctx, "post.latestJustifiedRoot");
        if (!std.mem.eql(u8, &state.latest_justified.root, &expected)) {
            std.debug.print(
                "fixture {s} case {s}: latest justified root mismatch\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        }
    }

    if (post_obj.get("latestFinalizedRoot")) |val| {
        const expected = try expect.expectBytesValue(FixtureError, types.Root, val, ctx, "post.latestFinalizedRoot");
        if (!std.mem.eql(u8, &state.latest_finalized.root, &expected)) {
            std.debug.print(
                "fixture {s} case {s}: latest finalized root mismatch\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        }
    }

    if (post_obj.get("historicalBlockHashesCount")) |val| {
        const expected = try expect.expectU64Value(FixtureError, val, ctx, "post.historicalBlockHashesCount");
        const actual: u64 = @intCast(state.historical_block_hashes.len());
        if (actual != expected) {
            std.debug.print(
                "fixture {s} case {s}: historical block hashes count mismatch (got {d}, want {d})\n",
                .{ ctx.fixture_label, ctx.case_name, actual, expected },
            );
            return FixtureError.FixtureMismatch;
        }
    }

    if (post_obj.get("validatorCount")) |val| {
        const expected = try expect.expectU64Value(FixtureError, val, ctx, "post.validatorCount");
        const actual: u64 = @intCast(state.validators.len());
        if (actual != expected) {
            std.debug.print(
                "fixture {s} case {s}: validator count mismatch (got {d}, want {d})\n",
                .{ ctx.fixture_label, ctx.case_name, actual, expected },
            );
            return FixtureError.FixtureMismatch;
        }
    }
}

fn parseCheckpoint(
    ctx: Context,
    parent: std.json.ObjectMap,
    field_name: []const u8,
) FixtureError!types.Checkpoint {
    const cp_obj = try expect.expectObject(FixtureError, parent, &.{field_name}, ctx, field_name);

    var root_label_buf: [96]u8 = undefined;
    const root_label = std.fmt.bufPrint(&root_label_buf, "{s}.root", .{field_name}) catch field_name;
    var slot_label_buf: [96]u8 = undefined;
    const slot_label = std.fmt.bufPrint(&slot_label_buf, "{s}.slot", .{field_name}) catch field_name;

    return types.Checkpoint{
        .root = try expect.expectBytesField(FixtureError, types.Root, cp_obj, &.{"root"}, ctx, root_label),
        .slot = try expect.expectU64Field(FixtureError, cp_obj, &.{"slot"}, ctx, slot_label),
    };
}

fn parseBlockHeader(
    ctx: Context,
    obj: std.json.ObjectMap,
) FixtureError!types.BeamBlockHeader {
    return types.BeamBlockHeader{
        .slot = try expect.expectU64Field(FixtureError, obj, &.{"slot"}, ctx, "latestBlockHeader.slot"),
        .proposer_index = try expect.expectU64Field(FixtureError, obj, &.{ "proposerIndex", "proposer_index" }, ctx, "latestBlockHeader.proposerIndex"),
        .parent_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "parentRoot", "parent_root" }, ctx, "latestBlockHeader.parentRoot"),
        .state_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "stateRoot", "state_root" }, ctx, "latestBlockHeader.stateRoot"),
        .body_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "bodyRoot", "body_root" }, ctx, "latestBlockHeader.bodyRoot"),
    };
}
