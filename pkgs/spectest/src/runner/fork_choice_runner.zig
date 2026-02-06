const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

const expect = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const Context = expect.Context;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const node = @import("@zeam/node");
const forkchoice = node.fcFactory;
const node_constants = node.constants;
const state_transition = @import("@zeam/state-transition");
const zeam_utils = @import("@zeam/utils");
const params = @import("@zeam/params");
const skip = @import("../skip.zig");

const JsonValue = std.json.Value;

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;

pub const name = "fork_choice";

pub const Handler = enum {
    test_attestation_processing,
    test_attestation_target_selection,
    test_fork_choice_head,
    test_fork_choice_reorgs,
};

pub const handlers = std.enums.values(Handler);

pub fn handlerLabel(comptime handler: Handler) []const u8 {
    return switch (handler) {
        .test_attestation_processing => "test_attestation_processing",
        .test_attestation_target_selection => "test_attestation_target_selection",
        .test_fork_choice_head => "test_fork_choice_head",
        .test_fork_choice_reorgs => "test_fork_choice_reorgs",
    };
}

pub fn handlerPath(comptime handler: Handler) []const u8 {
    return handlerLabel(handler);
}

pub fn includeFixtureFile(file_name: []const u8) bool {
    return std.mem.endsWith(u8, file_name, ".json");
}

pub fn baseRelRoot(comptime spec_fork: Fork) []const u8 {
    const kind = FixtureKind.fork_choice;
    return std.fmt.comptimePrint(
        "consensus/{s}/{s}/{s}",
        .{ kind.runnerModule(), spec_fork.path, kind.handlerSubdir() },
    );
}

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
            try tc.run(allocator);
        }

        pub fn init(allocator: Allocator, dir: std.fs.Dir) RunnerError!Self {
            const payload = try loadFixturePayload(allocator, dir, rel_path);
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

fn loadFixturePayload(
    allocator: Allocator,
    dir: std.fs.Dir,
    rel_path: []const u8,
) RunnerError![]u8 {
    const payload = dir.readFileAlloc(allocator, rel_path, read_max_bytes) catch |err| switch (err) {
        error.FileTooBig => {
            std.debug.print(
                "spectest: fixture {s} exceeds allowed size\n",
                .{rel_path},
            );
            return RunnerError.IoFailure;
        },
        else => {
            std.debug.print(
                "spectest: failed to read {s}: {s}\n",
                .{ rel_path, @errorName(err) },
            );
            return RunnerError.IoFailure;
        },
    };
    return payload;
}

pub fn runFixturePayload(
    comptime spec_fork: Fork,
    allocator: Allocator,
    fixture_label: []const u8,
    payload: []const u8,
) FixtureError!void {
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
        runCase(spec_fork, allocator, ctx, case_value) catch |err| switch (err) {
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
            "spectest: skipped {d} fork choice case(s) in fixture {s} due to configured skip\n",
            .{ skipped_cases, fixture_label },
        );
    }
}

const StepContext = struct {
    allocator: Allocator,
    fork_choice: *forkchoice.ForkChoice,
    state_map: *StateMap,
    allocated_states: *StateList,
    label_map: *LabelMap,
    fork_logger: zeam_utils.ModuleLogger,
    base_context: Context,
};

const StateMap = std.AutoHashMapUnmanaged(types.Root, *types.BeamState);
const StateList = std.ArrayList(*types.BeamState);
const LabelMap = std.StringHashMapUnmanaged(types.Root);

fn runCase(
    comptime spec_fork: Fork,
    allocator: Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!void {
    const case_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print(
                "fixture {s} case {s}: expected object\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.InvalidFixture;
        },
    };

    const network_value = case_obj.get("network") orelse JsonValue{ .null = {} };
    const network = switch (network_value) {
        .null => null,
        .string => |s| s,
        else => {
            std.debug.print(
                "fixture {s} case {s}: network must be string\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.InvalidFixture;
        },
    };
    if (network) |net| {
        if (!std.mem.eql(u8, net, spec_fork.name)) {
            std.debug.print(
                "fixture {s} case {s}: unsupported network {s} (expected {s})\n",
                .{ ctx.fixture_label, ctx.case_name, net, spec_fork.name },
            );
            return FixtureError.UnsupportedFixture;
        }
    }

    const anchor_state_value = case_obj.get("anchorState") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing anchorState\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };

    var anchor_state = try buildState(allocator, ctx.fixture_label, ctx.case_name, anchor_state_value);
    defer anchor_state.deinit();

    const anchor_block_value = case_obj.get("anchorBlock") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing anchorBlock\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };
    var anchor_block = try buildBlock(allocator, ctx.fixture_label, ctx.case_name, anchor_block_value, null);
    defer anchor_block.deinit();

    var chain_config = buildChainConfig(allocator, &anchor_state) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: failed to build chain config ({s})\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };
    defer chain_config.deinit(allocator);

    var logger_config = zeam_utils.getTestLoggerConfig();
    defer logger_config.deinit();

    var fork_choice = forkchoice.ForkChoice.init(allocator, .{
        .config = chain_config,
        .anchorState = &anchor_state,
        .logger = logger_config.logger(.forkchoice),
    }) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: fork choice init failed ({s})\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };

    var state_map = StateMap.empty;
    defer state_map.deinit(allocator);

    var allocated_states = StateList.empty;
    defer {
        for (allocated_states.items) |state_ptr| {
            state_ptr.deinit();
            allocator.destroy(state_ptr);
        }
        allocated_states.deinit(allocator);
    }

    var label_map = LabelMap.empty;
    defer label_map.deinit(allocator);

    var anchor_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, anchor_block, &anchor_root, allocator) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: anchor block hashing failed ({s})\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };

    state_map.put(allocator, anchor_root, &anchor_state) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: failed to index anchor state ({s})\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };
    label_map.put(allocator, "genesis", anchor_root) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: failed to store genesis label ({s})\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };

    const steps_array = switch (case_obj.get("steps") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing steps array\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    }) {
        .array => |arr| arr,
        else => {
            std.debug.print(
                "fixture {s} case {s}: steps must be array\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.InvalidFixture;
        },
    };

    var step_ctx = StepContext{
        .allocator = allocator,
        .fork_choice = &fork_choice,
        .state_map = &state_map,
        .allocated_states = &allocated_states,
        .label_map = &label_map,
        .fork_logger = logger_config.logger(.forkchoice),
        .base_context = ctx,
    };

    const skip_on_mismatch = skip.configured();

    for (steps_array.items, 0..) |step_value, step_index| {
        runStep(&step_ctx, step_index, step_value) catch |err| switch (err) {
            FixtureError.FixtureMismatch => {
                if (skip_on_mismatch) {
                    std.debug.print(
                        "spectest: skipping fork choice case {s} in {s} at step #{d} due to configured skip\n",
                        .{ ctx.case_name, ctx.fixture_label, step_index },
                    );
                    return FixtureError.SkippedFixture;
                }
                return err;
            },
            FixtureError.SkippedFixture => return FixtureError.SkippedFixture,
            else => return err,
        };
    }
}

fn runStep(
    ctx: *StepContext,
    step_index: usize,
    value: JsonValue,
) FixtureError!void {
    const json_ctx = ctx.base_context.withStep(step_index);

    const step_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: expected object\n",
                .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep() },
            );
            return FixtureError.InvalidFixture;
        },
    };

    const valid_flag = switch (step_obj.get("valid") orelse JsonValue{ .bool = true }) {
        .bool => |b| b,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: valid must be bool\n",
                .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep() },
            );
            return FixtureError.InvalidFixture;
        },
    };

    const step_type = try expectStringField(step_obj, &.{"stepType"}, json_ctx.fixture_label, json_ctx.case_name, json_ctx.step_index, "stepType");

    const checks_value = step_obj.get("checks");

    const result = blk: {
        if (std.mem.eql(u8, step_type, "block")) {
            break :blk processBlockStep(ctx, json_ctx.fixture_label, json_ctx.case_name, step_index, step_obj);
        } else if (std.mem.eql(u8, step_type, "tick")) {
            break :blk processTickStep(ctx, json_ctx.fixture_label, json_ctx.case_name, step_index, step_obj);
        } else if (std.mem.eql(u8, step_type, "attestation")) {
            std.debug.print(
                "fixture {s} case {s}{any}: attestation steps unsupported\n",
                .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep() },
            );
            return FixtureError.UnsupportedFixture;
        } else {
            std.debug.print(
                "fixture {s} case {s}{any}: unknown stepType {s}\n",
                .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep(), step_type },
            );
            return FixtureError.InvalidFixture;
        }
    };

    result catch |err| {
        if (valid_flag) {
            std.debug.print(
                "fixture {s} case {s}{any}: unexpected error {s}\n",
                .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep(), @errorName(err) },
            );
            return FixtureError.FixtureMismatch;
        }
        return;
    };

    if (!valid_flag) {
        std.debug.print(
            "fixture {s} case {s}{any}: expected failure but succeeded\n",
            .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep() },
        );
        return FixtureError.FixtureMismatch;
    }

    if (checks_value) |checks| {
        const checks_obj = switch (checks) {
            .object => |map| map,
            else => {
                std.debug.print(
                    "fixture {s} case {s}{any}: checks must be object\n",
                    .{ json_ctx.fixture_label, json_ctx.case_name, json_ctx.formatStep() },
                );
                return FixtureError.InvalidFixture;
            },
        };
        try applyChecks(ctx, json_ctx.fixture_label, json_ctx.case_name, step_index, checks_obj);
    }
}

fn expectObjectField(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    field: []const u8,
) FixtureError!std.json.ObjectMap {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectObject(FixtureError, obj, field_names, ctx, field);
}

fn expectRootField(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    context: []const u8,
) FixtureError!types.Root {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectBytesField(FixtureError, types.Root, obj, field_names, ctx, context);
}

fn expectU64Field(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    context: []const u8,
) FixtureError!u64 {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectU64Field(FixtureError, obj, field_names, ctx, context);
}

fn expectStringField(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    context: []const u8,
) FixtureError![]const u8 {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectStringField(FixtureError, obj, field_names, ctx, context);
}

fn expectObject(
    obj: std.json.ObjectMap,
    field: []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
) FixtureError!std.json.ObjectMap {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectObject(FixtureError, obj, &.{field}, ctx, field);
}

fn expectStringValue(
    value: JsonValue,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    context: []const u8,
) FixtureError![]const u8 {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectStringValue(FixtureError, value, ctx, context);
}

fn expectRootValue(
    value: JsonValue,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    context: []const u8,
) FixtureError!types.Root {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectBytesValue(FixtureError, types.Root, value, ctx, context);
}

fn expectU64Value(
    value: JsonValue,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    context: []const u8,
) FixtureError!u64 {
    const ctx = buildContext(fixture_path, case_name, step_index);
    return expect.expectU64Value(FixtureError, value, ctx, context);
}

fn appendRoots(
    list: anytype,
    container: JsonValue,
    fixture_path: []const u8,
    case_name: []const u8,
    context_label: []const u8,
) FixtureError!void {
    const ctx = buildContext(fixture_path, case_name, null);
    try expect.appendBytesDataField(FixtureError, types.Root, list, ctx, container, context_label);
}

fn appendBools(
    list: anytype,
    container: JsonValue,
    fixture_path: []const u8,
    case_name: []const u8,
    context_label: []const u8,
) FixtureError!void {
    const ctx = buildContext(fixture_path, case_name, null);
    try expect.appendBoolDataField(FixtureError, list, ctx, container, context_label);
}

fn buildContext(
    fixture_label: []const u8,
    case_name: []const u8,
    step_index: ?usize,
) Context {
    return Context{
        .fixture_label = fixture_label,
        .case_name = case_name,
        .step_index = step_index,
    };
}

fn processBlockStep(
    ctx: *StepContext,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    step_obj: std.json.ObjectMap,
) !void {
    const block_wrapper = step_obj.get("block") orelse {
        std.debug.print(
            "fixture {s} case {s}{any}: block step missing block field\n",
            .{ fixture_path, case_name, formatStep(step_index) },
        );
        return FixtureError.InvalidFixture;
    };

    const block_wrapper_obj: ?std.json.ObjectMap = switch (block_wrapper) {
        .object => |map| map,
        else => null,
    };

    const block_value = blk: {
        if (block_wrapper_obj) |wrapper_obj| {
            if (wrapper_obj.get("block")) |nested_block| {
                break :blk nested_block;
            }
        }
        break :blk block_wrapper;
    };

    var block = try buildBlock(ctx.allocator, fixture_path, case_name, block_value, step_index);
    defer block.deinit();

    var block_root: types.Root = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, ctx.allocator) catch |err| {
        std.debug.print(
            "fixture {s} case {s}{any}: hashing block failed ({s})\n",
            .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };

    const parent_state_ptr = ctx.state_map.get(block.parent_root) orelse {
        std.debug.print(
            "fixture {s} case {s}{any}: parent root 0x{x} unknown\n",
            .{ fixture_path, case_name, formatStep(step_index), &block.parent_root },
        );
        return FixtureError.FixtureMismatch;
    };

    const target_intervals = slotToIntervals(block.slot);
    try ctx.fork_choice.onInterval(target_intervals, true);

    const new_state_ptr = try ctx.allocator.create(types.BeamState);
    errdefer {
        new_state_ptr.deinit();
        ctx.allocator.destroy(new_state_ptr);
    }
    try types.sszClone(ctx.allocator, types.BeamState, parent_state_ptr.*, new_state_ptr);

    state_transition.apply_transition(ctx.allocator, new_state_ptr, block, .{ .logger = ctx.fork_logger, .validateResult = false }) catch |err| {
        std.debug.print(
            "fixture {s} case {s}{any}: state transition failed {s}\n",
            .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
        );
        return FixtureError.FixtureMismatch;
    };

    _ = ctx.fork_choice.onBlock(block, new_state_ptr, .{
        .currentSlot = block.slot,
        .blockDelayMs = 0,
        .blockRoot = block_root,
        .confirmed = true,
    }) catch |err| {
        std.debug.print(
            "fixture {s} case {s}{any}: forkchoice onBlock failed {s}\n",
            .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
        );
        return FixtureError.FixtureMismatch;
    };

    _ = try ctx.fork_choice.updateHead();

    ctx.state_map.put(ctx.allocator, block_root, new_state_ptr) catch |err| {
        std.debug.print(
            "fixture {s} case {s}{any}: failed to index block state ({s})\n",
            .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };
    ctx.allocated_states.append(ctx.allocator, new_state_ptr) catch |err| {
        std.debug.print(
            "fixture {s} case {s}{any}: failed to track state allocation ({s})\n",
            .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };

    var proposer_attestation = buildProposerAttestation(block, block_root, parent_state_ptr) catch |err| {
        std.debug.print(
            "fixture {s} case {s}{any}: unable to build proposer attestation ({s})\n",
            .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
        );
        return FixtureError.FixtureMismatch;
    };

    if (block_wrapper_obj) |wrapper_obj| {
        if (wrapper_obj.get("proposerAttestation")) |att_value| {
            proposer_attestation = try parseFixtureProposerAttestation(
                fixture_path,
                case_name,
                step_index,
                att_value,
            );
        }
    }

    const attestation = types.Attestation{
        .validator_id = proposer_attestation.validator_id,
        .data = proposer_attestation.data,
    };
    try ctx.fork_choice.onAttestation(attestation, false);

    if (block_wrapper_obj) |wrapper_obj| {
        if (wrapper_obj.get("blockRootLabel")) |label_value| {
            const label = switch (label_value) {
                .string => |s| s,
                else => {
                    std.debug.print(
                        "fixture {s} case {s}{any}: blockRootLabel must be string\n",
                        .{ fixture_path, case_name, formatStep(step_index) },
                    );
                    return FixtureError.InvalidFixture;
                },
            };
            ctx.label_map.put(ctx.allocator, label, block_root) catch |err| {
                std.debug.print(
                    "fixture {s} case {s}{any}: failed to record blockRootLabel {s} ({s})\n",
                    .{ fixture_path, case_name, formatStep(step_index), label, @errorName(err) },
                );
                return FixtureError.InvalidFixture;
            };
        }
    }
}

fn processTickStep(
    ctx: *StepContext,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    step_obj: std.json.ObjectMap,
) !void {
    const time_value = try expectU64Field(step_obj, &.{"time"}, fixture_path, case_name, step_index, "time");

    const anchor_genesis_time = ctx.fork_choice.anchorState.config.genesis_time;
    if (time_value < anchor_genesis_time) {
        std.debug.print(
            "fixture {s} case {s}{any}: tick time before genesis\n",
            .{ fixture_path, case_name, formatStep(step_index) },
        );
        return FixtureError.InvalidFixture;
    }

    const target_intervals = timeToIntervals(anchor_genesis_time, time_value);
    try ctx.fork_choice.onInterval(target_intervals, false);
}

fn applyChecks(
    ctx: *StepContext,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    checks_obj: std.json.ObjectMap,
) FixtureError!void {
    var it = checks_obj.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        if (std.mem.eql(u8, key, "headSlot")) {
            const expected = try expectU64Value(value, fixture_path, case_name, step_index, key);
            if (ctx.fork_choice.head.slot != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: head slot mismatch got {d} expected {d}\n",
                    .{ fixture_path, case_name, formatStep(step_index), ctx.fork_choice.head.slot, expected },
                );
                return FixtureError.FixtureMismatch;
            }
            continue;
        }

        if (std.mem.eql(u8, key, "headRoot")) {
            const expected = try expectRootValue(value, fixture_path, case_name, step_index, key);
            if (!std.mem.eql(u8, &ctx.fork_choice.head.blockRoot, &expected)) {
                std.debug.print(
                    "fixture {s} case {s}{any}: head root mismatch\n",
                    .{ fixture_path, case_name, formatStep(step_index) },
                );
                return FixtureError.FixtureMismatch;
            }
            continue;
        }

        if (std.mem.eql(u8, key, "headRootLabel")) {
            const label = switch (value) {
                .string => |s| s,
                else => {
                    std.debug.print(
                        "fixture {s} case {s}{any}: headRootLabel must be string\n",
                        .{ fixture_path, case_name, formatStep(step_index) },
                    );
                    return FixtureError.InvalidFixture;
                },
            };
            const head_root = ctx.fork_choice.head.blockRoot;
            if (ctx.label_map.get(label)) |expected_root| {
                if (!std.mem.eql(u8, &head_root, &expected_root)) {
                    std.debug.print(
                        "fixture {s} case {s}{any}: head root label {s} mismatch\n",
                        .{ fixture_path, case_name, formatStep(step_index), label },
                    );
                    return FixtureError.FixtureMismatch;
                }
            } else {
                ctx.label_map.put(ctx.allocator, label, head_root) catch |err| {
                    std.debug.print(
                        "fixture {s} case {s}{any}: failed to record label {s} ({s})\n",
                        .{ fixture_path, case_name, formatStep(step_index), label, @errorName(err) },
                    );
                    return FixtureError.InvalidFixture;
                };
            }
            continue;
        }

        if (std.mem.eql(u8, key, "time")) {
            const expected = try expectU64Value(value, fixture_path, case_name, step_index, key);
            if (ctx.fork_choice.fcStore.time != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: store time mismatch got {d} expected {d}\n",
                    .{ fixture_path, case_name, formatStep(step_index), ctx.fork_choice.fcStore.time, expected },
                );
                return FixtureError.FixtureMismatch;
            }
            continue;
        }

        if (std.mem.eql(u8, key, "latestJustifiedSlot")) {
            const expected = try expectU64Value(value, fixture_path, case_name, step_index, key);
            const actual = ctx.fork_choice.fcStore.latest_justified.slot;
            if (actual != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: latest justified slot mismatch got {d} expected {d}\n",
                    .{ fixture_path, case_name, formatStep(step_index), actual, expected },
                );
                return FixtureError.FixtureMismatch;
            }
            continue;
        }

        if (std.mem.eql(u8, key, "latestFinalizedSlot")) {
            const expected = try expectU64Value(value, fixture_path, case_name, step_index, key);
            const actual = ctx.fork_choice.fcStore.latest_finalized.slot;
            if (actual != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: latest finalized slot mismatch got {d} expected {d}\n",
                    .{ fixture_path, case_name, formatStep(step_index), actual, expected },
                );
                return FixtureError.FixtureMismatch;
            }
            continue;
        }

        if (std.mem.eql(u8, key, "attestationTargetSlot")) {
            const expected = try expectU64Value(value, fixture_path, case_name, step_index, key);
            const checkpoint = ctx.fork_choice.getAttestationTarget() catch |err| {
                std.debug.print(
                    "fixture {s} case {s}{any}: attestation target failed {s}\n",
                    .{ fixture_path, case_name, formatStep(step_index), @errorName(err) },
                );
                return FixtureError.FixtureMismatch;
            };
            if (checkpoint.slot != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: attestation target slot mismatch\n",
                    .{ fixture_path, case_name, formatStep(step_index) },
                );
                return FixtureError.FixtureMismatch;
            }
            continue;
        }

        if (std.mem.eql(u8, key, "attestationChecks")) {
            try verifyAttestationChecks(ctx, fixture_path, case_name, step_index, value);
            continue;
        }

        if (std.mem.eql(u8, key, "lexicographicHeadAmong")) {
            try verifyLexicographicHead(ctx, fixture_path, case_name, step_index, value);
            continue;
        }

        std.debug.print(
            "fixture {s} case {s}{any}: unsupported check {s}\n",
            .{ fixture_path, case_name, formatStep(step_index), key },
        );
        return FixtureError.UnsupportedFixture;
    }
}

fn verifyAttestationChecks(
    ctx: *StepContext,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    value: JsonValue,
) FixtureError!void {
    const arr = switch (value) {
        .array => |array| array,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: attestationChecks must be array\n",
                .{ fixture_path, case_name, formatStep(step_index) },
            );
            return FixtureError.InvalidFixture;
        },
    };

    for (arr.items) |entry| {
        const obj = switch (entry) {
            .object => |map| map,
            else => {
                std.debug.print(
                    "fixture {s} case {s}{any}: attestationCheck entry must be object\n",
                    .{ fixture_path, case_name, formatStep(step_index) },
                );
                return FixtureError.InvalidFixture;
            },
        };

        const validator = try expectU64Field(obj, &.{"validator"}, fixture_path, case_name, step_index, "validator");
        const location = try expectStringField(obj, &.{"location"}, fixture_path, case_name, step_index, "location");

        const tracker = ctx.fork_choice.attestations.get(validator) orelse {
            std.debug.print(
                "fixture {s} case {s}{any}: attestation tracker missing for validator {d}\n",
                .{ fixture_path, case_name, formatStep(step_index), validator },
            );
            return FixtureError.FixtureMismatch;
        };

        const proto = if (std.mem.eql(u8, location, "new"))
            tracker.latestNew
        else if (std.mem.eql(u8, location, "known"))
            tracker.latestKnown
        else
            null;

        if (proto == null) {
            std.debug.print(
                "fixture {s} case {s}{any}: validator {d} missing {s} attestation\n",
                .{ fixture_path, case_name, formatStep(step_index), validator, location },
            );
            return FixtureError.FixtureMismatch;
        }

        const attestation_data = proto.?.attestation_data orelse {
            std.debug.print(
                "fixture {s} case {s}{any}: validator {d} has no attestation payload\n",
                .{ fixture_path, case_name, formatStep(step_index), validator },
            );
            return FixtureError.FixtureMismatch;
        };

        if (obj.get("attestationSlot")) |slot_value| {
            const expected = try expectU64Value(slot_value, fixture_path, case_name, step_index, "attestationSlot");
            if (attestation_data.slot != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: validator {d} attestation slot mismatch\n",
                    .{ fixture_path, case_name, formatStep(step_index), validator },
                );
                return FixtureError.FixtureMismatch;
            }
        }

        if (obj.get("headSlot")) |slot_value| {
            const expected = try expectU64Value(slot_value, fixture_path, case_name, step_index, "headSlot");
            if (attestation_data.head.slot != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: validator {d} head slot mismatch\n",
                    .{ fixture_path, case_name, formatStep(step_index), validator },
                );
                return FixtureError.FixtureMismatch;
            }
        }

        if (obj.get("sourceSlot")) |slot_value| {
            const expected = try expectU64Value(slot_value, fixture_path, case_name, step_index, "sourceSlot");
            if (attestation_data.source.slot != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: validator {d} source slot mismatch\n",
                    .{ fixture_path, case_name, formatStep(step_index), validator },
                );
                return FixtureError.FixtureMismatch;
            }
        }

        if (obj.get("targetSlot")) |slot_value| {
            const expected = try expectU64Value(slot_value, fixture_path, case_name, step_index, "targetSlot");
            if (attestation_data.target.slot != expected) {
                std.debug.print(
                    "fixture {s} case {s}{any}: validator {d} target slot mismatch\n",
                    .{ fixture_path, case_name, formatStep(step_index), validator },
                );
                return FixtureError.FixtureMismatch;
            }
        }
    }
}

fn verifyLexicographicHead(
    ctx: *StepContext,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    value: JsonValue,
) FixtureError!void {
    const arr = switch (value) {
        .array => |entries| entries,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: lexicographicHeadAmong must be array\n",
                .{ fixture_path, case_name, formatStep(step_index) },
            );
            return FixtureError.InvalidFixture;
        },
    };

    if (arr.items.len == 0) {
        std.debug.print(
            "fixture {s} case {s}{any}: lexicographicHeadAmong cannot be empty\n",
            .{ fixture_path, case_name, formatStep(step_index) },
        );
        return FixtureError.InvalidFixture;
    }

    var best_label: []const u8 = undefined;
    var best_root: ?types.Root = null;

    for (arr.items) |entry| {
        const label = switch (entry) {
            .string => |s| s,
            else => {
                std.debug.print(
                    "fixture {s} case {s}{any}: lexicographicHeadAmong entries must be strings\n",
                    .{ fixture_path, case_name, formatStep(step_index) },
                );
                return FixtureError.InvalidFixture;
            },
        };

        const root = ctx.label_map.get(label) orelse {
            std.debug.print(
                "fixture {s} case {s}{any}: lexicographicHeadAmong label {s} not found (missing prior headRootLabel?)\n",
                .{ fixture_path, case_name, formatStep(step_index), label },
            );
            return FixtureError.InvalidFixture;
        };

        if (best_root) |best| {
            if (std.mem.order(u8, &root, &best) == .gt) {
                best_root = root;
                best_label = label;
            }
        } else {
            best_root = root;
            best_label = label;
        }
    }

    const expected_root = best_root orelse unreachable;
    const head_root = ctx.fork_choice.head.blockRoot;
    if (!std.mem.eql(u8, &head_root, &expected_root)) {
        std.debug.print(
            "fixture {s} case {s}{any}: head root mismatch for lexicographicHeadAmong (expected label {s})\n",
            .{ fixture_path, case_name, formatStep(step_index), best_label },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn buildProposerAttestation(
    block: types.BeamBlock,
    block_root: types.Root,
    parent_state: *types.BeamState,
) !types.Attestation {
    return types.Attestation{
        .validator_id = block.proposer_index,
        .data = .{
            .slot = block.slot,
            .head = .{ .root = block_root, .slot = block.slot },
            .target = .{ .root = block_root, .slot = block.slot },
            .source = .{
                .root = block.parent_root,
                .slot = parent_state.latest_block_header.slot,
            },
        },
    };
}

fn parseFixtureProposerAttestation(
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    value: JsonValue,
) FixtureError!types.Attestation {
    const att_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: proposerAttestation must be object\n",
                .{ fixture_path, case_name, formatStep(step_index) },
            );
            return FixtureError.InvalidFixture;
        },
    };

    var validator_label_buf: [96]u8 = undefined;
    const validator_label = std.fmt.bufPrint(&validator_label_buf, "block.step[{d}].proposerAttestation.validatorId", .{step_index}) catch "proposerAttestation.validatorId";
    const validator_id = try expectU64Field(att_obj, &.{ "validatorId", "validator_id" }, fixture_path, case_name, step_index, validator_label);

    var data_label_buf: [96]u8 = undefined;
    const data_label = std.fmt.bufPrint(&data_label_buf, "block.step[{d}].proposerAttestation.data", .{step_index}) catch "proposerAttestation.data";
    const data_obj = try expectObjectField(att_obj, &.{"data"}, fixture_path, case_name, step_index, data_label);

    var slot_label_buf: [96]u8 = undefined;
    const slot_label = std.fmt.bufPrint(&slot_label_buf, "{s}.slot", .{data_label}) catch "proposerAttestation.data.slot";
    const data_slot = try expectU64Field(data_obj, &.{"slot"}, fixture_path, case_name, step_index, slot_label);

    const head = try parseCheckpointField(data_obj, "head", fixture_path, case_name, step_index, data_label);
    const target = try parseCheckpointField(data_obj, "target", fixture_path, case_name, step_index, data_label);
    const source = try parseCheckpointField(data_obj, "source", fixture_path, case_name, step_index, data_label);

    return types.Attestation{
        .validator_id = validator_id,
        .data = .{
            .slot = data_slot,
            .head = head,
            .target = target,
            .source = source,
        },
    };
}

fn parseCheckpointField(
    parent: std.json.ObjectMap,
    field: []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: usize,
    label_prefix: []const u8,
) FixtureError!types.Checkpoint {
    var context_buf: [160]u8 = undefined;
    const checkpoint_context = std.fmt.bufPrint(&context_buf, "{s}.{s}", .{ label_prefix, field }) catch field;
    const checkpoint_obj = try expectObjectField(parent, &.{field}, fixture_path, case_name, step_index, checkpoint_context);

    var root_label_buf: [192]u8 = undefined;
    const root_label = std.fmt.bufPrint(&root_label_buf, "{s}.root", .{checkpoint_context}) catch "checkpoint.root";
    var slot_label_buf: [192]u8 = undefined;
    const slot_label = std.fmt.bufPrint(&slot_label_buf, "{s}.slot", .{checkpoint_context}) catch "checkpoint.slot";

    const root = try expectRootField(checkpoint_obj, &.{"root"}, fixture_path, case_name, step_index, root_label);
    const slot = try expectU64Field(checkpoint_obj, &.{"slot"}, fixture_path, case_name, step_index, slot_label);

    return .{ .root = root, .slot = slot };
}

fn buildBlock(
    allocator: Allocator,
    fixture_path: []const u8,
    case_name: []const u8,
    value: JsonValue,
    step_index: ?usize,
) FixtureError!types.BeamBlock {
    const obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: block must be object\n", .{ fixture_path, case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const slot = try expectU64Field(obj, &.{"slot"}, fixture_path, case_name, step_index, "slot");
    const proposer_index = try expectU64Field(obj, &.{ "proposer_index", "proposerIndex" }, fixture_path, case_name, step_index, "proposer_index");
    const parent_root = try expectRootField(obj, &.{ "parent_root", "parentRoot" }, fixture_path, case_name, step_index, "parent_root");
    const state_root = try expectRootField(obj, &.{ "state_root", "stateRoot" }, fixture_path, case_name, step_index, "state_root");

    const body_value = obj.get("body") orelse {
        std.debug.print("fixture {s} case {s}: block missing body\n", .{ fixture_path, case_name });
        return FixtureError.InvalidFixture;
    };
    const body_obj = switch (body_value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: body must be object\n", .{ fixture_path, case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const attestations_value = body_obj.get("attestations") orelse JsonValue{ .null = {} };
    const att_list = try parseAttestations(allocator, fixture_path, case_name, step_index, attestations_value);

    return types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = .{ .attestations = att_list },
    };
}

fn parseAttestations(
    allocator: Allocator,
    fixture_path: []const u8,
    case_name: []const u8,
    step_index: ?usize,
    value: JsonValue,
) FixtureError!types.AggregatedAttestations {
    switch (value) {
        .null => return types.AggregatedAttestations.init(allocator) catch return FixtureError.InvalidFixture,
        .object => |obj| {
            const data_value = obj.get("data") orelse {
                return types.AggregatedAttestations.init(allocator) catch return FixtureError.InvalidFixture;
            };
            const arr = switch (data_value) {
                .array => |array| array,
                else => {
                    std.debug.print(
                        "fixture {s} case {s}{any}: attestations.data must be array\n",
                        .{ fixture_path, case_name, formatStep(step_index) },
                    );
                    return FixtureError.InvalidFixture;
                },
            };

            var aggregated_attestations = types.AggregatedAttestations.init(allocator) catch return FixtureError.InvalidFixture;
            errdefer aggregated_attestations.deinit();

            for (arr.items, 0..) |item, idx| {
                const att_obj = switch (item) {
                    .object => |map| map,
                    else => {
                        std.debug.print(
                            "fixture {s} case {s}{any}: attestation #{} must be object\n",
                            .{ fixture_path, case_name, formatStep(step_index), idx },
                        );
                        return FixtureError.InvalidFixture;
                    },
                };

                const bits_value = att_obj.get("aggregationBits") orelse {
                    std.debug.print(
                        "fixture {s} case {s}{any}: attestation #{} missing aggregationBits\n",
                        .{ fixture_path, case_name, formatStep(step_index), idx },
                    );
                    return FixtureError.InvalidFixture;
                };
                const bits_obj = switch (bits_value) {
                    .object => |map| map,
                    else => {
                        std.debug.print(
                            "fixture {s} case {s}{any}: attestation #{} aggregationBits must be object\n",
                            .{ fixture_path, case_name, formatStep(step_index), idx },
                        );
                        return FixtureError.InvalidFixture;
                    },
                };
                const bits_data_value = bits_obj.get("data") orelse {
                    std.debug.print(
                        "fixture {s} case {s}{any}: attestation #{} aggregationBits missing data\n",
                        .{ fixture_path, case_name, formatStep(step_index), idx },
                    );
                    return FixtureError.InvalidFixture;
                };
                const bits_arr = switch (bits_data_value) {
                    .array => |array| array,
                    else => {
                        std.debug.print(
                            "fixture {s} case {s}{any}: attestation #{} aggregationBits.data must be array\n",
                            .{ fixture_path, case_name, formatStep(step_index), idx },
                        );
                        return FixtureError.InvalidFixture;
                    },
                };

                var aggregation_bits = types.AggregationBits.init(allocator) catch return FixtureError.InvalidFixture;
                errdefer aggregation_bits.deinit();

                for (bits_arr.items) |bit_value| {
                    const bit = switch (bit_value) {
                        .bool => |b| b,
                        else => {
                            std.debug.print(
                                "fixture {s} case {s}{any}: attestation #{} aggregationBits element must be bool\n",
                                .{ fixture_path, case_name, formatStep(step_index), idx },
                            );
                            return FixtureError.InvalidFixture;
                        },
                    };
                    aggregation_bits.append(bit) catch return FixtureError.InvalidFixture;
                }

                const data_obj = try expectObject(att_obj, "data", fixture_path, case_name, step_index);

                var slot_ctx_buf: [96]u8 = undefined;
                const slot_ctx = std.fmt.bufPrint(&slot_ctx_buf, "attestations[{d}].data.slot", .{idx}) catch "attestations.slot";
                const att_slot = try expectU64Field(data_obj, &.{"slot"}, fixture_path, case_name, step_index, slot_ctx);

                const head_obj = try expectObject(data_obj, "head", fixture_path, case_name, step_index);
                const target_obj = try expectObject(data_obj, "target", fixture_path, case_name, step_index);
                const source_obj = try expectObject(data_obj, "source", fixture_path, case_name, step_index);

                var head_root_ctx_buf: [112]u8 = undefined;
                const head_root_ctx = std.fmt.bufPrint(&head_root_ctx_buf, "attestations[{d}].data.head.root", .{idx}) catch "attestations.head.root";
                const head_root = try expectRootField(head_obj, &.{"root"}, fixture_path, case_name, step_index, head_root_ctx);
                var head_slot_ctx_buf: [112]u8 = undefined;
                const head_slot_ctx = std.fmt.bufPrint(&head_slot_ctx_buf, "attestations[{d}].data.head.slot", .{idx}) catch "attestations.head.slot";
                const head_slot = try expectU64Field(head_obj, &.{"slot"}, fixture_path, case_name, step_index, head_slot_ctx);

                var target_root_ctx_buf: [120]u8 = undefined;
                const target_root_ctx = std.fmt.bufPrint(&target_root_ctx_buf, "attestations[{d}].data.target.root", .{idx}) catch "attestations.target.root";
                const target_root = try expectRootField(target_obj, &.{"root"}, fixture_path, case_name, step_index, target_root_ctx);
                var target_slot_ctx_buf: [120]u8 = undefined;
                const target_slot_ctx = std.fmt.bufPrint(&target_slot_ctx_buf, "attestations[{d}].data.target.slot", .{idx}) catch "attestations.target.slot";
                const target_slot = try expectU64Field(target_obj, &.{"slot"}, fixture_path, case_name, step_index, target_slot_ctx);

                var source_root_ctx_buf: [120]u8 = undefined;
                const source_root_ctx = std.fmt.bufPrint(&source_root_ctx_buf, "attestations[{d}].data.source.root", .{idx}) catch "attestations.source.root";
                const source_root = try expectRootField(source_obj, &.{"root"}, fixture_path, case_name, step_index, source_root_ctx);
                var source_slot_ctx_buf: [120]u8 = undefined;
                const source_slot_ctx = std.fmt.bufPrint(&source_slot_ctx_buf, "attestations[{d}].data.source.slot", .{idx}) catch "attestations.source.slot";
                const source_slot = try expectU64Field(source_obj, &.{"slot"}, fixture_path, case_name, step_index, source_slot_ctx);

                const aggregated_attestation = types.AggregatedAttestation{
                    .aggregation_bits = aggregation_bits,
                    .data = .{
                        .slot = att_slot,
                        .head = .{ .root = head_root, .slot = head_slot },
                        .target = .{ .root = target_root, .slot = target_slot },
                        .source = .{ .root = source_root, .slot = source_slot },
                    },
                };

                aggregated_attestations.append(aggregated_attestation) catch |err| {
                    std.debug.print(
                        "fixture {s} case {s}{any}: attestation #{} append failed: {s}\n",
                        .{ fixture_path, case_name, formatStep(step_index), idx, @errorName(err) },
                    );
                    return FixtureError.InvalidFixture;
                };
            }

            return aggregated_attestations;
        },
        else => {
            std.debug.print(
                "fixture {s} case {s}{any}: attestations must be object\n",
                .{ fixture_path, case_name, formatStep(step_index) },
            );
            return FixtureError.InvalidFixture;
        },
    }
}

fn buildState(
    allocator: Allocator,
    fixture_path: []const u8,
    case_name: []const u8,
    value: JsonValue,
) FixtureError!types.BeamState {
    const ctx = buildContext(fixture_path, case_name, null);
    const pre_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: state must be object\n", .{ fixture_path, case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const config_obj = try expectObject(pre_obj, "config", fixture_path, case_name, null);
    const genesis_time = try expectU64Field(config_obj, &.{"genesisTime"}, fixture_path, case_name, null, "config.genesisTime");

    const slot = try expectU64Field(pre_obj, &.{"slot"}, fixture_path, case_name, null, "slot");

    const header_obj = try expectObject(pre_obj, "latestBlockHeader", fixture_path, case_name, null);
    const latest_block_header = try parseBlockHeader(header_obj, fixture_path, case_name);

    const latest_justified = try parseCheckpoint(pre_obj, "latestJustified", fixture_path, case_name);
    const latest_finalized = try parseCheckpoint(pre_obj, "latestFinalized", fixture_path, case_name);

    var historical = try types.HistoricalBlockHashes.init(allocator);
    errdefer historical.deinit();
    if (pre_obj.get("historicalBlockHashes")) |v| {
        try appendRoots(&historical, v, fixture_path, case_name, "historicalBlockHashes");
    }

    var justified_slots = try types.JustifiedSlots.init(allocator);
    errdefer justified_slots.deinit();
    if (pre_obj.get("justifiedSlots")) |v| {
        try appendBools(&justified_slots, v, fixture_path, case_name, "justifiedSlots");
    }

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
                        .{ fixture_path, case_name, idx, @errorName(err) },
                    );
                    return FixtureError.InvalidFixture;
                };
            }
        }
    }

    var just_roots = try types.JustificationRoots.init(allocator);
    errdefer just_roots.deinit();
    if (pre_obj.get("justificationsRoots")) |v| {
        try appendRoots(&just_roots, v, fixture_path, case_name, "justificationsRoots");
    }

    var just_validators = try types.JustificationValidators.init(allocator);
    errdefer just_validators.deinit();
    if (pre_obj.get("justificationsValidators")) |v| {
        try appendBools(&just_validators, v, fixture_path, case_name, "justificationsValidators");
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

fn parseBlockHeader(
    obj: std.json.ObjectMap,
    fixture_path: []const u8,
    case_name: []const u8,
) FixtureError!types.BeamBlockHeader {
    return types.BeamBlockHeader{
        .slot = try expectU64Field(obj, &.{"slot"}, fixture_path, case_name, null, "latestBlockHeader.slot"),
        .proposer_index = try expectU64Field(obj, &.{"proposerIndex"}, fixture_path, case_name, null, "latestBlockHeader.proposerIndex"),
        .parent_root = try expectRootField(obj, &.{"parentRoot"}, fixture_path, case_name, null, "latestBlockHeader.parentRoot"),
        .state_root = try expectRootField(obj, &.{"stateRoot"}, fixture_path, case_name, null, "latestBlockHeader.stateRoot"),
        .body_root = try expectRootField(obj, &.{"bodyRoot"}, fixture_path, case_name, null, "latestBlockHeader.bodyRoot"),
    };
}

fn parseCheckpoint(
    obj: std.json.ObjectMap,
    field: []const u8,
    fixture_path: []const u8,
    case_name: []const u8,
) FixtureError!types.Checkpoint {
    const cp_obj = try expectObject(obj, field, fixture_path, case_name, null);
    return types.Checkpoint{
        .root = try expectRootField(cp_obj, &.{"root"}, fixture_path, case_name, null, field),
        .slot = try expectU64Field(cp_obj, &.{"slot"}, fixture_path, case_name, null, field),
    };
}

fn buildChainConfig(allocator: Allocator, state: *types.BeamState) !configs.ChainConfig {
    const chain_spec =
        \\{"preset":"mainnet","name":"devnet0"}
    ;
    const parse_options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    const parse_result = json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, parse_options) catch |err| {
        std.debug.print("spectest: unable to parse chain config: {s}\n", .{@errorName(err)});
        return FixtureError.InvalidFixture;
    };
    var chain_options = parse_result.value;
    chain_options.genesis_time = state.config.genesis_time;

    const validators_slice = state.validators.constSlice();
    const num_validators = validators_slice.len;
    const pubkeys = try allocator.alloc(types.Bytes52, num_validators);
    errdefer allocator.free(pubkeys);
    for (validators_slice, 0..) |validator_info, idx| {
        pubkeys[idx] = validator_info.pubkey;
    }
    chain_options.validator_pubkeys = pubkeys;

    return configs.ChainConfig.init(configs.Chain.custom, chain_options) catch |err| {
        std.debug.print("spectest: unable to init chain config: {s}\n", .{@errorName(err)});
        return FixtureError.InvalidFixture;
    };
}

fn slotToIntervals(slot: u64) u64 {
    return slot * node_constants.INTERVALS_PER_SLOT;
}

fn timeToIntervals(genesis_time: u64, time_value: u64) u64 {
    const delta = time_value - genesis_time;
    const intervals_per_slot: u64 = node_constants.INTERVALS_PER_SLOT;
    const numerator = std.math.mulWide(u64, delta, intervals_per_slot);
    const quotient = numerator / params.SECONDS_PER_SLOT;
    return @intCast(quotient);
}

fn formatStep(step_index: ?usize) expect.StepSuffix {
    return expect.StepSuffix{ .step = step_index };
}
