const std = @import("std");
const zbench = @import("zbench");
const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");
const fixtures = @import("common/fixtures.zig");

const FIXTURE_PATH = "leanSpec/fixtures/consensus/state_transition/devnet/state_transition/test_block_processing/test_empty_blocks.json";

var g_logger_config: zeam_utils.ZeamLoggerConfig = undefined;
var g_pre: ?types.BeamState = null;
var g_block: ?types.BeamBlock = null;

/// Clone a BeamState via SSZ roundtrip (BeamState has no .clone() method).
fn cloneState(allocator: std.mem.Allocator, src: *const types.BeamState) !types.BeamState {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try ssz.serialize(types.BeamState, src.*, &buf, allocator);
    var dst: types.BeamState = undefined;
    try ssz.deserialize(types.BeamState, buf.items[0..], &dst, allocator);
    return dst;
}

fn benchApplyRawBlock(allocator: std.mem.Allocator) void {
    var working = cloneState(allocator, &g_pre.?) catch unreachable;
    defer working.deinit();
    var block_copy = g_block.?;
    const logger = g_logger_config.logger(.state_transition);
    state_transition.apply_raw_block(
        allocator,
        &working,
        &block_copy,
        logger,
        null,
    ) catch unreachable;
}

fn benchApplyTransition(allocator: std.mem.Allocator) void {
    var working = cloneState(allocator, &g_pre.?) catch unreachable;
    defer working.deinit();
    const block_copy = g_block.?;
    const logger = g_logger_config.logger(.state_transition);
    state_transition.apply_transition(
        allocator,
        &working,
        block_copy,
        .{ .logger = logger, .validateResult = false },
    ) catch unreachable;
}

pub fn main(init: std.process.Init) !void {
    _ = init;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    g_logger_config = zeam_utils.getTestLoggerConfig();

    const loaded = try fixtures.loadStateTransitionCase(allocator, FIXTURE_PATH);
    g_pre = loaded.pre;
    g_block = loaded.block;
    defer g_pre.?.deinit();
    defer g_block.?.deinit();

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    try bench.add("stf_apply_raw_block", benchApplyRawBlock, .{ .iterations = 100 });
    try bench.add("stf_apply_transition", benchApplyTransition, .{ .iterations = 100 });

    const io = std.Io.Threaded.global_single_threaded.io();
    const stdout = std.Io.File.stdout();
    try bench.run(io, stdout);
}
