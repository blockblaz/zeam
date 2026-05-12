const std = @import("std");
const spectest = @import("zeam_spectests");
const types = @import("@zeam/types");

const read_max_bytes: usize = 16 * 1024 * 1024; // 16 MiB upper bound per fixture file.

/// Load a leanSpec state-transition fixture JSON and return parsed `pre`
/// state + first `block` for STF benches. Caller owns deinit on both.
///
/// `rel_path` must be relative to the process working directory (repo root
/// when run via `zig build bench-stf`).
pub fn loadStateTransitionCase(
    allocator: std.mem.Allocator,
    rel_path: []const u8,
) !struct { pre: types.BeamState, block: types.BeamBlock } {
    // Use std.Io.Dir (Zig 0.16+) — std.fs.Dir no longer exists.
    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();
    const payload = try cwd.readFileAlloc(io, rel_path, allocator, .limited(read_max_bytes));
    defer allocator.free(payload);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |m| m,
        else => return error.InvalidFixture,
    };

    var it = root.iterator();
    const first = it.next() orelse return error.InvalidFixture;
    const case = switch (first.value_ptr.*) {
        .object => |m| m,
        else => return error.InvalidFixture,
    };

    const pre_val = case.get("pre") orelse return error.InvalidFixture;

    const blocks_val = case.get("blocks") orelse return error.InvalidFixture;
    const blocks_arr = switch (blocks_val) {
        .array => |a| a,
        else => return error.InvalidFixture,
    };
    if (blocks_arr.items.len == 0) return error.NoBlocks;
    const block_val = blocks_arr.items[0];

    const ctx = spectest.fixtures.Context{
        .fixture_label = "bench",
        .case_name = "bench",
    };

    var pre = try spectest.fixtures.buildState(allocator, ctx, pre_val);
    errdefer pre.deinit();

    const block = try spectest.fixtures.decodeBlock(allocator, block_val);

    return .{ .pre = pre, .block = block };
}
