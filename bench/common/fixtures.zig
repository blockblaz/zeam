const std = @import("std");
const spectest = @import("zeam_spectests");
const types = @import("@zeam/types");

/// Load a leanSpec state-transition fixture JSON and return parsed `pre`
/// state + first `block` for STF benches. Caller owns deinit on both.
///
/// Path must be relative to `fixtures_root` (typically the repo's
/// `leanSpec/tests/...` directory once the submodule is initialised).
pub fn loadStateTransitionCase(
    allocator: std.mem.Allocator,
    fixtures_root: std.fs.Dir,
    rel_path: []const u8,
) !struct { pre: types.BeamState, block: types.BeamBlock } {
    const payload = try spectest.fixtures.loadFixturePayload(allocator, fixtures_root, rel_path);
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
