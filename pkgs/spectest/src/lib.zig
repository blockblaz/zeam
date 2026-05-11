const std = @import("std");
const builtin = @import("builtin");

pub const forks = @import("./fork.zig");
pub const state_transition_runner = @import("./runner/state_transition_runner.zig");
pub const fork_choice_runner = @import("./runner/fork_choice_runner.zig");
pub const ssz_runner = @import("./runner/ssz_runner.zig");
pub const justifiability_runner = @import("./runner/justifiability_runner.zig");
pub const verify_signatures_runner = @import("./runner/verify_signatures_runner.zig");
pub const slot_clock_runner = @import("./runner/slot_clock_runner.zig");
pub const api_endpoint_runner = @import("./runner/api_endpoint_runner.zig");
pub const networking_codec_runner = @import("./runner/networking_codec_runner.zig");
pub const skip = @import("./skip.zig");
pub const generated = @import("./generated/index.zig");

// Local replacement for `std.testing.refAllDeclsRecursive`, which was
// removed in Zig 0.16. The generated index is a deeply nested struct
// tree (kind → fork → suite → handler → tests.zig), so the shallow
// `refAllDecls` alone leaves the inner `test "..."` blocks invisible to
// the test runner — we'd see "1/1 generated fixtures...OK" instead of
// the full fixture count.
fn refAllDeclsRecursive(comptime T: type) void {
    if (!builtin.is_test) return;
    @setEvalBranchQuota(50_000);
    inline for (comptime std.meta.declarations(T)) |decl| {
        if (@TypeOf(@field(T, decl.name)) == type) {
            switch (@typeInfo(@field(T, decl.name))) {
                .@"struct", .@"enum", .@"union", .@"opaque" => refAllDeclsRecursive(@field(T, decl.name)),
                else => {},
            }
        }
        _ = &@field(T, decl.name);
    }
}

test "generated fixtures" {
    refAllDeclsRecursive(generated);
}
