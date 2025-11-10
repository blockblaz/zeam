const std = @import("std");

pub const forks = @import("./fork.zig");
pub const state_transition_runner = @import("./state_transition_runner.zig");
pub const fork_choice_runner = @import("./fork_choice_runner.zig");
pub const generated = @import("./generated/index.zig");

test "generated fixtures" {
    std.testing.refAllDeclsRecursive(generated);
}
