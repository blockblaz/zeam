const std = @import("std");

pub const forks = @import("./fork.zig");
pub const state_transition_runner = @import("./runner/state_transition_runner.zig");
pub const fork_choice_runner = @import("./runner/fork_choice_runner.zig");
pub const ssz_runner = @import("./runner/ssz_runner.zig");
pub const justifiability_runner = @import("./runner/justifiability_runner.zig");
pub const verify_signatures_runner = @import("./runner/verify_signatures_runner.zig");
pub const slot_clock_runner = @import("./runner/slot_clock_runner.zig");
pub const api_endpoint_runner = @import("./runner/api_endpoint_runner.zig");
pub const skip = @import("./skip.zig");
pub const generated = @import("./generated/index.zig");

test "generated fixtures" {
    std.testing.refAllDeclsRecursive(generated);
}
