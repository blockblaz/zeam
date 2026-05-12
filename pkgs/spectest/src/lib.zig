const std = @import("std");

pub const forks = @import("./fork.zig");
pub const state_transition_runner = @import("./runner/state_transition_runner.zig");
pub const fork_choice_runner = @import("./runner/fork_choice_runner.zig");
pub const skip = @import("./skip.zig");
pub const generated = @import("./generated/index.zig");

/// Bench-facing surface — only the fixture-loading helpers, not the
/// verification glue. See bench/stf_bench.zig.
pub const fixtures = struct {
    pub const Context = state_transition_runner.Context;
    pub const buildState = state_transition_runner.buildState;
    pub const buildBlock = state_transition_runner.buildBlock;
    pub const decodeBlock = state_transition_runner.decodeBlock;
    pub const loadFixturePayload = state_transition_runner.loadFixturePayload;
    pub const runFixturePayload = state_transition_runner.runFixturePayload;
};

test "generated fixtures" {
    std.testing.refAllDecls(generated);
}
