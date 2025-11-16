const clockFactory = @import("./clock.zig");
pub const Clock = clockFactory.Clock;

const nodeFactory = @import("./node.zig");
pub const BeamNode = nodeFactory.BeamNode;

pub const fcFactory = @import("./forkchoice.zig");
pub const constants = @import("./constants.zig");

test "get tests" {
    _ = @import("./forkchoice.zig");
    _ = @import("./chain.zig");
    _ = @import("./utils.zig");
    @import("std").testing.refAllDeclsRecursive(@This());
}
