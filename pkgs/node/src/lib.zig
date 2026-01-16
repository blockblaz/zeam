const clockFactory = @import("./clock.zig");
pub const Clock = clockFactory.Clock;

const nodeFactory = @import("./node.zig");
pub const BeamNode = nodeFactory.BeamNode;

pub const chainFactory = @import("./chain.zig");
pub const fcFactory = @import("./forkchoice.zig");
pub const constants = @import("./constants.zig");
pub const utils = @import("./utils.zig");

const networks = @import("@zeam/network");
pub const NodeNameRegistry = networks.NodeNameRegistry;

test "get tests" {
    _ = @import("./forkchoice.zig");
    _ = @import("./chain.zig");
    _ = @import("./utils.zig");
    @import("std").testing.refAllDeclsRecursive(@This());
}
