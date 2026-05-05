const clockFactory = @import("./clock.zig");
pub const Clock = clockFactory.Clock;

const nodeFactory = @import("./node.zig");
pub const BeamNode = nodeFactory.BeamNode;

const chainFactory = @import("./chain.zig");
pub const BeamChain = chainFactory.BeamChain;

pub const fcFactory = @import("./forkchoice.zig");
pub const tree_visualizer = @import("./tree_visualizer.zig");
pub const constants = @import("./constants.zig");
pub const utils = @import("./utils.zig");
pub const detectBackend = utils.detectBackend;

pub const locking = @import("./locking.zig");
pub const BorrowedState = locking.BorrowedState;
pub const LockedMap = locking.LockedMap;
pub const BlockCache = locking.BlockCache;

pub const chain_worker = @import("./chain_worker.zig");
pub const ChainWorker = chain_worker.ChainWorker;
pub const ChainWorkerMessage = chain_worker.Message;

const networks = @import("@zeam/network");
pub const NodeNameRegistry = networks.NodeNameRegistry;

test "get tests" {
    _ = @import("./forkchoice.zig");
    _ = @import("./chain.zig");
    _ = @import("./utils.zig");
    _ = @import("./locking.zig");
    _ = @import("./chain_worker.zig");
    @import("std").testing.refAllDecls(@This());
}
