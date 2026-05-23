const clockFactory = @import("./clock.zig");
pub const Clock = clockFactory.Clock;

pub const slot_driver_watchdog = @import("./slot_driver_watchdog.zig");
pub const SlotDriverWatchdog = slot_driver_watchdog.SlotDriverWatchdog;

const nodeFactory = @import("./node.zig");
pub const BeamNode = nodeFactory.BeamNode;

const chainFactory = @import("./chain.zig");
pub const BeamChain = chainFactory.BeamChain;

pub const fcFactory = @import("./forkchoice.zig");
pub const testing = @import("./testing.zig");
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

pub const rc_beam_state = @import("./rc_beam_state.zig");
pub const RcBeamState = rc_beam_state.RcBeamState;

const networks = @import("@zeam/network");
pub const NodeNameRegistry = networks.NodeNameRegistry;

test "get tests" {
    _ = @import("./blocks_by_range_sync.zig");
    _ = @import("./forkchoice.zig");
    _ = @import("./chain.zig");
    _ = @import("./utils.zig");
    _ = @import("./locking.zig");
    _ = @import("./chain_worker.zig");
    _ = @import("./rc_beam_state.zig");
    _ = @import("./slot_driver_watchdog.zig");
    @import("std").testing.refAllDecls(@This());
}
