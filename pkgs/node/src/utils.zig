const std = @import("std");

const xev = @import("xev").Dynamic;
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const Mutex = zeam_utils.SyncMutex;

/// Detect the best available I/O backend at runtime.
/// On Linux this probes io_uring, falling back to epoll (needed for Shadow).
/// On single-backend platforms (macOS/kqueue) this is a no-op.
pub fn detectBackend() !void {
    if (@hasDecl(xev, "detect")) {
        try xev.detect();
    }
}

pub const EventLoop = struct {
    loop: *xev.Loop,
    // events from libp2p or other threads will also be pushed on it
    mutex: Mutex,

    const Self = @This();
    pub fn init(loop: *xev.Loop) !Self {
        const mutex = Mutex{};

        return Self{
            .loop = loop,
            .mutex = mutex,
        };
    }

    pub fn denit(self: *Self) !void {
        self.loop.deinit();
    }

    pub fn run(self: *Self, optMode: ?xev.RunMode) !void {
        const mode = optMode orelse xev.RunMode.until_done;
        // clock event should keep rearming itself and never run out
        try self.loop.run(mode);
    }
};

const OnIntervalCbType = *const fn (ud: *anyopaque, slot: isize) anyerror!void;
pub const OnIntervalCbWrapper = struct {
    ptr: *anyopaque,
    onIntervalCb: OnIntervalCbType,
    interval: isize = 0,
    // Both completions MUST be value-initialized (not `undefined`): `Timer.reset`
    // in `Clock.tickInterval` reads `c.flags.state` to decide whether the timer
    // is still armed, and requires `c_cancel` to be a valid `.{}` completion.
    // Re-arming a still-pending timer with `Timer.run` (which blindly re-inserts
    // the completion's intrusive heap node) corrupts the libxev timer pairing
    // heap into a cycle — a 100% CPU spin in `Loop.tick`.
    c: xev.Completion = .{},
    c_cancel: xev.Completion = .{},

    pub fn onInterval(self: OnIntervalCbWrapper) !void {
        return self.onIntervalCb(self.ptr, self.interval);
    }
};

pub fn computeSubnetId(validator_id: types.ValidatorIndex, committee_count: types.SubnetId) error{InvalidCommitteeCount}!types.SubnetId {
    return types.computeSubnetId(validator_id, committee_count);
}
