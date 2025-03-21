const std = @import("std");
const xev = @import("xev");

const params = @import("zeam-params");
const SECONDS_PER_SLOT = params.SECONDS_PER_SLOT;

const utils = @import("./utils.zig");

pub const Clock = struct {
    genesis_time: usize,
    events: utils.EventLoop,

    timer: xev.Timer,
    c: xev.Completion,

    const Self = @This();

    pub fn init(
        genesis_time: usize,
    ) !Self {
        const events = try utils.EventLoop.init();
        const timer = try xev.Timer.init();
        const c: xev.Completion = undefined;

        return Self{
            .genesis_time = genesis_time,
            .events = events,
            .timer = timer,
            .c = c,
        };
    }

    pub fn start(self: *Self) void {
        self.timer.run(&self.events.loop, &self.c, 1000, void, null, timerCallback);
    }

    pub fn run(self: *Self) !void {
        while (true) {
            try self.events.run(.until_done);
            self.start();
        }
    }
};

fn timerCallback(
    _: ?*void,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Timer.RunError!void,
) xev.CallbackAction {
    _ = result catch unreachable;
    return .disarm;
}
