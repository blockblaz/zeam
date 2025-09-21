const std = @import("std");
const Allocator = std.mem.Allocator;

const xev = @import("xev");

const constants = @import("./constants.zig");

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;

const CLOCK_DISPARITY_MS: isize = 100;

pub const Clock = struct {
    genesis_time_ms: isize,
    current_interval_time_ms: isize,
    current_interval: isize,
    events: utils.EventLoop,
    // track those who subscribed for on slot callbacks
    on_interval_cbs: std.ArrayList(*OnIntervalCbWrapper),

    timer: xev.Timer,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        genesis_time: usize,
        loop: *xev.Loop,
    ) !Self {
        const events = try utils.EventLoop.init(loop);
        const timer = try xev.Timer.init();

        const genesis_time_ms: isize = @intCast(genesis_time * std.time.ms_per_s);
        const current_interval = @divFloor(@as(isize, @intCast(std.time.milliTimestamp())) + CLOCK_DISPARITY_MS - genesis_time_ms, constants.SECONDS_PER_INTERVAL_MS);
        const current_interval_time_ms = genesis_time_ms + current_interval * constants.SECONDS_PER_INTERVAL_MS;

        return Self{
            .genesis_time_ms = genesis_time_ms,
            .current_interval_time_ms = current_interval_time_ms,
            .current_interval = current_interval,
            .events = events,
            .timer = timer,
            .on_interval_cbs = std.ArrayList(*OnIntervalCbWrapper).init(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.timer.deinit();
        for (self.on_interval_cbs.items) |cbWrapper| {
            allocator.destroy(cbWrapper);
        }
        self.on_interval_cbs.deinit();
    }

    pub fn tickInterval(self: *Self) void {
        const time_now_ms: isize = @intCast(std.time.milliTimestamp());
        while (self.current_interval_time_ms + constants.SECONDS_PER_INTERVAL_MS < time_now_ms + CLOCK_DISPARITY_MS) {
            self.current_interval_time_ms += constants.SECONDS_PER_INTERVAL_MS;
            self.current_interval += 1;
        }

        const next_interval_time_ms: isize = self.current_interval_time_ms + constants.SECONDS_PER_INTERVAL_MS;
        const time_to_next_interval_ms: usize = @intCast(next_interval_time_ms - time_now_ms);

        for (0..self.on_interval_cbs.items.len) |i| {
            const cbWrapper = self.on_interval_cbs.items[i];
            cbWrapper.interval = self.current_interval + 1;

            self.timer.run(
                self.events.loop,
                &cbWrapper.c,
                time_to_next_interval_ms,
                OnIntervalCbWrapper,
                cbWrapper,
                (struct {
                    fn callback(
                        ud: ?*OnIntervalCbWrapper,
                        _: *xev.Loop,
                        _: *xev.Completion,
                        r: xev.Timer.RunError!void,
                    ) xev.CallbackAction {
                        _ = r catch unreachable;
                        if (ud) |cb_wrapper| {
                            _ = cb_wrapper.onInterval() catch void;
                        }
                        return .disarm;
                    }
                }).callback,
            );
        }
    }

    pub fn run(self: *Self) !void {
        while (true) {
            self.tickInterval();
            try self.events.run(.until_done);
        }
    }

    pub fn subscribeOnSlot(self: *Self, cb: *OnIntervalCbWrapper) !void {
        try self.on_interval_cbs.append(cb);
    }
};
