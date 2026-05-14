const std = @import("std");
const Allocator = std.mem.Allocator;

const xev = @import("xev").Dynamic;
const zeam_metrics = @import("@zeam/metrics");
const zeam_utils = @import("@zeam/utils");

const constants = @import("./constants.zig");

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;

const CLOCK_DISPARITY_MS: isize = 100;

/// Sentinel for `last_tick_time_ms_atomic` meaning "tickInterval has
/// not run yet". Real timestamps are unix-epoch milliseconds (positive
/// and large), so any negative value is unambiguous; using `minInt`
/// avoids any chance of collision with a clock-skew artifact.
const NEVER_TICKED_MS: i64 = std.math.minInt(i64);

pub const Clock = struct {
    genesis_time_ms: isize,
    current_interval_time_ms: isize,
    current_interval: isize,
    /// Wall-clock millis at the most recent `tickInterval()` call, or
    /// `NEVER_TICKED_MS` before the first tick. Read concurrently by
    /// `SlotDriverWatchdog` (#863) — kept atomic so the watchdog
    /// thread never observes a torn value. Writers must use
    /// `release` ordering, readers `acquire` (or `monotonic` when the
    /// reader doesn't need to synchronise with anything else the
    /// writer published).
    last_tick_time_ms_atomic: std.atomic.Value(i64),
    events: utils.EventLoop,
    // track those who subscribed for on slot callbacks
    on_interval_cbs: std.ArrayList(*OnIntervalCbWrapper),
    allocator: Allocator,

    timer: xev.Timer,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();

    pub fn format(self: Self, writer: anytype) !void {
        try writer.print("Clock{{ genesis_time_ms={d}, current_interval={d} }}", .{ self.genesis_time_ms, self.current_interval });
    }

    pub fn init(
        allocator: Allocator,
        genesis_time: usize,
        loop: *xev.Loop,
        logger_config: *const zeam_utils.ZeamLoggerConfig,
    ) !Self {
        const events = try utils.EventLoop.init(loop);
        const timer = try xev.Timer.init();

        const genesis_time_ms: isize = @intCast(genesis_time * std.time.ms_per_s);
        const current_interval = @divFloor(@as(isize, @intCast(zeam_utils.unixTimestampMillis())) + CLOCK_DISPARITY_MS - genesis_time_ms, constants.SECONDS_PER_INTERVAL_MS);
        const current_interval_time_ms = genesis_time_ms + current_interval * constants.SECONDS_PER_INTERVAL_MS;

        return Self{
            .genesis_time_ms = genesis_time_ms,
            .current_interval_time_ms = current_interval_time_ms,
            .current_interval = current_interval,
            .last_tick_time_ms_atomic = std.atomic.Value(i64).init(NEVER_TICKED_MS),
            .events = events,
            .timer = timer,
            .on_interval_cbs = .empty,
            .allocator = allocator,
            .logger = logger_config.logger(.clock),
        };
    }

    /// Snapshot of the most recent `tickInterval()` wall-clock time, or
    /// `null` if `tickInterval()` has not run yet. Single atomic
    /// `acquire` load — safe to call from any thread.
    pub fn lastTickMs(self: *const Self) ?i64 {
        const v = self.last_tick_time_ms_atomic.load(.acquire);
        return if (v == NEVER_TICKED_MS) null else v;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.timer.deinit();
        for (self.on_interval_cbs.items) |cbWrapper| {
            allocator.destroy(cbWrapper);
        }
        self.on_interval_cbs.deinit(allocator);
    }

    pub fn tickInterval(self: *Self) void {
        const time_now_ms: isize = @intCast(zeam_utils.unixTimestampMillis());
        // Single-writer (libxev thread); monotonic load is sufficient here
        // — we only race the watchdog reader, which uses acquire on its load.
        const last_atomic = self.last_tick_time_ms_atomic.load(.monotonic);
        if (last_atomic != NEVER_TICKED_MS) {
            const elapsed_s: f32 = @as(f32, @floatFromInt(time_now_ms - @as(isize, @intCast(last_atomic)))) / 1000.0;
            zeam_metrics.lean_tick_interval_duration_seconds.record(elapsed_s);
            self.logger.info("slot_interval={d} duration={d:.3}s", .{ @mod(self.current_interval, constants.INTERVALS_PER_SLOT), elapsed_s });
        }
        // Release ordering pairs with the watchdog's acquire load in
        // `lastTickMs`, ensuring any writes the libxev thread did before
        // the tick are visible to the watchdog when it observes the new
        // timestamp.
        self.last_tick_time_ms_atomic.store(@intCast(time_now_ms), .release);
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
                        r catch |err| {
                            // Canceled is expected when tickInterval re-arms a still-pending
                            // completion (the old fire arrives with Canceled).  Swallow it
                            // silently; the new timer is already scheduled.
                            if (err != error.Canceled) std.debug.panic("unexpected xev timer error: {}", .{err});
                            return .disarm;
                        };
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
            const drain_timer = zeam_metrics.zeam_xev_clock_until_done_drain_seconds.start();
            try self.events.run(.until_done);
            const drain_s = drain_timer.observe();
            if (drain_s >= 0.5) {
                zeam_metrics.metrics.zeam_xev_clock_until_done_slow_ge_500ms_total.incr();
            }
            if (drain_s >= 1.0) {
                zeam_metrics.metrics.zeam_xev_clock_until_done_slow_ge_1s_total.incr();
                self.logger.warn("xev until_done drain took {d:.3}s (slot driver backlog; see #863)", .{drain_s});
            }
        }
    }

    pub fn subscribeOnSlot(self: *Self, cb: *OnIntervalCbWrapper) !void {
        try self.on_interval_cbs.append(self.allocator, cb);
    }
};
