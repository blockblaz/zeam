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
    /// `SlotDriverWatchdog` — kept atomic so the watchdog
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

    /// Host wall-clock slot derived directly from `unixTimestampMillis()` and
    /// `genesis_time_ms`, independent of the libxev tick / forkchoice
    /// `slot_clock.timeSlots` counter.
    ///
    /// Use this when sync-gating decisions must remain correct even while
    /// the libxev slot driver is stalled or forkchoice ticks are blocked
    /// behind a long-running mutator. Reading `slot_clock.timeSlots`
    /// in those decisions self-reinforces stalls: a starved counter caps
    /// the sync gap to zero, catch-up is skipped, the node stays stuck.
    ///
    /// Returns 0 when wall clock is at or before genesis.
    pub fn wallSlotNow(self: *const Self) u64 {
        const now_ms: isize = @intCast(zeam_utils.unixTimestampMillis());
        const slot_ms: u64 = @intCast(constants.SECONDS_PER_INTERVAL_MS * constants.INTERVALS_PER_SLOT);
        return wallSlotNowImpl(now_ms, self.genesis_time_ms, slot_ms);
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
        // Bound each xev drain pass to one io_uring CQE batch via
        // `.once` rather than `.until_done`.
        //
        // The earlier shape called `events.run(.until_done)` per pass,
        // which loops until `loop.active == 0`. Under sustained gossip
        // pressure (especially on a 4-subnet aggregator that sees 4×
        // attestation traffic, with ~74% of those attestations referring
        // to head blocks the node hadn't imported yet — see the issue
        // for the full trace), every callback enqueues additional work
        // (chain submits, peer-event broadcasts, RPC retries) so the
        // active-completion count never reaches zero and `tickInterval`
        // doesn't run again until the storm subsides. We observed
        // multi-second slot-driver stalls and ~96 finalized vs ~196 head
        // delta on the aggregator as a direct consequence.
        //
        // `.once` blocks until at least one completion is ready, then
        // drains every CQE the kernel returns in that syscall batch (up
        // to 128 per the io_uring backend) before returning. The next-interval
        // timer is itself a completion, so under no-flood conditions
        // we still wake every ~800ms and call `tickInterval` exactly
        // once per interval — the steady-state behaviour is unchanged.
        // Under flood the loop returns to the body of this function
        // after each batch; we re-tick `tickInterval` only when wall
        // clock has actually crossed the next interval boundary so
        // the per-tick log line and `lean_tick_interval_duration_seconds`
        // histogram retain their interval-cadence semantics (and don't
        // get spammed at the CQE-batch rate).
        //
        // The existing `zeam_xev_clock_until_done_drain_seconds`
        // histogram is repurposed: each pass is now bounded by one
        // batch, so values are expected to drop sharply (sub-ms median
        // under steady load). The two slow-drain counters
        // (>=500ms / >=1s) now flag pathologically large single CQE
        // batches rather than unbounded drain queues — still a useful
        // signal but rarely fires now. `zeam_xev_clock_drain_passes_total`
        // is the new pass-rate liveness counter.

        // Bootstrap: register the first interval timer so `.once` has
        // something to wait on. Subscribers must have called
        // `subscribeOnSlot` before `run`; if none did, `.once` would
        // block forever (which is the same observable behaviour the
        // pre-P4 `.until_done` loop produced — the busy-while exited
        // each pass with `loop.active == 0`).
        self.tickInterval();
        while (true) {
            const drain_timer = zeam_metrics.zeam_xev_clock_until_done_drain_seconds.start();
            try self.events.run(.once);
            zeam_metrics.metrics.zeam_xev_clock_drain_passes_total.incr();
            const drain_s = drain_timer.observe();
            if (drain_s >= 0.5) {
                zeam_metrics.metrics.zeam_xev_clock_until_done_slow_ge_500ms_total.incr();
            }
            if (drain_s >= 1.0) {
                zeam_metrics.metrics.zeam_xev_clock_until_done_slow_ge_1s_total.incr();
                self.logger.warn("xev .once drain batch took {d:.3}s (slot driver backlog; see #863)", .{drain_s});
            }

            // Only re-tick when wall clock has reached the next interval
            // boundary — **without** `CLOCK_DISPARITY_MS` slack on this
            // outer trigger. The inner `tickInterval` while-loop still
            // applies disparity for multi-interval catch-up once we enter
            // `tickInterval`. Using `+ CLOCK_DISPARITY_MS` here matched the
            // inner inequality and could fire a full `tickInterval()` up to
            // ~`CLOCK_DISPARITY_MS` early while the interval timer was still
            // legitimately pending; `tickInterval` then re-armed/canceled that
            // timer and the canceled completion does not run `onInterval`,
            // so gossip-heavy `.once` batches could skip slot duties.
            const time_now_ms: isize = @intCast(zeam_utils.unixTimestampMillis());
            if (self.current_interval_time_ms + constants.SECONDS_PER_INTERVAL_MS <= time_now_ms) {
                self.tickInterval();
            }
        }
    }

    pub fn subscribeOnSlot(self: *Self, cb: *OnIntervalCbWrapper) !void {
        try self.on_interval_cbs.append(self.allocator, cb);
    }
};

// Pure helper extracted for unit testing. `Clock.wallSlotNow` is just this
// function applied to live `unixTimestampMillis()` and the clock's stored
// `genesis_time_ms`; tests exercise the math here without spinning up xev.
fn wallSlotNowImpl(now_ms: isize, genesis_time_ms: isize, slot_ms: u64) u64 {
    if (now_ms <= genesis_time_ms) return 0;
    if (slot_ms == 0) return 0;
    const elapsed_ms: u64 = @intCast(now_ms - genesis_time_ms);
    return elapsed_ms / slot_ms;
}

test "wallSlotNowImpl returns 0 before/at genesis" {
    const slot_ms: u64 = @intCast(constants.SECONDS_PER_INTERVAL_MS * constants.INTERVALS_PER_SLOT);
    try std.testing.expectEqual(@as(u64, 0), wallSlotNowImpl(1000, 5000, slot_ms));
    try std.testing.expectEqual(@as(u64, 0), wallSlotNowImpl(5000, 5000, slot_ms));
}

test "wallSlotNowImpl advances independently of any tick counter" {
    const slot_ms: u64 = @intCast(constants.SECONDS_PER_INTERVAL_MS * constants.INTERVALS_PER_SLOT);
    // 31 slots after genesis, regardless of whether libxev has ticked even once.
    const now_ms: isize = @as(isize, 0) + @as(isize, @intCast(slot_ms)) * 31 + @as(isize, 200);
    try std.testing.expectEqual(@as(u64, 31), wallSlotNowImpl(now_ms, 0, slot_ms));
}

test "wallSlotNowImpl handles zero slot_ms defensively" {
    try std.testing.expectEqual(@as(u64, 0), wallSlotNowImpl(123_000, 0, 0));
}
