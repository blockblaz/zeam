//! Slot-driver stall watchdog (#863).
//!
//! Spawns a background OS thread that probes `Clock.last_tick_time_ms` at
//! a fixed interval. When the gap between wall clock and the last tick
//! exceeds `WATCHDOG_THRESHOLD_MS`, the watchdog:
//!
//!   * Logs an ERROR with the stall duration.
//!   * Bumps `zeam_slot_driver_stall_fired_total` and records the stall
//!     duration into `zeam_slot_driver_stall_seconds`.
//!
//! The watchdog is independent of libxev / chain-worker. Even if both
//! main loops are wedged inside a single completion or syscall, this
//! thread keeps running and surfaces the stall via logs + Prometheus.
//!
//! Per-thread stack dumps are intentionally NOT included in this PR.
//! Zig's signal-handler API is in flux on the 0.16 branch and a robust
//! cross-target implementation is best landed as a follow-up once the
//! stall metric tells us we even need it on a given deployment.
//!
//! Lifecycle:
//!   - `SlotDriverWatchdog.init(...)` constructs (does not spawn).
//!   - `start()` spawns the OS thread.
//!   - `stop()` flips the stop flag and joins.
//!
//! Safe to skip start() entirely — the watchdog is purely diagnostic.

const std = @import("std");
const Thread = std.Thread;

const zeam_metrics = @import("@zeam/metrics");
const zeam_utils = @import("@zeam/utils");

const Clock = @import("./clock.zig").Clock;

/// Probe interval. Cheap (atomic load + wall-clock read), so a tight
/// cadence keeps the detection latency low without burning measurable
/// CPU.
pub const DEFAULT_PROBE_MS: u64 = 1000;

/// Threshold above which the watchdog declares a stall. Picked so a
/// single nominal slot interval (~800ms) plus normal jitter does not
/// trip it; multi-second stalls (the #863 symptom) do.
pub const DEFAULT_THRESHOLD_MS: u64 = 5000;

/// Hysteresis: after firing, suppress further firings until the slot
/// driver ticks again at least once. Otherwise a single 600s freeze
/// would log every probe-interval for the entire freeze duration.
const SUPPRESS_REFIRE: bool = true;

pub const SlotDriverWatchdog = struct {
    clock: *Clock,
    logger: zeam_utils.ModuleLogger,
    probe_ms: u64,
    threshold_ms: u64,
    stop_flag: std.atomic.Value(bool),
    thread: ?Thread,

    pub const Options = struct {
        probe_ms: u64 = DEFAULT_PROBE_MS,
        threshold_ms: u64 = DEFAULT_THRESHOLD_MS,
    };

    pub fn init(
        clock: *Clock,
        logger: zeam_utils.ModuleLogger,
        opts: Options,
    ) SlotDriverWatchdog {
        return .{
            .clock = clock,
            .logger = logger,
            .probe_ms = opts.probe_ms,
            .threshold_ms = opts.threshold_ms,
            .stop_flag = std.atomic.Value(bool).init(false),
            .thread = null,
        };
    }

    pub fn start(self: *SlotDriverWatchdog) !void {
        if (self.thread != null) return error.AlreadyRunning;
        self.thread = try Thread.spawn(.{}, runLoop, .{self});
    }

    pub fn stop(self: *SlotDriverWatchdog) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Sleep helper. Zig 0.16 dropped `std.Thread.sleep`; mirror
    /// `pkgs/node/src/stress.zig::sleepSecs` and use libc nanosleep
    /// directly so this watchdog stays cross-target without a libxev
    /// timer (which would itself depend on the loop we are watching).
    fn sleepMs(ms: u64) void {
        const total_ns: u128 = @as(u128, ms) * @as(u128, std.time.ns_per_ms);
        var ts: std.c.timespec = .{
            .sec = @intCast(@divFloor(total_ns, std.time.ns_per_s)),
            .nsec = @intCast(@mod(total_ns, std.time.ns_per_s)),
        };
        _ = std.c.nanosleep(&ts, &ts);
    }

    fn runLoop(self: *SlotDriverWatchdog) void {
        var last_observed_tick_ms: ?isize = null;
        var firing_for_current_stall = false;

        while (!self.stop_flag.load(.acquire)) {
            sleepMs(self.probe_ms);
            if (self.stop_flag.load(.acquire)) break;

            // `last_tick_time_ms` is mutated unsynchronised on the libxev
            // thread. We accept torn reads on 32-bit platforms — the worst
            // case is a transient spurious "stall" log, which is harmless
            // for diagnostic instrumentation.
            const last_tick_opt = self.clock.last_tick_time_ms;
            const last_tick = last_tick_opt orelse continue;

            const now_ms: isize = @intCast(zeam_utils.unixTimestampMillis());
            const delta_ms: isize = now_ms - last_tick;
            if (delta_ms < 0) continue; // clock skew — skip probe

            // Reset the per-stall firing latch when the slot driver has
            // ticked since our last fire, so a subsequent stall fires
            // again.
            if (SUPPRESS_REFIRE and firing_for_current_stall) {
                if (last_observed_tick_ms == null or last_tick != last_observed_tick_ms.?) {
                    firing_for_current_stall = false;
                }
            }
            last_observed_tick_ms = last_tick;

            if (@as(u64, @intCast(delta_ms)) < self.threshold_ms) continue;
            if (SUPPRESS_REFIRE and firing_for_current_stall) continue;

            const stall_s: f32 = @as(f32, @floatFromInt(delta_ms)) / 1000.0;
            zeam_metrics.metrics.zeam_slot_driver_stall_fired_total.incr();
            zeam_metrics.metrics.zeam_slot_driver_stall_seconds.observe(stall_s);
            self.logger.err(
                "slot-driver stall detected: last tick {d:.3}s ago (threshold={d}ms). See #863.",
                .{ stall_s, self.threshold_ms },
            );
            firing_for_current_stall = true;
        }
    }
};
