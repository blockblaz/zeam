const std = @import("std");
const metrics_lib = @import("metrics");

/// Error types for the metrics system
pub const MetricsError = error{
    ServerAlreadyRunning,
    MetricsNotInitialized,
};

/// Returns true if the current target is a ZKVM environment.
/// This is used to disable metrics in contexts where they don't make sense.
pub fn isZKVM() bool {
    // Some ZKVMs might emulate linux, so this check might need to be updated.
    return @import("builtin").target.os.tag == .freestanding;
}

// Platform-specific time function
fn getTimestamp() i128 {
    // For freestanding targets, we might not have access to system time
    // In that case, we'll use a simple counter or return 0
    if (isZKVM()) {
        // For freestanding environments, we can't measure real time
        // Return 0 for now - in a real implementation you'd want a cycle counter
        return 0;
    } else {
        return std.time.nanoTimestamp();
    }
}

// Global metrics instance
// Note: Metrics are initialized as no-op by default. When init() is not called,
// or when called on ZKVM targets, all metric operations are no-ops automatically.
// This design eliminates the need for conditional checks in metric recording functions.
var metrics = metrics_lib.initializeNoop(Metrics);
var g_initialized: bool = false;

const Metrics = struct {
    chain_onblock_duration_seconds: ChainHistogram,
    block_processing_duration_seconds: BlockProcessingHistogram,
    lean_head_slot: LeanHeadSlotGauge,

    const ChainHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    const BlockProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    const LeanHeadSlotGauge = metrics_lib.Gauge(u64);
};

/// Timer struct returned to the application.
pub const Timer = struct {
    start_time: i128,
    histogram: *const anyopaque, // We'll store which histogram to use
    is_chain: bool,

    /// Stops the timer and records the duration in the histogram.
    pub fn observe(self: Timer) f32 {
        const end_time = getTimestamp();
        const duration_ns = end_time - self.start_time;

        // For freestanding targets where we can't measure time, just record 0
        const duration_seconds = if (duration_ns == 0) 0.0 else @as(f32, @floatFromInt(duration_ns)) / 1_000_000_000.0;

        if (self.is_chain) {
            metrics.chain_onblock_duration_seconds.observe(duration_seconds);
        } else {
            metrics.block_processing_duration_seconds.observe(duration_seconds);
        }

        return duration_seconds;
    }
};

/// A wrapper struct that exposes a `start` function to match the existing API.
pub const Histogram = struct {
    is_chain: bool,

    pub fn start(self: *const Histogram) Timer {
        return Timer{
            .start_time = getTimestamp(),
            .histogram = undefined, // Not used in this implementation
            .is_chain = self.is_chain,
        };
    }
};

/// The public variables the application interacts with.
/// Calling `.start()` on these will start a new timer.
pub var chain_onblock_duration_seconds: Histogram = Histogram{ .is_chain = true };
pub var block_processing_duration_seconds: Histogram = Histogram{ .is_chain = false };

/// Initializes the metrics system. Must be called once at startup.
pub fn init(allocator: std.mem.Allocator) !void {
    _ = allocator; // Not needed for basic histograms
    if (g_initialized) return;

    // For ZKVM targets, use no-op metrics
    if (isZKVM()) {
        std.log.info("Using no-op metrics for ZKVM target", .{});
        g_initialized = true;
        return;
    }

    metrics = .{
        .chain_onblock_duration_seconds = Metrics.ChainHistogram.init("chain_onblock_duration_seconds", .{ .help = "Time taken to process a block in the chain's onBlock function." }, .{}),
        .block_processing_duration_seconds = Metrics.BlockProcessingHistogram.init("block_processing_duration_seconds", .{ .help = "Time taken to process a block in the state transition function." }, .{}),
        .lean_head_slot = Metrics.LeanHeadSlotGauge.init("lean_head_slot", .{ .help = "Latest slot of the lean chain." }, .{}),
    };

    g_initialized = true;
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: anytype) !void {
    if (!g_initialized) return error.NotInitialized;

    // For ZKVM targets, write no metrics
    if (isZKVM()) {
        try writer.writeAll("# Metrics disabled for ZKVM target\n");
        return;
    }

    try metrics_lib.write(&metrics, writer);
}

// Routes module for setting up metrics endpoints
pub const routes = @import("./routes.zig");

// Event system modules
pub const events = @import("./events.zig");
pub const event_broadcaster = @import("./event_broadcaster.zig");

/// Sets the lean head slot metric.
/// This should be called whenever the fork choice head is updated.
/// Note: Automatically no-op if metrics are not initialized or running on ZKVM.
pub fn setLeanHeadSlot(slot: u64) void {
    metrics.lean_head_slot.set(slot);
}

// Compatibility functions for the old API
pub fn chain_onblock_duration_seconds_start() Timer {
    return chain_onblock_duration_seconds.start();
}
