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
// Public so that callers can directly access and record metrics without wrapper functions.
pub var metrics = metrics_lib.initializeNoop(Metrics);
var g_initialized: bool = false;

const Metrics = struct {
    chain_onblock_duration_seconds: ChainHistogram,
    block_processing_duration_seconds: BlockProcessingHistogram,
    lean_head_slot: LeanHeadSlotGauge,
    lean_latest_justified_slot: LeanLatestJustifiedSlotGauge,
    lean_latest_finalized_slot: LeanLatestFinalizedSlotGauge,
    lean_state_transition_time_seconds: StateTransitionHistogram,
    lean_state_transition_slots_processed_total: SlotsProcessedCounter,
    lean_state_transition_slots_processing_time_seconds: SlotsProcessingHistogram,
    lean_state_transition_block_processing_time_seconds: BlockProcessingTimeHistogram,
    lean_state_transition_attestations_processed_total: AttestationsProcessedCounter,
    lean_state_transition_attestations_processing_time_seconds: AttestationsProcessingHistogram,

    const ChainHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    const BlockProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    const StateTransitionHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4 });
    const SlotsProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const BlockProcessingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const AttestationsProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const LeanHeadSlotGauge = metrics_lib.Gauge(u64);
    const LeanLatestJustifiedSlotGauge = metrics_lib.Gauge(u64);
    const LeanLatestFinalizedSlotGauge = metrics_lib.Gauge(u64);
    const SlotsProcessedCounter = metrics_lib.Counter(u64);
    const AttestationsProcessedCounter = metrics_lib.Counter(u64);
};

/// Timer struct returned to the application.
/// Uses a function pointer to record to the appropriate histogram via type erasure.
pub const Timer = struct {
    start_time: i128,
    context: *anyopaque,
    observeFn: *const fn (*anyopaque, f32) void,

    /// Stops the timer and records the duration in the histogram.
    pub fn observe(self: Timer) f32 {
        const end_time = getTimestamp();
        const duration_ns = end_time - self.start_time;

        // For freestanding targets where we can't measure time, just record 0
        const duration_seconds = if (duration_ns == 0) 0.0 else @as(f32, @floatFromInt(duration_ns)) / 1_000_000_000.0;

        self.observeFn(self.context, duration_seconds);

        return duration_seconds;
    }
};

/// A wrapper struct that exposes a `start` function to match the existing API.
pub const Histogram = struct {
    context: *anyopaque,
    observeFn: *const fn (*anyopaque, f32) void,

    pub fn start(self: *const Histogram) Timer {
        return Timer{
            .start_time = getTimestamp(),
            .context = self.context,
            .observeFn = self.observeFn,
        };
    }
};

// Type-erased observe functions for each histogram type
fn observeChainOnblock(ctx: *anyopaque, value: f32) void {
    const histogram: *Metrics.ChainHistogram = @ptrCast(@alignCast(ctx));
    histogram.observe(value);
}

fn observeBlockProcessing(ctx: *anyopaque, value: f32) void {
    const histogram: *Metrics.BlockProcessingHistogram = @ptrCast(@alignCast(ctx));
    histogram.observe(value);
}

fn observeStateTransition(ctx: *anyopaque, value: f32) void {
    const histogram: *Metrics.StateTransitionHistogram = @ptrCast(@alignCast(ctx));
    histogram.observe(value);
}

// No-op observe function for when metrics are not initialized
fn observeNoop(ctx: *anyopaque, value: f32) void {
    _ = ctx;
    _ = value;
}

/// The public variables the application interacts with.
/// Calling `.start()` on these will start a new timer.
/// Initialized with no-op defaults; properly initialized in init() after the metrics are created.
/// This allows them to be used safely even if init() is never called (e.g., in tests).
pub var chain_onblock_duration_seconds: Histogram = .{
    .context = undefined,
    .observeFn = &observeNoop,
};
pub var block_processing_duration_seconds: Histogram = .{
    .context = undefined,
    .observeFn = &observeNoop,
};

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
        .lean_latest_justified_slot = Metrics.LeanLatestJustifiedSlotGauge.init("lean_latest_justified_slot", .{ .help = "Latest justified slot." }, .{}),
        .lean_latest_finalized_slot = Metrics.LeanLatestFinalizedSlotGauge.init("lean_latest_finalized_slot", .{ .help = "Latest finalized slot." }, .{}),
        .lean_state_transition_time_seconds = Metrics.StateTransitionHistogram.init("lean_state_transition_time_seconds", .{ .help = "Time to process state transition." }, .{}),
        .lean_state_transition_slots_processed_total = Metrics.SlotsProcessedCounter.init("lean_state_transition_slots_processed_total", .{ .help = "Total number of processed slots." }, .{}),
        .lean_state_transition_slots_processing_time_seconds = Metrics.SlotsProcessingHistogram.init("lean_state_transition_slots_processing_time_seconds", .{ .help = "Time taken to process slots." }, .{}),
        .lean_state_transition_block_processing_time_seconds = Metrics.BlockProcessingTimeHistogram.init("lean_state_transition_block_processing_time_seconds", .{ .help = "Time taken to process block." }, .{}),
        .lean_state_transition_attestations_processed_total = Metrics.AttestationsProcessedCounter.init("lean_state_transition_attestations_processed_total", .{ .help = "Total number of processed attestations." }, .{}),
        .lean_state_transition_attestations_processing_time_seconds = Metrics.AttestationsProcessingHistogram.init("lean_state_transition_attestations_processing_time_seconds", .{ .help = "Time taken to process attestations." }, .{}),
    };

    // Initialize histogram wrappers with pointers to the actual metrics
    chain_onblock_duration_seconds = Histogram{
        .context = @ptrCast(&metrics.chain_onblock_duration_seconds),
        .observeFn = &observeChainOnblock,
    };
    block_processing_duration_seconds = Histogram{
        .context = @ptrCast(&metrics.block_processing_duration_seconds),
        .observeFn = &observeBlockProcessing,
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
