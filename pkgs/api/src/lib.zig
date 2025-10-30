const std = @import("std");
const zeam_metrics = @import("@zeam/metrics");

/// Error types for the metrics system
pub const MetricsError = error{
    ServerAlreadyRunning,
    MetricsNotInitialized,
};

pub const metrics = zeam_metrics.metrics;
pub const Timer = zeam_metrics.Timer;
pub const Histogram = zeam_metrics.Histogram;
pub const isZKVM = zeam_metrics.isZKVM;

pub const chain_onblock_duration_seconds = &zeam_metrics.chain_onblock_duration_seconds;
pub const block_processing_duration_seconds = &zeam_metrics.block_processing_duration_seconds;

/// Initializes the metrics system. Must be called once at startup.
pub fn init(allocator: std.mem.Allocator) !void {
    try zeam_metrics.init(allocator);
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: anytype) !void {
    try zeam_metrics.writeMetrics(writer);
}

// Routes module for setting up metrics endpoints
pub const routes = @import("./routes.zig");

// Event system modules
pub const events = @import("./events.zig");
pub const event_broadcaster = @import("./event_broadcaster.zig");
