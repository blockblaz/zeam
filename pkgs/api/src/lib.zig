const std = @import("std");
const zeam_metrics = @import("@zeam/metrics");

/// Error types for the metrics system
pub const MetricsError = error{
    ServerAlreadyRunning,
    MetricsNotInitialized,
};

/// Initializes the metrics system. Must be called once at startup.
pub fn init(allocator: std.mem.Allocator) !void {
    try zeam_metrics.init(allocator);
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: *std.Io.Writer) !void {
    try zeam_metrics.writeMetrics(writer);
}

// Routes module for setting up metrics endpoints
pub const routes = @import("./routes.zig");

// Event system modules
pub const events = @import("./events.zig");
pub const event_broadcaster = @import("./event_broadcaster.zig");

test "get tests" {
    @import("std").testing.refAllDeclsRecursive(@This());
}
