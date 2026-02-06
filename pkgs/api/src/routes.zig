const std = @import("std");
const metrics = @import("./lib.zig");

/// Metrics route handler for /metrics endpoint
pub fn metricsHandler(allocator: std.mem.Allocator, request: *std.http.Server.Request) !void {
    var metrics_output = std.Io.Writer.Allocating.init(allocator);
    defer metrics_output.deinit();

    metrics.writeMetrics(&metrics_output.writer) catch {
        _ = request.respond("Internal Server Error\n", .{}) catch {};
        return;
    };

    _ = request.respond(metrics_output.written(), .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "text/plain; version=0.0.4; charset=utf-8" },
        },
    }) catch {};
}
