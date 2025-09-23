const std = @import("std");
const metrics = @import("@zeam/metrics");

/// Simple metrics server that runs in a background thread
pub fn startMetricsServer(allocator: std.mem.Allocator, port: u16) !void {
    // Create a simple HTTP server context
    const ctx = try allocator.create(SimpleMetricsServer);
    errdefer allocator.destroy(ctx);
    ctx.* = .{
        .allocator = allocator,
        .port = port,
    };

    // Start server in background thread
    const thread = try std.Thread.spawn(.{}, SimpleMetricsServer.run, .{ctx});
    thread.detach();

    std.log.info("Metrics server started on port {d}", .{port});
}

/// Simple metrics server context
const SimpleMetricsServer = struct {
    allocator: std.mem.Allocator,
    port: u16,

    fn run(self: *SimpleMetricsServer) !void {
        // `startMetricsServer` creates this, so we need to free it here
        defer self.allocator.destroy(self);
        const address = try std.net.Address.parseIp4("0.0.0.0", self.port);
        var server = try address.listen(.{ .reuse_address = true });
        defer server.deinit();

        std.log.info("HTTP server listening on http://0.0.0.0:{d}", .{self.port});

        while (true) {
            const connection = server.accept() catch continue;
            defer connection.stream.close();

            // Handle HTTP request
            var buffer: [4096]u8 = undefined;
            var http_server = std.http.Server.init(connection, &buffer);
            var request = http_server.receiveHead() catch continue;

            // Route handling
            if (std.mem.eql(u8, request.head.target, "/metrics")) {
                try self.handleMetrics(&request);
            } else if (std.mem.eql(u8, request.head.target, "/health")) {
                try self.handleHealth(&request);
            } else {
                _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
            }
        }
    }

    fn handleMetrics(self: *SimpleMetricsServer, request: *std.http.Server.Request) !void {
        var metrics_output = std.ArrayList(u8).init(self.allocator);
        defer metrics_output.deinit();

        metrics.writeMetrics(metrics_output.writer()) catch {
            _ = request.respond("Internal Server Error\n", .{}) catch {};
            return;
        };

        _ = request.respond(metrics_output.items, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain; version=0.0.4; charset=utf-8" },
            },
        }) catch {};
    }

    fn handleHealth(self: *SimpleMetricsServer, request: *std.http.Server.Request) !void {
        _ = self; // Use self to avoid unused parameter warning
        const response = "{\"status\":\"healthy\",\"service\":\"zeam-metrics\"}";
        _ = request.respond(response, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
    }
};
