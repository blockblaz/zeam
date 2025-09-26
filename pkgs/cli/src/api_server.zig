const std = @import("std");
const api = @import("@zeam/api");
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;

/// Simple metrics server that runs in a background thread
pub fn startAPIServer(allocator: std.mem.Allocator, port: u16) !void {
    // Initialize the global event broadcaster
    try event_broadcaster.initGlobalBroadcaster(allocator);

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

/// Handle individual HTTP connections in a separate thread
fn handleConnection(connection: std.net.Server.Connection, allocator: std.mem.Allocator) void {
    defer connection.stream.close();

    var buffer: [4096]u8 = undefined;
    var http_server = std.http.Server.init(connection, &buffer);
    var request = http_server.receiveHead() catch |err| {
        std.log.warn("Failed to receive HTTP head: {}", .{err});
        return;
    };

    // Route handling
    if (std.mem.eql(u8, request.head.target, "/events")) {
        // Handle SSE connection - this will keep the connection alive
        SimpleMetricsServer.handleSSEEvents(connection.stream, allocator) catch |err| {
            std.log.warn("SSE connection failed: {}", .{err});
        };
    } else if (std.mem.eql(u8, request.head.target, "/metrics")) {
        // Handle metrics request
        var metrics_output = std.ArrayList(u8).init(allocator);
        defer metrics_output.deinit();

        api.writeMetrics(metrics_output.writer()) catch {
            _ = request.respond("Internal Server Error\n", .{}) catch {};
            return;
        };

        _ = request.respond(metrics_output.items, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain; version=0.0.4; charset=utf-8" },
            },
        }) catch {};
    } else if (std.mem.eql(u8, request.head.target, "/health")) {
        // Handle health check
        const response = "{\"status\":\"healthy\",\"service\":\"zeam-metrics\"}";
        _ = request.respond(response, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
    } else {
        _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
    }
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

            // For SSE connections, we need to handle them differently
            // We'll spawn a new thread for each connection to handle persistence
            _ = std.Thread.spawn(.{}, handleConnection, .{ connection, self.allocator }) catch |err| {
                std.log.warn("Failed to spawn connection handler: {}", .{err});
                connection.stream.close();
                continue;
            };
        }
    }

    fn handleSSEEvents(stream: std.net.Stream, allocator: std.mem.Allocator) !void {
        _ = allocator;
        // Set SSE headers manually by writing HTTP response
        const sse_headers = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/event-stream\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Access-Control-Allow-Origin: *\r\n" ++
            "Access-Control-Allow-Headers: Cache-Control\r\n" ++
            "\r\n";

        // Send initial response with SSE headers
        try stream.writeAll(sse_headers);

        // Send initial connection event
        const connection_event = "event: connection\ndata: {\"status\":\"connected\"}\n\n";
        try stream.writeAll(connection_event);

        // Register this connection with the global event broadcaster
        try event_broadcaster.addGlobalConnection(stream);

        // Keep the connection alive - the broadcaster will handle event streaming
        // This thread will stay alive as long as the connection is active
        while (true) {
            // Send periodic heartbeat to keep connection alive
            const heartbeat = ": heartbeat\n\n";
            stream.writeAll(heartbeat) catch |err| {
                std.log.warn("SSE connection closed: {}", .{err});
                break;
            };

            // Wait between SSE heartbeats
            std.time.sleep(constants.SSE_HEARTBEAT_SECONDS * std.time.ns_per_s);
        }
    }
};
