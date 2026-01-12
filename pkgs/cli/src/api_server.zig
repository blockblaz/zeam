const std = @import("std");
const api = @import("@zeam/api");
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;
const types = @import("@zeam/types");
const ssz = @import("ssz");
const utils_lib = @import("@zeam/utils");
const LoggerConfig = utils_lib.ZeamLoggerConfig;
const ModuleLogger = utils_lib.ModuleLogger;

/// Global chain pointer (set after node initialization)
/// Using anyopaque to avoid circular dependency with node.zig
var global_chain_ptr: ?*anyopaque = null;
var chain_ptr_mutex = std.Thread.Mutex{};

/// Register the chain instance to enable finalized state endpoint
/// The chain_ptr must point to a BeamChain
pub fn registerChain(chain_ptr: *anyopaque) void {
    chain_ptr_mutex.lock();
    defer chain_ptr_mutex.unlock();
    global_chain_ptr = chain_ptr;
}

/// Internal function to get finalized lean state (BeamState) from the registered chain
/// Returns the finalized checkpoint lean state (BeamState) if available
fn getFinalizedStateInternal(_allocator: std.mem.Allocator) ?*const types.BeamState {
    _ = _allocator;
    chain_ptr_mutex.lock();
    defer chain_ptr_mutex.unlock();

    const chain_ptr = global_chain_ptr orelse return null;

    // Cast the opaque pointer directly to BeamChain pointer
    // This is safer than casting through the Node structure
    const chainFactory = @import("@zeam/node").chainFactory;
    const BeamChain = chainFactory.BeamChain;

    const chain: *const BeamChain = @ptrCast(@alignCast(chain_ptr));

    // Use the public method to safely get the finalized state
    return chain.getFinalizedState();
}

/// Simple metrics server that runs in a background thread
pub fn startAPIServer(allocator: std.mem.Allocator, port: u16, logger_config: *LoggerConfig) !void {
    // Initialize the global event broadcaster for SSE events
    // This is idempotent - safe to call even if already initialized elsewhere (e.g., node.zig)
    try event_broadcaster.initGlobalBroadcaster(allocator);

    // Create a logger instance for the API server
    const logger = logger_config.logger(.metrics);

    // Create a simple HTTP server context
    const ctx = try allocator.create(SimpleMetricsServer);
    errdefer allocator.destroy(ctx);
    ctx.* = .{
        .allocator = allocator,
        .port = port,
        .logger = logger,
    };

    // Start server in background thread
    const thread = try std.Thread.spawn(.{}, SimpleMetricsServer.run, .{ctx});
    thread.detach();

    logger.info("Metrics server thread spawned for port {d}", .{port});
}

/// Handle finalized checkpoint state endpoint
/// Serves the finalized checkpoint lean state (BeamState) as SSZ octet-stream at /lean/states/finalized
fn handleFinalizedCheckpointState(request: *std.http.Server.Request, allocator: std.mem.Allocator, logger: ModuleLogger) !void {
    // Retrieve the finalized lean state (BeamState)
    const finalized_lean_state = getFinalizedStateInternal(allocator) orelse {
        _ = request.respond("Not Found: Finalized checkpoint lean state not available\n", .{ .status = .not_found }) catch {};
        return;
    };

    // Serialize lean state (BeamState) to SSZ
    var ssz_output = std.ArrayList(u8).init(allocator);
    defer ssz_output.deinit();

    ssz.serialize(types.BeamState, finalized_lean_state.*, &ssz_output) catch |err| {
        logger.err("Failed to serialize finalized lean state to SSZ: {}", .{err});
        _ = request.respond("Internal Server Error: Serialization failed\n", .{ .status = .internal_server_error }) catch {};
        return;
    };

    // Format content-length header value
    var content_length_buf: [32]u8 = undefined;
    const content_length_str = try std.fmt.bufPrint(&content_length_buf, "{d}", .{ssz_output.items.len});

    // Respond with lean state (BeamState) as SSZ octet-stream
    _ = request.respond(ssz_output.items, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "content-length", .value = content_length_str },
        },
    }) catch |err| {
        logger.warn("Failed to respond with finalized lean state: {}", .{err});
        return err;
    };
}

/// Handle individual HTTP connections in a separate thread
fn handleConnection(connection: std.net.Server.Connection, allocator: std.mem.Allocator, logger: ModuleLogger) void {
    defer connection.stream.close();

    var buffer: [4096]u8 = undefined;
    var http_server = std.http.Server.init(connection, &buffer);
    var request = http_server.receiveHead() catch |err| {
        logger.warn("Failed to receive HTTP head: {}", .{err});
        return;
    };

    // Route handling
    if (std.mem.eql(u8, request.head.target, "/events")) {
        // Handle SSE connection - this will keep the connection alive
        SimpleMetricsServer.handleSSEEvents(connection.stream, allocator, logger) catch |err| {
            logger.warn("SSE connection failed: {}", .{err});
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
    } else if (std.mem.eql(u8, request.head.target, "/lean/states/finalized")) {
        // Handle finalized checkpoint state endpoint
        handleFinalizedCheckpointState(&request, allocator, logger) catch |err| {
            logger.warn("Failed to handle finalized checkpoint state request: {}", .{err});
            _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
        };
    } else {
        _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
    }
}

/// Simple metrics server context
const SimpleMetricsServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    logger: ModuleLogger,

    fn run(self: *SimpleMetricsServer) void {
        // `startMetricsServer` creates this, so we need to free it here
        defer self.allocator.destroy(self);

        const address = std.net.Address.parseIp4("0.0.0.0", self.port) catch |err| {
            self.logger.err("Failed to parse server address 0.0.0.0:{d}: {}", .{ self.port, err });
            return;
        };

        var server = address.listen(.{ .reuse_address = true }) catch |err| {
            self.logger.err("Failed to listen on port {d}: {}", .{ self.port, err });
            return;
        };
        defer server.deinit();

        self.logger.info("HTTP server listening on http://0.0.0.0:{d}", .{self.port});

        while (true) {
            const connection = server.accept() catch continue;

            // For SSE connections, we need to handle them differently
            // We'll spawn a new thread for each connection to handle persistence
            _ = std.Thread.spawn(.{}, handleConnection, .{ connection, self.allocator, self.logger }) catch |err| {
                self.logger.warn("Failed to spawn connection handler: {}", .{err});
                connection.stream.close();
                continue;
            };
        }
    }

    fn handleSSEEvents(stream: std.net.Stream, allocator: std.mem.Allocator, logger: ModuleLogger) !void {
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
                logger.warn("SSE connection closed: {}", .{err});
                break;
            };

            // Wait between SSE heartbeats
            std.time.sleep(constants.SSE_HEARTBEAT_SECONDS * std.time.ns_per_s);
        }
    }
};
