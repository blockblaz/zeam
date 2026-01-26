const std = @import("std");
const api = @import("@zeam/api");
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;
const types = @import("@zeam/types");
const ssz = @import("ssz");
const utils_lib = @import("@zeam/utils");
const LoggerConfig = utils_lib.ZeamLoggerConfig;
const ModuleLogger = utils_lib.ModuleLogger;
const node_lib = @import("@zeam/node");
const BeamChain = node_lib.chainFactory.BeamChain;

/// API server that runs in a background thread
/// Handles metrics, SSE events, health checks, checkpoint endpoints, and finalized state
/// chain is optional - if null, endpoints will return 503
/// (API server starts before chain initialization, so chain may not be available yet)
pub fn startAPIServer(allocator: std.mem.Allocator, port: u16, logger_config: *LoggerConfig, chain: ?*BeamChain) !void {
    // Initialize the global event broadcaster for SSE events
    // This is idempotent - safe to call even if already initialized elsewhere (e.g., node.zig)
    try event_broadcaster.initGlobalBroadcaster(allocator);

    // Create a logger instance for the API server
    const logger = logger_config.logger(.api_server);

    // Create the API server context
    const ctx = try allocator.create(ApiServer);
    errdefer allocator.destroy(ctx);
    ctx.* = .{
        .allocator = allocator,
        .port = port,
        .logger = logger,
        .chain = chain,
    };

    // Start server in background thread
    const thread = try std.Thread.spawn(.{}, ApiServer.run, .{ctx});
    thread.detach();

    logger.info("API server thread spawned for port {d}", .{port});
}

/// API server context
const ApiServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    logger: ModuleLogger,
    chain: ?*BeamChain,

    const Self = @This();

    fn run(self: *Self) void {
        // `startAPIServer` creates this, so we need to free it here
        defer self.allocator.destroy(self);

        const address = std.net.Address.parseIp4("0.0.0.0", self.port) catch |err| {
            self.logger.err("failed to parse server address 0.0.0.0:{d}: {}", .{ self.port, err });
            return;
        };

        var server = address.listen(.{ .reuse_address = true }) catch |err| {
            self.logger.err("failed to listen on port {d}: {}", .{ self.port, err });
            return;
        };
        defer server.deinit();

        self.logger.info("HTTP server listening on http://0.0.0.0:{d}", .{self.port});

        while (true) {
            const connection = server.accept() catch continue;

            // For SSE connections, we need to handle them differently
            // We'll spawn a new thread for each connection to handle persistence
            _ = std.Thread.spawn(.{}, Self.handleConnection, .{ self, connection }) catch |err| {
                self.logger.warn("failed to spawn connection handler: {}", .{err});
                connection.stream.close();
                continue;
            };
        }
    }

    /// Handle individual HTTP connections in a separate thread
    fn handleConnection(self: *const Self, connection: std.net.Server.Connection) void {
        defer connection.stream.close();

        var buffer: [4096]u8 = undefined;
        var http_server = std.http.Server.init(connection, &buffer);
        var request = http_server.receiveHead() catch |err| {
            self.logger.warn("failed to receive HTTP head: {}", .{err});
            return;
        };

        // Route handling
        if (std.mem.eql(u8, request.head.target, "/events")) {
            // Handle SSE connection - this will keep the connection alive
            self.handleSSEEvents(connection.stream) catch |err| {
                self.logger.warn("SSE connection failed: {}", .{err});
            };
        } else if (std.mem.eql(u8, request.head.target, "/metrics")) {
            // Handle metrics request
            self.handleMetrics(&request);
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/health")) {
            // Handle health check
            self.handleHealth(&request);
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/states/finalized")) {
            // Handle finalized checkpoint state endpoint
            self.handleFinalizedCheckpointState(&request) catch |err| {
                self.logger.warn("failed to handle finalized checkpoint state request: {}", .{err});
                _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
            };
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/checkpoints/justified")) {
            // Handle justified checkpoint endpoint
            self.handleJustifiedCheckpoint(&request) catch |err| {
                self.logger.warn("failed to handle justified checkpoint request: {}", .{err});
                _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
            };
        } else {
            _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
        }
    }

    /// Handle metrics endpoint
    fn handleMetrics(self: *const Self, request: *std.http.Server.Request) void {
        var metrics_output = std.ArrayList(u8).init(self.allocator);
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
    }

    /// Handle health check endpoint
    fn handleHealth(_: *const Self, request: *std.http.Server.Request) void {
        const response = "{\"status\":\"healthy\",\"service\":\"zeam-api\"}";
        _ = request.respond(response, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
    }

    /// Handle finalized checkpoint state endpoint
    /// Serves the finalized checkpoint lean state (BeamState) as SSZ octet-stream at /lean/v0/states/finalized
    fn handleFinalizedCheckpointState(self: *const Self, request: *std.http.Server.Request) !void {
        // Get the chain (may be null if API server started before chain initialization)
        const chain = self.chain orelse {
            _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
            return;
        };

        // Get finalized state from chain (chain handles its own locking internally)
        const finalized_lean_state = chain.getFinalizedState() orelse {
            _ = request.respond("Not Found: Finalized checkpoint lean state not available\n", .{ .status = .not_found }) catch {};
            return;
        };

        // Serialize lean state (BeamState) to SSZ
        var ssz_output = std.ArrayList(u8).init(self.allocator);
        defer ssz_output.deinit();

        ssz.serialize(types.BeamState, finalized_lean_state.*, &ssz_output) catch |err| {
            self.logger.err("failed to serialize finalized lean state to SSZ: {}", .{err});
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
            self.logger.warn("failed to respond with finalized lean state: {}", .{err});
            return err;
        };
    }

    /// Handle justified checkpoint endpoint
    /// Returns checkpoint info as JSON at /lean/v0/checkpoints/justified
    /// Useful for monitoring consensus progress and fork choice state
    fn handleJustifiedCheckpoint(self: *const Self, request: *std.http.Server.Request) !void {
        // Get the chain (may be null if API server started before chain initialization)
        const chain = self.chain orelse {
            _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
            return;
        };

        // Get justified checkpoint from chain (chain handles its own locking internally)
        const justified_checkpoint = chain.getJustifiedCheckpoint();

        // Convert checkpoint to JSON string
        const json_string = justified_checkpoint.toJsonString(self.allocator) catch |err| {
            self.logger.err("failed to serialize justified checkpoint to JSON: {}", .{err});
            _ = request.respond("Internal Server Error: Serialization failed\n", .{ .status = .internal_server_error }) catch {};
            return;
        };
        defer self.allocator.free(json_string);

        // Respond with JSON
        _ = request.respond(json_string, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch |err| {
            self.logger.warn("failed to respond with justified checkpoint: {}", .{err});
            return err;
        };
    }

    /// Handle SSE events endpoint
    fn handleSSEEvents(self: *const Self, stream: std.net.Stream) !void {
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
                self.logger.warn("SSE connection closed: {}", .{err});
                break;
            };

            // Wait between SSE heartbeats
            std.time.sleep(constants.SSE_HEARTBEAT_SECONDS * std.time.ns_per_s);
        }
    }
};
