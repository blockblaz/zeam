const std = @import("std");
const api = @import("@zeam/api");
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;
const types = @import("@zeam/types");
const ssz = @import("ssz");

/// Global node pointer (set after node initialization)
/// Using anyopaque to avoid circular dependency with node.zig
var global_node_ptr: ?*anyopaque = null;
var node_ptr_mutex = std.Thread.Mutex{};

/// Register the node instance to enable finalized state endpoint
/// The node_ptr must point to a BeamNode with accessible chain field
pub fn registerNode(node_ptr: *anyopaque) void {
    node_ptr_mutex.lock();
    defer node_ptr_mutex.unlock();
    global_node_ptr = node_ptr;
}

/// Internal function to get finalized state from the registered node
/// This function casts the opaque pointer and accesses the chain structure
/// The node structure is: Node { beam_node: BeamNode { chain: *BeamChain { ... } } }
fn getFinalizedStateInternal(_allocator: std.mem.Allocator) ?*const types.BeamState {
    _ = _allocator;
    node_ptr_mutex.lock();
    defer node_ptr_mutex.unlock();
    
    const node_ptr = global_node_ptr orelse return null;
    
    // Cast to access the chain structure
    // Node structure from cli/src/node.zig has: beam_node: BeamNode
    // BeamNode from node/src/node.zig has: chain: *BeamChain (pointer!)
    const NodeType = struct {
        beam_node: struct {
            chain: *struct {
                forkChoice: struct {
                    fcStore: struct {
                        latest_finalized: types.Checkpoint,
                    },
                },
                states: std.AutoHashMap(types.Root, *types.BeamState),
            },
        },
    };
    
    const node: *NodeType = @ptrCast(@alignCast(node_ptr));
    const finalized_checkpoint = node.beam_node.chain.forkChoice.fcStore.latest_finalized;
    return node.beam_node.chain.states.get(finalized_checkpoint.root);
}

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

/// Handle finalized checkpoint state endpoint
/// Serves the finalized checkpoint state as SSZ octet-stream at /lean/states/finalized
fn handleFinalizedCheckpointState(request: *std.http.Server.Request, allocator: std.mem.Allocator) !void {
    // Retrieve the finalized state
    const finalized_state = getFinalizedStateInternal(allocator) orelse {
        _ = request.respond("Not Found: Finalized checkpoint state not available\n", .{ .status = .not_found }) catch {};
        return;
    };

    // Serialize state to SSZ
    var ssz_output = std.ArrayList(u8).init(allocator);
    defer ssz_output.deinit();

    ssz.serialize(types.BeamState, finalized_state.*, &ssz_output) catch |err| {
        std.log.err("Failed to serialize finalized state to SSZ: {}", .{err});
        _ = request.respond("Internal Server Error: Serialization failed\n", .{ .status = .internal_server_error }) catch {};
        return;
    };

    // Format content-length header value
    var content_length_buf: [32]u8 = undefined;
    const content_length_str = try std.fmt.bufPrint(&content_length_buf, "{d}", .{ssz_output.items.len});

    // Respond with SSZ octet-stream
    _ = request.respond(ssz_output.items, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "content-length", .value = content_length_str },
        },
    }) catch |err| {
        std.log.warn("Failed to respond with finalized state: {}", .{err});
        return err;
    };
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
    } else if (std.mem.eql(u8, request.head.target, "/lean/states/finalized")) {
        // Handle finalized checkpoint state endpoint
        handleFinalizedCheckpointState(&request, allocator) catch |err| {
            std.log.warn("Failed to handle finalized checkpoint state request: {}", .{err});
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
