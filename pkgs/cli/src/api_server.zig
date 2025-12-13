const std = @import("std");
const api = @import("@zeam/api");
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;
const node = @import("@zeam/node");

// Global chain reference for API access
var global_chain: ?*node.BeamChain = null;
var chain_mutex = std.Thread.Mutex{};

/// Register the chain for API access
pub fn registerChain(chain: *node.BeamChain) void {
    chain_mutex.lock();
    defer chain_mutex.unlock();
    global_chain = chain;
}

/// Get the global chain reference
fn getChain() ?*node.BeamChain {
    chain_mutex.lock();
    defer chain_mutex.unlock();
    return global_chain;
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
    } else if (std.mem.startsWith(u8, request.head.target, "/api/forkchoice/graph")) {
        // Handle fork choice graph request
        handleForkChoiceGraph(&request, allocator) catch |err| {
            std.log.warn("Fork choice graph request failed: {}", .{err});
            _ = request.respond("Internal Server Error\n", .{}) catch {};
        };
    } else {
        _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
    }
}

/// Handle fork choice graph API request
fn handleForkChoiceGraph(request: *std.http.Server.Request, allocator: std.mem.Allocator) !void {
    // Get chain reference
    const chain = getChain() orelse {
        const error_response = "{\"error\":\"Chain not initialized\"}";
        _ = request.respond(error_response, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
        return;
    };

    // Parse query parameters for max_slots (default: 50)
    var max_slots: usize = 50;
    if (std.mem.indexOf(u8, request.head.target, "?slots=")) |query_start| {
        const slots_param = request.head.target[query_start + 7 ..];
        if (std.mem.indexOf(u8, slots_param, "&")) |end| {
            max_slots = std.fmt.parseInt(usize, slots_param[0..end], 10) catch 50;
        } else {
            max_slots = std.fmt.parseInt(usize, slots_param, 10) catch 50;
        }
    }

    // Build the graph data
    var graph_json = std.ArrayList(u8).init(allocator);
    defer graph_json.deinit();

    try buildGraphJSON(chain, graph_json.writer(), max_slots, allocator);

    // Send response
    _ = request.respond(graph_json.items, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    }) catch {};
}

/// Build fork choice graph in Grafana node-graph JSON format
fn buildGraphJSON(
    chain: *node.BeamChain,
    writer: anytype,
    max_slots: usize,
    allocator: std.mem.Allocator,
) !void {
    // Thread-safe snapshot - lock held only during copy
    const snapshot = try chain.forkChoice.snapshot(allocator);
    defer snapshot.deinit(allocator);

    const proto_nodes = snapshot.nodes;

    // Determine the slot threshold (show only recent slots)
    const current_slot = snapshot.head.slot;
    const min_slot = if (current_slot > max_slots) current_slot - max_slots else 0;

    // Build nodes and edges
    var nodes_list = std.ArrayList(u8).init(allocator);
    defer nodes_list.deinit();
    var edges_list = std.ArrayList(u8).init(allocator);
    defer edges_list.deinit();

    var node_count: usize = 0;
    var edge_count: usize = 0;

    // Find max weight for normalization
    var max_weight: isize = 1;
    for (proto_nodes) |pnode| {
        if (pnode.slot >= min_slot and pnode.weight > max_weight) {
            max_weight = pnode.weight;
        }
    }

    // Build nodes
    // Find the finalized node index to check ancestry
    const finalized_idx = blk: {
        for (proto_nodes, 0..) |n, i| {
            if (std.mem.eql(u8, &n.blockRoot, &snapshot.latest_finalized_root)) {
                break :blk i;
            }
        }
        break :blk null;
    };

    for (proto_nodes, 0..) |pnode, idx| {
        if (pnode.slot < min_slot) continue;

        // Determine node role and color
        const is_head = std.mem.eql(u8, &pnode.blockRoot, &snapshot.head.blockRoot);
        const is_justified = std.mem.eql(u8, &pnode.blockRoot, &snapshot.latest_justified_root);

        // A block is finalized if:
        // 1. It equals the finalized checkpoint, OR
        // 2. The finalized block is a descendant of it (block is ancestor of finalized)
        const is_finalized = blk: {
            // Check if this block IS the finalized block
            if (std.mem.eql(u8, &pnode.blockRoot, &snapshot.latest_finalized_root)) {
                break :blk true;
            }
            // Check if this block is an ancestor of the finalized block
            if (finalized_idx) |fin_idx| {
                var current_idx: ?usize = fin_idx;
                while (current_idx) |curr| {
                    if (curr == idx) break :blk true;
                    current_idx = proto_nodes[curr].parent;
                }
            }
            break :blk false;
        };

        const role = if (is_finalized)
            "finalized"
        else if (is_justified)
            "justified"
        else if (is_head)
            "head"
        else
            "normal";

        // Normalized weight for arc (0.0 to 1.0, draws partial circle border)
        // Represents fraction of circle filled (0.5 = half circle, 1.0 = full circle)
        const arc_weight: f64 = if (max_weight > 0)
            @as(f64, @floatFromInt(pnode.weight)) / @as(f64, @floatFromInt(max_weight))
        else
            0.0;

        // Use separate arc fields for each color (only one is set per node, others are 0)
        // This allows manual arc section configuration with explicit colors
        // TODO: Use chain.forkChoice.isBlockTimely(blockDelayMs) once implemented
        // For now, treat all non-finalized/non-justified/non-head blocks as timely
        const arc_timely: f64 = if (!is_finalized and !is_justified and !is_head) arc_weight else 0.0;
        const arc_head: f64 = if (is_head) arc_weight else 0.0;
        const arc_justified: f64 = if (is_justified) arc_weight else 0.0;
        const arc_finalized: f64 = if (is_finalized) arc_weight else 0.0;

        // Block root as hex
        const hex_prefix = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(pnode.blockRoot[0..4])});
        defer allocator.free(hex_prefix);
        const full_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&pnode.blockRoot)});
        defer allocator.free(full_root);

        if (node_count > 0) {
            try nodes_list.appendSlice(",");
        }

        try std.fmt.format(nodes_list.writer(),
            \\{{"id":"{s}","title":"Slot {d}","mainStat":"{d}","secondaryStat":"{d}","arc__timely":{d:.4},"arc__head":{d:.4},"arc__justified":{d:.4},"arc__finalized":{d:.4},"detail__role":"{s}","detail__hex_prefix":"{s}"}}
        , .{
            full_root,
            pnode.slot,
            pnode.weight,
            pnode.slot,
            arc_timely,
            arc_head,
            arc_justified,
            arc_finalized,
            role,
            hex_prefix,
        });

        node_count += 1;

        // Build edges (parent -> child relationships)
        if (pnode.parent) |parent_idx| {
            const parent_node = proto_nodes[parent_idx];
            if (parent_node.slot >= min_slot) {
                const parent_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&parent_node.blockRoot)});
                defer allocator.free(parent_root);

                const is_best_child = if (parent_node.bestChild) |bc| bc == idx else false;

                if (edge_count > 0) {
                    try edges_list.appendSlice(",");
                }

                try std.fmt.format(edges_list.writer(),
                    \\{{"id":"edge_{d}","source":"{s}","target":"{s}","mainStat":"","detail__is_best_child":{}}}
                , .{
                    edge_count,
                    parent_root,
                    full_root,
                    is_best_child,
                });

                edge_count += 1;
            }
        }
    }

    // Write final JSON
    try std.fmt.format(writer,
        \\{{"nodes":[{s}],"edges":[{s}]}}
    , .{ nodes_list.items, edges_list.items });
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
