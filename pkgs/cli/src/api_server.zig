const std = @import("std");
const api = @import("@zeam/api");
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;
const node = @import("@zeam/node");

const QUERY_SLOTS_PREFIX = "?slots=";
const DEFAULT_MAX_SLOTS: usize = 50;
const MAX_ALLOWED_SLOTS: usize = 200;
const ACCEPT_POLL_NS: u64 = 50 * std.time.ns_per_ms;

pub const APIServerHandle = struct {
    thread: std.Thread,
    ctx: *SimpleMetricsServer,

    pub fn stop(self: *APIServerHandle) void {
        self.ctx.stop.store(true, .seq_cst);
        self.thread.join();
    }
};

pub fn startAPIServer(allocator: std.mem.Allocator, port: u16, forkchoice: *node.fcFactory.ForkChoice) !APIServerHandle {
    try event_broadcaster.initGlobalBroadcaster(allocator);

    const ctx = try allocator.create(SimpleMetricsServer);
    errdefer allocator.destroy(ctx);
    ctx.* = .{
        .allocator = allocator,
        .port = port,
        .forkchoice = forkchoice,
        .stop = std.atomic.Value(bool).init(false),
    };

    const thread = try std.Thread.spawn(.{}, SimpleMetricsServer.run, .{ctx});

    std.log.info("Metrics server started on port {d}", .{port});
    return .{
        .thread = thread,
        .ctx = ctx,
    };
}

fn handleNonSSERequest(request: *std.http.Server.Request, allocator: std.mem.Allocator, forkchoice: *node.fcFactory.ForkChoice) void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const request_allocator = arena.allocator();

    if (std.mem.eql(u8, request.head.target, "/metrics")) {
        var metrics_output = std.ArrayList(u8).init(request_allocator);
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
        const response = "{\"status\":\"healthy\",\"service\":\"zeam-metrics\"}";
        _ = request.respond(response, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
    } else if (std.mem.startsWith(u8, request.head.target, "/api/forkchoice/graph")) {
        handleForkChoiceGraph(request, request_allocator, forkchoice) catch |err| {
            std.log.warn("Fork choice graph request failed: {}", .{err});
            _ = request.respond("Internal Server Error\n", .{}) catch {};
        };
    } else {
        _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
    }
}

fn routeConnection(connection: std.net.Server.Connection, allocator: std.mem.Allocator, forkchoice: *node.fcFactory.ForkChoice) void {
    var buffer: [4096]u8 = undefined;
    var http_server = std.http.Server.init(connection, &buffer);
    var request = http_server.receiveHead() catch |err| {
        std.log.warn("Failed to receive HTTP head: {}", .{err});
        connection.stream.close();
        return;
    };

    if (std.mem.eql(u8, request.head.target, "/events")) {
        _ = std.Thread.spawn(.{}, SimpleMetricsServer.handleSSEConnection, .{ connection.stream, allocator }) catch |err| {
            std.log.warn("Failed to spawn SSE handler: {}", .{err});
            connection.stream.close();
        };
        return;
    }

    handleNonSSERequest(&request, allocator, forkchoice);
    connection.stream.close();
}

fn handleForkChoiceGraph(request: *std.http.Server.Request, allocator: std.mem.Allocator, forkchoice: *node.fcFactory.ForkChoice) !void {
    var max_slots: usize = DEFAULT_MAX_SLOTS;
    if (std.mem.indexOf(u8, request.head.target, QUERY_SLOTS_PREFIX)) |query_start| {
        const slots_param = request.head.target[query_start + QUERY_SLOTS_PREFIX.len ..];
        if (std.mem.indexOf(u8, slots_param, "&")) |end| {
            max_slots = std.fmt.parseInt(usize, slots_param[0..end], 10) catch DEFAULT_MAX_SLOTS;
        } else {
            max_slots = std.fmt.parseInt(usize, slots_param, 10) catch DEFAULT_MAX_SLOTS;
        }
    }

    if (max_slots > MAX_ALLOWED_SLOTS) max_slots = MAX_ALLOWED_SLOTS;

    var graph_json = std.ArrayList(u8).init(allocator);
    defer graph_json.deinit();

    try buildGraphJSON(forkchoice, graph_json.writer(), max_slots, allocator);

    _ = request.respond(graph_json.items, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    }) catch {};
}

/// Build fork choice graph in Grafana node-graph JSON format
fn buildGraphJSON(
    forkchoice: *node.fcFactory.ForkChoice,
    writer: anytype,
    max_slots: usize,
    allocator: std.mem.Allocator,
) !void {
    const snapshot = try forkchoice.snapshot(allocator);
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

        // Get finalized slot for orphaned block detection
        const finalized_slot = if (finalized_idx) |fin_idx| proto_nodes[fin_idx].slot else 0;

        // A block is orphaned if:
        // 1. It's at or before finalized slot, AND
        // 2. It's NOT on the canonical chain (not finalized)
        const is_orphaned = blk: {
            // Only blocks at or before finalized slot can be orphaned
            if (pnode.slot > finalized_slot) break :blk false;
            // If already finalized (canonical), not orphaned
            if (is_finalized) break :blk false;

            // If it's old enough to be finalized but isn't, it's orphaned
            break :blk true;
        };

        const role = if (is_finalized)
            "finalized"
        else if (is_justified)
            "justified"
        else if (is_head)
            "head"
        else if (is_orphaned)
            "orphaned"
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
        // For now, treat all non-finalized/non-justified/non-head/non-orphaned blocks as timely
        const arc_timely: f64 = if (!is_finalized and !is_justified and !is_head and !is_orphaned) arc_weight else 0.0;
        const arc_head: f64 = if (is_head) arc_weight else 0.0;
        const arc_justified: f64 = if (is_justified) arc_weight else 0.0;
        const arc_finalized: f64 = if (is_finalized) arc_weight else 0.0;
        const arc_orphaned: f64 = if (is_orphaned) arc_weight else 0.0;

        // Block root as hex
        const hex_prefix = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(pnode.blockRoot[0..4])});
        defer allocator.free(hex_prefix);
        const full_root = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&pnode.blockRoot)});
        defer allocator.free(full_root);

        if (node_count > 0) {
            try nodes_list.appendSlice(",");
        }

        try std.fmt.format(nodes_list.writer(),
            \\{{"id":"{s}","title":"Slot {d}","mainStat":"{d}","secondaryStat":"{d}","arc__timely":{d:.4},"arc__head":{d:.4},"arc__justified":{d:.4},"arc__finalized":{d:.4},"arc__orphaned":{d:.4},"detail__role":"{s}","detail__hex_prefix":"{s}"}}
        , .{
            full_root,
            pnode.slot,
            pnode.weight,
            pnode.slot,
            arc_timely,
            arc_head,
            arc_justified,
            arc_finalized,
            arc_orphaned,
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
    forkchoice: *node.fcFactory.ForkChoice,
    stop: std.atomic.Value(bool),

    fn run(self: *SimpleMetricsServer) !void {
        defer self.allocator.destroy(self);
        const address = try std.net.Address.parseIp4("0.0.0.0", self.port);
        var server = try address.listen(.{ .reuse_address = true, .force_nonblocking = true });
        defer server.deinit();

        std.log.info("HTTP server listening on http://0.0.0.0:{d}", .{self.port});

        while (true) {
            if (self.stop.load(.acquire)) break;
            const connection = server.accept() catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(ACCEPT_POLL_NS);
                    continue;
                }
                std.log.warn("Failed to accept connection: {}", .{err});
                continue;
            };

            routeConnection(connection, self.allocator, self.forkchoice);
        }
    }

    fn handleSSEConnection(stream: std.net.Stream, allocator: std.mem.Allocator) void {
        SimpleMetricsServer.handleSSEEvents(stream, allocator) catch |err| {
            std.log.warn("SSE connection failed: {}", .{err});
        };
        stream.close();
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
