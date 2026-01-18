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
const BeamChain = node_lib.BeamChain;

const QUERY_SLOTS_PREFIX = "?slots=";
const DEFAULT_MAX_SLOTS: usize = 50;
const MAX_ALLOWED_SLOTS: usize = 200;
const ACCEPT_POLL_NS: u64 = 50 * std.time.ns_per_ms;
// Conservative defaults for a local metrics server.
const MAX_SSE_CONNECTIONS: usize = 32;
const MAX_GRAPH_INFLIGHT: usize = 2;
const RATE_LIMIT_RPS: f64 = 2.0;
const RATE_LIMIT_BURST: f64 = 5.0;
const RATE_LIMIT_MAX_ENTRIES: usize = 256; // Max tracked IPs to bound memory.
const RATE_LIMIT_CLEANUP_THRESHOLD: usize = RATE_LIMIT_MAX_ENTRIES / 2; // Trigger lazy cleanup.
const RATE_LIMIT_STALE_NS: u64 = 10 * std.time.ns_per_min; // Evict entries idle past TTL.
const RATE_LIMIT_CLEANUP_COOLDOWN_NS: u64 = 60 * std.time.ns_per_s;

pub const APIServerHandle = struct {
    thread: std.Thread,
    ctx: *ApiServer,

    pub fn stop(self: *APIServerHandle) void {
        self.ctx.stop.store(true, .seq_cst);
        self.thread.join();
    }

    pub fn setChain(self: *APIServerHandle, chain: *BeamChain) void {
        self.ctx.setChain(chain);
    }
};

/// API server that runs in a background thread
/// Handles metrics, SSE events, health checks, forkchoice graph, and checkpoint state endpoints
/// chain is optional - if null, chain-dependent endpoints will return 503
pub fn startAPIServer(allocator: std.mem.Allocator, port: u16, logger_config: *LoggerConfig, chain: ?*BeamChain) !APIServerHandle {
    // Initialize the global event broadcaster for SSE events
    // This is idempotent - safe to call even if already initialized elsewhere (e.g., node.zig)
    try event_broadcaster.initGlobalBroadcaster(allocator);

    var rate_limiter = try RateLimiter.init(allocator);
    errdefer rate_limiter.deinit();

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
        .stop = std.atomic.Value(bool).init(false),
        .sse_active = 0,
        .graph_inflight = 0,
        .rate_limiter = rate_limiter,
    };

    const thread = try std.Thread.spawn(.{}, ApiServer.run, .{ctx});

    logger.info("API server started on port {d}", .{port});
    return .{
        .thread = thread,
        .ctx = ctx,
    };
}

fn routeConnection(connection: std.net.Server.Connection, allocator: std.mem.Allocator, ctx: *ApiServer) void {
    var buffer: [4096]u8 = undefined;
    var http_server = std.http.Server.init(connection, &buffer);
    var request = http_server.receiveHead() catch |err| {
        ctx.logger.warn("failed to receive HTTP head: {}", .{err});
        connection.stream.close();
        return;
    };

    if (std.mem.eql(u8, request.head.target, "/events")) {
        if (!ctx.tryAcquireSSE()) {
            _ = request.respond("Service Unavailable\n", .{ .status = .service_unavailable }) catch {};
            connection.stream.close();
            return;
        }
        _ = std.Thread.spawn(.{}, ApiServer.handleSSEConnection, .{ connection.stream, ctx }) catch |err| {
            ctx.logger.warn("failed to spawn SSE handler: {}", .{err});
            ctx.releaseSSE();
            connection.stream.close();
        };
        return;
    }

    handleNonSSERequestWithAddr(&request, allocator, ctx, connection.address);
    connection.stream.close();
}

fn handleNonSSERequestWithAddr(
    request: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    ctx: *ApiServer,
    client_addr: std.net.Address,
) void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const request_allocator = arena.allocator();

    if (std.mem.eql(u8, request.head.target, "/metrics")) {
        ctx.handleMetrics(request, request_allocator);
    } else if (std.mem.eql(u8, request.head.target, "/health")) {
        ctx.handleHealth(request);
    } else if (std.mem.eql(u8, request.head.target, "/lean/states/finalized")) {
        ctx.handleFinalizedCheckpointState(request) catch |err| {
            ctx.logger.warn("failed to handle finalized checkpoint state request: {}", .{err});
            _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
        };
    } else if (std.mem.startsWith(u8, request.head.target, "/api/forkchoice/graph")) {
        handleForkChoiceGraph(request, request_allocator, ctx, client_addr) catch |err| {
            ctx.logger.warn("fork choice graph request failed: {}", .{err});
            _ = request.respond("Internal Server Error\n", .{}) catch {};
        };
    } else {
        _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
    }
}

/// API server context
const ApiServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    logger: ModuleLogger,
    chain: ?*BeamChain,
    chain_mutex: std.Thread.Mutex = .{},
    stop: std.atomic.Value(bool),
    sse_active: usize,
    graph_inflight: usize,
    rate_limiter: RateLimiter,
    sse_mutex: std.Thread.Mutex = .{},
    graph_mutex: std.Thread.Mutex = .{},

    const Self = @This();

    fn setChain(self: *ApiServer, chain: *BeamChain) void {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        self.chain = chain;
    }

    fn getChain(self: *ApiServer) ?*BeamChain {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        return self.chain;
    }

    fn run(self: *Self) !void {
        defer self.allocator.destroy(self);
        defer self.rate_limiter.deinit();
        const address = std.net.Address.parseIp4("0.0.0.0", self.port) catch |err| {
            self.logger.err("failed to parse server address 0.0.0.0:{d}: {}", .{ self.port, err });
            return;
        };
        var server = address.listen(.{ .reuse_address = true, .force_nonblocking = true }) catch |err| {
            self.logger.err("failed to listen on port {d}: {}", .{ self.port, err });
            return;
        };
        defer server.deinit();

        self.logger.info("HTTP server listening on http://0.0.0.0:{d}", .{self.port});

        while (true) {
            if (self.stop.load(.acquire)) break;
            const connection = server.accept() catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(ACCEPT_POLL_NS);
                    continue;
                }
                self.logger.warn("failed to accept connection: {}", .{err});
                continue;
            };

            routeConnection(connection, self.allocator, self);
        }
    }

    /// Handle metrics endpoint
    fn handleMetrics(_: *ApiServer, request: *std.http.Server.Request, allocator: std.mem.Allocator) void {
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
    }

    /// Handle health check endpoint
    fn handleHealth(_: *ApiServer, request: *std.http.Server.Request) void {
        const response = "{\"status\":\"healthy\",\"service\":\"zeam-api\"}";
        _ = request.respond(response, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
    }

    /// Handle finalized checkpoint state endpoint
    /// Serves the finalized checkpoint lean state (BeamState) as SSZ octet-stream at /lean/states/finalized
    fn handleFinalizedCheckpointState(self: *ApiServer, request: *std.http.Server.Request) !void {
        // Get the chain (may be null if API server started before chain initialization)
        const chain = self.getChain() orelse {
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

    /// Handle SSE events endpoint
    fn handleSSEEvents(self: *ApiServer, stream: std.net.Stream) !void {
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

    fn handleSSEConnection(stream: std.net.Stream, ctx: *ApiServer) void {
        ctx.handleSSEEvents(stream) catch |err| {
            ctx.logger.warn("SSE connection failed: {}", .{err});
        };
        stream.close();
        ctx.releaseSSE();
    }

    fn tryAcquireSSE(self: *ApiServer) bool {
        self.sse_mutex.lock();
        defer self.sse_mutex.unlock();
        // Limit long-lived SSE connections to avoid unbounded threads.
        if (self.sse_active >= MAX_SSE_CONNECTIONS) return false;
        self.sse_active += 1;
        return true;
    }

    fn releaseSSE(self: *ApiServer) void {
        self.sse_mutex.lock();
        defer self.sse_mutex.unlock();
        if (self.sse_active > 0) self.sse_active -= 1;
    }

    fn tryAcquireGraph(self: *ApiServer) bool {
        self.graph_mutex.lock();
        defer self.graph_mutex.unlock();
        // Cap concurrent graph JSON generation.
        if (self.graph_inflight >= MAX_GRAPH_INFLIGHT) return false;
        self.graph_inflight += 1;
        return true;
    }

    fn releaseGraph(self: *ApiServer) void {
        self.graph_mutex.lock();
        defer self.graph_mutex.unlock();
        if (self.graph_inflight > 0) self.graph_inflight -= 1;
    }
};

fn handleForkChoiceGraph(
    request: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    ctx: *ApiServer,
    client_addr: std.net.Address,
) !void {
    const chain = ctx.getChain() orelse {
        _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
        return;
    };

    // Per-IP token bucket + global in-flight cap for the graph endpoint.
    if (!ctx.rate_limiter.allow(client_addr)) {
        _ = request.respond("Too Many Requests\n", .{ .status = .too_many_requests }) catch {};
        return;
    }
    if (!ctx.tryAcquireGraph()) {
        _ = request.respond("Too Many Requests\n", .{ .status = .too_many_requests }) catch {};
        return;
    }
    defer ctx.releaseGraph();

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

    try buildGraphJSON(&chain.forkChoice, graph_json.writer(), max_slots, allocator);

    _ = request.respond(graph_json.items, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    }) catch {};
}

/// Build fork choice graph in Grafana node-graph JSON format
fn buildGraphJSON(
    forkchoice: *node_lib.fcFactory.ForkChoice,
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

const RateLimitEntry = struct {
    tokens: f64,
    last_refill_ns: u64,
};

const RateLimiter = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(RateLimitEntry),
    mutex: std.Thread.Mutex = .{},
    last_cleanup_ns: u64 = 0,

    fn init(allocator: std.mem.Allocator) !RateLimiter {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(RateLimitEntry).init(allocator),
        };
    }

    fn deinit(self: *RateLimiter) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    fn allow(self: *RateLimiter, addr: std.net.Address) bool {
        const now_signed = std.time.nanoTimestamp();
        const now: u64 = if (now_signed > 0) @intCast(now_signed) else 0;
        var key_buf: [64]u8 = undefined;
        const key = addrToKey(&key_buf, addr) orelse return true;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.count() > RATE_LIMIT_CLEANUP_THRESHOLD and now - self.last_cleanup_ns > RATE_LIMIT_CLEANUP_COOLDOWN_NS) {
            // Opportunistic TTL cleanup with cooldown to prevent repeated full scans on the hot path.
            self.evictStale(now);
        }

        var entry = self.entries.getPtr(key) orelse blk: {
            const owned_key = self.allocator.dupe(u8, key) catch return true;
            self.entries.putNoClobber(owned_key, .{ .tokens = RATE_LIMIT_BURST, .last_refill_ns = now }) catch {
                self.allocator.free(owned_key);
                return true;
            };
            break :blk self.entries.getPtr(owned_key).?;
        };

        // Refill
        const elapsed_ns = now - entry.last_refill_ns;
        if (elapsed_ns > 0) {
            const refill = (@as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s))) * RATE_LIMIT_RPS;
            entry.tokens = @min(RATE_LIMIT_BURST, entry.tokens + refill);
            entry.last_refill_ns = now;
        }

        if (entry.tokens < 1.0) return false;
        entry.tokens -= 1.0;
        return true;
    }

    fn evictStale(self: *RateLimiter, now: u64) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.last_refill_ns > RATE_LIMIT_STALE_NS) {
                self.allocator.free(entry.key_ptr.*);
                _ = self.entries.remove(entry.key_ptr.*);
            }
        }
        self.last_cleanup_ns = now;
    }
};

fn addrToKey(buf: []u8, addr: std.net.Address) ?[]const u8 {
    return switch (addr.any.family) {
        std.posix.AF.INET => blk: {
            const addr_in = addr.in;
            const bytes = std.mem.asBytes(&addr_in.sa.addr);
            break :blk std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch return null;
        },
        std.posix.AF.INET6 => blk: {
            const addr_in6 = addr.in6;
            const bytes = std.mem.asBytes(&addr_in6.sa.addr);
            break :blk std.fmt.bufPrint(buf, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
                @as(u16, bytes[0]) << 8 | @as(u16, bytes[1]),
                @as(u16, bytes[2]) << 8 | @as(u16, bytes[3]),
                @as(u16, bytes[4]) << 8 | @as(u16, bytes[5]),
                @as(u16, bytes[6]) << 8 | @as(u16, bytes[7]),
                @as(u16, bytes[8]) << 8 | @as(u16, bytes[9]),
                @as(u16, bytes[10]) << 8 | @as(u16, bytes[11]),
                @as(u16, bytes[12]) << 8 | @as(u16, bytes[13]),
                @as(u16, bytes[14]) << 8 | @as(u16, bytes[15]),
            }) catch return null;
        },
        else => null,
    };
}
