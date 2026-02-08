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

/// API server that runs in a background thread
/// Handles metrics, SSE events, health checks, forkchoice graph, and checkpoint state endpoints
/// chain is optional - if null, chain-dependent endpoints will return 503
/// (API server starts before chain initialization, so chain may not be available yet)
pub fn startAPIServer(allocator: std.mem.Allocator, port: u16, logger_config: *LoggerConfig, chain: ?*BeamChain) !*ApiServer {
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
        .chain = std.atomic.Value(?*BeamChain).init(chain),
        .stopped = std.atomic.Value(bool).init(false),
        .sse_active = 0,
        .graph_inflight = 0,
        .rate_limiter = rate_limiter,
        .thread = undefined,
    };

    ctx.thread = try std.Thread.spawn(.{}, ApiServer.run, .{ctx});

    logger.info("API server started on port {d}", .{port});
    return ctx;
}

fn routeConnection(connection: std.net.Server.Connection, allocator: std.mem.Allocator, ctx: *ApiServer) void {
    const read_buffer = allocator.alloc(u8, 4096) catch {
        ctx.logger.err("failed to allocate read buffer", .{});
        return;
    };
    defer allocator.free(read_buffer);
    const write_buffer = allocator.alloc(u8, 4096) catch {
        ctx.logger.err("failed to allocate write buffer", .{});
        return;
    };
    defer allocator.free(write_buffer);

    var stream_reader = connection.stream.reader(read_buffer);
    var stream_writer = connection.stream.writer(write_buffer);

    var http_server = std.http.Server.init(stream_reader.interface(), &stream_writer.interface);
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
    } else {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const request_allocator = arena.allocator();

        if (std.mem.eql(u8, request.head.target, "/metrics")) {
            ctx.handleMetrics(&request);
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/health")) {
            ctx.handleHealth(&request);
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/states/finalized")) {
            ctx.handleFinalizedCheckpointState(&request) catch |err| {
                ctx.logger.warn("failed to handle finalized checkpoint state request: {}", .{err});
                _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
            };
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/checkpoints/justified")) {
            ctx.handleJustifiedCheckpoint(&request) catch |err| {
                ctx.logger.warn("failed to handle justified checkpoint request: {}", .{err});
                _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
            };
        } else if (std.mem.startsWith(u8, request.head.target, "/api/forkchoice/graph")) {
            const chain = ctx.getChain() orelse {
                _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
                connection.stream.close();
                return;
            };
            if (!ctx.rate_limiter.allow(connection.address) or !ctx.tryAcquireGraph()) {
                _ = request.respond("Too Many Requests\n", .{ .status = .too_many_requests }) catch {};
            } else {
                defer ctx.releaseGraph();
                handleForkChoiceGraph(&request, request_allocator, chain) catch |err| {
                    ctx.logger.warn("fork choice graph request failed: {}", .{err});
                    _ = request.respond("Internal Server Error\n", .{}) catch {};
                };
            }
        } else {
            _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
        }
    }
    connection.stream.close();
}

/// API server context
pub const ApiServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    logger: ModuleLogger,
    chain: std.atomic.Value(?*BeamChain),
    stopped: std.atomic.Value(bool),
    sse_active: usize,
    graph_inflight: usize,
    rate_limiter: RateLimiter,
    sse_mutex: std.Thread.Mutex = .{},
    graph_mutex: std.Thread.Mutex = .{},
    thread: std.Thread,

    const Self = @This();

    pub fn stop(self: *Self) void {
        self.stopped.store(true, .seq_cst);
        self.thread.join();
        self.rate_limiter.deinit();
        self.allocator.destroy(self);
    }

    pub fn setChain(self: *Self, chain: *BeamChain) void {
        self.chain.store(chain, .release);
    }

    fn getChain(self: *const Self) ?*BeamChain {
        return self.chain.load(.acquire);
    }

    fn run(self: *Self) void {
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
            if (self.stopped.load(.acquire)) break;
            const connection = server.accept() catch |err| {
                if (err == error.WouldBlock) {
                    std.Thread.sleep(ACCEPT_POLL_NS);
                    continue;
                }
                self.logger.warn("failed to accept connection: {}", .{err});
                continue;
            };

            routeConnection(connection, self.allocator, self);
        }

        // Allow active SSE threads to drain before destroying context
        while (blk: {
            self.sse_mutex.lock();
            defer self.sse_mutex.unlock();
            break :blk self.sse_active != 0;
        }) {
            std.Thread.sleep(ACCEPT_POLL_NS);
        }
    }

    /// Handle metrics endpoint
    fn handleMetrics(self: *const Self, request: *std.http.Server.Request) void {
        var allocating_writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer allocating_writer.deinit();

        api.writeMetrics(&allocating_writer.writer) catch {
            _ = request.respond("Internal Server Error\n", .{}) catch {};
            return;
        };

        // Get the written data from the allocating writer
        const written_data = allocating_writer.writer.buffer[0..allocating_writer.writer.end];

        _ = request.respond(written_data, .{
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
        var ssz_output: std.ArrayList(u8) = .empty;
        defer ssz_output.deinit(self.allocator);

        ssz.serialize(types.BeamState, finalized_lean_state.*, &ssz_output, self.allocator) catch |err| {
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
        const chain = self.getChain() orelse {
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
    fn handleSSEEvents(self: *Self, stream: std.net.Stream) !void {
        var registered = false;
        errdefer if (!registered) stream.close();
        // Set SSE headers manually by writing HTTP response
        const sse_headers = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/event-stream\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Access-Control-Allow-Origin: *\r\n" ++
            "Access-Control-Allow-Headers: Cache-Control\r\n" ++
            "\r\n";

        var write_buf: [4096]u8 = undefined;
        var stream_writer = stream.writer(&write_buf);

        // Send initial response with SSE headers
        try stream_writer.interface.writeAll(sse_headers);
        try stream_writer.interface.flush();

        // Send initial connection event
        const connection_event = "event: connection\ndata: {\"status\":\"connected\"}\n\n";
        try stream_writer.interface.writeAll(connection_event);
        try stream_writer.interface.flush();

        // Register this connection with the global event broadcaster
        const connection = try event_broadcaster.addGlobalConnection(stream);
        registered = true;

        // Keep the connection alive - the broadcaster will handle event streaming
        // This thread will stay alive as long as the connection is active
        while (true) {
            if (self.stopped.load(.acquire)) break;
            // Send periodic heartbeat to keep connection alive
            const heartbeat = ": heartbeat\n\n";
            connection.sendRaw(heartbeat) catch |err| {
                self.logger.warn("SSE connection closed: {}", .{err});
                break;
            };

            // Wait between SSE heartbeats
            std.Thread.sleep(constants.SSE_HEARTBEAT_SECONDS * std.time.ns_per_s);
        }
    }

    fn handleSSEConnection(stream: std.net.Stream, ctx: *Self) void {
        ctx.handleSSEEvents(stream) catch |err| {
            ctx.logger.warn("SSE connection failed: {}", .{err});
        };
        event_broadcaster.removeGlobalConnection(stream);
        ctx.releaseSSE();
    }

    fn tryAcquireSSE(self: *Self) bool {
        self.sse_mutex.lock();
        defer self.sse_mutex.unlock();
        // Limit long-lived SSE connections to avoid unbounded threads.
        if (self.sse_active >= MAX_SSE_CONNECTIONS) return false;
        self.sse_active += 1;
        return true;
    }

    fn releaseSSE(self: *Self) void {
        self.sse_mutex.lock();
        defer self.sse_mutex.unlock();
        if (self.sse_active > 0) self.sse_active -= 1;
    }

    fn tryAcquireGraph(self: *Self) bool {
        self.graph_mutex.lock();
        defer self.graph_mutex.unlock();
        // Cap concurrent graph JSON generation.
        if (self.graph_inflight >= MAX_GRAPH_INFLIGHT) return false;
        self.graph_inflight += 1;
        return true;
    }

    fn releaseGraph(self: *Self) void {
        self.graph_mutex.lock();
        defer self.graph_mutex.unlock();
        if (self.graph_inflight > 0) self.graph_inflight -= 1;
    }
};

fn handleForkChoiceGraph(
    request: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    chain: *BeamChain,
) !void {
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

    var graph_json: std.ArrayList(u8) = .empty;
    defer graph_json.deinit(allocator);

    try node_lib.tree_visualizer.buildForkChoiceGraphJSON(&chain.forkChoice, &graph_json, max_slots, allocator);

    _ = request.respond(graph_json.items, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    }) catch {};
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
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.last_refill_ns > RATE_LIMIT_STALE_NS) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
            }
        }
        self.last_cleanup_ns = now;
    }
};

fn addrToKey(buf: []u8, addr: std.net.Address) ?[]const u8 {
    return switch (addr.any.family) {
        std.posix.AF.INET => blk: {
            const addr_in = addr.in;
            // Use @ptrCast to get network-order bytes (big-endian) regardless of host endianness
            const bytes = @as(*const [4]u8, @ptrCast(&addr_in.sa.addr));
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
