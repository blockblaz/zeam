const std = @import("std");
const api = @import("@zeam/api");
const net = std.Io.net;
const constants = @import("constants.zig");
const event_broadcaster = api.event_broadcaster;
const types = @import("@zeam/types");
const ssz = @import("ssz");
const utils_lib = @import("@zeam/utils");
const LoggerConfig = utils_lib.ZeamLoggerConfig;
const ModuleLogger = utils_lib.ModuleLogger;
const node_lib = @import("@zeam/node");
const BeamChain = node_lib.BeamChain;
const zeam_metrics = @import("@zeam/metrics");

// Max bytes accepted for an admin POST body. The only body we currently
// parse is `{"enabled": true|false}`, which is well under this limit.
const ADMIN_BODY_MAX_BYTES: usize = 1024;

const QUERY_SLOTS_PREFIX = "?slots=";
const DEFAULT_MAX_SLOTS: usize = 50;
const MAX_ALLOWED_SLOTS: usize = 200;
const ACCEPT_POLL_NS: u64 = 50 * std.time.ns_per_ms;
const STARTUP_POLL_NS: u64 = 1 * std.time.ns_per_ms;
// Conservative defaults for a local metrics server.
const MAX_SSE_CONNECTIONS: usize = 32;
const MAX_GRAPH_INFLIGHT: usize = 2;
const RATE_LIMIT_RPS: f64 = 2.0;
const RATE_LIMIT_BURST: f64 = 5.0;
const RATE_LIMIT_MAX_ENTRIES: usize = 256; // Max tracked IPs to bound memory.
const RATE_LIMIT_CLEANUP_THRESHOLD: usize = RATE_LIMIT_MAX_ENTRIES / 2; // Trigger lazy cleanup.
const RATE_LIMIT_STALE_NS: u64 = 10 * std.time.ns_per_min; // Evict entries idle past TTL.
const RATE_LIMIT_CLEANUP_COOLDOWN_NS: u64 = 60 * std.time.ns_per_s;

/// Startup status for synchronizing server thread initialization
const StartupStatus = enum(u8) {
    pending,
    success,
    failed,
};

/// API server that runs in a background thread
/// Handles SSE events, health checks, forkchoice graph, and checkpoint state endpoints
/// chain is optional - if null, chain-dependent endpoints will return 503
/// (API server starts before chain initialization, so chain may not be available yet)
/// Note: Metrics are served by the separate metrics_server on a different port
pub fn startAPIServer(allocator: std.mem.Allocator, port: u16, logger_config: *LoggerConfig, chain: ?*BeamChain) !*ApiServer {
    // Initialize the global event broadcaster for SSE events
    // This is idempotent - safe to call even if already initialized elsewhere (e.g., node.zig)
    try event_broadcaster.initGlobalBroadcaster(allocator);

    var rate_limiter = try RateLimiter.init(allocator);

    // Create a logger instance for the API server
    const logger = logger_config.logger(.api_server);

    // Create the API server context
    const ctx = allocator.create(ApiServer) catch |err| {
        rate_limiter.deinit();
        return err;
    };
    ctx.* = .{
        .allocator = allocator,
        .port = port,
        .logger = logger,
        .chain = std.atomic.Value(?*BeamChain).init(chain),
        .stopped = std.atomic.Value(bool).init(false),
        .startup_status = std.atomic.Value(StartupStatus).init(.pending),
        .sse_active = 0,
        .graph_inflight = 0,
        .rate_limiter = rate_limiter,
        .thread = undefined,
    };

    ctx.thread = std.Thread.spawn(.{}, ApiServer.run, .{ctx}) catch |err| {
        rate_limiter.deinit();
        allocator.destroy(ctx);
        return err;
    };

    // Wait for thread to report startup result (success or failure)
    while (ctx.startup_status.load(.acquire) == .pending) {
        utils_lib.sleepNs(STARTUP_POLL_NS);
    }

    // Check if startup failed
    if (ctx.startup_status.load(.acquire) == .failed) {
        ctx.thread.join();
        rate_limiter.deinit();
        allocator.destroy(ctx);
        return error.ServerStartupFailed;
    }

    logger.info("API server started on port {d}", .{port});
    return ctx;
}

fn routeConnection(io: std.Io, connection: net.Stream, allocator: std.mem.Allocator, ctx: *ApiServer) void {
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

    var stream_reader = connection.reader(io, read_buffer);
    var stream_writer = connection.writer(io, write_buffer);

    var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    var request = http_server.receiveHead() catch |err| {
        ctx.logger.warn("failed to receive HTTP head: {}", .{err});
        connection.close(io);
        return;
    };

    if (std.mem.eql(u8, request.head.target, "/events")) {
        if (!ctx.tryAcquireSSE()) {
            _ = request.respond("Service Unavailable\n", .{ .status = .service_unavailable }) catch {};
            connection.close(io);
            return;
        }
        _ = std.Thread.spawn(.{}, ApiServer.handleSSEConnection, .{ connection, ctx }) catch |err| {
            ctx.logger.warn("failed to spawn SSE handler: {}", .{err});
            ctx.releaseSSE();
            connection.close(io);
        };
        return;
    } else {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const request_allocator = arena.allocator();

        if (std.mem.eql(u8, request.head.target, "/lean/v0/health")) {
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
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/fork_choice")) {
            ctx.handleForkChoice(&request, request_allocator) catch |err| {
                ctx.logger.warn("failed to handle fork choice request: {}", .{err});
                _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
            };
        } else if (std.mem.eql(u8, request.head.target, "/lean/v0/admin/aggregator")) {
            ctx.handleAggregatorAdmin(&request, request_allocator) catch |err| {
                ctx.logger.warn("failed to handle aggregator admin request: {}", .{err});
                _ = request.respond("Internal Server Error\n", .{ .status = .internal_server_error }) catch {};
            };
        } else if (std.mem.startsWith(u8, request.head.target, "/api/forkchoice/graph")) {
            const chain = ctx.getChain() orelse {
                _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
                connection.close(io);
                return;
            };
            if (!ctx.rate_limiter.allow(connection.socket.address) or !ctx.tryAcquireGraph()) {
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
    connection.close(io);
}

/// API server context
pub const ApiServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    logger: ModuleLogger,
    chain: std.atomic.Value(?*BeamChain),
    stopped: std.atomic.Value(bool),
    startup_status: std.atomic.Value(StartupStatus),
    sse_active: usize,
    graph_inflight: usize,
    rate_limiter: RateLimiter,
    sse_mutex: utils_lib.SyncMutex = .{},
    graph_mutex: utils_lib.SyncMutex = .{},
    thread: std.Thread,

    const Self = @This();

    pub fn stop(self: *Self) void {
        // Use swap to atomically set stopped=true and check if already stopped
        // This prevents double-stop causing undefined behavior (double join/destroy)
        if (self.stopped.swap(true, .seq_cst)) return;
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
        const io = std.Io.Threaded.global_single_threaded.io();
        const address = net.IpAddress.parseIp4("0.0.0.0", self.port) catch |err| {
            self.logger.err("failed to parse server address 0.0.0.0:{d}: {}", .{ self.port, err });
            self.startup_status.store(.failed, .release);
            return;
        };
        var server = address.listen(io, .{ .reuse_address = true }) catch |err| {
            self.logger.err("failed to listen on port {d}: {}", .{ self.port, err });
            self.startup_status.store(.failed, .release);
            return;
        };
        defer server.deinit(io);

        // Signal successful startup to the spawning thread
        self.startup_status.store(.success, .release);
        self.logger.info("API server listening on http://0.0.0.0:{d}", .{self.port});

        while (true) {
            if (self.stopped.load(.acquire)) break;
            const connection = server.accept(io) catch |err| {
                if (err == error.WouldBlock) {
                    utils_lib.sleepNs(ACCEPT_POLL_NS);
                    continue;
                }
                self.logger.warn("failed to accept connection: {}", .{err});
                continue;
            };

            routeConnection(io, connection, self.allocator, self);
        }

        // Allow active SSE threads to drain before destroying context
        while (blk: {
            self.sse_mutex.lock();
            defer self.sse_mutex.unlock();
            break :blk self.sse_active != 0;
        }) {
            utils_lib.sleepNs(ACCEPT_POLL_NS);
        }
    }

    /// Handle health check endpoint
    fn handleHealth(_: *const Self, request: *std.http.Server.Request) void {
        const response = "{\"status\":\"healthy\",\"service\":\"lean-rpc-api\"}";
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

        // Get finalized state from chain. After slice (a-2) the chain
        // returns a `BorrowedState` (see `pkgs/node/src/locking.zig`)
        // whose backing lock is held until `deinit()` runs — keep the
        // borrow alive only as long as we read `state`. Serialise into
        // an owned `ArrayList(u8)` first, then drop the borrow before
        // doing any HTTP I/O so we do not hold the lock across a network
        // write.
        var finalized_borrow = chain.getFinalizedState() orelse {
            _ = request.respond("Not Found: Finalized checkpoint lean state not available\n", .{ .status = .not_found }) catch {};
            return;
        };
        // assertReleasedOrPanic registered FIRST so it runs LAST (LIFO):
        // by the time it runs, the deinit defer has already set
        // `released = true`. Catches a future helper that bypasses
        // deinit. PR #820 / issue #803.
        defer finalized_borrow.assertReleasedOrPanic();
        defer finalized_borrow.deinit();

        // Serialize lean state (BeamState) to SSZ
        var ssz_output: std.ArrayList(u8) = .empty;
        defer ssz_output.deinit(self.allocator);

        ssz.serialize(types.BeamState, finalized_borrow.state.*, &ssz_output, self.allocator) catch |err| {
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

    /// Handle fork choice endpoint
    /// Returns full fork choice state as JSON at /lean/v0/fork_choice
    /// Includes head, justified, finalized checkpoints, safe target, and all proto nodes
    fn handleForkChoice(self: *const Self, request: *std.http.Server.Request, allocator: std.mem.Allocator) !void {
        const chain = self.getChain() orelse {
            _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
            return;
        };

        const snapshot = chain.forkChoice.snapshot(allocator) catch |err| {
            self.logger.err("failed to get fork choice snapshot: {}", .{err});
            _ = request.respond("Internal Server Error: Snapshot failed\n", .{ .status = .internal_server_error }) catch {};
            return;
        };
        defer snapshot.deinit(allocator);

        var json_output: std.ArrayList(u8) = .empty;
        defer json_output.deinit(allocator);

        node_lib.tree_visualizer.buildForkChoiceJSON(snapshot, &json_output, allocator) catch |err| {
            self.logger.err("failed to build fork choice JSON: {}", .{err});
            _ = request.respond("Internal Server Error: JSON serialization failed\n", .{ .status = .internal_server_error }) catch {};
            return;
        };

        _ = request.respond(json_output.items, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch |err| {
            self.logger.warn("failed to respond with fork choice: {}", .{err});
            return err;
        };
    }

    /// Handle aggregator role admin endpoint at /lean/v0/admin/aggregator.
    ///
    /// GET returns `{"is_aggregator": <bool>}` with the node's current role.
    ///
    /// POST expects `{"enabled": <bool>}` and returns
    /// `{"is_aggregator": <new>, "previous": <old>}`. The flag is flipped
    /// atomically on the chain; the gossip import path and the tick-driven
    /// aggregator path pick up the new value on their next read.
    ///
    /// Scope matches leanEthereum/leanSpec#636: this toggle does not change
    /// gossip subnet subscriptions (those are decided once at startup) and
    /// is not persisted across restarts. Use the CLI `--is-aggregator` flag
    /// to seed the value on each start.
    fn handleAggregatorAdmin(self: *const Self, request: *std.http.Server.Request, allocator: std.mem.Allocator) !void {
        const chain = self.getChain() orelse {
            _ = request.respond("Service Unavailable: Chain not initialized\n", .{ .status = .service_unavailable }) catch {};
            return;
        };

        switch (request.head.method) {
            .GET => {
                var buf: [64]u8 = undefined;
                const body = try std.fmt.bufPrint(&buf, "{{\"is_aggregator\":{s}}}", .{boolToJson(chain.isAggregator())});
                _ = request.respond(body, .{
                    .extra_headers = &.{
                        .{ .name = "content-type", .value = "application/json; charset=utf-8" },
                    },
                }) catch {};
            },
            .POST => try self.handleAggregatorPost(request, allocator, chain),
            else => {
                _ = request.respond("Method Not Allowed\n", .{
                    .status = .method_not_allowed,
                    .extra_headers = &.{
                        .{ .name = "allow", .value = "GET, POST" },
                    },
                }) catch {};
            },
        }
    }

    fn handleAggregatorPost(
        self: *const Self,
        request: *std.http.Server.Request,
        allocator: std.mem.Allocator,
        chain: *BeamChain,
    ) !void {
        // Require a content-length header and bound it; admin toggle bodies
        // are tiny (roughly `{"enabled":false}` = 17 bytes). Reading past the
        // declared length trips a state-machine assertion in std.http once
        // the reader has transitioned to `.ready`.
        const content_length = request.head.content_length orelse {
            _ = request.respond("Bad Request: content-length required\n", .{ .status = .bad_request }) catch {};
            return;
        };
        if (content_length == 0) {
            _ = request.respond("Bad Request: missing body\n", .{ .status = .bad_request }) catch {};
            return;
        }
        if (content_length > ADMIN_BODY_MAX_BYTES) {
            _ = request.respond("Payload Too Large\n", .{ .status = .payload_too_large }) catch {};
            return;
        }

        var body_buf: [ADMIN_BODY_MAX_BYTES]u8 = undefined;
        const reader = request.readerExpectContinue(&body_buf) catch {
            _ = request.respond("Bad Request: could not read body\n", .{ .status = .bad_request }) catch {};
            return;
        };

        const len: usize = @intCast(content_length);
        const body_bytes = try allocator.alloc(u8, len);
        defer allocator.free(body_bytes);
        var read_total: usize = 0;
        while (read_total < len) {
            const n = reader.readSliceShort(body_bytes[read_total..]) catch {
                _ = request.respond("Bad Request: body read failed\n", .{ .status = .bad_request }) catch {};
                return;
            };
            if (n == 0) break;
            read_total += n;
        }
        if (read_total != len) {
            _ = request.respond("Bad Request: short body\n", .{ .status = .bad_request }) catch {};
            return;
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, body_bytes, .{}) catch {
            _ = request.respond("Bad Request: invalid JSON\n", .{ .status = .bad_request }) catch {};
            return;
        };
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => {
                _ = request.respond("Bad Request: expected JSON object\n", .{ .status = .bad_request }) catch {};
                return;
            },
        };

        const enabled_field = obj.get("enabled") orelse {
            _ = request.respond("Bad Request: missing 'enabled' field\n", .{ .status = .bad_request }) catch {};
            return;
        };

        const enabled = switch (enabled_field) {
            .bool => |b| b,
            else => {
                _ = request.respond("Bad Request: 'enabled' must be a boolean\n", .{ .status = .bad_request }) catch {};
                return;
            },
        };

        self.logger.info("admin API: POST /lean/v0/admin/aggregator enabled={any}", .{enabled});
        const previous = chain.setAggregator(enabled);
        zeam_metrics.metrics.lean_is_aggregator.set(if (enabled) 1 else 0);

        var buf: [128]u8 = undefined;
        const body = try std.fmt.bufPrint(
            &buf,
            "{{\"is_aggregator\":{s},\"previous\":{s}}}",
            .{ boolToJson(enabled), boolToJson(previous) },
        );
        _ = request.respond(body, .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            },
        }) catch {};
    }

    /// Handle SSE events endpoint
    fn handleSSEEvents(self: *Self, stream: net.Stream) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        var registered = false;
        errdefer if (!registered) stream.close(io);
        // Set SSE headers manually by writing HTTP response
        const sse_headers = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/event-stream\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Access-Control-Allow-Origin: *\r\n" ++
            "Access-Control-Allow-Headers: Cache-Control\r\n" ++
            "\r\n";

        var write_buf: [4096]u8 = undefined;
        var stream_writer = stream.writer(io, &write_buf);

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
            utils_lib.sleepNs(constants.SSE_HEARTBEAT_SECONDS * std.time.ns_per_s);
        }
    }

    fn handleSSEConnection(stream: net.Stream, ctx: *Self) void {
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
    mutex: utils_lib.SyncMutex = .{},
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

    fn allow(self: *RateLimiter, addr: net.IpAddress) bool {
        const now_signed = utils_lib.monotonicTimestampNs();
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

inline fn boolToJson(b: bool) []const u8 {
    return if (b) "true" else "false";
}

fn addrToKey(buf: []u8, addr: net.IpAddress) ?[]const u8 {
    return switch (addr) {
        .ip4 => |ip4| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            ip4.bytes[0],
            ip4.bytes[1],
            ip4.bytes[2],
            ip4.bytes[3],
        }) catch null,
        .ip6 => |ip6| std.fmt.bufPrint(buf, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
            @as(u16, ip6.bytes[0]) << 8 | @as(u16, ip6.bytes[1]),
            @as(u16, ip6.bytes[2]) << 8 | @as(u16, ip6.bytes[3]),
            @as(u16, ip6.bytes[4]) << 8 | @as(u16, ip6.bytes[5]),
            @as(u16, ip6.bytes[6]) << 8 | @as(u16, ip6.bytes[7]),
            @as(u16, ip6.bytes[8]) << 8 | @as(u16, ip6.bytes[9]),
            @as(u16, ip6.bytes[10]) << 8 | @as(u16, ip6.bytes[11]),
            @as(u16, ip6.bytes[12]) << 8 | @as(u16, ip6.bytes[13]),
            @as(u16, ip6.bytes[14]) << 8 | @as(u16, ip6.bytes[15]),
        }) catch null,
    };
}
