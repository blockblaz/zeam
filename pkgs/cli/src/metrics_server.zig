const std = @import("std");
const api = @import("@zeam/api");
const utils_lib = @import("@zeam/utils");
const LoggerConfig = utils_lib.ZeamLoggerConfig;
const ModuleLogger = utils_lib.ModuleLogger;

const ACCEPT_POLL_NS: u64 = 50 * std.time.ns_per_ms;
const STARTUP_POLL_NS: u64 = 1 * std.time.ns_per_ms;

/// Simple metrics server that only serves Prometheus metrics at /metrics endpoint.
/// This is a lightweight server separate from the main API server.
/// It has no rate limiting, SSE support, or chain dependency.
pub fn startMetricsServer(
    allocator: std.mem.Allocator,
    port: u16,
    logger_config: *LoggerConfig,
) !*MetricsServer {
    const logger = logger_config.logger(.metrics_server);

    const ctx = try allocator.create(MetricsServer);
    ctx.* = .{
        .allocator = allocator,
        .port = port,
        .logger = logger,
        .stopped = std.atomic.Value(bool).init(false),
        .startup_status = std.atomic.Value(StartupStatus).init(.pending),
        .thread = undefined,
    };

    ctx.thread = std.Thread.spawn(.{}, MetricsServer.run, .{ctx}) catch |err| {
        allocator.destroy(ctx);
        return err;
    };

    // Wait for thread to report startup result (success or failure)
    while (ctx.startup_status.load(.acquire) == .pending) {
        std.Thread.sleep(STARTUP_POLL_NS);
    }

    // Check if startup failed
    if (ctx.startup_status.load(.acquire) == .failed) {
        ctx.thread.join();
        allocator.destroy(ctx);
        return error.ServerStartupFailed;
    }

    logger.info("Metrics server started on port {d}", .{port});
    return ctx;
}

/// Startup status for synchronizing server thread initialization
const StartupStatus = enum(u8) {
    pending,
    success,
    failed,
};

/// Metrics server context
pub const MetricsServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    logger: ModuleLogger,
    stopped: std.atomic.Value(bool),
    startup_status: std.atomic.Value(StartupStatus),
    thread: std.Thread,

    const Self = @This();

    pub fn stop(self: *Self) void {
        // Use swap to atomically set stopped=true and check if already stopped
        // This prevents double-stop causing undefined behavior (double join/destroy)
        if (self.stopped.swap(true, .seq_cst)) return;
        self.thread.join();
        self.allocator.destroy(self);
    }

    fn run(self: *Self) void {
        const address = std.net.Address.parseIp4("0.0.0.0", self.port) catch |err| {
            self.logger.err("failed to parse server address 0.0.0.0:{d}: {}", .{ self.port, err });
            self.startup_status.store(.failed, .release);
            return;
        };
        var server = address.listen(.{ .reuse_address = true, .force_nonblocking = true }) catch |err| {
            self.logger.err("failed to listen on port {d}: {}", .{ self.port, err });
            self.startup_status.store(.failed, .release);
            return;
        };
        defer server.deinit();

        // Signal successful startup to the spawning thread
        self.startup_status.store(.success, .release);
        self.logger.info("Metrics server listening on http://0.0.0.0:{d}", .{self.port});

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

            self.handleConnection(connection);
        }
    }

    fn handleConnection(self: *Self, connection: std.net.Server.Connection) void {
        defer connection.stream.close();

        const read_buffer = self.allocator.alloc(u8, 4096) catch {
            self.logger.err("failed to allocate read buffer", .{});
            return;
        };
        defer self.allocator.free(read_buffer);
        const write_buffer = self.allocator.alloc(u8, 4096) catch {
            self.logger.err("failed to allocate write buffer", .{});
            return;
        };
        defer self.allocator.free(write_buffer);

        var stream_reader = connection.stream.reader(read_buffer);
        var stream_writer = connection.stream.writer(write_buffer);

        var http_server = std.http.Server.init(stream_reader.interface(), &stream_writer.interface);
        var request = http_server.receiveHead() catch |err| {
            self.logger.warn("failed to receive HTTP head: {}", .{err});
            return;
        };

        if (std.mem.eql(u8, request.head.target, "/metrics")) {
            self.handleMetrics(&request);
        } else {
            _ = request.respond("Not Found\n", .{ .status = .not_found }) catch {};
        }
    }

    /// Handle metrics endpoint - returns Prometheus metrics
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
};
