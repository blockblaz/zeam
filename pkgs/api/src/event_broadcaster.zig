const std = @import("std");

const types = @import("@zeam/types");

const events = @import("./events.zig");

const Checkpoint = types.Checkpoint;
const Mutex = Thread.Mutex;
const Thread = std.Thread;

/// Maximum size of the SSE send buffer in event_broadcaster.zig. Serialized events
/// must not exceed this to avoid buffer overflow when sending.
pub const sse_send_buffer_size = 512;

/// SSE connection wrapper
pub const SSEConnection = struct {
    stream: std.net.Stream,
    allocator: std.mem.Allocator,
    mutex: Mutex,

    pub fn init(stream: std.net.Stream, allocator: std.mem.Allocator) SSEConnection {
        return SSEConnection{
            .stream = stream,
            .allocator = allocator,
            .mutex = Mutex{},
        };
    }

    pub fn sendEvent(self: *SSEConnection, event_json: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var write_buf: [sse_send_buffer_size]u8 = undefined;
        var writer = self.stream.writer(&write_buf);
        try writer.interface.writeAll(event_json);
        try writer.interface.flush();
    }

    pub fn deinit(self: *SSEConnection) void {
        self.stream.close();
    }
};

/// Thread-safe event broadcaster for SSE connections
pub const EventBroadcaster = struct {
    connections: std.ArrayList(*SSEConnection),
    mutex: Mutex,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .connections = .empty,
            .mutex = Mutex{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |connection| {
            connection.deinit();
            self.allocator.destroy(connection);
        }
        self.connections.deinit(self.allocator);
    }

    /// Add a new SSE connection
    pub fn addConnection(self: *Self, stream: std.net.Stream) !void {
        const connection = try self.allocator.create(SSEConnection);
        connection.* = SSEConnection.init(stream, self.allocator);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.connections.append(self.allocator, connection);
    }

    /// Remove a connection (typically when it's closed)
    pub fn removeConnection(self: *Self, connection: *SSEConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items, 0..) |conn, i| {
            if (conn == connection) {
                _ = self.connections.swapRemove(i);
                connection.deinit();
                self.allocator.destroy(connection);
                break;
            }
        }
    }

    /// Broadcast an event to all connected clients
    pub fn broadcastEvent(self: *Self, event: *events.ChainEvent) !void {
        const event_json = try events.serializeEventToJson(self.allocator, event.*);
        defer {
            event.deinit(self.allocator);
            self.allocator.free(event_json);
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        while (i < self.connections.items.len) {
            const connection = self.connections.items[i];

            // Try to send the event
            connection.sendEvent(event_json) catch |err| {
                // If sending fails, remove the connection
                std.log.warn("Failed to send event to SSE connection: {}", .{err});
                connection.deinit();
                self.allocator.destroy(connection);
                _ = self.connections.swapRemove(i);
                continue;
            };

            i += 1;
        }
    }

    /// Get the number of connected clients
    pub fn getConnectionCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.connections.items.len;
    }
};

// Global broadcaster instance
var global_broadcaster: ?EventBroadcaster = null;
var broadcaster_mutex = Mutex{};

/// Initialize the global event broadcaster
pub fn initGlobalBroadcaster(allocator: std.mem.Allocator) !void {
    broadcaster_mutex.lock();
    defer broadcaster_mutex.unlock();

    if (global_broadcaster == null) {
        global_broadcaster = EventBroadcaster.init(allocator);
    }
}

/// Deinitialize the global event broadcaster
pub fn deinitGlobalBroadcaster() void {
    broadcaster_mutex.lock();
    defer broadcaster_mutex.unlock();

    if (global_broadcaster) |*broadcaster| {
        broadcaster.deinit();
        global_broadcaster = null;
    }
}

/// Get the global broadcaster instance
pub fn getGlobalBroadcaster() ?*EventBroadcaster {
    broadcaster_mutex.lock();
    defer broadcaster_mutex.unlock();

    return if (global_broadcaster) |*broadcaster| broadcaster else null;
}

/// Add a connection to the global broadcaster
pub fn addGlobalConnection(stream: std.net.Stream) !void {
    if (getGlobalBroadcaster()) |broadcaster| {
        try broadcaster.addConnection(stream);
    } else {
        return error.BroadcasterNotInitialized;
    }
}

/// Broadcast an event globally
pub fn broadcastGlobalEvent(event: *events.ChainEvent) !void {
    if (getGlobalBroadcaster()) |broadcaster| {
        try broadcaster.broadcastEvent(event);
    } else {
        return error.BroadcasterNotInitialized;
    }
}

test "event broadcaster basic functionality" {
    const allocator = std.testing.allocator;

    var broadcaster = EventBroadcaster.init(allocator);
    defer broadcaster.deinit();

    // Test initial state
    try std.testing.expect(broadcaster.getConnectionCount() == 0);

    // Use a socket pair so the stream is a real socket (std.net.Stream's writer uses sendmsg, which requires a socket, not a pipe fd).
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    defer std.posix.close(fds[0]); // read end; write end fds[1] is owned by the connection and closed in broadcaster.deinit()

    const stream = std.net.Stream{ .handle = fds[1] };

    // Add connection
    try broadcaster.addConnection(stream);
    try std.testing.expect(broadcaster.getConnectionCount() == 1);

    // Test broadcasting an event (writes to the socket; read end fds[0] is left open so the write succeeds)
    const proto_block = types.ProtoBlock{
        .slot = 123,
        .blockRoot = [_]u8{1} ** 32,
        .parentRoot = [_]u8{2} ** 32,
        .stateRoot = [_]u8{3} ** 32,
        .timeliness = true,
        .confirmed = true,
    };

    const head_event = try events.NewHeadEvent.fromProtoBlock(allocator, proto_block);

    var chain_event = events.ChainEvent{ .new_head = head_event };

    try broadcaster.broadcastEvent(&chain_event);

    try std.testing.expect(broadcaster.getConnectionCount() == 1);
}

test "global broadcaster functionality" {
    const allocator = std.testing.allocator;

    try initGlobalBroadcaster(allocator);
    defer deinitGlobalBroadcaster();

    try std.testing.expect(getGlobalBroadcaster() != null);
    try std.testing.expect(getGlobalBroadcaster().?.getConnectionCount() == 0);

    // Test global event broadcasting
    const checkpoint = Checkpoint{
        .slot = 120,
        .root = [_]u8{5} ** 32,
    };

    const just_event = try events.NewJustificationEvent.fromCheckpoint(allocator, checkpoint, 123);

    var chain_event = events.ChainEvent{ .new_justification = just_event };

    // Should not error even with no connections
    try broadcastGlobalEvent(&chain_event);
}
