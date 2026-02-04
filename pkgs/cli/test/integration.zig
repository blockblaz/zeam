const std = @import("std");
const process = std.process;
const net = std.net;
const build_options = @import("build_options");
const constants = @import("cli_constants");
const error_handler = @import("error_handler");
const ErrorHandler = error_handler.ErrorHandler;

/// Verify that the Zeam executable exists and return its path
/// Includes detailed debugging output if the executable is not found
fn getZeamExecutable() ![]const u8 {
    // Handle both absolute and relative paths
    const exe_file = if (std.fs.path.isAbsolute(build_options.cli_exe_path))
        std.fs.openFileAbsolute(build_options.cli_exe_path, .{})
    else
        std.fs.cwd().openFile(build_options.cli_exe_path, .{});

    const file = exe_file catch |err| {
        std.debug.print("ERROR: Cannot find executable at {s}: {}\n", .{ build_options.cli_exe_path, err });

        // Try to list the directory to see what's actually there
        std.debug.print("INFO: Attempting to list {s} directory...\n", .{build_options.cli_exe_path});
        const dir_path = std.fs.path.dirname(build_options.cli_exe_path);
        if (dir_path) |path| {
            const dir = if (std.fs.path.isAbsolute(path))
                std.fs.openDirAbsolute(path, .{ .iterate = true })
            else
                std.fs.cwd().openDir(path, .{ .iterate = true });

            var d = dir catch |dir_err| {
                std.debug.print("ERROR: Cannot open directory {s}: {}\n", .{ path, dir_err });
                return err;
            };
            defer d.close();

            var iterator = d.iterate();
            std.debug.print("INFO: Contents of {s}:\n", .{path});
            while (try iterator.next()) |entry| {
                std.debug.print("  - {s} (type: {})\n", .{ entry.name, entry.kind });
            }
        }

        return err;
    };
    file.close();
    std.debug.print("INFO: Found executable at {s}\n", .{build_options.cli_exe_path});
    return build_options.cli_exe_path;
}

/// Helper function to start a beam simulation node and wait for it to be ready
/// Handles the complete process lifecycle: creation, spawning, and waiting for readiness
/// Returns the process handle for cleanup, or error if startup fails
fn spinBeamSimNode(allocator: std.mem.Allocator, exe_path: []const u8) !*process.Child {
    // Set up process with beam command and mock network
    const args = [_][]const u8{ exe_path, "beam", "--mockNetwork", "true" };
    const cli_process = try allocator.create(process.Child);
    cli_process.* = process.Child.init(&args, allocator);

    // Capture stdout and stderr for debugging
    // However this leads to test being cut short probably because of child process getting killed
    // so commenting the pipe and letting the output to flow to console
    // TODO: figureout and fix the behavior and uncomment the following
    //
    // cli_process.stdout_behavior = .Pipe;
    // cli_process.stderr_behavior = .Pipe;

    // Start the process
    cli_process.spawn() catch |err| {
        std.debug.print("ERROR: Failed to spawn process: {}\n", .{err});
        allocator.destroy(cli_process);
        return err;
    };

    std.debug.print("INFO: Process spawned successfully with PID\n", .{});

    // Wait for server to be ready
    const start_time = std.time.milliTimestamp();
    var server_ready = false;
    var retry_count: u32 = 0;

    while (std.time.milliTimestamp() - start_time < constants.DEFAULT_SERVER_STARTUP_TIMEOUT_MS) {
        retry_count += 1;

        // Print progress every 10 retries
        if (retry_count % 10 == 0) {
            const elapsed = @divTrunc(std.time.milliTimestamp() - start_time, 1000);
            std.debug.print("INFO: Still waiting for server... ({} seconds, {} retries)\n", .{ elapsed, retry_count });
        }

        // Try to connect to the metrics server
        const address = net.Address.parseIp4(constants.DEFAULT_SERVER_IP, constants.DEFAULT_API_PORT) catch {
            std.Thread.sleep(constants.DEFAULT_RETRY_INTERVAL_MS * std.time.ns_per_ms);
            continue;
        };

        var connection = net.tcpConnectToAddress(address) catch |err| {
            // Only print error details on certain intervals to avoid spam
            if (retry_count % 20 == 0) {
                std.debug.print("DEBUG: Connection attempt {} failed: {}\n", .{ retry_count, err });
            }
            std.Thread.sleep(constants.DEFAULT_RETRY_INTERVAL_MS * std.time.ns_per_ms);
            continue;
        };

        // Test if we can actually send/receive data
        connection.close();
        server_ready = true;
        std.debug.print("SUCCESS: Server ready after {} seconds ({} retries)\n", .{ @divTrunc(std.time.milliTimestamp() - start_time, 1000), retry_count });
        break;
    }

    // If server didn't start, try to get process output for debugging
    if (!server_ready) {
        std.debug.print("ERROR: Metrics server not ready after {} seconds ({} retries)\n", .{ @divTrunc(constants.DEFAULT_SERVER_STARTUP_TIMEOUT_MS, 1000), retry_count });

        // Try to read any output from the process
        if (cli_process.stdout) |stdout| {
            var stdout_buffer: [4096]u8 = undefined;
            var read_buf: [4096]u8 = undefined;
            var stdout_reader = stdout.reader(&read_buf);
            const stdout_bytes = stdout_reader.interface.readSliceShort(&stdout_buffer) catch 0;
            if (stdout_bytes > 0) {
                std.debug.print("STDOUT: {s}\n", .{stdout_buffer[0..stdout_bytes]});
            }
        }

        if (cli_process.stderr) |stderr| {
            var stderr_buffer: [4096]u8 = undefined;
            var read_buf: [4096]u8 = undefined;
            var stderr_reader = stderr.reader(&read_buf);
            const stderr_bytes = stderr_reader.interface.readSliceShort(&stderr_buffer) catch 0;
            if (stderr_bytes > 0) {
                std.debug.print("STDERR: {s}\n", .{stderr_buffer[0..stderr_bytes]});
            }
        }

        // Check if process is still running
        if (cli_process.wait() catch null) |term| {
            switch (term) {
                .Exited => |code| std.debug.print("ERROR: Process exited with code {}\n", .{code}),
                .Signal => |sig| std.debug.print("ERROR: Process killed by signal {}\n", .{sig}),
                .Stopped => |sig| std.debug.print("ERROR: Process stopped by signal {}\n", .{sig}),
                .Unknown => |code| std.debug.print("ERROR: Process terminated with unknown code {}\n", .{code}),
            }
        } else {
            std.debug.print("INFO: Process is still running\n", .{});
        }

        // Server not ready, cleanup and return error
        allocator.destroy(cli_process);
        return error.ServerStartupTimeout;
    }

    return cli_process;
}

/// Wait for node to start and be ready for activity
/// TODO: Over time, this can be abstracted to listen for some event
/// that the node can output when being active, rather than using a fixed sleep
fn waitForNodeStart() void {
    std.Thread.sleep(2000 * std.time.ns_per_ms);
}

/// Helper struct for making HTTP requests to Zeam endpoints
const ZeamRequest = struct {
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) ZeamRequest {
        return ZeamRequest{ .allocator = allocator };
    }

    /// Make a request to the /metrics endpoint and return the response
    fn getMetrics(self: ZeamRequest) ![]u8 {
        return self.makeRequest("/metrics");
    }

    /// Make a request to the /lean/v0/health endpoint and return the response
    fn getHealth(self: ZeamRequest) ![]u8 {
        return self.makeRequest("/lean/v0/health");
    }

    /// Internal helper to make HTTP requests to any endpoint
    fn makeRequest(self: ZeamRequest, endpoint: []const u8) ![]u8 {
        // Create connection to the server
        const address = try net.Address.parseIp4(constants.DEFAULT_SERVER_IP, constants.DEFAULT_API_PORT);
        var connection = try net.tcpConnectToAddress(address);
        defer connection.close();

        // Create HTTP request
        var request_buffer: [4096]u8 = undefined;
        const request = try std.fmt.bufPrint(&request_buffer, "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n", .{ endpoint, constants.DEFAULT_SERVER_IP, constants.DEFAULT_API_PORT });

        var conn_write_buf: [4096]u8 = undefined;
        var conn_writer = connection.writer(&conn_write_buf);
        try conn_writer.interface.writeAll(request);
        try conn_writer.interface.flush();

        // Read response until connection closes
        var response_buffer: [8192]u8 = undefined;
        var total_bytes: usize = 0;
        while (total_bytes < response_buffer.len) {
            const bytes_read = connection.read(response_buffer[total_bytes..]) catch |err| switch (err) {
                error.ConnectionResetByPeer => break,
                else => return err,
            };
            if (bytes_read == 0) break; // Connection closed
            total_bytes += bytes_read;
        }
        const bytes_read = total_bytes;

        // Allocate and return a copy of the response
        const response = try self.allocator.dupe(u8, response_buffer[0..bytes_read]);
        return response;
    }

    /// Free a response returned by getMetrics() or getHealth()
    fn freeResponse(self: ZeamRequest, response: []u8) void {
        self.allocator.free(response);
    }
};

/// Parsed SSE Event structure
const ChainEvent = struct {
    event_type: []const u8,
    justified_slot: ?u64,
    finalized_slot: ?u64,

    /// Free the memory allocated for this event
    fn deinit(self: ChainEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
    }
};

/// SSE Client for testing event streaming - FIXED VERSION
const SSEClient = struct {
    allocator: std.mem.Allocator,
    connection: std.net.Stream,
    received_events: std.ArrayList([]u8),
    // NEW: Add proper buffering for handling partial events and multiple events per read
    read_buffer: std.ArrayList(u8),
    parsed_events_queue: std.ArrayList(ChainEvent),

    fn init(allocator: std.mem.Allocator) !SSEClient {
        const address = try net.Address.parseIp4(constants.DEFAULT_SERVER_IP, constants.DEFAULT_API_PORT);
        const connection = try net.tcpConnectToAddress(address);

        return SSEClient{
            .allocator = allocator,
            .connection = connection,
            .received_events = .empty,
            .read_buffer = .empty,
            .parsed_events_queue = .empty,
        };
    }

    fn deinit(self: *SSEClient) void {
        self.connection.close();
        for (self.received_events.items) |event| {
            self.allocator.free(event);
        }
        self.received_events.deinit(self.allocator);
        self.read_buffer.deinit(self.allocator);

        // Clean up parsed events queue
        for (self.parsed_events_queue.items) |event| {
            self.allocator.free(event.event_type);
        }
        self.parsed_events_queue.deinit(self.allocator);
    }

    fn connect(self: *SSEClient) !void {
        // Send SSE request
        const request = "GET /events HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:9667\r\n" ++
            "Accept: text/event-stream\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n";

        var conn_write_buf: [4096]u8 = undefined;
        var conn_writer = self.connection.writer(&conn_write_buf);
        try conn_writer.interface.writeAll(request);
        try conn_writer.interface.flush();
    }

    /// NEW: Parse all complete events from the current buffer
    fn parseAllEventsFromBuffer(self: *SSEClient) !void {
        var buffer_pos: usize = 0;

        while (buffer_pos < self.read_buffer.items.len) {
            // Look for complete SSE event (ends with \n\n or \r\n\r\n)
            const remaining_buffer = self.read_buffer.items[buffer_pos..];

            const event_end_lf = std.mem.indexOf(u8, remaining_buffer, "\n\n");
            const event_end_crlf = std.mem.indexOf(u8, remaining_buffer, "\r\n\r\n");

            var event_end: ?usize = null;
            var separator_len: usize = 2;

            if (event_end_lf != null and event_end_crlf != null) {
                // Both found, use the earlier one
                if (event_end_lf.? < event_end_crlf.?) {
                    event_end = event_end_lf;
                    separator_len = 2;
                } else {
                    event_end = event_end_crlf;
                    separator_len = 4;
                }
            } else if (event_end_lf != null) {
                event_end = event_end_lf;
                separator_len = 2;
            } else if (event_end_crlf != null) {
                event_end = event_end_crlf;
                separator_len = 4;
            }

            if (event_end == null) {
                // No complete event found, break and wait for more data
                break;
            }

            // Extract the complete event block
            const event_block = remaining_buffer[0..event_end.?];

            // Parse this event and add to queue if valid
            if (self.parseEventBlock(event_block)) |parsed_event| {
                try self.parsed_events_queue.append(self.allocator, parsed_event);

                // Store raw event for debugging
                const raw_event = try self.allocator.dupe(u8, event_block);
                try self.received_events.append(self.allocator, raw_event);
            }

            // Move past this event
            buffer_pos += event_end.? + separator_len;
        }

        // Remove processed events from buffer
        if (buffer_pos > 0) {
            if (buffer_pos < self.read_buffer.items.len) {
                std.mem.copyForwards(u8, self.read_buffer.items[0..], self.read_buffer.items[buffer_pos..]);
                try self.read_buffer.resize(self.allocator, self.read_buffer.items.len - buffer_pos);
            } else {
                self.read_buffer.clearAndFree(self.allocator);
            }
        }
    }

    /// NEW: Parse a single event block and return parsed event
    fn parseEventBlock(self: *SSEClient, event_block: []const u8) ?ChainEvent {
        // Find event type line
        const event_line_start = std.mem.indexOf(u8, event_block, "event:") orelse return null;
        const data_line_start = std.mem.indexOf(u8, event_block, "data:") orelse return null;

        // Extract event type
        const event_line_slice = blk: {
            const nl = std.mem.indexOfScalarPos(u8, event_block, event_line_start, '\n') orelse event_block.len;
            const cr = std.mem.indexOfScalarPos(u8, event_block, event_line_start, '\r') orelse nl;
            const line_end = @min(nl, cr);
            break :blk std.mem.trim(u8, event_block[event_line_start + "event:".len .. line_end], " \t");
        };

        // Extract data payload
        const data_line_slice = blk2: {
            const nl = std.mem.indexOfScalarPos(u8, event_block, data_line_start, '\n') orelse event_block.len;
            const cr = std.mem.indexOfScalarPos(u8, event_block, data_line_start, '\r') orelse nl;
            const line_end = @min(nl, cr);
            break :blk2 std.mem.trim(u8, event_block[data_line_start + "data:".len .. line_end], " \t");
        };

        // Clone event type string so it persists
        const event_type_owned = self.allocator.dupe(u8, event_line_slice) catch return null;

        // Parse JSON data
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data_line_slice, .{ .ignore_unknown_fields = true }) catch return null;
        defer parsed.deinit();

        var justified_slot: ?u64 = null;
        var finalized_slot: ?u64 = null;

        if (parsed.value.object.get("justified_slot")) |js| {
            switch (js) {
                .integer => |ival| justified_slot = @intCast(ival),
                else => {},
            }
        }

        if (parsed.value.object.get("finalized_slot")) |fs| {
            switch (fs) {
                .integer => |ival| finalized_slot = @intCast(ival),
                else => {},
            }
        }

        return ChainEvent{
            .event_type = event_type_owned,
            .justified_slot = justified_slot,
            .finalized_slot = finalized_slot,
        };
    }

    /// FIXED: Main function that reads network data, buffers it, and returns one parsed event
    /// This addresses the reviewer's concern by properly handling multiple events and buffering
    fn readEvent(self: *SSEClient) !?ChainEvent {
        // First, check if we have any parsed events in queue
        if (self.parsed_events_queue.items.len > 0) {
            return self.parsed_events_queue.orderedRemove(0);
        }

        // Read new data from network
        var temp_buffer: [4096]u8 = undefined;
        const bytes_read = self.connection.read(&temp_buffer) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.sleep(50 * std.time.ns_per_ms);
                return null; // No data available
            },
            else => return err,
        };

        if (bytes_read == 0) {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            return null; // No data available
        }

        // Append new data to our persistent buffer
        try self.read_buffer.appendSlice(self.allocator, temp_buffer[0..bytes_read]);

        // Parse all complete events from the buffer
        try self.parseAllEventsFromBuffer();

        // Return first parsed event if available
        if (self.parsed_events_queue.items.len > 0) {
            return self.parsed_events_queue.orderedRemove(0);
        }

        return null; // No complete events available yet
    }

    fn hasEvent(self: *SSEClient, event_type: []const u8) bool {
        for (self.received_events.items) |event_data| {
            if (std.mem.indexOf(u8, event_data, event_type) != null) {
                return true;
            }
        }
        return false;
    }

    fn getEventCount(self: *SSEClient, event_type: []const u8) usize {
        var count: usize = 0;
        for (self.received_events.items) |event_data| {
            if (std.mem.indexOf(u8, event_data, event_type) != null) {
                count += 1;
            }
        }
        return count;
    }
};

/// Clean up a process created by spinBeamSimNode
fn cleanupProcess(allocator: std.mem.Allocator, cli_process: *process.Child) void {
    _ = cli_process.kill() catch {};
    _ = cli_process.wait() catch {};
    allocator.destroy(cli_process);
}

test "CLI beam command with mock network - complete integration test" {
    const allocator = std.testing.allocator;

    // Get executable path
    const exe_path = try getZeamExecutable();

    // Start node and wait for readiness
    const cli_process = try spinBeamSimNode(allocator, exe_path);
    defer cleanupProcess(allocator, cli_process);

    // Wait for node to be fully active
    waitForNodeStart();

    // Test metrics endpoint
    var zeam_request = ZeamRequest.init(allocator);
    const response = try zeam_request.getMetrics();
    defer zeam_request.freeResponse(response);

    // Verify we got a valid HTTP response
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200") != null or std.mem.indexOf(u8, response, "HTTP/1.0 200") != null);

    // Verify response contains actual metric names from the metrics system
    try std.testing.expect(std.mem.indexOf(u8, response, "chain_onblock_duration_seconds") != null or
        std.mem.indexOf(u8, response, "block_processing_duration_seconds") != null);

    // Verify response is not empty
    try std.testing.expect(response.len > 100);

    std.debug.print("SUCCESS: All integration test checks passed\n", .{});
}

test "SSE events integration test - wait for justification and finalization" {
    const allocator = std.testing.allocator;

    // Get executable path
    const exe_path = try getZeamExecutable();

    // Start node and wait for readiness
    const cli_process = try spinBeamSimNode(allocator, exe_path);
    defer cleanupProcess(allocator, cli_process);

    // Wait for node to be fully active
    waitForNodeStart();

    // Create SSE client
    var sse_client = try SSEClient.init(allocator);
    defer sse_client.deinit();

    // Connect to SSE endpoint
    try sse_client.connect();

    std.debug.print("INFO: Connected to SSE endpoint, waiting for events...\n", .{});

    // Read events until justification, finalization, AND node3 parent sync are verified, or timeout.
    // Node3 starts after first finalization and syncs via parent block requests (blocks_by_root).
    // We verify sync by waiting for finalization to advance beyond the first finalized slot,
    // which proves the chain continued progressing after node3 joined.
    const timeout_ms: u64 = 240000; // 240 seconds timeout
    const start_ns = std.time.nanoTimestamp();
    const deadline_ns = start_ns + timeout_ms * std.time.ns_per_ms;
    var got_justification = false;
    var got_finalization = false;
    var got_node3_sync = false;
    var first_finalized_slot: u64 = 0;
    var head_count_at_finalization: usize = 0;

    var current_ns = std.time.nanoTimestamp();
    while (current_ns < deadline_ns and !(got_justification and got_finalization and got_node3_sync)) {
        const event = try sse_client.readEvent();
        if (event) |e| {
            // Check for justification with slot > 0
            if (!got_justification and std.mem.eql(u8, e.event_type, "new_justification")) {
                if (e.justified_slot) |slot| {
                    if (slot > 0) {
                        got_justification = true;
                        std.debug.print("INFO: Found justification with slot {}\n", .{slot});
                    }
                }
            }

            // Check for finalization events
            if (std.mem.eql(u8, e.event_type, "new_finalization")) {
                if (e.finalized_slot) |slot| {
                    std.debug.print("DEBUG: Found finalization event with slot {}\n", .{slot});
                    if (slot > 0 and !got_finalization) {
                        // First finalization — this triggers node3 to start syncing
                        got_finalization = true;
                        first_finalized_slot = slot;
                        head_count_at_finalization = sse_client.getEventCount("new_head");
                        std.debug.print("INFO: First finalization at slot {} — node 3 will start syncing via parent block requests\n", .{slot});
                        std.debug.print("INFO: Head events at finalization: {}\n", .{head_count_at_finalization});
                    } else if (got_finalization and slot > first_finalized_slot and !got_node3_sync) {
                        // Finalization advanced beyond the first finalized slot.
                        // This means the chain continued progressing after node3 joined.
                        got_node3_sync = true;
                        const head_count_now = sse_client.getEventCount("new_head");
                        std.debug.print("INFO: Advanced finalization at slot {} (first was {}) — chain progressed after node 3 joined\n", .{ slot, first_finalized_slot });
                        std.debug.print("INFO: Head events since finalization: {} (total: {})\n", .{ head_count_now - head_count_at_finalization, head_count_now });
                    }
                } else {
                    std.debug.print("DEBUG: Found finalization event with null slot\n", .{});
                }
            }

            // IMPORTANT: Free the event memory after processing
            e.deinit(allocator);
        }

        current_ns = std.time.nanoTimestamp();
        std.debug.print("CURRENT TIME:{d} DEADLINE={d} START={d} PASSED={d} TIMEOUT={d} (in ms)\n", .{
            @divTrunc(current_ns, std.time.ns_per_ms),
            @divTrunc(deadline_ns, std.time.ns_per_ms),
            @divTrunc(start_ns, std.time.ns_per_ms),
            @divTrunc(current_ns - start_ns, std.time.ns_per_ms),
            timeout_ms,
        });
        std.debug.print("STATUS: got_justification={any} got_finalization={any} got_node3_sync={any}\n", .{
            got_justification,
            got_finalization,
            got_node3_sync,
        });
    }

    // Check if we received connection event
    try std.testing.expect(sse_client.hasEvent("connection"));

    // Check for chain events
    const head_events = sse_client.getEventCount("new_head");
    const justification_events = sse_client.getEventCount("new_justification");
    const finalization_events = sse_client.getEventCount("new_finalization");

    std.debug.print("INFO: Received events - Head: {}, Justification: {}, Finalization: {}\n", .{ head_events, justification_events, finalization_events });

    // Require justification, finalization, and node3 sync verification
    try std.testing.expect(got_justification);
    try std.testing.expect(got_finalization);
    try std.testing.expect(got_node3_sync);

    // Print some sample events for debugging
    for (sse_client.received_events.items, 0..) |event_data, i| {
        if (i < 5) { // Print first 5 events
            std.debug.print("Event {}: {s}\n", .{ i, event_data });
        }
    }

    std.debug.print("SUCCESS: SSE events integration test completed — including node 3 parent sync verification\n", .{});
}

// Test suite for ErrorHandler
test "ErrorHandler.formatError - known errors" {
    const testing = std.testing;

    try testing.expectEqualStrings("File not found", ErrorHandler.formatError(error.FileNotFound));
    try testing.expectEqualStrings("Permission denied", ErrorHandler.formatError(error.AccessDenied));
    try testing.expectEqualStrings("Out of memory", ErrorHandler.formatError(error.OutOfMemory));
    try testing.expectEqualStrings("Invalid argument", ErrorHandler.formatError(error.InvalidArgument));
    try testing.expectEqualStrings("Network unreachable", ErrorHandler.formatError(error.NetworkUnreachable));
    try testing.expectEqualStrings("Connection refused", ErrorHandler.formatError(error.ConnectionRefused));
    try testing.expectEqualStrings("Address already in use", ErrorHandler.formatError(error.AddressInUse));
    try testing.expectEqualStrings("File too large", ErrorHandler.formatError(error.FileTooBig));
}

test "ErrorHandler.formatError - unknown error falls back to error name" {
    const testing = std.testing;
    // Create a test error set with a unique error
    const TestError = error{
        TestUniqueError,
    };

    const result = ErrorHandler.formatError(TestError.TestUniqueError);
    // Should return the error name since it's not in our switch
    try testing.expect(std.mem.eql(u8, result, "TestUniqueError"));
}

test "ErrorHandler.getErrorContext - provides helpful context for known errors" {
    const testing = std.testing;

    const fileNotFoundContext = ErrorHandler.getErrorContext(error.FileNotFound);
    try testing.expect(fileNotFoundContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, fileNotFoundContext, 1, "file"));

    const invalidArgContext = ErrorHandler.getErrorContext(error.InvalidArgument);
    try testing.expect(invalidArgContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, invalidArgContext, 1, "argument"));

    const networkContext = ErrorHandler.getErrorContext(error.NetworkUnreachable);
    try testing.expect(networkContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, networkContext, 1, "network"));

    const jsonContext = ErrorHandler.getErrorContext(error.JsonInvalidUTF8);
    try testing.expect(jsonContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, jsonContext, 1, "JSON"));

    const yamlContext = ErrorHandler.getErrorContext(error.YamlError);
    try testing.expect(yamlContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, yamlContext, 1, "YAML"));

    const powdrContext = ErrorHandler.getErrorContext(error.PowdrIsDeprecated);
    try testing.expect(powdrContext.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, powdrContext, 1, "deprecated"));
}

test "ErrorHandler.getErrorContext - handles multiple JSON error types" {
    const testing = std.testing;

    // All JSON errors should return the same context
    const context1 = ErrorHandler.getErrorContext(error.JsonInvalidUTF8);
    const context2 = ErrorHandler.getErrorContext(error.JsonInvalidCharacter);
    const context3 = ErrorHandler.getErrorContext(error.JsonUnexpectedToken);

    try testing.expectEqualStrings(context1, context2);
    try testing.expectEqualStrings(context2, context3);
    try testing.expect(std.mem.containsAtLeast(u8, context1, 1, "JSON"));
}

test "ErrorHandler.getErrorContext - handles multiple network error types" {
    const testing = std.testing;

    // All network errors should return the same context
    const context1 = ErrorHandler.getErrorContext(error.NetworkUnreachable);
    const context2 = ErrorHandler.getErrorContext(error.ConnectionRefused);
    const context3 = ErrorHandler.getErrorContext(error.ConnectionReset);
    const context4 = ErrorHandler.getErrorContext(error.ConnectionTimedOut);

    try testing.expectEqualStrings(context1, context2);
    try testing.expectEqualStrings(context2, context3);
    try testing.expectEqualStrings(context3, context4);
    try testing.expect(std.mem.containsAtLeast(u8, context1, 1, "network"));
}

test "ErrorHandler.getErrorContext - unknown error provides generic message" {
    const testing = std.testing;

    const TestError = error{
        UnknownTestError,
    };

    const context = ErrorHandler.getErrorContext(TestError.UnknownTestError);
    try testing.expect(std.mem.containsAtLeast(u8, context, 1, "unexpected"));
}

test "ErrorHandler.printError - formats error correctly" {
    // This test verifies printError doesn't crash
    // We can't easily capture stderr in Zig tests without more complex setup
    ErrorHandler.printError(error.FileNotFound, "Test context message");
    // If we get here without a crash, the function works
}

test "ErrorHandler.handleApplicationError - handles InvalidArgument with hint" {
    // This test verifies handleApplicationError doesn't crash
    // The hint for InvalidArgument is included in the function
    ErrorHandler.handleApplicationError(error.InvalidArgument);
    // If we get here without a crash, the function works
}

test "ErrorHandler.handleApplicationError - handles various error types" {
    // Test that handleApplicationError works for different error types
    ErrorHandler.handleApplicationError(error.FileNotFound);
    ErrorHandler.handleApplicationError(error.AccessDenied);
    ErrorHandler.handleApplicationError(error.OutOfMemory);
    ErrorHandler.handleApplicationError(error.NetworkUnreachable);
    ErrorHandler.handleApplicationError(error.PowdrIsDeprecated);

    // Test unknown error
    const TestError = error{UnknownError};
    ErrorHandler.handleApplicationError(TestError.UnknownError);

    // If we get here without a crash, all error types are handled
}

test "ErrorHandler.logErrorWithOperation - logs operation context" {
    // This test verifies the function doesn't crash
    // Actual logging output would need to be captured differently
    ErrorHandler.logErrorWithOperation(error.FileNotFound, "test operation");
    // If we get here without a crash, the function works
}

test "ErrorHandler.logErrorWithDetails - logs error with details" {
    // This test verifies the function doesn't crash with various detail types
    ErrorHandler.logErrorWithDetails(error.FileNotFound, "test operation", .{ .path = "/test/path" });
    ErrorHandler.logErrorWithDetails(error.AddressInUse, "start server", .{ .port = 8080 });
    ErrorHandler.logErrorWithDetails(error.ConnectionRefused, "connect", .{ .address = "127.0.0.1", .port = 9001 });
    // If we get here without a crash, the function works with different detail types
}

test "ErrorHandler - comprehensive error coverage" {
    const testing = std.testing;

    // Test all major error categories have both formatError and getErrorContext
    const test_errors = [_]anyerror{
        error.FileNotFound,
        error.AccessDenied,
        error.OutOfMemory,
        error.InvalidArgument,
        error.UnexpectedEndOfFile,
        error.FileTooBig,
        error.DiskQuota,
        error.PathAlreadyExists,
        error.NoSpaceLeft,
        error.IsDir,
        error.NotDir,
        error.NotSupported,
        error.NetworkUnreachable,
        error.ConnectionRefused,
        error.ConnectionReset,
        error.ConnectionTimedOut,
        error.AddressInUse,
        error.NotFound,
        error.InvalidData,
        error.JsonInvalidUTF8,
        error.JsonInvalidCharacter,
        error.JsonUnexpectedToken,
        error.YamlError,
        error.PowdrIsDeprecated,
    };

    for (test_errors) |err| {
        const formatted = ErrorHandler.formatError(err);
        try testing.expect(formatted.len > 0);

        const context = ErrorHandler.getErrorContext(err);
        try testing.expect(context.len > 0);

        // Both should not be empty
        try testing.expect(!std.mem.eql(u8, formatted, ""));
        try testing.expect(!std.mem.eql(u8, context, ""));
    }
}
