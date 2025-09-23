const std = @import("std");
const process = std.process;
const net = std.net;
const build_options = @import("build_options");
const constants = @import("cli_constants");

/// Verify that the Zeam executable exists and return its path
/// Includes detailed debugging output if the executable is not found
fn getZeamExecutable() ![]const u8 {
    const exe_file = std.fs.openFileAbsolute(build_options.cli_exe_path, .{}) catch |err| {
        std.debug.print("ERROR: Cannot find executable at {s}: {}\n", .{ build_options.cli_exe_path, err });

        // Try to list the directory to see what's actually there
        std.debug.print("INFO: Attempting to list {s} directory...\n", .{build_options.cli_exe_path});
        const dir_path = std.fs.path.dirname(build_options.cli_exe_path);
        if (dir_path) |path| {
            var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch |dir_err| {
                std.debug.print("ERROR: Cannot open directory {s}: {}\n", .{ path, dir_err });
                return err;
            };
            defer dir.close();

            var iterator = dir.iterate();
            std.debug.print("INFO: Contents of {s}:\n", .{path});
            while (try iterator.next()) |entry| {
                std.debug.print("  - {s} (type: {})\n", .{ entry.name, entry.kind });
            }
        }

        return err;
    };
    exe_file.close();
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
    cli_process.stdout_behavior = .Pipe;
    cli_process.stderr_behavior = .Pipe;

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
        const address = net.Address.parseIp4(constants.DEFAULT_SERVER_IP, constants.DEFAULT_METRICS_PORT) catch {
            std.time.sleep(constants.DEFAULT_RETRY_INTERVAL_MS * std.time.ns_per_ms);
            continue;
        };

        var connection = net.tcpConnectToAddress(address) catch |err| {
            // Only print error details on certain intervals to avoid spam
            if (retry_count % 20 == 0) {
                std.debug.print("DEBUG: Connection attempt {} failed: {}\n", .{ retry_count, err });
            }
            std.time.sleep(constants.DEFAULT_RETRY_INTERVAL_MS * std.time.ns_per_ms);
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
            const stdout_bytes = stdout.readAll(&stdout_buffer) catch 0;
            if (stdout_bytes > 0) {
                std.debug.print("STDOUT: {s}\n", .{stdout_buffer[0..stdout_bytes]});
            }
        }

        if (cli_process.stderr) |stderr| {
            var stderr_buffer: [4096]u8 = undefined;
            const stderr_bytes = stderr.readAll(&stderr_buffer) catch 0;
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
    std.time.sleep(2000 * std.time.ns_per_ms);
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

    /// Make a request to the /health endpoint and return the response
    fn getHealth(self: ZeamRequest) ![]u8 {
        return self.makeRequest("/health");
    }

    /// Internal helper to make HTTP requests to any endpoint
    fn makeRequest(self: ZeamRequest, endpoint: []const u8) ![]u8 {
        // Create connection to the server
        const address = try net.Address.parseIp4(constants.DEFAULT_SERVER_IP, constants.DEFAULT_METRICS_PORT);
        var connection = try net.tcpConnectToAddress(address);
        defer connection.close();

        // Create HTTP request
        var request_buffer: [4096]u8 = undefined;
        const request = try std.fmt.bufPrint(&request_buffer, "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n", .{ endpoint, constants.DEFAULT_SERVER_IP, constants.DEFAULT_METRICS_PORT });

        try connection.writeAll(request);

        // Read response
        var response_buffer: [8192]u8 = undefined;
        const bytes_read = try connection.readAll(&response_buffer);

        // Allocate and return a copy of the response
        const response = try self.allocator.dupe(u8, response_buffer[0..bytes_read]);
        return response;
    }

    /// Free a response returned by getMetrics() or getHealth()
    fn freeResponse(self: ZeamRequest, response: []u8) void {
        self.allocator.free(response);
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
