const std = @import("std");
const process = std.process;
const net = std.net;
const build_options = @import("build_options");

test "CLI beam command with mock network - complete integration test" {
    const allocator = std.testing.allocator;

    // Verify executable exists first
    const exe_file = std.fs.openFileAbsolute(build_options.cli_exe_path, .{}) catch |err| {
        std.debug.print("ERROR: Cannot find executable at {s}: {}\n", .{ build_options.cli_exe_path, err });

        // Try to list the directory to see what's actually there
        std.debug.print("INFO: Attempting to list zig-out/bin directory...\n", .{});
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

    // Start CLI with beam command and mock network - use build option for executable path
    const args = [_][]const u8{ build_options.cli_exe_path, "beam", "--mockNetwork", "true" };
    var cli_process = process.Child.init(&args, allocator);

    // Capture stdout and stderr for debugging
    cli_process.stdout_behavior = .Pipe;
    cli_process.stderr_behavior = .Pipe;

    defer {
        _ = cli_process.kill() catch {};
        _ = cli_process.wait() catch {};
    }

    // Start the process
    cli_process.spawn() catch |err| {
        std.debug.print("ERROR: Failed to spawn process: {}\n", .{err});
        return err;
    };

    std.debug.print("INFO: Process spawned successfully with PID\n", .{});

    // Wait for metrics server to be ready (with extended timeout for CI)
    const metrics_port: u16 = 9667;
    const start_time = std.time.milliTimestamp();
    const max_wait_time = 120000; // Increased to 120 seconds for CI environments
    const retry_interval = 1000; // Increased to 1000ms between retries
    var server_ready = false;
    var retry_count: u32 = 0;

    while (std.time.milliTimestamp() - start_time < max_wait_time) {
        retry_count += 1;

        // Print progress every 10 retries
        if (retry_count % 10 == 0) {
            const elapsed = @divTrunc(std.time.milliTimestamp() - start_time, 1000);
            std.debug.print("INFO: Still waiting for server... ({} seconds, {} retries)\n", .{ elapsed, retry_count });
        }

        // Try to connect to the metrics server
        const address = net.Address.parseIp4("127.0.0.1", metrics_port) catch {
            std.time.sleep(retry_interval * std.time.ns_per_ms);
            continue;
        };

        var connection = net.tcpConnectToAddress(address) catch |err| {
            // Only print error details on certain intervals to avoid spam
            if (retry_count % 20 == 0) {
                std.debug.print("DEBUG: Connection attempt {} failed: {}\n", .{ retry_count, err });
            }
            std.time.sleep(retry_interval * std.time.ns_per_ms);
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
        std.debug.print("ERROR: Metrics server not ready after {} seconds ({} retries)\n", .{ @divTrunc(max_wait_time, 1000), retry_count });

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
    }

    // Verify server started successfully
    try std.testing.expect(server_ready);

    // Let the node run for a bit to generate some activity
    std.time.sleep(2000 * std.time.ns_per_ms);

    // Make HTTP request to metrics endpoint
    const address = try net.Address.parseIp4("127.0.0.1", metrics_port);
    var connection = try net.tcpConnectToAddress(address);
    defer connection.close();

    // Create HTTP request
    var request_buffer: [4096]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "GET /metrics HTTP/1.1\r\n" ++
        "Host: 127.0.0.1:9667\r\n" ++
        "Connection: close\r\n" ++
        "\r\n", .{});

    try connection.writeAll(request);

    // Read response
    var response_buffer: [8192]u8 = undefined;
    const bytes_read = try connection.readAll(&response_buffer);
    const response = response_buffer[0..bytes_read];

    // Verify we got a valid HTTP response
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200") != null or std.mem.indexOf(u8, response, "HTTP/1.0 200") != null);

    // Verify response contains metrics data (should contain some metric names)
    try std.testing.expect(std.mem.indexOf(u8, response, "# HELP") != null or std.mem.indexOf(u8, response, "# TYPE") != null);

    // Verify response is not empty
    try std.testing.expect(response.len > 100);

    // Make multiple requests to verify consistency
    for (0..3) |i| {
        var connection2 = try net.tcpConnectToAddress(address);
        defer connection2.close();

        var request_buffer2: [4096]u8 = undefined;
        const request2 = try std.fmt.bufPrint(&request_buffer2, "GET /metrics HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:9667\r\n" ++
            "Connection: close\r\n" ++
            "\r\n", .{});

        try connection2.writeAll(request2);

        var response_buffer2: [8192]u8 = undefined;
        const bytes_read2 = try connection2.readAll(&response_buffer2);
        const response2 = response_buffer2[0..bytes_read2];

        // Verify HTTP response is valid
        try std.testing.expect(std.mem.indexOf(u8, response2, "HTTP/1.1 200") != null or std.mem.indexOf(u8, response2, "HTTP/1.0 200") != null);

        // Verify response is not empty
        try std.testing.expect(response2.len > 100);

        std.debug.print("INFO: Request {} completed successfully\n", .{i + 1});

        // Small delay between requests
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    std.debug.print("SUCCESS: All integration test checks passed\n", .{});
}
