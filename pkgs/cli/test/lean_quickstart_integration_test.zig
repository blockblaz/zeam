const std = @import("std");
const Allocator = std.mem.Allocator;
const process = std.process;
const net = std.net;
const build_options = @import("build_options");
const beam_test = @import("beam_integration_test.zig");
const SSEClient = beam_test.SSEClient;
const ChainEvent = beam_test.ChainEvent;

const TestConfig = struct {
    genesis_time: u64,
    num_validators: u32,
    network_dir: []const u8,
    timeout_seconds: u64 = 600,
};

const FinalizationResult = struct {
    finalized: bool,
    finalization_slot: u64,
    finalization_root: [32]u8,
    timeout_reached: bool = false,
};

/// Generate the network directory structure and validator-config.yaml for lean-quickstart
fn generateLeanQuickstartConfig(allocator: Allocator, config: TestConfig) !void {
    const cwd = std.fs.cwd();

    // Create network directory structure
    cwd.makeDir(config.network_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const genesis_dir = try std.fmt.allocPrint(allocator, "{s}/genesis", .{config.network_dir});
    defer allocator.free(genesis_dir);

    cwd.makeDir(genesis_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const data_dir = try std.fmt.allocPrint(allocator, "{s}/data", .{config.network_dir});
    defer allocator.free(data_dir);

    cwd.makeDir(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Generate config.yaml (genesis time will be updated by generate-genesis.sh)
    const config_yaml = try std.fmt.allocPrint(allocator,
        \\# Genesis Settings
        \\GENESIS_TIME: {d}
        \\# Validator Settings  
        \\VALIDATOR_COUNT: {d}
        \\
    , .{ config.genesis_time, config.num_validators });
    defer allocator.free(config_yaml);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.yaml", .{genesis_dir});
    defer allocator.free(config_path);
    try cwd.writeFile(.{ .sub_path = config_path, .data = config_yaml });

    // Generate validator-config.yaml with TWO zeam nodes
    // CRITICAL: Must include metricsPort field for each validator!
    const validator_config_yaml =
        \\shuffle: roundrobin
        \\validators:
        \\  - name: "zeam_0"
        \\    privkey: "a000000000000000000000000000000000000000000000000000000000000001"
        \\    enrFields:
        \\      ip: "127.0.0.1"
        \\      quic: 9100
        \\    metricsPort: 9669
        \\    count: 1
        \\  - name: "zeam_1"
        \\    privkey: "b000000000000000000000000000000000000000000000000000000000000002"
        \\    enrFields:
        \\      ip: "127.0.0.1"
        \\      quic: 9101
        \\    metricsPort: 9670
        \\    count: 1
        \\
    ;

    const validator_config_path = try std.fmt.allocPrint(allocator, "{s}/validator-config.yaml", .{genesis_dir});
    defer allocator.free(validator_config_path);
    try cwd.writeFile(.{ .sub_path = validator_config_path, .data = validator_config_yaml });

    std.debug.print("✅ Generated lean-quickstart configuration structure\n", .{});
    std.debug.print("   Network dir: {s}\n", .{config.network_dir});
    std.debug.print("   Genesis dir: {s}\n", .{genesis_dir});
}

/// Run lean-quickstart's generate-genesis.sh script
fn runGenesisGenerator(allocator: Allocator, network_dir: []const u8) !void {
    std.debug.print("🔧 Running lean-quickstart genesis generator...\n", .{});

    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    const generate_script = try std.fmt.allocPrint(allocator, "{s}/lean-quickstart/generate-genesis.sh", .{cwd_path});
    defer allocator.free(generate_script);

    const genesis_dir = try std.fmt.allocPrint(allocator, "{s}/genesis", .{network_dir});
    defer allocator.free(genesis_dir);

    const genesis_dir_abs = try std.fs.cwd().realpathAlloc(allocator, genesis_dir);
    defer allocator.free(genesis_dir_abs);

    const args = &[_][]const u8{
        "/bin/bash",
        generate_script,
        genesis_dir_abs,
    };

    std.debug.print("   Command: {s} {s} {s}\n", .{ args[0], args[1], args[2] });

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = args,
        .max_output_bytes = 1024 * 1024, // 1MB
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term != .Exited or result.term.Exited != 0) {
        std.debug.print("❌ Genesis generation failed!\n", .{});
        std.debug.print("STDOUT:\n{s}\n", .{result.stdout});
        std.debug.print("STDERR:\n{s}\n", .{result.stderr});
        return error.GenesisGenerationFailed;
    }

    std.debug.print("✅ Genesis generation completed successfully\n", .{});
    std.debug.print("{s}\n", .{result.stdout});
}

const NodeProcess = struct {
    child: *process.Child,
    env_map: *process.EnvMap,
    allocator: Allocator,

    /// Cleanup the node process using graceful SIGTERM
    ///
    /// CLEANUP FLOW:
    /// 1. Send SIGTERM to spin-node.sh process
    /// 2. The script's trap (line 169) catches SIGTERM
    /// 3. The cleanup() function (lines 149-167) executes
    /// 4. cleanup() kills the zeam child processes with kill -9
    /// 5. The script exits cleanly
    ///
    /// This mimics the user pressing Ctrl+C in an interactive session.
    fn deinit(self: *NodeProcess) void {
        std.debug.print("🧹 Initiating graceful shutdown via SIGTERM...\n", .{});

        // Send SIGTERM to trigger the cleanup trap in spin-node.sh
        // This mimics pressing Ctrl+C in an interactive session
        const pid = self.child.id;

        const sigterm_result = std.posix.kill(pid, std.posix.SIG.TERM) catch |err| {
            std.debug.print("⚠️  Failed to send SIGTERM to PID {d}: {}\n", .{ pid, err });
            // Continue to force kill
            _ = self.child.kill() catch {};
            _ = self.child.wait() catch {};
            self.env_map.deinit();
            self.allocator.destroy(self.env_map);
            self.allocator.destroy(self.child);
            return;
        };
        _ = sigterm_result;

        std.debug.print("✅ SIGTERM sent to PID {d}, waiting for cleanup...\n", .{pid});

        // Give the script time to run its cleanup() function
        // The trap will catch SIGTERM and execute cleanup which kills child processes
        std.time.sleep(3 * std.time.ns_per_s);

        // Try to wait for the process to exit gracefully
        const wait_result = self.child.wait() catch |err| {
            std.debug.print("⚠️  Process didn't exit cleanly: {}, force killing...\n", .{err});
            _ = self.child.kill() catch {};
            self.env_map.deinit();
            self.allocator.destroy(self.env_map);
            self.allocator.destroy(self.child);
            return;
        };

        std.debug.print("✅ Process exited: {}\n", .{wait_result});

        self.env_map.deinit();
        self.allocator.destroy(self.env_map);
        self.allocator.destroy(self.child);
    }
};

/// Spawn a single node using lean-quickstart spin-node.sh
///
/// IMPORTANT BEHAVIOR:
/// - Sets working directory to lean-quickstart/ so relative paths work (source parse-vc.sh, etc.)
/// - spin-node.sh spawns the zeam node as a background process (line 141: eval "$execCmd" &)
/// - Then it waits indefinitely (line 173: wait -n $process_ids)
/// - The wait -n fails on macOS (bash 3.2 doesn't support -n flag) but this is OK
/// - The zeam node IS already running in the background when wait fails
/// - We will send SIGTERM during cleanup to trigger the script's cleanup trap
///
/// This function returns immediately with the script's process handle.
/// The script will error at wait, but the node is already running.
fn spawnNodeViaLeanQuickstart(
    allocator: Allocator,
    node_name: []const u8,
    network_dir: []const u8,
) !*NodeProcess {
    std.debug.print("🚀 Spawning node via lean-quickstart: {s}\n", .{node_name});

    // Get absolute path to lean-quickstart
    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    const spin_script = try std.fmt.allocPrint(allocator, "{s}/lean-quickstart/spin-node.sh", .{cwd_path});
    defer allocator.free(spin_script);

    // IMPORTANT: lean-quickstart scripts expect NETWORK_DIR to be RELATIVE to the script directory
    // Since spin-node.sh is in lean-quickstart/, and our network_dir is in zeam/, we use ../network_dir
    const relative_network_dir = try std.fmt.allocPrint(allocator, "../{s}", .{network_dir});
    defer allocator.free(relative_network_dir);

    // Build command: NETWORK_DIR=... bash spin-node.sh --node <node_name> --validatorConfig genesis_bootnode
    const args = &[_][]const u8{
        "/bin/bash",
        spin_script,
        "--node",
        node_name,
        "--validatorConfig",
        "genesis_bootnode",
    };

    std.debug.print("   Command: {s} {s} --node {s}\n", .{ args[0], args[1], node_name });
    std.debug.print("   NETWORK_DIR: {s} (relative to script)\n", .{relative_network_dir});

    const node_child = try allocator.create(process.Child);
    node_child.* = process.Child.init(args, allocator);

    // CRITICAL: Set working directory to lean-quickstart/
    // This makes relative paths in spin-node.sh work correctly:
    // - source parse-vc.sh → finds it in current directory
    // - source client-cmds/zeam-cmd.sh → finds it relative to current directory
    const lean_quickstart_dir = try std.fmt.allocPrint(allocator, "{s}/lean-quickstart", .{cwd_path});
    defer allocator.free(lean_quickstart_dir);

    node_child.cwd = lean_quickstart_dir;

    // Set NETWORK_DIR environment variable
    // IMPORTANT: env_map must persist for the lifetime of the process
    const env_map = try allocator.create(process.EnvMap);
    env_map.* = try process.getEnvMap(allocator);

    // Use relative path that the scripts expect
    try env_map.put("NETWORK_DIR", relative_network_dir);
    node_child.env_map = env_map;

    // Capture output for debugging
    node_child.stdout_behavior = .Ignore;
    node_child.stderr_behavior = .Inherit;

    // Spawn the process
    node_child.spawn() catch |err| {
        std.debug.print("❌ ERROR: Failed to spawn node process: {}\n", .{err});
        env_map.deinit();
        allocator.destroy(env_map);
        allocator.destroy(node_child);
        return err;
    };

    std.debug.print("✅ Node process spawned: {s} (PID: {d})\n", .{ node_name, node_child.id });

    const node_process = try allocator.create(NodeProcess);
    node_process.* = NodeProcess{
        .child = node_child,
        .env_map = env_map,
        .allocator = allocator,
    };

    return node_process;
}

/// Wait for node to be ready by polling its metrics port
fn waitForNodeStartup(metrics_port: u16, timeout_seconds: u64) !void {
    std.debug.print("⏳ Waiting for node on port {d} to start (timeout: {d}s)...\n", .{ metrics_port, timeout_seconds });

    const start_time = std.time.milliTimestamp();
    const timeout_ms = timeout_seconds * 1000;
    var attempt: usize = 0;

    while (std.time.milliTimestamp() - start_time < timeout_ms) {
        attempt += 1;

        if (attempt % 10 == 0) {
            const elapsed = @divTrunc(std.time.milliTimestamp() - start_time, 1000);
            std.debug.print("⏱️  Still waiting for port {d}... ({d}s elapsed, attempt {d})\n", .{ metrics_port, elapsed, attempt });
        }

        const address = net.Address.parseIp4("127.0.0.1", metrics_port) catch {
            std.time.sleep(1000 * std.time.ns_per_ms);
            continue;
        };

        var connection = net.tcpConnectToAddress(address) catch {
            std.time.sleep(1000 * std.time.ns_per_ms);
            continue;
        };
        connection.close();

        std.debug.print("✅ Node on port {d} is ready\n", .{metrics_port});
        return;
    }

    std.debug.print("❌ Timeout waiting for node on port {d}\n", .{metrics_port});
    return error.NodeStartupTimeout;
}

/// Monitor SSE events for finalization
fn monitorForFinalization(allocator: Allocator, metrics_port: u16, timeout_seconds: u64) !FinalizationResult {
    std.debug.print("📡 Creating SSE client for port {d}...\n", .{metrics_port});

    var sse_client = try SSEClient.init(allocator, metrics_port);
    defer sse_client.deinit();

    try sse_client.connect();
    std.debug.print("✅ Connected to SSE endpoint, waiting for finalization events...\n", .{});

    const deadline_ns = std.time.nanoTimestamp() + (@as(i64, @intCast(timeout_seconds)) * std.time.ns_per_s);
    var event_count: usize = 0;
    var null_count: usize = 0;
    var last_progress_time = std.time.nanoTimestamp();

    while (std.time.nanoTimestamp() < deadline_ns) {
        const event_result = sse_client.readEvent() catch |err| {
            std.debug.print("❌ Error reading SSE event: {}\n", .{err});
            return error.SSEReadError;
        };

        if (event_result == null) {
            null_count += 1;

            if (null_count % 20 == 0) {
                const now = std.time.nanoTimestamp();
                if (now - last_progress_time > 5 * std.time.ns_per_s) {
                    const elapsed = @divTrunc(now - (deadline_ns - @as(i64, @intCast(timeout_seconds)) * std.time.ns_per_s), std.time.ns_per_s);
                    const remaining = @divTrunc(deadline_ns - now, std.time.ns_per_s);
                    std.debug.print("⏱️  Still waiting for events... ({d} events received, {d}s elapsed, {d}s remaining)\n", .{ event_count, elapsed, remaining });
                    last_progress_time = now;
                }
            }

            continue;
        }

        const e = event_result.?;
        event_count += 1;
        std.debug.print("📨 Event #{d}: {s}\n", .{ event_count, e.event_type });

        if (std.mem.eql(u8, e.event_type, "new_finalization")) {
            if (e.finalized_slot) |slot| {
                std.debug.print("🔍 Found finalization event with slot {d}\n", .{slot});
                if (slot > 0) {
                    std.debug.print("🎉 Finalization detected at slot {d}!\n", .{slot});
                    e.deinit(allocator);
                    return FinalizationResult{
                        .finalized = true,
                        .finalization_slot = slot,
                        .finalization_root = [_]u8{0} ** 32,
                        .timeout_reached = false,
                    };
                }
            }
        }

        e.deinit(allocator);
    }

    std.debug.print("❌ Timeout reached after {d} seconds\n", .{timeout_seconds});
    std.debug.print("📊 Total events received: {d}\n", .{event_count});
    return FinalizationResult{
        .finalized = false,
        .finalization_slot = 0,
        .finalization_root = [_]u8{0} ** 32,
        .timeout_reached = true,
    };
}

/// Main test function using lean-quickstart
fn runTwoNodesViaLeanQuickstart(allocator: Allocator, config: TestConfig) !FinalizationResult {
    std.debug.print("\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════\n", .{});
    std.debug.print("🚀 STARTING LEAN-QUICKSTART TWO-NODE INTEGRATION TEST\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════\n", .{});
    std.debug.print("Test config: genesis_time={d}, num_validators={d}, timeout={d}s\n", .{ config.genesis_time, config.num_validators, config.timeout_seconds });
    std.debug.print("\n", .{});

    // Hardcoded metrics ports from validator-config.yaml
    const node_0_port: u16 = 9669;
    const node_1_port: u16 = 9670;

    std.debug.print("▶️  STEP 1: Generating genesis via lean-quickstart\n", .{});
    try runGenesisGenerator(allocator, config.network_dir);

    std.debug.print("\n▶️  STEP 2: Spawning Node 0 via spin-node.sh (port {d})\n", .{node_0_port});
    const node_0_process = try spawnNodeViaLeanQuickstart(allocator, "zeam_0", config.network_dir);
    defer {
        std.debug.print("\n🧹 Cleaning up node 0 process...\n", .{});
        node_0_process.deinit();
        allocator.destroy(node_0_process);
    }

    std.debug.print("\n▶️  STEP 3: Spawning Node 1 via spin-node.sh (port {d})\n", .{node_1_port});
    const node_1_process = try spawnNodeViaLeanQuickstart(allocator, "zeam_1", config.network_dir);
    defer {
        std.debug.print("\n🧹 Cleaning up node 1 process...\n", .{});
        node_1_process.deinit();
        allocator.destroy(node_1_process);
    }

    std.debug.print("\n✅ Both spin-node.sh processes spawned\n", .{});

    std.debug.print("\n▶️  STEP 4: Waiting for nodes to start (60s timeout each)...\n", .{});
    try waitForNodeStartup(node_0_port, 60);
    try waitForNodeStartup(node_1_port, 60);

    std.debug.print("\n✅ Both nodes are ready!\n", .{});

    std.debug.print("\n▶️  STEP 5: Monitoring for finalization via SSE (timeout: {d}s)...\n", .{config.timeout_seconds});
    const result = try monitorForFinalization(allocator, node_0_port, config.timeout_seconds);

    std.debug.print("\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════\n", .{});
    std.debug.print("🏁 TEST COMPLETE - Finalized: {}\n", .{result.finalized});
    std.debug.print("═══════════════════════════════════════════════════════════\n", .{});

    return result;
}

fn cleanupNetworkDirectory(allocator: Allocator, network_dir: []const u8) !void {
    _ = allocator;
    const cwd = std.fs.cwd();
    cwd.deleteTree(network_dir) catch {
        // Ignore cleanup errors (directory may not exist)
    };
}

test "lean_quickstart_two_node_finalization_integration" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Set genesis time in the future to allow nodes to sync
    const genesis_time = @as(u64, @intCast(std.time.timestamp())) + 30;

    const config = TestConfig{
        .genesis_time = genesis_time,
        .num_validators = 2,
        .network_dir = "test_lean_quickstart_network",
        .timeout_seconds = 600,
    };

    std.debug.print("🚀 Starting Lean-Quickstart Integration Test\n", .{});
    std.debug.print("📁 Network directory: {s}\n", .{config.network_dir});
    std.debug.print("⏰ Genesis time: {d} (in ~30 seconds)\n", .{config.genesis_time});
    std.debug.print("⏰ Current time: {d}\n", .{std.time.timestamp()});
    std.debug.print("👥 Number of validators: {d}\n", .{config.num_validators});
    std.debug.print("⏱️  Timeout: {d} seconds\n", .{config.timeout_seconds});

    // Generate lean-quickstart configuration
    try generateLeanQuickstartConfig(allocator, config);

    // Run the test
    const result = try runTwoNodesViaLeanQuickstart(allocator, config);

    // Cleanup
    try cleanupNetworkDirectory(allocator, config.network_dir);

    // Verify results
    if (result.timeout_reached) {
        std.debug.print("❌ Test failed: Timeout reached after {d} seconds\n", .{config.timeout_seconds});
        return error.TestTimeout;
    }

    if (!result.finalized) {
        std.debug.print("❌ Test failed: No finalization detected\n", .{});
        return error.NoFinalization;
    }

    std.debug.print("✅ Test passed: Finalization detected at slot {d}\n", .{result.finalization_slot});
    std.debug.print("🎉 Lean-Quickstart Integration Test completed successfully!\n", .{});
}
