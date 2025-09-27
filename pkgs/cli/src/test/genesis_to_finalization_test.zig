const std = @import("std");
const Allocator = std.mem.Allocator;
const node_lib = @import("@zeam/node");
const BeamNode = node_lib.BeamNode;
const Clock = node_lib.Clock;
const utils_lib = @import("@zeam/utils");
const node = @import("../node.zig");
const Node = node.Node;
const NodeOptions = node.NodeOptions;
const NodeCommand = @import("../main.zig").NodeCommand;
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const enr_lib = @import("enr");
const enr = enr_lib;
const sft = @import("@zeam/state-transition");
const api = @import("@zeam/api");
const api_server = @import("../api_server.zig");
const xev = @import("xev");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;

/// Generates a test ENR with the specified IP and QUIC port
/// Based on the genENR function from tools/src/main.zig
fn generateTestENR(allocator: Allocator, ip: []const u8, quic_port: u16) ![]const u8 {
    // Use a fixed test secret key for deterministic ENRs
    const test_secret_key = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    var signable_enr = enr.SignableENR.fromSecretKeyString(test_secret_key) catch {
        return error.ENRCreationFailed;
    };

    // Set IP address
    const ip_addr = std.net.Ip4Address.parse(ip, 0) catch {
        return error.InvalidIPAddress;
    };
    const ip_addr_bytes = std.mem.asBytes(&ip_addr.sa.addr);
    signable_enr.set("ip", ip_addr_bytes) catch {
        return error.ENRSetIPFailed;
    };

    // Set QUIC port
    var quic_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &quic_bytes, quic_port, .big);
    signable_enr.set("quic", &quic_bytes) catch {
        return error.ENRSetQUICFailed;
    };

    // Write ENR to buffer
    try enr.writeSignableENR(buffer.writer(), &signable_enr);
    return buffer.toOwnedSlice();
}

const TestConfig = struct {
    genesis_time: u64,
    num_validators: u32,
    test_dir: []const u8,
    timeout_seconds: u64 = 300, // 5 minutes default
};

const FinalizationResult = struct {
    finalized: bool,
    finalization_slot: u64,
    finalization_root: [32]u8,
    timeout_reached: bool = false,
};

/// Generates proper genesis directory structure like the genesis tool
pub fn generateGenesisDirectory(allocator: Allocator, config: TestConfig) !void {
    const cwd = std.fs.cwd();

    // Create test directory
    cwd.makeDir(config.test_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // Directory already exists, that's fine
        else => return err,
    };

    // Create network subdirectories for each node
    const node0_dir = try std.fmt.allocPrint(allocator, "{s}/node0", .{config.test_dir});
    defer allocator.free(node0_dir);
    const node1_dir = try std.fmt.allocPrint(allocator, "{s}/node1", .{config.test_dir});
    defer allocator.free(node1_dir);

    cwd.makeDir(node0_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    cwd.makeDir(node1_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Generate config.yaml (proper format expected by genesisConfigFromYAML)
    const config_yaml = try std.fmt.allocPrint(allocator,
        \\GENESIS_TIME: {d}
        \\VALIDATOR_COUNT: {d}
    , .{ config.genesis_time, config.num_validators });
    defer allocator.free(config_yaml);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.yaml", .{config.test_dir});
    defer allocator.free(config_path);
    try cwd.writeFile(.{ .sub_path = config_path, .data = config_yaml });

    // Generate nodes.yaml (array format expected by nodesFromYAML) - using programmatically generated ENRs with different ports
    const enr_0 = try generateTestENR(allocator, "192.0.2.1", 9000);
    defer allocator.free(enr_0);
    const enr_1 = try generateTestENR(allocator, "192.0.2.1", 9001);
    defer allocator.free(enr_1);

    const nodes_yaml = try std.fmt.allocPrint(allocator,
        \\- "{s}"
        \\- "{s}"
    , .{ enr_0, enr_1 });
    defer allocator.free(nodes_yaml);

    const nodes_path = try std.fmt.allocPrint(allocator, "{s}/nodes.yaml", .{config.test_dir});
    defer allocator.free(nodes_path);
    try cwd.writeFile(.{ .sub_path = nodes_path, .data = nodes_yaml });

    // Generate validators.yaml (format expected by validatorIndicesFromYAML)
    // Note: validator indices should align with bootnode array indices (0, 1)
    const validators_yaml =
        \\zeam_0:
        \\  - 0
        \\zeam_1:
        \\  - 1
    ;

    const validators_path = try std.fmt.allocPrint(allocator, "{s}/validators.yaml", .{config.test_dir});
    defer allocator.free(validators_path);
    try cwd.writeFile(.{ .sub_path = validators_path, .data = validators_yaml });

    // Generate network keys for each node (required by buildStartOptions)
    const key_content = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    const key0_path = try std.fmt.allocPrint(allocator, "{s}/key", .{node0_dir});
    defer allocator.free(key0_path);
    try cwd.writeFile(.{ .sub_path = key0_path, .data = key_content });

    const key1_path = try std.fmt.allocPrint(allocator, "{s}/key", .{node1_dir});
    defer allocator.free(key1_path);
    try cwd.writeFile(.{ .sub_path = key1_path, .data = key_content });
}

/// Runs two nodes in-process to finalization using real cli.Node
fn runTwoNodesInProcessToFinalization(allocator: Allocator, config: TestConfig) !FinalizationResult {
    std.debug.print("🔄 Starting two nodes in-process to finalization using real cli.Node...\n", .{});

    // Create logger configs for both nodes
    var logger_config1 = utils_lib.getLoggerConfig(.debug, utils_lib.FileBehaviourParams{ .fileActiveLevel = .debug, .filePath = "./log", .fileName = "zeam_0" });
    var logger_config2 = utils_lib.getLoggerConfig(.debug, utils_lib.FileBehaviourParams{ .fileActiveLevel = .debug, .filePath = "./log", .fileName = "zeam_1" });

    // Create NodeCommand configurations for both nodes (like CLI args)
    const node_cmd_0 = NodeCommand{
        .custom_genesis = config.test_dir,
        .node_id = 0,
        .metrics_enable = false,
        .metrics_port = 9667,
        .override_genesis_time = config.genesis_time,
        .network_dir = try std.fmt.allocPrint(allocator, "{s}/node0", .{config.test_dir}),
    };
    defer allocator.free(node_cmd_0.network_dir);

    const node_cmd_1 = NodeCommand{
        .custom_genesis = config.test_dir,
        .node_id = 1,
        .metrics_enable = false,
        .metrics_port = 9668,
        .override_genesis_time = config.genesis_time,
        .network_dir = try std.fmt.allocPrint(allocator, "{s}/node1", .{config.test_dir}),
    };
    defer allocator.free(node_cmd_1.network_dir);

    // Build start options for both nodes (like buildStartOptions does)
    var start_options_0: NodeOptions = .{
        .node_id = 0,
        .metrics_enable = false,
        .metrics_port = 9667,
        .bootnodes = undefined,
        .genesis_spec = undefined,
        .validator_indices = undefined,
        .local_priv_key = undefined,
        .logger_config = &logger_config1,
    };
    defer start_options_0.deinit(allocator);

    var start_options_1: NodeOptions = .{
        .node_id = 1,
        .metrics_enable = false,
        .metrics_port = 9668,
        .bootnodes = undefined,
        .genesis_spec = undefined,
        .validator_indices = undefined,
        .local_priv_key = undefined,
        .logger_config = &logger_config2,
    };
    defer start_options_1.deinit(allocator);

    // Load configurations from genesis files
    try node.buildStartOptions(allocator, node_cmd_0, &start_options_0);
    try node.buildStartOptions(allocator, node_cmd_1, &start_options_1);

    // Create real Node instances using the same initialization as CLI
    var node_0: Node = undefined;
    try node_0.init(allocator, &start_options_0);
    defer node_0.deinit();

    var node_1: Node = undefined;
    try node_1.init(allocator, &start_options_1);
    defer node_1.deinit();

    std.debug.print("✅ Created two real Node instances with proper genesis loading\n", .{});

    // Run nodes and monitor for finalization
    return try runNodesWithFinalizationMonitoring(allocator, &node_0, &node_1, config.timeout_seconds);
}

/// Runs real Nodes and monitors for finalization
fn runNodesWithFinalizationMonitoring(allocator: Allocator, node_0: *Node, node_1: *Node, timeout_seconds: u64) !FinalizationResult {
    _ = allocator; // Suppress unused parameter warning

    // Create timeout timer
    var timeout_timer = try std.time.Timer.start();
    const timeout_ns = timeout_seconds * std.time.ns_per_s;

    std.debug.print("🔄 Starting real Nodes and monitoring for finalization...\n", .{});

    // Start nodes in separate threads using Node.run()
    const node1_thread = try std.Thread.spawn(.{}, Node.run, .{node_0});
    const node2_thread = try std.Thread.spawn(.{}, Node.run, .{node_1});

    // Give nodes time to initialize
    std.time.sleep(1000 * std.time.ns_per_ms);

    // Monitor for finalization by accessing the underlying beam_node
    while (timeout_timer.read() < timeout_ns) {
        // Check finalization state from both nodes' underlying beam nodes
        const node1_finalized = node_0.beam_node.chain.forkChoice.fcStore.latest_finalized.slot > 0;
        const node2_finalized = node_1.beam_node.chain.forkChoice.fcStore.latest_finalized.slot > 0;

        if (node1_finalized or node2_finalized) {
            const finalization_slot = if (node1_finalized) node_0.beam_node.chain.forkChoice.fcStore.latest_finalized.slot else node_1.beam_node.chain.forkChoice.fcStore.latest_finalized.slot;
            const finalization_root = if (node1_finalized) node_0.beam_node.chain.forkChoice.fcStore.latest_finalized.root else node_1.beam_node.chain.forkChoice.fcStore.latest_finalized.root;

            std.debug.print("✅ Finalization detected at slot {d}\n", .{finalization_slot});

            // Give threads a moment to finish current operations, then detach
            // This avoids the segfault by allowing network cleanup to complete
            std.time.sleep(2000 * std.time.ns_per_ms);
            node1_thread.detach();
            node2_thread.detach();

            return FinalizationResult{
                .finalized = true,
                .finalization_slot = finalization_slot,
                .finalization_root = finalization_root,
                .timeout_reached = false,
            };
        }

        // Small sleep to prevent busy waiting
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    // Timeout reached - properly stop Nodes
    std.debug.print("❌ Timeout reached after {d} seconds\n", .{timeout_seconds});

    // Give threads a moment to finish current operations, then detach
    // This avoids the segfault by allowing network cleanup to complete
    std.time.sleep(2000 * std.time.ns_per_ms);
    node1_thread.detach();
    node2_thread.detach();

    return FinalizationResult{
        .finalized = false,
        .finalization_slot = 0,
        .finalization_root = [_]u8{0} ** 32,
        .timeout_reached = true,
    };
}

/// Cleans up genesis directory and all subdirectories
fn cleanupGenesisDirectory(allocator: Allocator, test_dir: []const u8) !void {
    _ = allocator; // Suppress unused parameter warning

    const cwd = std.fs.cwd();
    cwd.deleteTree(test_dir) catch |err| switch (err) {
        error.AccessDenied, error.FileBusy, error.FileSystem, error.SymLinkLoop, error.NameTooLong, error.NotDir, error.SystemResources, error.ReadOnlyFileSystem, error.InvalidUtf8, error.BadPathName, error.NetworkNotFound, error.DeviceBusy, error.NoDevice, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.Unexpected, error.FileTooBig, error.InvalidWtf8 => return err,
        // If directory doesn't exist, that's fine - nothing to clean up
    };
}

test "genesis_generator_two_node_finalization_sim" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Configuration for the test
    const config = TestConfig{
        .genesis_time = @as(u64, @intCast(std.time.timestamp())),
        .num_validators = 3,
        .test_dir = "test_genesis_two_nodes",
        .timeout_seconds = 300, // 5 minutes
    };

    std.debug.print("🚀 Starting Genesis Generator Two-Node Finalization Test \n", .{});
    std.debug.print("📁 Test directory: {s}\n", .{config.test_dir});
    std.debug.print("⏰ Genesis time: {d}\n", .{config.genesis_time});
    std.debug.print("👥 Number of validators: {d}\n", .{config.num_validators});
    std.debug.print("⏱️  Timeout: {d} seconds\n", .{config.timeout_seconds});

    // Create log directory (required by logger)
    const cwd = std.fs.cwd();
    cwd.makeDir("log") catch |err| switch (err) {
        error.PathAlreadyExists => {}, // Directory already exists, that's fine
        else => return err,
    };

    // Generate proper genesis directory structure (like genesis tool)
    try generateGenesisDirectory(allocator, config);
    std.debug.print("✅ Generated proper genesis directory structure\n", .{});

    // Run two nodes in-process to finalization (using Node command approach)
    const result = try runTwoNodesInProcessToFinalization(allocator, config);

    // Clean up genesis directory
    try cleanupGenesisDirectory(allocator, config.test_dir);

    // Verify the result
    if (result.timeout_reached) {
        std.debug.print("❌ Test failed: Timeout reached after {d} seconds\n", .{config.timeout_seconds});
        return error.TestTimeout;
    }

    if (!result.finalized) {
        std.debug.print("❌ Test failed: No finalization detected\n", .{});
        return error.NoFinalization;
    }

    std.debug.print("✅ Test passed: Finalization detected at slot {d}\n", .{result.finalization_slot});
    std.debug.print("🎉 Genesis Generator Two-Node Finalization Test completed successfully!\n", .{});
}
