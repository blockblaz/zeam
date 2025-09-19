const std = @import("std");
const Allocator = std.mem.Allocator;
const node_lib = @import("@zeam/node");
const BeamNode = node_lib.BeamNode;
const Clock = node_lib.Clock;
const utils_lib = @import("@zeam/utils");
const Logger = utils_lib.ZeamLogger;
const node = @import("../node.zig");
const Node = node.Node;
const NodeOptions = node.NodeOptions;
const NodeCommand = @import("../main.zig").NodeCommand;
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const enr_lib = @import("enr");
const sft = @import("@zeam/state-transition");
const metrics = @import("@zeam/metrics");
const metrics_server = @import("../metrics_server.zig");
const xev = @import("xev");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;

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

    // Generate nodes.yaml (array format expected by nodesFromYAML) - using valid ENRs from fixtures
    const nodes_yaml =
        \\- "enr:-IW4QA0pljjdLfxS_EyUxNAxJSoGCwmOVNJauYWsTiYHyWG5Bky-7yCEktSvu_w-PWUrmzbc8vYL_Mx5pgsAix2OfOMBgmlkgnY0gmlwhKwUAAGEcXVpY4IfkIlzZWNwMjU2azGhA6mw8mfwe-3TpjMMSk7GHe3cURhOn9-ufyAqy40wEyui"
        \\- "enr:-IW4QOh370UNQipE8qYlVRK3MpT7I0hcOmrTgLO9agIxuPS2B485Se8LTQZ4Rhgo6eUuEXgMAa66Wt7lRYNHQo9zk8QBgmlkgnY0gmlwhKwUAAOEcXVpY4IfkIlzZWNwMjU2azGhA7NTxgfOmGE2EQa4HhsXxFOeHdTLYIc2MEBczymm9IUN"
    ;

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

/// Wrapper Node struct that includes BeamNode and Clock with controllable execution
const TestNode = struct {
    beam_node: BeamNode,
    clock: Clock,
    network: networks.EthLibp2p,
    enr: enr_lib.ENR,
    loop: xev.Loop,
    options: *const NodeOptions,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: *const NodeOptions) !Self {
        // Initialize similar to Node.init but with our controlled structure
        if (options.metrics_enable) {
            try metrics.init(allocator);
            try metrics_server.startMetricsServer(allocator, options.metrics_port);
        }

        // Create chain spec and config
        const chain_spec =
            \\{"preset": "mainnet", "name": "beamdev"}
        ;
        const json_options = std.json.ParseOptions{
            .ignore_unknown_fields = true,
            .allocate = .alloc_if_needed,
        };
        var chain_options = (try std.json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, json_options)).value;

        chain_options.genesis_time = options.genesis_spec.genesis_time;
        chain_options.num_validators = options.genesis_spec.num_validators;
        const chain_config = try configs.ChainConfig.init(configs.Chain.custom, chain_options);
        var anchorState = try sft.genGenesisState(allocator, chain_config.genesis);
        errdefer anchorState.deinit(allocator);

        // Create event loop
        var loop = try xev.Loop.init(.{});

        // Create ENR and network addresses
        var enr: enr_lib.ENR = undefined;
        const self_node_index = options.validator_indices[0];
        try enr_lib.ENR.decodeTxtInto(&enr, options.bootnodes[self_node_index]);
        try enr.kvs.put("ip", "\x00\x00\x00\x00"); // Listen on all interfaces

        // Set unique port for each node to avoid conflicts
        const base_port: u16 = 9000;
        const unique_port = base_port + @as(u16, @intCast(options.node_id));
        const port_bytes = [_]u8{ @as(u8, @intCast((unique_port >> 8) & 0xFF)), @as(u8, @intCast(unique_port & 0xFF)) };
        try enr.kvs.put("quic", &port_bytes);

        var node_multiaddrs = try enr.multiaddrP2PQUIC(allocator);
        defer node_multiaddrs.deinit(allocator);
        const listen_addresses = try node_multiaddrs.toOwnedSlice(allocator);

        // Create connect peers list (following the pattern from node.zig)
        var connect_peer_list: std.ArrayListUnmanaged(Multiaddr) = .empty;
        defer connect_peer_list.deinit(allocator);

        for (options.bootnodes, 0..) |bootnode, i| {
            if (i != self_node_index) {
                var peer_enr: enr_lib.ENR = undefined;
                try enr_lib.ENR.decodeTxtInto(&peer_enr, bootnode);
                defer peer_enr.deinit();
                var peer_multiaddr_list = try peer_enr.multiaddrP2PQUIC(allocator);
                defer peer_multiaddr_list.deinit(allocator);
                const peer_multiaddrs = try peer_multiaddr_list.toOwnedSlice(allocator);
                defer allocator.free(peer_multiaddrs);
                try connect_peer_list.appendSlice(allocator, peer_multiaddrs);
            }
        }

        const connect_peers = try connect_peer_list.toOwnedSlice(allocator);

        // Initialize network
        var network = try networks.EthLibp2p.init(allocator, &loop, .{ .networkId = 0, .listen_addresses = listen_addresses, .connect_peers = connect_peers, .local_private_key = options.local_priv_key }, options.logger);
        errdefer network.deinit();

        // Initialize clock
        var clock = try Clock.init(allocator, chain_config.genesis.genesis_time, &loop);
        errdefer clock.deinit(allocator);

        // Initialize BeamNode
        const beam_node = try BeamNode.init(allocator, .{
            .nodeId = options.node_id,
            .config = chain_config,
            .anchorState = anchorState,
            .backend = network.getNetworkInterface(),
            .clock = &clock,
            .db = .{},
            .validator_ids = options.validator_indices,
            .logger = options.logger,
        });

        return Self{
            .beam_node = beam_node,
            .clock = clock,
            .network = network,
            .enr = enr,
            .loop = loop,
            .options = options,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.clock.deinit(self.allocator);
        self.beam_node.deinit();
        self.network.deinit();
        self.enr.deinit();
        self.loop.deinit();
    }

    pub fn start(self: *Self) !void {
        self.running.store(true, .monotonic);

        // Start network and beam node
        try self.network.run();
        try self.beam_node.run();

        // Controlled clock execution instead of infinite Clock.run()
        while (self.running.load(.monotonic)) {
            self.clock.tickInterval();
            try self.clock.events.run(.until_done);
            // Small yield to allow stop signal checking
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .monotonic);
    }
};

/// Runs two nodes in-process to finalization using wrapper Node approach
fn runTwoNodesInProcessToFinalization(allocator: Allocator, config: TestConfig) !FinalizationResult {
    std.debug.print("🔄 Starting two nodes in-process to finalization using TestNode wrapper approach...\n", .{});

    // Create loggers for both nodes
    var logger1 = utils_lib.getLogger(.debug, utils_lib.FileBehaviourParams{ .fileActiveLevel = .debug, .filePath = "./log", .fileName = "zeam_0" });
    var logger2 = utils_lib.getLogger(.debug, utils_lib.FileBehaviourParams{ .fileActiveLevel = .debug, .filePath = "./log", .fileName = "zeam_1" });

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
        .logger = &logger1,
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
        .logger = &logger2,
    };
    defer start_options_1.deinit(allocator);

    // Load configurations from genesis files
    try node.buildStartOptions(allocator, node_cmd_0, &start_options_0);
    try node.buildStartOptions(allocator, node_cmd_1, &start_options_1);

    // Create TestNode instances with controlled execution
    var test_node_0 = try TestNode.init(allocator, &start_options_0);
    defer test_node_0.deinit();
    var test_node_1 = try TestNode.init(allocator, &start_options_1);
    defer test_node_1.deinit();

    std.debug.print("✅ Created two TestNode instances with proper genesis loading\n", .{});

    // Run nodes and monitor for finalization
    return try runNodesWithFinalizationMonitoring(allocator, &test_node_0, &test_node_1, config.timeout_seconds);
}

/// Runs TestNodes and monitors for finalization with proper shutdown capability
fn runNodesWithFinalizationMonitoring(allocator: Allocator, test_node_0: *TestNode, test_node_1: *TestNode, timeout_seconds: u64) !FinalizationResult {
    _ = allocator; // Suppress unused parameter warning

    // Create timeout timer
    var timeout_timer = try std.time.Timer.start();
    const timeout_ns = timeout_seconds * std.time.ns_per_s;

    std.debug.print("🔄 Starting TestNodes and monitoring for finalization...\n", .{});

    // Start nodes in separate threads using TestNode.start()
    const node1_thread = try std.Thread.spawn(.{}, TestNode.start, .{test_node_0});
    const node2_thread = try std.Thread.spawn(.{}, TestNode.start, .{test_node_1});

    // Give nodes time to initialize
    std.time.sleep(1000 * std.time.ns_per_ms);

    // Monitor for finalization by accessing the underlying beam_node
    while (timeout_timer.read() < timeout_ns) {
        // Check finalization state from both nodes' underlying beam nodes
        const node1_finalized = test_node_0.beam_node.chain.forkChoice.fcStore.latest_finalized.slot > 0;
        const node2_finalized = test_node_1.beam_node.chain.forkChoice.fcStore.latest_finalized.slot > 0;

        if (node1_finalized or node2_finalized) {
            const finalization_slot = if (node1_finalized) test_node_0.beam_node.chain.forkChoice.fcStore.latest_finalized.slot else test_node_1.beam_node.chain.forkChoice.fcStore.latest_finalized.slot;
            const finalization_root = if (node1_finalized) test_node_0.beam_node.chain.forkChoice.fcStore.latest_finalized.root else test_node_1.beam_node.chain.forkChoice.fcStore.latest_finalized.root;

            std.debug.print("✅ Finalization detected at slot {d}\n", .{finalization_slot});

            // Stop both nodes
            test_node_0.stop();
            test_node_1.stop();

            // Use consistent cleanup approach
            node1_thread.detach();
            node2_thread.detach();
            std.time.sleep(1000 * std.time.ns_per_ms);

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

    // Timeout reached - properly stop TestNodes
    std.debug.print("❌ Timeout reached after {d} seconds\n", .{timeout_seconds});

    test_node_0.stop();
    test_node_1.stop();

    // Use consistent cleanup approach
    node1_thread.detach();
    node2_thread.detach();
    std.time.sleep(1000 * std.time.ns_per_ms);

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

    std.debug.print("🚀 Starting Genesis Generator Two-Node Finalization Test (Node Command Approach)\n", .{});
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
