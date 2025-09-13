const std = @import("std");
const json = std.json;
const build_options = @import("build_options");

const simargs = @import("simargs");

const types = @import("@zeam/types");
const nodeLib = @import("@zeam/node");
const Clock = nodeLib.Clock;
const stateProvingManager = @import("@zeam/state-proving-manager");
const BeamNode = nodeLib.BeamNode;
const xev = @import("xev");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;

const configs = @import("@zeam/configs");
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;

const utilsLib = @import("@zeam/utils");

const sftFactory = @import("@zeam/state-transition");
const metrics = @import("@zeam/metrics");
const metricsServer = @import("metrics_server.zig");

const networks = @import("@zeam/network");

const generatePrometheusConfig = @import("prometheus.zig").generatePrometheusConfig;
const yaml = @import("yaml");
const enr = @import("enr");
const ENR = enr.ENR;

const prefix = "zeam_";

const ZeamArgs = struct {
    genesis: u64 = 1234,
    log_filename: []const u8 = "consensus", // Default logger filename
    log_filepath: []const u8 = "./log", // Default logger filepath
    log_file_active_level: std.log.Level = .debug, //default log file ActiveLevel
    console_log_level: std.log.Level = .info, //default console log level
    // choosing 3 vals as default so that default beam cmd run which runs two nodes to interop
    // can justify and finalize
    num_validators: u64 = 3,
    help: bool = false,
    version: bool = false,

    __commands__: union(enum) {
        clock: struct {
            help: bool = false,
        },
        beam: struct {
            help: bool = false,
            mockNetwork: bool = false,
            metricsPort: u16 = 9667,
        },
        prove: struct {
            dist_dir: []const u8 = "zig-out/bin",
            zkvm: stateProvingManager.ZKVMs = .risc0,
            help: bool = false,

            pub const __shorts__ = .{
                .dist_dir = .d,
                .zkvm = .z,
            };

            pub const __messages__ = .{
                .dist_dir = "Directory where the zkvm guest programs are found",
            };
        },
        prometheus: struct {
            help: bool = false,

            __commands__: union(enum) {
                genconfig: struct {
                    metrics_port: u16 = 9667,
                    filename: []const u8 = "prometheus.yml",
                    help: bool = false,

                    pub const __shorts__ = .{
                        .metrics_port = .p,
                        .filename = .f,
                    };

                    pub const __messages__ = .{
                        .metrics_port = "Port to use for publishing metrics",
                        .filename = "output name for the config file",
                    };
                },

                pub const __messages__ = .{
                    .genconfig = "Generate the prometheus configuration file",
                };
            },
        },
        lean_node: struct {
            help: bool = false,
            config_filepath: []const u8 = "./config.yaml",
            bootnodes_filepath: []const u8 = "./nodes.yaml",
            validators_filepath: []const u8 = "./validators.yaml",
            genesis_filepath: ?[]const u8,
            node_id: u32 = 0,
            metrics_enable: bool = false,
            metrics_port: u16 = 9667,

            pub const __shorts__ = .{
                .help = .h,
            };

            pub const __messages__ = .{
                .config_filepath = "Path to the config yaml file",
                .bootnodes_filepath = "Path to the bootnodes yaml file",
                .validators_filepath = "Path to the validators yaml file",
                .genesis_filepath = "Path to the genesis state file",
                .node_id = "Node id for this lean node",
                .metrics_port = "Port to use for publishing metrics",
                .metrics_enable = "Enable metrics endpoint",
            };
        },

        pub const __messages__ = .{
            .clock = "Run the clock service for slot timing",
            .beam = "Run a full Beam node",
            .prove = "Generate and verify ZK proofs for state transitions on a mock chain",
            .prometheus = "Prometheus configuration management",
            .lean_node = "Run a lean node",
        };
    },

    pub const __messages__ = .{
        .genesis = "Genesis time for the chain",
        .num_validators = "Number of validators",
        .log_filename = "Log Filename",
        .log_filepath = "Log Filepath - must exist",
        .log_file_active_level = "Log File Active Level, May be separate from console log level",
        .console_log_level = "Log Level for console logging",
    };

    pub const __shorts__ = .{
        .help = .h,
        .version = .v,
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const app_description = "Zeam - Zig implementation of Beam Chain, a ZK-based Ethereum Consensus Protocol";
    const app_version = build_options.version;

    const opts = try simargs.parse(allocator, ZeamArgs, app_description, app_version);
    const genesis = opts.args.genesis;
    const num_validators = opts.args.num_validators;
    const log_filename = opts.args.log_filename;
    const log_filepath = opts.args.log_filepath;
    const log_file_active_level = opts.args.log_file_active_level;
    const console_log_level = opts.args.console_log_level;

    std.debug.print("opts ={any} genesis={d} num_validators={d}\n", .{ opts, genesis, num_validators });

    switch (opts.args.__commands__) {
        .clock => {
            var loop = try xev.Loop.init(.{});
            var clock = try Clock.init(gpa.allocator(), genesis, &loop);
            std.debug.print("clock {any}\n", .{clock});

            try clock.run();
        },
        .prove => |provecmd| {
            std.debug.print("distribution dir={s}\n", .{provecmd.dist_dir});
            var logger = utilsLib.getLogger(null, null);

            const options = stateProvingManager.ZKStateTransitionOpts{
                .zkvm = blk: switch (provecmd.zkvm) {
                    .risc0 => break :blk .{ .risc0 = .{ .program_path = "zig-out/bin/risc0_runtime.elf" } },
                    .powdr => return error.PowdrIsDeprecated,
                },
                .logger = &logger,
            };

            // generate a mock chain with 5 blocks including genesis i.e. 4 blocks on top of genesis
            const mock_config = types.GenesisSpec{
                .genesis_time = genesis,
                .num_validators = num_validators,
            };
            const mock_chain = try sftFactory.genMockChain(allocator, 5, mock_config);

            // starting beam state
            var beam_state = mock_chain.genesis_state;
            // block 0 is genesis so we have to apply block 1 onwards
            for (mock_chain.blocks[1..]) |block| {
                std.debug.print("\nprestate slot blockslot={d} stateslot={d}\n", .{ block.message.slot, beam_state.slot });
                const proof = try stateProvingManager.prove_transition(beam_state, block, options, allocator);
                // transition beam state for the next block
                try sftFactory.apply_transition(allocator, &beam_state, block, .{ .logger = &logger });

                // verify the block
                try stateProvingManager.verify_transition(proof, [_]u8{0} ** 32, [_]u8{0} ** 32, options);
            }
        },
        .beam => |beamcmd| {
            try metrics.init(allocator);

            // Start metrics HTTP server
            try metricsServer.startMetricsServer(allocator, beamcmd.metricsPort);

            std.debug.print("beam opts ={any}\n", .{beamcmd});

            const mock_network = beamcmd.mockNetwork;

            // some base mainnet spec would be loaded to build this up
            const chain_spec =
                \\{"preset": "mainnet", "name": "beamdev"}
            ;
            const options = json.ParseOptions{
                .ignore_unknown_fields = true,
                .allocate = .alloc_if_needed,
            };
            var chain_options = (try json.parseFromSlice(ChainOptions, gpa.allocator(), chain_spec, options)).value;

            const time_now_ms: usize = @intCast(std.time.milliTimestamp());
            const time_now: usize = @intCast(time_now_ms / std.time.ms_per_s);

            chain_options.genesis_time = time_now;
            chain_options.num_validators = num_validators;
            const chain_config = try ChainConfig.init(Chain.custom, chain_options);
            const anchorState = try sftFactory.genGenesisState(gpa.allocator(), chain_config.genesis);

            // TODO we seem to be needing one loop because then the events added to loop are not being fired
            // in the order to which they have been added even with the an appropriate delay added
            // behavior of this further needs to be investigated but for now we will share the same loop
            const loop = try allocator.create(xev.Loop);
            loop.* = try xev.Loop.init(.{});

            // Create loggers first so they can be passed to network implementations
            var logger1 = utilsLib.getScopedLogger(.n1, console_log_level, utilsLib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = log_filepath, .fileName = log_filename });
            var logger2 = utilsLib.getScopedLogger(.n2, console_log_level, utilsLib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = log_filepath, .fileName = log_filename });

            var backend1: networks.NetworkInterface = undefined;
            var backend2: networks.NetworkInterface = undefined;
            if (mock_network) {
                var network: *networks.Mock = try allocator.create(networks.Mock);
                network.* = try networks.Mock.init(allocator, loop, &logger1);
                backend1 = network.getNetworkInterface();
                backend2 = network.getNetworkInterface();
                std.debug.print("---\n\n mock gossip {any}\n\n", .{backend1.gossip});
            } else {
                var network1: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);
                const listen_addresses1 = &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9001")};
                // these addresses are converted to a slice in the `run` function of `EthLibp2p` so it can be freed safely after `run` returns
                defer for (listen_addresses1) |addr| addr.deinit();
                network1.* = try networks.EthLibp2p.init(allocator, loop, .{ .networkId = 0, .listen_addresses = listen_addresses1, .connect_peers = null }, &logger1);
                try network1.run();
                backend1 = network1.getNetworkInterface();

                // init a new lib2p network here to connect with network1
                var network2: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);
                // these addresses are converted to a slice in the `run` function of `EthLibp2p` so it can be freed safely after `run` returns
                const listen_addresses2 = &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9002")};
                defer for (listen_addresses2) |addr| addr.deinit();
                const connect_peers = &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/127.0.0.1/tcp/9001")};
                defer for (connect_peers) |addr| addr.deinit();
                network2.* = try networks.EthLibp2p.init(allocator, loop, .{ .networkId = 1, .listen_addresses = listen_addresses2, .connect_peers = connect_peers }, &logger2);
                try network2.run();
                backend2 = network2.getNetworkInterface();
                std.debug.print("---\n\n mock gossip {any}\n\n", .{backend1.gossip});
            }

            var clock = try allocator.create(Clock);
            clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop);

            var validator_ids_1 = [_]usize{1};
            var validator_ids_2 = [_]usize{2};

            var beam_node_1 = try BeamNode.init(allocator, .{
                // options
                .nodeId = 0,
                .config = chain_config,
                .anchorState = anchorState,
                .backend = backend1,
                .clock = clock,
                .db = .{},
                .validator_ids = &validator_ids_1,
                .logger = &logger1,
            });
            var beam_node_2 = try BeamNode.init(allocator, .{
                // options
                .nodeId = 1,
                .config = chain_config,
                .anchorState = anchorState,
                .backend = backend2,
                .clock = clock,
                .db = .{},
                .validator_ids = &validator_ids_2,
                .logger = &logger2,
            });

            try beam_node_1.run();
            try beam_node_2.run();
            try clock.run();
        },
        .prometheus => |prometheus| switch (prometheus.__commands__) {
            .genconfig => |genconfig| {
                const generated_config = try generatePrometheusConfig(allocator, genconfig.metrics_port);
                const cwd = std.fs.cwd();
                const config_file = try cwd.createFile(genconfig.filename, .{ .truncate = true });
                defer config_file.close();
                try config_file.writeAll(generated_config);
            },
        },
        .lean_node => |leancmd| {
            const start_options = StartNodeOptions{
                .node_id = leancmd.node_id,
                .config_filepath = leancmd.config_filepath,
                .bootnodes_filepath = leancmd.bootnodes_filepath,
                .validators_filepath = leancmd.validators_filepath,
                .genesis_filepath = leancmd.genesis_filepath,
                .metrics_enable = leancmd.metrics_enable,
                .metrics_port = leancmd.metrics_port,
                .log_filename = log_filename,
                .log_filepath = log_filepath,
                .log_file_active_level = log_file_active_level,
                .console_log_level = console_log_level,
            };

            try startNode(allocator, start_options);
        },
    }
}

const StartNodeOptions = struct {
    node_id: u32,
    config_filepath: []const u8,
    bootnodes_filepath: []const u8,
    validators_filepath: []const u8,
    genesis_filepath: ?[]const u8,
    metrics_enable: bool,
    metrics_port: u16,
    log_filename: []const u8,
    log_filepath: []const u8,
    log_file_active_level: std.log.Level,
    console_log_level: std.log.Level,
};

fn startNode(allocator: std.mem.Allocator, options: StartNodeOptions) !void {
    // Freeing the global secp256k1 context at the end of the program
    defer enr.deinitGlobalSecp256k1Ctx();

    const node_id = options.node_id;
    const config_filepath = options.config_filepath;
    const bootnodes_filepath = options.bootnodes_filepath;
    const validators_filepath = options.validators_filepath;
    const genesis_filepath = options.genesis_filepath;
    // TODO: support genesis file loading when ssz library supports it
    _ = genesis_filepath;

    var parsed_bootnodes = try configs.loadFromYAMLFile(allocator, bootnodes_filepath);
    defer parsed_bootnodes.deinit(allocator);

    var parsed_config = try configs.loadFromYAMLFile(allocator, config_filepath);
    defer parsed_config.deinit(allocator);

    var parsed_validators = try configs.loadFromYAMLFile(allocator, validators_filepath);
    defer parsed_validators.deinit(allocator);

    const bootnodes = try nodesFromYAML(allocator, parsed_bootnodes);
    defer allocator.free(bootnodes);

    const genesis_spec = try genesisConfigFromYAML(parsed_config);

    const validator_indices = try validatorIndicesFromYAML(allocator, node_id, parsed_validators);
    defer allocator.free(validator_indices);

    if (options.metrics_enable) {
        try metrics.init(allocator);
        try metricsServer.startMetricsServer(allocator, options.metrics_port);
    }

    // some base mainnet spec would be loaded to build this up
    const chain_spec =
        \\{"preset": "mainnet", "name": "beamdev"}
    ;
    const json_options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };
    var chain_options = (try json.parseFromSlice(ChainOptions, allocator, chain_spec, json_options)).value;

    chain_options.genesis_time = genesis_spec.genesis_time;
    chain_options.num_validators = genesis_spec.num_validators;
    const chain_config = try ChainConfig.init(Chain.custom, chain_options);
    const anchorState = try sftFactory.genGenesisState(allocator, chain_config.genesis);

    // TODO we seem to be needing one loop because then the events added to loop are not being fired
    // in the order to which they have been added even with the an appropriate delay added
    // behavior of this further needs to be investigated but for now we will share the same loop
    const loop = try allocator.create(xev.Loop);
    loop.* = try xev.Loop.init(.{});

    const self_node_index = validator_indices[0];
    var network = try allocator.create(networks.EthLibp2p);
    var node_enr: ENR = undefined;
    defer node_enr.deinit();
    try ENR.decodeTxtInto(&node_enr, bootnodes[self_node_index]);

    // Overriding the IP to 0.0.0.0 to listen on all interfaces
    try node_enr.kvs.put("ip", "\x00\x00\x00\x00");

    var node_multiaddrs = try node_enr.multiaddrP2PQUIC(allocator);
    defer node_multiaddrs.deinit(allocator);
    const listen_addresses = try node_multiaddrs.toOwnedSlice(allocator);
    // these addresses are converted to a slice in the `run` function of `EthLibp2p` so it can be freed safely after `run` returns
    defer {
        for (listen_addresses) |addr| addr.deinit();
        allocator.free(listen_addresses);
    }

    var connect_peer_list: std.ArrayListUnmanaged(Multiaddr) = .empty;
    defer connect_peer_list.deinit(allocator);

    for (bootnodes, 0..) |n, i| {
        if (i != self_node_index) {
            var n_enr: ENR = undefined;
            try ENR.decodeTxtInto(&n_enr, n);
            var peer_multiaddr_list = try n_enr.multiaddrP2PQUIC(allocator);
            defer peer_multiaddr_list.deinit(allocator);
            const peer_multiaddrs = try peer_multiaddr_list.toOwnedSlice(allocator);
            defer allocator.free(peer_multiaddrs);
            try connect_peer_list.appendSlice(allocator, peer_multiaddrs);
        }
    }

    const connect_peers = try connect_peer_list.toOwnedSlice(allocator);
    defer {
        for (connect_peers) |addr| addr.deinit();
        allocator.free(connect_peers);
    }

    var logger = utilsLib.getScopedLogger(.default, options.console_log_level, utilsLib.FileBehaviourParams{ .fileActiveLevel = options.log_file_active_level, .filePath = options.log_filepath, .fileName = options.log_filename });

    network.* = try networks.EthLibp2p.init(allocator, loop, .{ .networkId = 0, .listen_addresses = listen_addresses, .connect_peers = connect_peers }, &logger);
    try network.run();
    const backend = network.getNetworkInterface();

    var clock = try allocator.create(Clock);
    clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop);

    var beam_node = try BeamNode.init(allocator, .{
        // options
        .nodeId = node_id,
        .config = chain_config,
        .anchorState = anchorState,
        .backend = backend,
        .clock = clock,
        .db = .{},
        .validator_ids = validator_indices,
        .logger = &logger,
    });

    try beam_node.run();
    std.debug.print("Lean node {d} listened on {?d}\n", .{ node_id, try node_enr.getQUIC() });
    try clock.run();
}

fn genesisConfigFromYAML(config: yaml.Yaml) !types.GenesisSpec {
    const genesis_spec: types.GenesisSpec = .{
        .genesis_time = @intCast(config.docs.items[0].map.get("GENESIS_TIME").?.int),
        .num_validators = @intCast(config.docs.items[0].map.get("VALIDATOR_COUNT").?.int),
    };
    return genesis_spec;
}

fn nodesFromYAML(allocator: std.mem.Allocator, nodes_config: yaml.Yaml) ![]const []const u8 {
    return try nodes_config.parse(allocator, [][]const u8);
}

fn validatorIndicesFromYAML(allocator: std.mem.Allocator, node_id: u32, validators_config: yaml.Yaml) ![]usize {
    var validator_indices: std.ArrayListUnmanaged(usize) = .empty;
    defer validator_indices.deinit(allocator);

    var node_key_buf: [prefix.len + 4]u8 = undefined;
    const node_key = try std.fmt.bufPrint(&node_key_buf, "{s}{d}", .{ prefix, node_id });
    for (validators_config.docs.items[0].map.get(node_key).?.list) |item| {
        try validator_indices.append(allocator, @intCast(item.int));
    }
    return try validator_indices.toOwnedSlice(allocator);
}

test "config yaml parsing" {
    var config1 = try configs.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/src/fixtures/config.yaml");
    defer config1.deinit(std.testing.allocator);
    const genesis_spec = try genesisConfigFromYAML(config1);
    try std.testing.expectEqual(9, genesis_spec.num_validators);
    try std.testing.expectEqual(1704085200, genesis_spec.genesis_time);

    var config2 = try configs.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/src/fixtures/validators.yaml");
    defer config2.deinit(std.testing.allocator);
    const validator_indices = try validatorIndicesFromYAML(std.testing.allocator, 0, config2);
    defer std.testing.allocator.free(validator_indices);
    try std.testing.expectEqual(3, validator_indices.len);
    try std.testing.expectEqual(1, validator_indices[0]);
    try std.testing.expectEqual(4, validator_indices[1]);
    try std.testing.expectEqual(7, validator_indices[2]);

    var config3 = try configs.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/src/fixtures/nodes.yaml");
    defer config3.deinit(std.testing.allocator);
    const nodes = try nodesFromYAML(std.testing.allocator, config3);
    defer std.testing.allocator.free(nodes);
    try std.testing.expectEqual(3, nodes.len);
    try std.testing.expectEqualStrings("enr:-IW4QA0pljjdLfxS_EyUxNAxJSoGCwmOVNJauYWsTiYHyWG5Bky-7yCEktSvu_w-PWUrmzbc8vYL_Mx5pgsAix2OfOMBgmlkgnY0gmlwhKwUAAGEcXVpY4IfkIlzZWNwMjU2azGhA6mw8mfwe-3TpjMMSk7GHe3cURhOn9-ufyAqy40wEyui", nodes[0]);
    try std.testing.expectEqualStrings("enr:-IW4QNx7F6OKXCmx9igmSwOAOdUEiQ9Et73HNygWV1BbuFgkXZLMslJVgpLYmKAzBF-AO0qJYq40TtqvtFkfeh2jzqYBgmlkgnY0gmlwhKwUAAKEcXVpY4IfkIlzZWNwMjU2azGhA2hqUIfSG58w4lGPMiPp9llh1pjFuoSRUuoHmwNdHELw", nodes[1]);
    try std.testing.expectEqualStrings("enr:-IW4QOh370UNQipE8qYlVRK3MpT7I0hcOmrTgLO9agIxuPS2B485Se8LTQZ4Rhgo6eUuEXgMAa66Wt7lRYNHQo9zk8QBgmlkgnY0gmlwhKwUAAOEcXVpY4IfkIlzZWNwMjU2azGhA7NTxgfOmGE2EQa4HhsXxFOeHdTLYIc2MEBczymm9IUN", nodes[2]);
}
