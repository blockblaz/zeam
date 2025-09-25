const std = @import("std");
const json = std.json;
const build_options = @import("build_options");
const constants = @import("constants.zig");

const simargs = @import("simargs");

const types = @import("@zeam/types");
const node_lib = @import("@zeam/node");
const Clock = node_lib.Clock;
const state_proving_manager = @import("@zeam/state-proving-manager");
const BeamNode = node_lib.BeamNode;
const xev = @import("xev");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;

const configs = @import("@zeam/configs");
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;

const utils_lib = @import("@zeam/utils");

const sft_factory = @import("@zeam/state-transition");
const metrics = @import("@zeam/metrics");
const metrics_server = @import("metrics_server.zig");

const networks = @import("@zeam/network");

const generatePrometheusConfig = @import("prometheus.zig").generatePrometheusConfig;
const yaml = @import("yaml");
const node = @import("node.zig");
const enr_lib = @import("enr");

pub const NodeCommand = struct {
    help: bool = false,
    custom_genesis: []const u8,
    node_id: u32 = 0,
    metrics_enable: bool = false,
    metrics_port: u16 = constants.DEFAULT_METRICS_PORT,
    override_genesis_time: ?u64,
    network_dir: []const u8 = "./network",

    pub const __shorts__ = .{
        .help = .h,
    };

    pub const __messages__ = .{
        .custom_genesis = "Custom genesis directory path",
        .node_id = "Node id for this lean node",
        .metrics_port = "Port to use for publishing metrics",
        .metrics_enable = "Enable metrics endpoint",
        .network_dir = "Directory to store network related information, e.g., peer ids, keys, etc.",
        .override_genesis_time = "Override genesis time in the config.yaml",
        .help = "Show help information for the node command",
    };
};

const ZeamArgs = struct {
    genesis: u64 = 1234,
    log_filename: []const u8 = "consensus", // Default logger filename
    log_filepath: []const u8 = "./log", // Default logger filepath
    log_file_active_level: std.log.Level = .debug, //default log file ActiveLevel
    monocolor_file_log: bool = false, //dont log colors in log files
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
            metricsPort: u16 = constants.DEFAULT_METRICS_PORT,
        },
        prove: struct {
            dist_dir: []const u8 = "zig-out/bin",
            zkvm: state_proving_manager.ZKVMs = .risc0,
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
                    metrics_port: u16 = constants.DEFAULT_METRICS_PORT,
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
        node: NodeCommand,

        pub const __messages__ = .{
            .clock = "Run the clock service for slot timing",
            .beam = "Run a full Beam node",
            .prove = "Generate and verify ZK proofs for state transitions on a mock chain",
            .prometheus = "Prometheus configuration management",
            .node = "Run a lean node",
        };
    },

    pub const __messages__ = .{
        .genesis = "Genesis time for the chain",
        .num_validators = "Number of validators",
        .log_filename = "Log Filename",
        .log_filepath = "Log Filepath - must exist",
        .log_file_active_level = "Log File Active Level, May be separate from console log level",
        .monocolor_file_log = "Dont Log color formatted log in files for use in non color supported editors",
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
    const monocolor_file_log = opts.args.monocolor_file_log;
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
            var zeam_logger_config = utils_lib.getLoggerConfig(null, null);
            const logger = zeam_logger_config.logger(.state_proving_manager);
            const stf_logger = zeam_logger_config.logger(.state_transition);

            const options = state_proving_manager.ZKStateTransitionOpts{
                .zkvm = blk: switch (provecmd.zkvm) {
                    .risc0 => break :blk .{ .risc0 = .{ .program_path = "zig-out/bin/risc0_runtime.elf" } },
                    .powdr => return error.PowdrIsDeprecated,
                },
                .logger = logger,
            };

            // generate a mock chain with 5 blocks including genesis i.e. 4 blocks on top of genesis
            const mock_config = types.GenesisSpec{
                .genesis_time = genesis,
                .num_validators = num_validators,
            };
            const mock_chain = try sft_factory.genMockChain(allocator, 5, mock_config);

            // starting beam state
            var beam_state = mock_chain.genesis_state;
            // block 0 is genesis so we have to apply block 1 onwards
            for (mock_chain.blocks[1..]) |block| {
                std.debug.print("\nprestate slot blockslot={d} stateslot={d}\n", .{ block.message.slot, beam_state.slot });
                const proof = try state_proving_manager.prove_transition(beam_state, block, options, allocator);
                // transition beam state for the next block
                try sft_factory.apply_transition(allocator, &beam_state, block, .{ .logger = stf_logger });

                // verify the block
                try state_proving_manager.verify_transition(proof, [_]u8{0} ** 32, [_]u8{0} ** 32, options);
            }
        },
        .beam => |beamcmd| {
            try metrics.init(allocator);

            // Start metrics HTTP server
            try metrics_server.startMetricsServer(allocator, beamcmd.metricsPort);

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
            // transfer ownership of the chain_options to ChainConfig
            const chain_config = try ChainConfig.init(Chain.custom, chain_options);
            const anchorState = try sft_factory.genGenesisState(gpa.allocator(), chain_config.genesis);

            // TODO we seem to be needing one loop because then the events added to loop are not being fired
            // in the order to which they have been added even with the an appropriate delay added
            // behavior of this further needs to be investigated but for now we will share the same loop
            const loop = try allocator.create(xev.Loop);
            loop.* = try xev.Loop.init(.{});

            // Ensure log directory exists if log_filepath is not provided or is the default "./log"
            if (std.mem.eql(u8, log_filepath, "./log")) {
                var cwd = std.fs.cwd();
                if (cwd.openDir(log_filepath, .{})) |_| {} else |_| {
                    cwd.makeDir(log_filepath) catch |err| {
                        std.debug.print("ERROR : Failed to create log directory: {any}\n", .{err});
                    };
                }
            }

            // Create loggers first so they can be passed to network implementations
            var logger1_config = utils_lib.getScopedLoggerConfig(.n1, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = log_filepath, .fileName = log_filename, .monocolorFile = monocolor_file_log });
            var logger2_config = utils_lib.getScopedLoggerConfig(.n2, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = log_filepath, .fileName = log_filename, .monocolorFile = monocolor_file_log });

            var backend1: networks.NetworkInterface = undefined;
            var backend2: networks.NetworkInterface = undefined;
            if (mock_network) {
                var network: *networks.Mock = try allocator.create(networks.Mock);
                network.* = try networks.Mock.init(allocator, loop, logger1_config.logger(.network));
                backend1 = network.getNetworkInterface();
                backend2 = network.getNetworkInterface();
                logger1_config.logger(null).debug("--- mock gossip {any}", .{backend1.gossip});
            } else {
                var network1: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);
                const key_pair1 = enr_lib.KeyPair.generate();
                const priv_key1 = key_pair1.v4.toString();
                const listen_addresses1 = &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9001")};
                // these addresses are converted to a slice in the `run` function of `EthLibp2p` so it can be freed safely after `run` returns
                defer for (listen_addresses1) |addr| addr.deinit();
                const network_name1 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name1);
                network1.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 0,
                    .network_name = network_name1,
                    .local_private_key = &priv_key1,
                    .listen_addresses = listen_addresses1,
                    .connect_peers = null,
                }, logger1_config.logger(.network));
                try network1.run();
                backend1 = network1.getNetworkInterface();

                // init a new lib2p network here to connect with network1
                var network2: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);
                const key_pair2 = enr_lib.KeyPair.generate();
                const priv_key2 = key_pair2.v4.toString();
                // these addresses are converted to a slice in the `run` function of `EthLibp2p` so it can be freed safely after `run` returns
                const listen_addresses2 = &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9002")};
                defer for (listen_addresses2) |addr| addr.deinit();
                const connect_peers = &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/127.0.0.1/tcp/9001")};
                defer for (connect_peers) |addr| addr.deinit();
                const network_name2 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name2);
                network2.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 1,
                    .network_name = network_name2,
                    .local_private_key = &priv_key2,
                    .listen_addresses = listen_addresses2,
                    .connect_peers = connect_peers,
                }, logger2_config.logger(.network));
                try network2.run();
                backend2 = network2.getNetworkInterface();
                logger1_config.logger(null).debug("--- ethlibp2p gossip {any}", .{backend1.gossip});
            }

            var clock = try allocator.create(Clock);
            clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop);

            var validator_ids_1 = [_]usize{1};
            var validator_ids_2 = [_]usize{2};

            var beam_node_1 = try BeamNode.init(allocator, .{
                // options
                .nodeId = 0,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend1,
                .clock = clock,
                .db = .{},
                .validator_ids = &validator_ids_1,
                .logger_config = &logger1_config,
            });
            var beam_node_2 = try BeamNode.init(allocator, .{
                // options
                .nodeId = 1,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend2,
                .clock = clock,
                .db = .{},
                .validator_ids = &validator_ids_2,
                .logger_config = &logger2_config,
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
        .node => |leancmd| {
            var zeam_logger_config = utils_lib.getLoggerConfig(console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = log_filepath, .fileName = log_filename });

            var start_options: node.NodeOptions = .{
                .node_id = leancmd.node_id,
                .metrics_enable = leancmd.metrics_enable,
                .metrics_port = leancmd.metrics_port,
                .bootnodes = undefined,
                .genesis_spec = undefined,
                .validator_indices = undefined,
                .local_priv_key = undefined,
                .logger_config = &zeam_logger_config,
            };

            defer start_options.deinit(allocator);

            try node.buildStartOptions(allocator, leancmd, &start_options);

            var lean_node: node.Node = undefined;
            try lean_node.init(allocator, &start_options);
            defer lean_node.deinit();
            try lean_node.run();
        },
    }
}

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
