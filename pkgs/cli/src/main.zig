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

const database = @import("@zeam/database");

const sft_factory = @import("@zeam/state-transition");
const api = @import("@zeam/api");
const api_server = @import("api_server.zig");

const networks = @import("@zeam/network");

const generatePrometheusConfig = @import("prometheus.zig").generatePrometheusConfig;
const yaml = @import("yaml");
const node = @import("node.zig");
const enr_lib = @import("enr");

pub const NodeCommand = struct {
    help: bool = false,
    custom_genesis: []const u8,
    // internal libp2p network id, only matters when two or more nodes are run in same process
    network_id: u32 = 0,
    // the string id to pick configuration in validators.yaml/validator_config.yaml
    @"node-id": []const u8,
    // the private libp2p key arg currently ignored but supported to be cross client compatible for
    // lean-quickstart standard args 1. data-dir 2. node-id 3. node-key
    @"node-key": []const u8 = constants.DEFAULT_NODE_KEY,
    // 1. a special value of "genesis_bootnode" for validator config means its a genesis bootnode and so
    //   the configuration is to be picked from genesis
    // 2. otherwise validator_config is dir path to this nodes's validator_config.yaml and validatrs.yaml
    //   and one must use all the nodes in genesis nodes.yaml as peers
    validator_config: []const u8,
    metrics_enable: bool = false,
    metrics_port: u16 = constants.DEFAULT_METRICS_PORT,
    override_genesis_time: ?u64,
    @"network-dir": []const u8 = "./network",
    @"data-dir": []const u8 = constants.DEFAULT_DATA_DIR,

    pub const __shorts__ = .{
        .help = .h,
    };

    pub const __messages__ = .{
        .custom_genesis = "Custom genesis directory path",
        .network_id = "Internal libp2p network id relevant when running nodes in same process",
        .@"node-id" = "The node id in the genesis config for this lean node",
        .@"node-key" = "Path to the node key file",
        .validator_config = "Path to the validator config directory or 'genesis_bootnode'",
        .metrics_port = "Port to use for publishing metrics",
        .metrics_enable = "Enable metrics endpoint",
        .@"network-dir" = "Directory to store network related information, e.g., peer ids, keys, etc.",
        .override_genesis_time = "Override genesis time in the config.yaml",
        .@"data-dir" = "Path to the data directory",
        .help = "Show help information for the node command",
    };
};

const ZeamArgs = struct {
    genesis: u64 = 1234,
    log_filename: []const u8 = "consensus", // Default logger filename
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
            data_dir: []const u8 = constants.DEFAULT_DATA_DIR,
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
                    .openvm => break :blk .{ .openvm = .{ .program_path = "zig-out/bin/zeam-stf-openvm", .result_path = "/tmp/openvm-results" } },
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
            try api.init(allocator);

            // Start metrics HTTP server
            try api_server.startAPIServer(allocator, beamcmd.metricsPort);

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
            var anchorState: types.BeamState = undefined;
            try anchorState.genGenesisState(gpa.allocator(), chain_config.genesis);
            defer anchorState.deinit();

            // TODO we seem to be needing one loop because then the events added to loop are not being fired
            // in the order to which they have been added even with the an appropriate delay added
            // behavior of this further needs to be investigated but for now we will share the same loop
            const loop = try allocator.create(xev.Loop);
            loop.* = try xev.Loop.init(.{});

            try std.fs.cwd().makePath(beamcmd.data_dir);

            // Create loggers first so they can be passed to network implementations
            var logger1_config = utils_lib.getScopedLoggerConfig(.n1, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.data_dir, .fileName = log_filename, .monocolorFile = monocolor_file_log });
            var logger2_config = utils_lib.getScopedLoggerConfig(.n2, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.data_dir, .fileName = log_filename, .monocolorFile = monocolor_file_log });

            var backend1: networks.NetworkInterface = undefined;
            var backend2: networks.NetworkInterface = undefined;

            // These are owned by the network implementations and will be freed in their deinit functions
            // We will run network1 and network2 after the nodes are running to avoid race conditions
            var network1: *networks.EthLibp2p = undefined;
            var network2: *networks.EthLibp2p = undefined;
            var listen_addresses1: []Multiaddr = undefined;
            var listen_addresses2: []Multiaddr = undefined;
            var connect_peers: []Multiaddr = undefined;
            defer {
                for (listen_addresses1) |addr| addr.deinit();
                allocator.free(listen_addresses1);
                for (listen_addresses2) |addr| addr.deinit();
                allocator.free(listen_addresses2);
                for (connect_peers) |addr| addr.deinit();
                allocator.free(connect_peers);
            }

            if (mock_network) {
                var network: *networks.Mock = try allocator.create(networks.Mock);
                network.* = try networks.Mock.init(allocator, loop, logger1_config.logger(.network));
                backend1 = network.getNetworkInterface();
                backend2 = network.getNetworkInterface();
                logger1_config.logger(null).debug("--- mock gossip {any}", .{backend1.gossip});
            } else {
                network1 = try allocator.create(networks.EthLibp2p);
                const key_pair1 = enr_lib.KeyPair.generate();
                const priv_key1 = key_pair1.v4.toString();
                listen_addresses1 = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9001")});
                const network_name1 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name1);
                network1.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 0,
                    .network_name = network_name1,
                    .local_private_key = &priv_key1,
                    .listen_addresses = listen_addresses1,
                    .connect_peers = null,
                }, logger1_config.logger(.network));
                backend1 = network1.getNetworkInterface();

                // init a new lib2p network here to connect with network1
                network2 = try allocator.create(networks.EthLibp2p);
                const key_pair2 = enr_lib.KeyPair.generate();
                const priv_key2 = key_pair2.v4.toString();
                listen_addresses2 = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9002")});
                connect_peers = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/127.0.0.1/tcp/9001")});
                const network_name2 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name2);
                network2.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 1,
                    .network_name = network_name2,
                    .local_private_key = &priv_key2,
                    .listen_addresses = listen_addresses2,
                    .connect_peers = connect_peers,
                }, logger2_config.logger(.network));
                backend2 = network2.getNetworkInterface();
                logger1_config.logger(null).debug("--- ethlibp2p gossip {any}", .{backend1.gossip});
            }

            var clock = try allocator.create(Clock);
            clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop);

            //one missing validator is by design
            var validator_ids_1 = [_]usize{1};
            var validator_ids_2 = [_]usize{2};

            const data_dir_1 = try std.fmt.allocPrint(allocator, "{s}/node1", .{beamcmd.data_dir});
            defer allocator.free(data_dir_1);
            const data_dir_2 = try std.fmt.allocPrint(allocator, "{s}/node2", .{beamcmd.data_dir});
            defer allocator.free(data_dir_2);

            var db_1 = try database.Db.open(allocator, logger1_config.logger(.database), data_dir_1);
            defer db_1.deinit();
            var db_2 = try database.Db.open(allocator, logger2_config.logger(.database), data_dir_2);
            defer db_2.deinit();

            var beam_node_1: BeamNode = undefined;
            try beam_node_1.init(allocator, .{
                // options
                .nodeId = 0,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend1,
                .clock = clock,
                .validator_ids = &validator_ids_1,
                .db = db_1,
                .logger_config = &logger1_config,
            });

            var beam_node_2: BeamNode = undefined;
            try beam_node_2.init(allocator, .{
                // options
                .nodeId = 1,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend2,
                .clock = clock,
                .validator_ids = &validator_ids_2,
                .db = db_2,
                .logger_config = &logger2_config,
            });

            try beam_node_1.run();
            try beam_node_2.run();

            if (!mock_network) {
                try network1.run();
                try network2.run();
            }

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
            try std.fs.cwd().makePath(leancmd.@"data-dir");
            var zeam_logger_config = utils_lib.getLoggerConfig(console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = leancmd.@"data-dir", .fileName = log_filename });

            var start_options: node.NodeOptions = .{
                .network_id = leancmd.network_id,
                .node_key = leancmd.@"node-id",
                .validator_config = leancmd.validator_config,
                .node_key_index = undefined,
                .metrics_enable = leancmd.metrics_enable,
                .metrics_port = leancmd.metrics_port,
                .bootnodes = undefined,
                .genesis_spec = undefined,
                .validator_indices = undefined,
                .local_priv_key = undefined,
                .logger_config = &zeam_logger_config,
                .database_path = leancmd.@"data-dir",
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
