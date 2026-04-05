const std = @import("std");
const json = std.json;
const build_options = @import("build_options");
const constants = @import("constants.zig");

const simargs = @import("simargs");

// Suppress verbose YAML tokenizer/parser debug logs while preserving errors/warnings
pub const std_options: std.Options = .{
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .tokenizer, .level = .err },
        .{ .scope = .parser, .level = .err },
    },
};

const types = @import("@zeam/types");
const xmss = @import("@zeam/xmss");
const node_lib = @import("@zeam/node");
const Clock = node_lib.Clock;
const state_proving_manager = @import("@zeam/state-proving-manager");
const BeamNode = node_lib.BeamNode;
const xev = @import("xev");

const configs = @import("@zeam/configs");
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;

const utils_lib = @import("@zeam/utils");
const key_manager_lib = @import("@zeam/key-manager");
const zeam_metrics = @import("@zeam/metrics");

const database = @import("@zeam/database");

const sft_factory = @import("@zeam/state-transition");
const api = @import("@zeam/api");
const api_server = @import("api_server.zig");
const metrics_server = @import("metrics_server.zig");

const networks = @import("@zeam/network");

const generatePrometheusConfig = @import("prometheus.zig").generatePrometheusConfig;
const yaml = @import("yaml");
const node = @import("node.zig");
const enr_lib = @import("enr");

const ZERO_HASH = types.ZERO_HASH;

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
    // 2. otherwise validator_config is dir path to this nodes's validator_config.yaml and annotated_validators.yaml
    //   and one must use all the nodes in genesis nodes.yaml as peers
    validator_config: []const u8,
    metrics_enable: bool = false,
    @"api-port": u16 = constants.DEFAULT_API_PORT,
    @"metrics-port": u16 = constants.DEFAULT_METRICS_PORT,
    override_genesis_time: ?u64,
    @"sig-keys-dir": []const u8 = "hash-sig-keys",
    @"network-dir": []const u8 = "./network",
    @"data-dir": []const u8 = constants.DEFAULT_DATA_DIR,
    @"checkpoint-sync-url": ?[]const u8 = null,
    @"is-aggregator": bool = false,
    @"attestation-committee-count": ?u64 = null,
    @"aggregate-subnet-ids": ?[]const u8 = null,
    /// UDP port for zig-ethp2p QUIC listener. 0 means OS-assigned random port.
    @"ethp2p-quic-port": u16 = 0,
    /// UDP port for the discv5 discovery listener. 0 means OS-assigned random port.
    @"discv5-port": u16 = 0,

    pub const __shorts__ = .{
        .help = .h,
    };

    pub const __messages__ = .{
        .custom_genesis = "Custom genesis directory path",
        .network_id = "Internal network id relevant when running nodes in same process",
        .@"node-id" = "The node id in the genesis config for this lean node",
        .@"node-key" = "Path to the node key file",
        .validator_config = "Path to the validator config directory or 'genesis_bootnode'",
        .@"api-port" = "Port for the API server (health, events, forkchoice graph, checkpoint state)",
        .@"metrics-port" = "Port for the Prometheus metrics server",
        .metrics_enable = "Enable API and metrics servers (health, events, forkchoice graph, checkpoint state, metrics)",
        .@"network-dir" = "Directory to store network related information, e.g., peer ids, keys, etc.",
        .override_genesis_time = "Override genesis time in the config.yaml",
        .@"sig-keys-dir" = "Relative path of custom genesis to signature key directory",
        .@"data-dir" = "Path to the data directory",
        .@"checkpoint-sync-url" = "URL to fetch finalized checkpoint state from for checkpoint sync (e.g., http://localhost:5052/lean/v0/states/finalized)",
        .@"is-aggregator" = "Enable aggregator mode for committee signature aggregation",
        .@"attestation-committee-count" = "Number of attestation committees (subnets); overrides config.yaml ATTESTATION_COMMITTEE_COUNT",
        .@"aggregate-subnet-ids" = "Comma-separated list of subnet ids to additionally subscribe and aggregate gossip attestations (e.g. '0,1,2'); adds to automatic computation from validator ids",
        .@"ethp2p-quic-port" = "UDP port for zig-ethp2p QUIC listener (0 = OS-assigned random port)",
        .@"discv5-port" = "UDP port for discv5 peer discovery listener (0 = OS-assigned random port)",
        .help = "Show help information for the node command",
    };
};

const BeamCmd = struct {
    help: bool = false,
    mockNetwork: bool = false,
    @"api-port": u16 = constants.DEFAULT_API_PORT,
    @"metrics-port": u16 = constants.DEFAULT_METRICS_PORT,
    data_dir: []const u8 = constants.DEFAULT_DATA_DIR,
    @"is-aggregator": bool = true,

    pub fn format(self: BeamCmd, writer: anytype) !void {
        try writer.print("BeamCmd{{ mockNetwork={}, api-port={d}, metrics-port={d}, data_dir=\"{s}\", is-aggregator={} }}", .{
            self.mockNetwork,
            self.@"api-port",
            self.@"metrics-port",
            self.data_dir,
            self.@"is-aggregator",
        });
    }
};

/// Test-only CLI: sign a fixed message for (epoch, slot) and dump signature hex.
const TestsigCmd = struct {
    help: bool = false,
    @"private-key": ?[]const u8 = null,
    @"key-path": ?[]const u8 = null,
    epoch: u64 = 0,
    slot: u64 = 0,

    pub const __messages__ = .{
        .@"private-key" = "Seed phrase for key generation (testing only); use with --key-path for SSZ key files",
        .@"key-path" = "Path to validator_X_pk.ssz; loads keypair from pk.ssz and same-dir validator_X_sk.ssz",
        .epoch = "Epoch number for signing",
        .slot = "Slot number (encoded in signed message)",
        .help = "Show help for testsig",
    };
};

const ZeamArgs = struct {
    genesis: u64 = 1234,
    log_filename: []const u8 = "consensus", // Default logger filename
    log_file_active_level: std.log.Level = .debug, //default log file ActiveLevel
    monocolor_file_log: bool = false, //dont log colors in log files
    console_log_level: std.log.Level = .info, //default console log level
    help: bool = false,
    version: bool = false,

    __commands__: union(enum) {
        clock: struct {
            help: bool = false,
        },
        beam: BeamCmd,
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
                    @"metrics-port": u16 = constants.DEFAULT_METRICS_PORT,
                    filename: []const u8 = "prometheus.yml",
                    help: bool = false,

                    pub const __shorts__ = .{
                        .@"metrics-port" = .p,
                        .filename = .f,
                    };

                    pub const __messages__ = .{
                        .@"metrics-port" = "Port for the metrics server to scrape",
                        .filename = "output name for the config file",
                    };
                },

                pub const __messages__ = .{
                    .genconfig = "Generate the prometheus configuration file",
                };
            },
        },
        node: NodeCommand,
        testsig: TestsigCmd,

        pub const __messages__ = .{
            .clock = "Run the clock service for slot timing",
            .beam = "Run a full Beam node",
            .prove = "Generate and verify ZK proofs for state transitions on a mock chain",
            .prometheus = "Prometheus configuration management",
            .node = "Run a lean node",
            .testsig = "Dump a signature for (private-key, epoch, slot); testing only",
        };
    },

    pub const __messages__ = .{
        .genesis = "Genesis time for the chain",
        .log_filename = "Log Filename",
        .log_file_active_level = "Log File Active Level, May be separate from console log level",
        .monocolor_file_log = "Dont Log color formatted log in files for use in non color supported editors",
        .console_log_level = "Log Level for console logging",
    };

    pub const __shorts__ = .{
        .help = .h,
        .version = .v,
    };

    pub fn format(self: ZeamArgs, writer: anytype) !void {
        try writer.print("ZeamArgs(genesis={d}, log_filename=\"{s}\", console_log_level={s}, file_log_level={s}", .{
            self.genesis,
            self.log_filename,
            @tagName(self.console_log_level),
            @tagName(self.log_file_active_level),
        });
        try writer.writeAll(", command=");
        switch (self.__commands__) {
            .clock => try writer.writeAll("clock"),
            .beam => |cmd| try writer.print("{f}", .{cmd}),
            .prove => |cmd| try writer.print("prove(zkvm={s}, dist_dir=\"{s}\")", .{ @tagName(cmd.zkvm), cmd.dist_dir }),
            .prometheus => |cmd| switch (cmd.__commands__) {
                .genconfig => |genconfig| try writer.print("prometheus.genconfig(api_port={d}, filename=\"{s}\")", .{ genconfig.@"api-port", genconfig.filename }),
            },
            .node => |cmd| try writer.print("node(node-id=\"{s}\", custom_genesis=\"{s}\", validator_config=\"{s}\", data-dir=\"{s}\", api_port={d}), is-aggregator={}", .{ cmd.@"node-id", cmd.custom_genesis, cmd.validator_config, cmd.@"data-dir", cmd.@"api-port", cmd.@"is-aggregator" }),
            .testsig => |cmd| try writer.print("testsig(epoch={d}, slot={d})", .{ cmd.epoch, cmd.slot }),
        }
        try writer.writeAll(")");
    }
};

const error_handler = @import("error_handler.zig");
const ErrorHandler = error_handler.ErrorHandler;

pub fn main() void {
    mainInner() catch |err| {
        if (err == error.MissingSubCommand) {
            std.process.exit(1);
        }
        ErrorHandler.handleApplicationError(err);
        std.process.exit(1);
    };
}

fn mainInner() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const leaked = gpa.deinit();
        if (leaked == .leak) {
            std.log.err("Memory leak detected!", .{});
            std.process.exit(1);
        }
    }

    const app_description = "Zeam - Zig implementation of Beam Chain, a ZK-based Ethereum Consensus Protocol";
    const app_version = build_options.version;

    var parse_arena = std.heap.ArenaAllocator.init(allocator);
    defer parse_arena.deinit();

    const opts = simargs.parse(parse_arena.allocator(), ZeamArgs, app_description, app_version) catch |err| {
        std.debug.print("Failed to parse command-line arguments: {s}\n", .{@errorName(err)});
        std.debug.print("Run 'zeam --help' for usage information.\n", .{});
        return err;
    };
    defer opts.deinit();

    const genesis = opts.args.genesis;
    const log_filename = opts.args.log_filename;
    const log_file_active_level = opts.args.log_file_active_level;
    const monocolor_file_log = opts.args.monocolor_file_log;
    const console_log_level = opts.args.console_log_level;

    std.debug.print("opts={any} genesis={d}\n", .{ opts.args, genesis });

    switch (opts.args.__commands__) {
        .clock => {
            var loop = xev.Loop.init(.{}) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "initialize event loop");
                return err;
            };
            var clock = Clock.init(gpa.allocator(), genesis, &loop) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "initialize clock");
                return err;
            };
            std.debug.print("clock={any}\n", .{clock});

            clock.run() catch |err| {
                ErrorHandler.logErrorWithOperation(err, "run clock service");
                return err;
            };
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
                    .dummy => break :blk .{ .dummy = .{} },
                },
                .logger = logger,
            };

            // generate a mock chain with 5 blocks including genesis i.e. 4 blocks on top of genesis
            var mock_chain = sft_factory.genMockChain(allocator, 5, null) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "generate mock chain");
                return err;
            };
            defer mock_chain.deinit(allocator);

            // starting beam state - take ownership and clean it up ourselves
            var beam_state = mock_chain.genesis_state;
            defer beam_state.deinit();

            var output = try allocator.alloc(u8, 3 * 1024 * 1024);
            defer allocator.free(output);
            // block 0 is genesis so we have to apply block 1 onwards
            for (mock_chain.blocks[1..]) |signed_block| {
                const block = signed_block.message.block;
                std.debug.print("\nprestate slot blockslot={d} stateslot={d}\n", .{ block.slot, beam_state.slot });
                var proof = state_proving_manager.prove_transition(beam_state, block, options, allocator, output[0..]) catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "generate proof", .{ .slot = block.slot });
                    return err;
                };
                defer proof.deinit();
                // transition beam state for the next block
                sft_factory.apply_transition(allocator, &beam_state, block, .{ .logger = stf_logger }) catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "apply transition", .{ .slot = block.slot });
                    return err;
                };

                // verify the block
                state_proving_manager.verify_transition(proof, types.ZERO_HASH, ZERO_HASH, options) catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "verify proof", .{ .slot = block.slot });
                    return err;
                };
            }
            std.log.info("Successfully proved and verified all transitions", .{});
        },
        .beam => |beamcmd| {
            api.init(allocator) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "initialize API");
                return err;
            };

            var api_server_handle: ?*api_server.ApiServer = null;
            var metrics_server_handle: ?*metrics_server.MetricsServer = null;
            defer if (api_server_handle) |handle| handle.stop();
            defer if (metrics_server_handle) |handle| handle.stop();

            // Set node lifecycle metrics
            zeam_metrics.metrics.lean_node_info.set(.{ .name = "zeam", .version = build_options.version }, 1) catch {};
            zeam_metrics.metrics.lean_node_start_time_seconds.set(@intCast(std.time.timestamp()));

            // Create logger config for API and metrics servers
            var api_logger_config = utils_lib.getLoggerConfig(console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.data_dir, .fileName = log_filename, .monocolorFile = monocolor_file_log });

            // Validate that API and metrics ports are different
            if (beamcmd.@"api-port" == beamcmd.@"metrics-port") {
                std.log.err("API port and metrics port cannot be the same (both set to {d})", .{beamcmd.@"api-port"});
                return error.PortConflict;
            }

            // Start metrics server (doesn't need chain reference)
            metrics_server_handle = metrics_server.startMetricsServer(allocator, beamcmd.@"metrics-port", &api_logger_config) catch |err| {
                ErrorHandler.logErrorWithDetails(err, "start metrics server", .{ .port = beamcmd.@"metrics-port" });
                return err;
            };

            // Start API server early. Pass null for chain - in .beam command mode, chains are created later
            api_server_handle = api_server.startAPIServer(allocator, beamcmd.@"api-port", &api_logger_config, null) catch |err| {
                ErrorHandler.logErrorWithDetails(err, "start API server", .{ .port = beamcmd.@"api-port" });
                return err;
            };

            std.debug.print("beam={any}\n", .{beamcmd});

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

            // Create key manager FIRST to get validator pubkeys for genesis
            // Using 3 validators for 3-node setup with initial sync testing
            // Nodes 1,2 start immediately; Node 3 starts after finalization to test sync
            const num_validators: usize = 3;
            var key_manager = try key_manager_lib.getTestKeyManager(allocator, num_validators, 1000);
            defer key_manager.deinit();

            // Get validator pubkeys from keymanager
            const pubkeys = try key_manager.getAllPubkeys(allocator, num_validators);
            var owns_pubkeys = true;
            defer if (owns_pubkeys) allocator.free(pubkeys);

            // Set validator_pubkeys in chain_options
            chain_options.validator_pubkeys = pubkeys;
            owns_pubkeys = false; // ownership moved into genesis spec

            const time_now_ms: usize = @intCast(std.time.milliTimestamp());
            const time_now: usize = @intCast(time_now_ms / std.time.ms_per_s);
            chain_options.genesis_time = time_now;

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
            var logger3_config = utils_lib.getScopedLoggerConfig(.n3, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.data_dir, .fileName = log_filename, .monocolorFile = monocolor_file_log });

            var backend1: networks.NetworkInterface = undefined;
            var backend2: networks.NetworkInterface = undefined;
            var backend3: networks.NetworkInterface = undefined;

            // These are owned by their heap allocations and freed in the defer below.
            var disc1: *networks.EthP2PDiscovery = undefined;
            var disc2: *networks.EthP2PDiscovery = undefined;
            var disc3: *networks.EthP2PDiscovery = undefined;
            var ethp2p1: *networks.EthP2PNetwork = undefined;
            var ethp2p2: *networks.EthP2PNetwork = undefined;
            var ethp2p3: *networks.EthP2PNetwork = undefined;

            // Create shared registry for beam simulation with validator ID mappings
            // This registry will be used by both the mock network (if enabled) and the beam nodes
            const shared_registry = try allocator.create(node_lib.NodeNameRegistry);
            errdefer allocator.destroy(shared_registry);
            shared_registry.* = node_lib.NodeNameRegistry.init(allocator);
            errdefer shared_registry.deinit();

            try shared_registry.addValidatorMapping(0, "zeam_n1");
            try shared_registry.addValidatorMapping(1, "zeam_n2");
            try shared_registry.addValidatorMapping(2, "zeam_n3"); // Node 3 gets validator 2 (delayed start)

            try shared_registry.addPeerMapping("zeam_n1", "zeam_n1");
            try shared_registry.addPeerMapping("zeam_n2", "zeam_n2");
            try shared_registry.addPeerMapping("zeam_n3", "zeam_n3");

            if (mock_network) {
                var network: *networks.Mock = try allocator.create(networks.Mock);
                network.* = try networks.Mock.init(allocator, loop, logger1_config.logger(.network), shared_registry);
                backend1 = network.getNetworkInterface();
                backend2 = network.getNetworkInterface();
                backend3 = network.getNetworkInterface();
                logger1_config.logger(null).debug("--- mock gossip {f}", .{backend1.gossip});
            } else {
                // Generate secp256k1 key pairs for all three nodes.
                const key_pair1 = enr_lib.KeyPair.generate();
                const key_pair2 = enr_lib.KeyPair.generate();
                const key_pair3 = enr_lib.KeyPair.generate();

                // Derive each node's discv5 NodeId from its compressed public key.
                const node_id1 = try networks.nodeIdFromCompressedPubkey(key_pair1.publicKey().v4.serialize());
                const node_id2 = try networks.nodeIdFromCompressedPubkey(key_pair2.publicKey().v4.serialize());

                // Node 2 and 3 bootstrap from node 1; node 1 bootstraps from node 2.
                const bootstrap1 = [_]networks.DiscoveryBootstrapEntry{
                    .{ .node_id = node_id2, .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 19102) },
                };
                const bootstrap2 = [_]networks.DiscoveryBootstrapEntry{
                    .{ .node_id = node_id1, .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 19101) },
                };
                const bootstrap3 = [_]networks.DiscoveryBootstrapEntry{
                    .{ .node_id = node_id1, .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 19101) },
                };

                // Derive raw 32-byte private keys from key pairs.
                var privkey1: [32]u8 = undefined;
                var privkey2: [32]u8 = undefined;
                var privkey3: [32]u8 = undefined;
                _ = try std.fmt.hexToBytes(&privkey1, &key_pair1.v4.toString());
                _ = try std.fmt.hexToBytes(&privkey2, &key_pair2.v4.toString());
                _ = try std.fmt.hexToBytes(&privkey3, &key_pair3.v4.toString());

                const network_name1 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name1);
                const test_registry1 = try allocator.create(node_lib.NodeNameRegistry);
                test_registry1.* = node_lib.NodeNameRegistry.init(allocator);
                errdefer allocator.destroy(test_registry1);

                disc1 = try allocator.create(networks.EthP2PDiscovery);
                disc1.* = try networks.EthP2PDiscovery.init(allocator, .{
                    .networkId = 0,
                    .local_privkey = privkey1,
                    .listen_port = 19101,
                    .bootstrap_entries = &bootstrap1,
                    .node_registry = test_registry1,
                }, logger1_config.logger(.network));
                var node_id_buf1: [64]u8 = undefined;
                const local_peer_id1 = disc1.localNodeIdHex(&node_id_buf1);
                ethp2p1 = try allocator.create(networks.EthP2PNetwork);
                ethp2p1.* = try networks.EthP2PNetwork.init(allocator, loop, .{
                    .networkId = 0,
                    .network_name = network_name1,
                    .local_peer_id = local_peer_id1,
                    .quic_listen_port = 0,
                    .node_registry = test_registry1,
                    .attestation_committee_count = chain_config.spec.attestation_committee_count,
                }, logger1_config.logger(.network));
                try disc1.getPeerEvents().subscribe(ethp2p1.getPeerEventHandler());
                const iface1 = ethp2p1.getNetworkInterface();
                backend1 = .{ .gossip = iface1.gossip, .reqresp = iface1.reqresp, .peers = disc1.getPeerEvents() };

                const network_name2 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name2);
                const test_registry2 = try allocator.create(node_lib.NodeNameRegistry);
                test_registry2.* = node_lib.NodeNameRegistry.init(allocator);
                errdefer allocator.destroy(test_registry2);

                disc2 = try allocator.create(networks.EthP2PDiscovery);
                disc2.* = try networks.EthP2PDiscovery.init(allocator, .{
                    .networkId = 1,
                    .local_privkey = privkey2,
                    .listen_port = 19102,
                    .bootstrap_entries = &bootstrap2,
                    .node_registry = test_registry2,
                }, logger2_config.logger(.network));
                var node_id_buf2: [64]u8 = undefined;
                const local_peer_id2 = disc2.localNodeIdHex(&node_id_buf2);
                ethp2p2 = try allocator.create(networks.EthP2PNetwork);
                ethp2p2.* = try networks.EthP2PNetwork.init(allocator, loop, .{
                    .networkId = 1,
                    .network_name = network_name2,
                    .local_peer_id = local_peer_id2,
                    .quic_listen_port = 0,
                    .node_registry = test_registry2,
                    .attestation_committee_count = chain_config.spec.attestation_committee_count,
                }, logger2_config.logger(.network));
                try disc2.getPeerEvents().subscribe(ethp2p2.getPeerEventHandler());
                const iface2 = ethp2p2.getNetworkInterface();
                backend2 = .{ .gossip = iface2.gossip, .reqresp = iface2.reqresp, .peers = disc2.getPeerEvents() };

                const network_name3 = try allocator.dupe(u8, chain_config.spec.name);
                errdefer allocator.free(network_name3);
                const test_registry3 = try allocator.create(node_lib.NodeNameRegistry);
                test_registry3.* = node_lib.NodeNameRegistry.init(allocator);
                errdefer allocator.destroy(test_registry3);

                disc3 = try allocator.create(networks.EthP2PDiscovery);
                disc3.* = try networks.EthP2PDiscovery.init(allocator, .{
                    .networkId = 2,
                    .local_privkey = privkey3,
                    .listen_port = 19103,
                    .bootstrap_entries = &bootstrap3,
                    .node_registry = test_registry3,
                }, logger3_config.logger(.network));
                var node_id_buf3: [64]u8 = undefined;
                const local_peer_id3 = disc3.localNodeIdHex(&node_id_buf3);
                ethp2p3 = try allocator.create(networks.EthP2PNetwork);
                ethp2p3.* = try networks.EthP2PNetwork.init(allocator, loop, .{
                    .networkId = 2,
                    .network_name = network_name3,
                    .local_peer_id = local_peer_id3,
                    .quic_listen_port = 0,
                    .node_registry = test_registry3,
                    .attestation_committee_count = chain_config.spec.attestation_committee_count,
                }, logger3_config.logger(.network));
                try disc3.getPeerEvents().subscribe(ethp2p3.getPeerEventHandler());
                const iface3 = ethp2p3.getNetworkInterface();
                backend3 = .{ .gossip = iface3.gossip, .reqresp = iface3.reqresp, .peers = disc3.getPeerEvents() };
                logger1_config.logger(null).debug("--- zig-ethp2p gossip {f}", .{backend1.gossip});
            }

            var clock = try allocator.create(Clock);
            clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop);

            // 3-node setup: validators 0,1 start immediately; validator 2 (node 3) starts after finalization
            var validator_ids_1 = [_]usize{0};
            var validator_ids_2 = [_]usize{1};
            var validator_ids_3 = [_]usize{2}; // Node 3 gets validator 2, starts delayed

            const data_dir_1 = try std.fmt.allocPrint(allocator, "{s}/node1", .{beamcmd.data_dir});
            defer allocator.free(data_dir_1);
            const data_dir_2 = try std.fmt.allocPrint(allocator, "{s}/node2", .{beamcmd.data_dir});
            defer allocator.free(data_dir_2);
            const data_dir_3 = try std.fmt.allocPrint(allocator, "{s}/node3", .{beamcmd.data_dir});
            defer allocator.free(data_dir_3);

            var db_1 = try database.Db.open(allocator, logger1_config.logger(.database), data_dir_1);
            defer db_1.deinit();
            var db_2 = try database.Db.open(allocator, logger2_config.logger(.database), data_dir_2);
            defer db_2.deinit();
            var db_3 = try database.Db.open(allocator, logger3_config.logger(.database), data_dir_3);
            defer db_3.deinit();

            // Use the same shared registry for all beam nodes
            const registry_1 = shared_registry;
            const registry_2 = shared_registry;
            const registry_3 = shared_registry;

            var beam_node_1: BeamNode = undefined;
            try beam_node_1.init(allocator, .{
                // options
                .nodeId = 0,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend1,
                .clock = clock,
                .validator_ids = &validator_ids_1,
                .key_manager = &key_manager,
                .db = db_1,
                .logger_config = &logger1_config,
                .node_registry = registry_1,
                .is_aggregator = beamcmd.@"is-aggregator",
            });

            if (api_server_handle) |handle| {
                handle.setChain(beam_node_1.chain);
            }

            var beam_node_2: BeamNode = undefined;
            try beam_node_2.init(allocator, .{
                // options
                .nodeId = 1,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend2,
                .clock = clock,
                .validator_ids = &validator_ids_2,
                .key_manager = &key_manager,
                .db = db_2,
                .logger_config = &logger2_config,
                .node_registry = registry_2,
                .is_aggregator = false,
            });

            // Node 3 setup - delayed start for initial sync testing
            // This node starts after nodes 1,2 reach finalization and will sync from peers
            // We init node 3 upfront but only call run() after finalization is reached
            var beam_node_3: BeamNode = undefined;
            try beam_node_3.init(allocator, .{
                .nodeId = 2,
                .config = chain_config,
                .anchorState = &anchorState,
                .backend = backend3,
                .clock = clock,
                .validator_ids = &validator_ids_3,
                .key_manager = &key_manager,
                .db = db_3,
                .logger_config = &logger3_config,
                .node_registry = registry_3,
                .is_aggregator = false,
            });

            // Delayed runner - starts both network3 and node3 together
            // Node 3 starts only after finalization has advanced beyond genesis on node 1,
            // ensuring there are finalized blocks for node 3 to sync from.
            const DelayedNodeRunner = struct {
                beam_node: *BeamNode,
                /// Reference node whose finalization status determines when node 3 starts
                reference_node: *BeamNode,
                disc: ?*networks.EthP2PDiscovery = null,
                ethp2p: ?*networks.EthP2PNetwork = null,
                started: bool = false,

                pub fn onInterval(ptr: *anyopaque, interval: isize) !void {
                    const self: *@This() = @ptrCast(@alignCast(ptr));
                    if (self.started) return;

                    // Wait until finalization has advanced beyond genesis on the reference node
                    const finalized_slot = self.reference_node.chain.forkChoice.fcStore.latest_finalized.slot;
                    if (finalized_slot == 0) return;

                    std.debug.print("\n=== STARTING NODE 3 (delayed sync node) at interval {d} ===\n", .{interval});
                    std.debug.print("=== Finalization reached slot {d} on reference node — starting node 3 ===\n", .{finalized_slot});
                    std.debug.print("=== Node 3 will sync from genesis using parent block syncing ===\n\n", .{});

                    // Start discovery + messaging FIRST so node3 joins fresh without pre-cached gossip blocks
                    if (self.disc) |d| {
                        try d.start();
                    }
                    if (self.ethp2p) |ep| {
                        try ep.start();
                    }

                    try self.beam_node.run();
                    self.started = true;

                    std.debug.print("=== NODE 3 STARTED - will now sync via STATUS and parent block requests ===\n\n", .{});
                }
            };

            var delayed_runner = DelayedNodeRunner{
                .beam_node = &beam_node_3,
                .reference_node = &beam_node_1,
                .disc = if (!mock_network) disc3 else null,
                .ethp2p = if (!mock_network) ethp2p3 else null,
            };
            const delayed_cb = try allocator.create(node_lib.utils.OnIntervalCbWrapper);
            delayed_cb.* = .{
                .ptr = &delayed_runner,
                .onIntervalCb = DelayedNodeRunner.onInterval,
            };

            // Start nodes 1, 2 immediately (node 3 starts delayed after finalization)
            try beam_node_1.run();
            try beam_node_2.run();

            // Register delayed runner callback with clock
            try clock.subscribeOnSlot(delayed_cb);

            if (!mock_network) {
                try disc1.start();
                try ethp2p1.start();
                try disc2.start();
                try ethp2p2.start();
                // disc3.start() and ethp2p3.start() are called in DelayedNodeRunner.onInterval
                // to ensure node3 joins fresh without pre-cached gossip blocks
            }

            try clock.run();
        },
        .prometheus => |prometheus| switch (prometheus.__commands__) {
            .genconfig => |genconfig| {
                const generated_config = generatePrometheusConfig(allocator, genconfig.@"metrics-port") catch |err| {
                    ErrorHandler.logErrorWithOperation(err, "generate Prometheus config");
                    return err;
                };
                defer allocator.free(generated_config);

                const cwd = std.fs.cwd();
                const config_file = cwd.createFile(genconfig.filename, .{ .truncate = true }) catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "create Prometheus config file", .{ .filename = genconfig.filename });
                    return err;
                };
                defer config_file.close();
                var write_buf: [4096]u8 = undefined;
                var writer = config_file.writer(&write_buf);
                writer.interface.writeAll(generated_config) catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "write Prometheus config", .{ .filename = genconfig.filename });
                    return err;
                };
                writer.interface.flush() catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "flush Prometheus config", .{ .filename = genconfig.filename });
                    return err;
                };
                std.log.info("Successfully generated Prometheus config: {s}", .{genconfig.filename});
            },
        },
        .node => |leancmd| {
            std.fs.cwd().makePath(leancmd.@"data-dir") catch |err| {
                ErrorHandler.logErrorWithDetails(err, "create data directory", .{ .path = leancmd.@"data-dir" });
                return err;
            };

            var zeam_logger_config = utils_lib.getLoggerConfig(console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = leancmd.@"data-dir", .fileName = log_filename });

            // Create empty node registry upfront to avoid undefined pointer in error paths
            const node_registry = try allocator.create(node_lib.NodeNameRegistry);
            node_registry.* = node_lib.NodeNameRegistry.init(allocator);

            var start_options: node.NodeOptions = .{
                .network_id = leancmd.network_id,
                .node_key = leancmd.@"node-id",
                .validator_config = leancmd.validator_config,
                .node_key_index = undefined,
                .metrics_enable = leancmd.metrics_enable,
                .is_aggregator = leancmd.@"is-aggregator",
                .api_port = leancmd.@"api-port",
                .metrics_port = leancmd.@"metrics-port",
                .bootnodes = &.{}, // Initialize to empty slice to avoid segfault in deinit
                .genesis_spec = undefined,
                .validator_assignments = &.{}, // Initialize to empty slice to avoid segfault in deinit
                .local_priv_key = &.{}, // Initialize to empty slice to avoid segfault in deinit
                .logger_config = &zeam_logger_config,
                .database_path = leancmd.@"data-dir",
                .hash_sig_key_dir = &.{}, // Initialize to empty slice to avoid segfault in deinit
                .node_registry = node_registry,
            };

            defer start_options.deinit(allocator);

            node.buildStartOptions(allocator, leancmd, &start_options) catch |err| {
                ErrorHandler.logErrorWithDetails(err, "build node start options", .{
                    .node_id = leancmd.@"node-id",
                    .validator_config = leancmd.validator_config,
                    .custom_genesis = leancmd.custom_genesis,
                });
                return err;
            };

            var lean_node: node.Node = undefined;
            lean_node.init(allocator, &start_options) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "initialize lean node");
                return err;
            };
            defer lean_node.deinit();

            lean_node.run() catch |err| {
                ErrorHandler.logErrorWithOperation(err, "run lean node");
                return err;
            };
        },
        .testsig => |cmd| {
            var keypair: xmss.KeyPair = undefined;

            if (cmd.@"key-path") |key_path| {
                if (!std.mem.endsWith(u8, key_path, "_pk.ssz")) {
                    std.debug.print("key-path must point to a file named *_pk.ssz (e.g. validator_0_pk.ssz)\n", .{});
                    return error.InvalidKeyPath;
                }
                const sk_path = std.fmt.allocPrint(allocator, "{s}_sk.ssz", .{key_path[0 .. key_path.len - "_pk.ssz".len]}) catch |err| {
                    ErrorHandler.logErrorWithOperation(err, "build private key path");
                    return err;
                };
                defer allocator.free(sk_path);

                keypair = key_manager_lib.loadKeypairFromFiles(allocator, sk_path, key_path) catch |err| {
                    ErrorHandler.logErrorWithOperation(err, "load keypair from SSZ files");
                    return err;
                };
            } else if (cmd.@"private-key") |seed| {
                const num_active_epochs = @max(cmd.epoch + 1, 1);
                keypair = xmss.KeyPair.generate(allocator, seed, 0, num_active_epochs) catch |err| {
                    ErrorHandler.logErrorWithOperation(err, "generate key from seed");
                    return err;
                };
            } else {
                std.debug.print("testsig requires either --private-key (seed) or --key-path (path to *_pk.ssz)\n", .{});
                return error.MissingTestsigKey;
            }
            defer keypair.deinit();

            var pk_buf: [64]u8 = undefined;
            const pk_len = keypair.pubkeyToBytes(&pk_buf) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "serialize public key");
                return err;
            };
            const pk_hex = std.fmt.allocPrint(allocator, "0x{x}", .{pk_buf[0..pk_len]}) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "format public key hex");
                return err;
            };
            defer allocator.free(pk_hex);
            std.debug.print("public_key: {s}\n", .{pk_hex});

            var message: [32]u8 = [_]u8{0} ** 32;
            std.mem.writeInt(u64, message[0..8], cmd.slot, .little);

            const epoch_u32: u32 = @intCast(cmd.epoch);
            var signature = keypair.sign(&message, epoch_u32) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "sign message");
                return err;
            };
            defer signature.deinit();

            var sig_buf: [types.SIGSIZE]u8 = undefined;
            const bytes_written = signature.toBytes(&sig_buf) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "serialize signature");
                return err;
            };

            const sig_slice = sig_buf[0..bytes_written];
            const hex_str = std.fmt.allocPrint(allocator, "0x{x}", .{sig_slice}) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "format signature hex");
                return err;
            };
            defer allocator.free(hex_str);
            std.debug.print("signature: {s}\n", .{hex_str});
        },
    }
}

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
