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
const ThreadPool = @import("@zeam/thread-pool").ThreadPool;
const xev = @import("xev").Dynamic;
const Multiaddr = @import("multiaddr").Multiaddr;

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
    @"custom-genesis": []const u8,
    // internal libp2p network id, only matters when two or more nodes are run in same process
    @"network-id": u32 = 0,
    // the string id to pick configuration in validators.yaml/validator_config.yaml
    @"node-id": []const u8,
    // the private libp2p key arg currently ignored but supported to be cross client compatible for
    // lean-quickstart standard args 1. data-dir 2. node-id 3. node-key
    @"node-key": []const u8 = constants.DEFAULT_NODE_KEY,
    // 1. a special value of "genesis_bootnode" for validator config means its a genesis bootnode and so
    //   the configuration is to be picked from genesis
    // 2. otherwise validator_config is dir path to this nodes's validator_config.yaml and annotated_validators.yaml
    //   and one must use all the nodes in genesis nodes.yaml as peers
    @"validator-config": []const u8,
    @"metrics-enable": bool = false,
    @"api-port": u16 = constants.DEFAULT_API_PORT,
    @"metrics-port": u16 = constants.DEFAULT_METRICS_PORT,
    @"override-genesis-time": ?u64,
    @"sig-keys-dir": []const u8 = "hash-sig-keys",
    @"network-dir": []const u8 = "./network",
    @"data-dir": []const u8 = constants.DEFAULT_DATA_DIR,
    @"checkpoint-sync-url": ?[]const u8 = null,
    @"is-aggregator": bool = false,
    @"attestation-committee-count": ?u64 = null,
    @"aggregate-subnet-ids": ?[]const u8 = null,
    @"db-backend": database.Backend = .rocksdb,
    @"chain-spec": ?[]const u8 = null,
    /// Slice c-2b commit 3 of #803: route producer-side gossip
    /// handlers through the chain-worker queue. Default `true` post
    /// devnet-4 burn-in (#788 follow-up + slice (d)/(e) PR): the
    /// worker path is the supported prod path; the synchronous path
    /// stays in place as a kill-switch via `--chain-worker false`.
    @"chain-worker": bool = true,

    pub const __shorts__ = .{
        .help = .h,
    };

    pub const __messages__ = .{
        .@"custom-genesis" = "Custom genesis directory path",
        .@"network-id" = "Internal libp2p network id relevant when running nodes in same process",
        .@"node-id" = "The node id in the genesis config for this lean node",
        .@"node-key" = "Path to the node key file",
        .@"validator-config" = "Path to the validator config directory or 'genesis_bootnode'",
        .@"api-port" = "Port for the API server (health, events, forkchoice graph, checkpoint state)",
        .@"metrics-port" = "Port for the Prometheus metrics server",
        .@"metrics-enable" = "Enable API and metrics servers (health, events, forkchoice graph, checkpoint state, metrics)",
        .@"network-dir" = "Directory to store network related information, e.g., peer ids, keys, etc.",
        .@"override-genesis-time" = "Override genesis time in the config.yaml",
        .@"sig-keys-dir" = "Relative path of custom genesis to signature key directory",
        .@"data-dir" = "Path to the data directory",
        .@"checkpoint-sync-url" = "URL to fetch finalized checkpoint state from for checkpoint sync (e.g., http://localhost:5052/lean/v0/states/finalized)",
        .@"is-aggregator" = "Seed the node's aggregator role on startup. The role can be toggled at runtime via POST /lean/v0/admin/aggregator.",
        .@"attestation-committee-count" = "Number of attestation committees (subnets); overrides config.yaml ATTESTATION_COMMITTEE_COUNT",
        .@"aggregate-subnet-ids" = "Comma-separated list of subnet ids to additionally subscribe and aggregate gossip attestations (e.g. '0,1,2'); adds to automatic computation from validator ids",
        .@"db-backend" = "Database backend to use for on-disk state: 'rocksdb' (default) or 'lmdb'",
        .@"chain-spec" = "Path to the chain specification file, if unspecified falls back to the default setting",
        .@"chain-worker" = "Route gossip block + attestation handlers through the dedicated chain-worker thread. On by default; pass `--chain-worker false` to fall back to the legacy synchronous path as a kill-switch.",
        .help = "Show help information for the node command",
    };
};

const BeamCmd = struct {
    help: bool = false,
    mockNetwork: bool = false,
    @"api-port": u16 = constants.DEFAULT_API_PORT,
    @"metrics-port": u16 = constants.DEFAULT_METRICS_PORT,
    @"data-dir": []const u8 = constants.DEFAULT_DATA_DIR,
    @"is-aggregator": bool = true,
    @"db-backend": database.Backend = .rocksdb,

    pub fn format(self: BeamCmd, writer: anytype) !void {
        try writer.print("BeamCmd{{ mockNetwork={}, api-port={d}, metrics-port={d}, data-dir=\"{s}\", is-aggregator={}, db-backend={s} }}", .{
            self.mockNetwork,
            self.@"api-port",
            self.@"metrics-port",
            self.@"data-dir",
            self.@"is-aggregator",
            @tagName(self.@"db-backend"),
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
            @"dist-dir": []const u8 = "zig-out/bin",
            zkvm: state_proving_manager.ZKVMs = .risc0,
            help: bool = false,

            pub const __shorts__ = .{
                .@"dist-dir" = .d,
                .zkvm = .z,
            };

            pub const __messages__ = .{
                .@"dist-dir" = "Directory where the zkvm guest programs are found",
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
            .prove => |cmd| try writer.print("prove(zkvm={s}, dist-dir=\"{s}\")", .{ @tagName(cmd.zkvm), cmd.@"dist-dir" }),
            .prometheus => |cmd| switch (cmd.__commands__) {
                .genconfig => |genconfig| try writer.print("prometheus.genconfig(api-port={d}, filename=\"{s}\")", .{ genconfig.@"api-port", genconfig.filename }),
            },
            .node => |cmd| try writer.print("node(node-id=\"{s}\", custom-genesis=\"{s}\", validator-config=\"{s}\", data-dir=\"{s}\", api-port={d}), is-aggregator={}", .{ cmd.@"node-id", cmd.@"custom-genesis", cmd.@"validator-config", cmd.@"data-dir", cmd.@"api-port", cmd.@"is-aggregator" }),
            .testsig => |cmd| try writer.print("testsig(epoch={d}, slot={d})", .{ cmd.epoch, cmd.slot }),
        }
        try writer.writeAll(")");
    }
};

const error_handler = @import("error_handler.zig");
const ErrorHandler = error_handler.ErrorHandler;

pub fn main(init: std.process.Init) void {
    mainInner(init) catch |err| {
        if (err == error.MissingSubCommand) {
            std.process.exit(1);
        }
        ErrorHandler.handleApplicationError(err);
        std.process.exit(1);
    };
}

fn mainInner(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
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

    const opts = simargs.structargs.parse(parse_arena.allocator(), init.io, init.minimal.args, ZeamArgs, .{
        .argument_prompt = app_description,
        .version_string = app_version,
    }) catch |err| {
        std.debug.print("Failed to parse command-line arguments: {s}\n", .{@errorName(err)});
        std.debug.print("Run 'zeam --help' for usage information.\n", .{});
        return err;
    };
    defer opts.deinit();

    const genesis = opts.options.genesis;
    const log_filename = opts.options.log_filename;
    const log_file_active_level = opts.options.log_file_active_level;
    const monocolor_file_log = opts.options.monocolor_file_log;
    const console_log_level = opts.options.console_log_level;

    std.debug.print("opts={any} genesis={d}\n", .{ opts.options, genesis });

    // Detect the best available I/O backend (io_uring or epoll on Linux).
    node_lib.detectBackend() catch |err| {
        ErrorHandler.logErrorWithOperation(err, "detect I/O backend");
        return err;
    };

    switch (opts.options.__commands__) {
        .clock => {
            var loop = xev.Loop.init(.{}) catch |err| {
                ErrorHandler.logErrorWithOperation(err, "initialize event loop");
                return err;
            };
            var clock_logger_config = utils_lib.getLoggerConfig(console_log_level, null);
            var clock = Clock.init(gpa.allocator(), genesis, &loop, &clock_logger_config) catch |err| {
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
            std.debug.print("distribution dir={s}\n", .{provecmd.@"dist-dir"});
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
                const block = signed_block.block;
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
            zeam_metrics.metrics.lean_node_start_time_seconds.set(@intCast(utils_lib.unixTimestampSeconds()));

            // Create logger config for API and metrics servers
            var api_logger_config = utils_lib.getLoggerConfig(console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.@"data-dir", .fileName = log_filename, .monocolorFile = monocolor_file_log });

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
                \\{"preset": "mainnet", "name": "beamdev", "fork_digest": "12345678"}
            ;
            const options = json.ParseOptions{
                .ignore_unknown_fields = true,
                .allocate = .alloc_if_needed,
            };
            // See pkgs/cli/src/node.zig (and #831): `parseFromSlice` returns
            // string fields aliased into the `Parsed` arena. `ChainSpec.deinit`
            // later calls `allocator.free` on `name` / `fork_digest`, so move
            // both fields onto the top-level allocator before the arena dies.
            const parsed = try json.parseFromSlice(ChainOptions, gpa.allocator(), chain_spec, options);
            defer parsed.deinit();
            var chain_options = parsed.value;
            chain_options.name = try gpa.allocator().dupe(u8, chain_options.name.?);
            errdefer if (chain_options.name) |n| gpa.allocator().free(n);
            chain_options.fork_digest = try gpa.allocator().dupe(u8, chain_options.fork_digest.?);
            errdefer if (chain_options.fork_digest) |d| gpa.allocator().free(d);

            // Create key manager FIRST to get validator pubkeys for genesis
            // Using 3 validators for 3-node setup with initial sync testing
            // Nodes 1,2 start immediately; Node 3 starts after finalization to test sync
            const num_validators: usize = 3;
            var key_manager = try key_manager_lib.getTestKeyManager(allocator, num_validators, 1000);
            // Defer order (LIFO): key_manager.deinit() runs first so it can drop its
            // map entries while the cached XMSS handles are still valid, then the
            // process-global cache itself is freed. key_manager.deinit() only
            // deinits keys it owns (addKeypair), not borrowed ones (addCachedKeypair);
            // the cache is the real owner of those handles and would otherwise
            // leak until process exit since it uses the page allocator.
            defer key_manager_lib.deinitGlobalKeyCache();
            defer key_manager.deinit();

            // Get validator pubkeys from keymanager
            const all_pubkeys = try key_manager.getAllPubkeys(allocator, num_validators);
            var owns_pubkeys = true;
            defer if (owns_pubkeys) {
                allocator.free(all_pubkeys.attestation_pubkeys);
                allocator.free(all_pubkeys.proposal_pubkeys);
            };

            // Set validator pubkeys in chain_options
            chain_options.validator_attestation_pubkeys = all_pubkeys.attestation_pubkeys;
            chain_options.validator_proposal_pubkeys = all_pubkeys.proposal_pubkeys;
            owns_pubkeys = false; // ownership moved into genesis spec

            const time_now_ms: usize = @intCast(utils_lib.unixTimestampMillis());
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

            try std.Io.Dir.cwd().createDirPath(init.io, beamcmd.@"data-dir");

            // Create loggers first so they can be passed to network implementations
            var logger1_config = utils_lib.getScopedLoggerConfig(.n1, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.@"data-dir", .fileName = log_filename, .monocolorFile = monocolor_file_log });
            var logger2_config = utils_lib.getScopedLoggerConfig(.n2, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.@"data-dir", .fileName = log_filename, .monocolorFile = monocolor_file_log });
            var logger3_config = utils_lib.getScopedLoggerConfig(.n3, console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = beamcmd.@"data-dir", .fileName = log_filename, .monocolorFile = monocolor_file_log });

            var backend1: networks.NetworkInterface = undefined;
            var backend2: networks.NetworkInterface = undefined;
            var backend3: networks.NetworkInterface = undefined;

            // These are owned by the network implementations and will be freed in their deinit functions
            // We will run network1, network2, and network3 after the nodes are running to avoid race conditions
            var network1: *networks.EthLibp2p = undefined;
            var network2: *networks.EthLibp2p = undefined;
            var network3: *networks.EthLibp2p = undefined;
            // Initialize to empty slices to avoid undefined behavior in defer when mock_network=true
            var listen_addresses1: []Multiaddr = &.{};
            var listen_addresses2: []Multiaddr = &.{};
            var listen_addresses3: []Multiaddr = &.{};
            var connect_peers: []Multiaddr = &.{};
            var connect_peers3: []Multiaddr = &.{};
            defer {
                for (listen_addresses1) |addr| addr.deinit();
                if (listen_addresses1.len > 0) allocator.free(listen_addresses1);
                for (listen_addresses2) |addr| addr.deinit();
                if (listen_addresses2.len > 0) allocator.free(listen_addresses2);
                for (listen_addresses3) |addr| addr.deinit();
                if (listen_addresses3.len > 0) allocator.free(listen_addresses3);
                for (connect_peers) |addr| addr.deinit();
                if (connect_peers.len > 0) allocator.free(connect_peers);
                for (connect_peers3) |addr| addr.deinit();
                if (connect_peers3.len > 0) allocator.free(connect_peers3);
            }

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
                network1 = try allocator.create(networks.EthLibp2p);
                const key_pair1 = enr_lib.KeyPair.generate();
                const priv_key1 = key_pair1.v4.toString();
                listen_addresses1 = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9001")});
                const fork_digest1 = try allocator.dupe(u8, chain_config.spec.fork_digest);
                errdefer allocator.free(fork_digest1);
                // Create empty registry for test network
                const test_registry1 = try allocator.create(node_lib.NodeNameRegistry);
                errdefer allocator.destroy(test_registry1);
                test_registry1.* = node_lib.NodeNameRegistry.init(allocator);
                errdefer test_registry1.deinit();

                network1.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 0,
                    .fork_digest = fork_digest1,
                    .local_private_key = &priv_key1,
                    .listen_addresses = listen_addresses1,
                    .connect_peers = null,
                    .node_registry = test_registry1,
                }, logger1_config.logger(.network));
                backend1 = network1.getNetworkInterface();

                // init a new lib2p network here to connect with network1
                network2 = try allocator.create(networks.EthLibp2p);
                const key_pair2 = enr_lib.KeyPair.generate();
                const priv_key2 = key_pair2.v4.toString();
                listen_addresses2 = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9002")});
                connect_peers = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/127.0.0.1/tcp/9001")});
                const fork_digest2 = try allocator.dupe(u8, chain_config.spec.fork_digest);
                errdefer allocator.free(fork_digest2);
                // Create empty registry for test network
                const test_registry2 = try allocator.create(node_lib.NodeNameRegistry);
                errdefer allocator.destroy(test_registry2);
                test_registry2.* = node_lib.NodeNameRegistry.init(allocator);
                errdefer test_registry2.deinit();

                network2.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 1,
                    .fork_digest = fork_digest2,
                    .local_private_key = &priv_key2,
                    .listen_addresses = listen_addresses2,
                    .connect_peers = connect_peers,
                    .node_registry = test_registry2,
                }, logger2_config.logger(.network));
                backend2 = network2.getNetworkInterface();

                // init network3 for node 3 (delayed sync node)
                network3 = try allocator.create(networks.EthLibp2p);
                const key_pair3 = enr_lib.KeyPair.generate();
                const priv_key3 = key_pair3.v4.toString();
                listen_addresses3 = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/0.0.0.0/tcp/9003")});
                connect_peers3 = try allocator.dupe(Multiaddr, &[_]Multiaddr{try Multiaddr.fromString(allocator, "/ip4/127.0.0.1/tcp/9001")});
                const fork_digest3 = try allocator.dupe(u8, chain_config.spec.fork_digest);
                errdefer allocator.free(fork_digest3);
                const test_registry3 = try allocator.create(node_lib.NodeNameRegistry);
                errdefer allocator.destroy(test_registry3);
                test_registry3.* = node_lib.NodeNameRegistry.init(allocator);
                errdefer test_registry3.deinit();

                network3.* = try networks.EthLibp2p.init(allocator, loop, .{
                    .networkId = 2,
                    .fork_digest = fork_digest3,
                    .local_private_key = &priv_key3,
                    .listen_addresses = listen_addresses3,
                    .connect_peers = connect_peers3,
                    .node_registry = test_registry3,
                }, logger3_config.logger(.network));
                backend3 = network3.getNetworkInterface();
                logger1_config.logger(null).debug("--- ethlibp2p gossip {f}", .{backend1.gossip});
            }

            var clock = try allocator.create(Clock);
            clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop, &logger1_config);

            // Shared worker pool for CPU-bound chain work (attestation signature verification).
            // One pool is shared across all nodes in the process so total worker threads stay bounded
            // regardless of the number of nodes in the simulation.
            const cpu_count = std.Thread.getCpuCount() catch 2;
            const reserved_system_threads: usize = 4; // main, p2p, api server, metrics server
            const desired_workers = @max(@as(usize, 1), cpu_count -| reserved_system_threads);
            const worker_count = @min(desired_workers, @as(usize, ThreadPool.max_thread_count));
            const thread_pool = try ThreadPool.init(.{
                .allocator = allocator,
                .io = init.io,
                .thread_count = @intCast(worker_count),
            });
            defer thread_pool.deinit();

            // Pre-warm the XMSS verifier on the main thread before any worker
            // can call `verifyAggregatedPayload`. The Rust-side verifier setup
            // is documented as idempotent but is not hardened against
            // first-time-init races between concurrent callers; doing it once
            // here removes that race regardless of the Rust implementation.
            xmss.setupVerifier() catch |err| {
                std.debug.print("xmss.setupVerifier failed: {any}\n", .{err});
                return err;
            };

            // 3-node setup: validators 0,1 start immediately; validator 2 (node 3) starts after finalization
            var validator_ids_1 = [_]usize{0};
            var validator_ids_2 = [_]usize{1};
            var validator_ids_3 = [_]usize{2}; // Node 3 gets validator 2, starts delayed

            const data_dir_1 = try std.fmt.allocPrint(allocator, "{s}/node1", .{beamcmd.@"data-dir"});
            defer allocator.free(data_dir_1);
            const data_dir_2 = try std.fmt.allocPrint(allocator, "{s}/node2", .{beamcmd.@"data-dir"});
            defer allocator.free(data_dir_2);
            const data_dir_3 = try std.fmt.allocPrint(allocator, "{s}/node3", .{beamcmd.@"data-dir"});
            defer allocator.free(data_dir_3);

            const db_backend = beamcmd.@"db-backend";
            var db_1 = try database.Db.openBackend(allocator, logger1_config.logger(.database), data_dir_1, db_backend);
            defer db_1.deinit();
            var db_2 = try database.Db.openBackend(allocator, logger2_config.logger(.database), data_dir_2, db_backend);
            defer db_2.deinit();
            var db_3 = try database.Db.openBackend(allocator, logger3_config.logger(.database), data_dir_3, db_backend);
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
                .thread_pool = thread_pool,
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
                .thread_pool = thread_pool,
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
                .thread_pool = thread_pool,
            });

            // Delayed runner - starts both network3 and node3 together
            // Node 3 starts only after finalization has advanced beyond genesis on node 1,
            // ensuring there are finalized blocks for node 3 to sync from.
            const DelayedNodeRunner = struct {
                beam_node: *BeamNode,
                /// Reference node whose finalization status determines when node 3 starts
                reference_node: *BeamNode,
                network: ?*networks.EthLibp2p = null,
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

                    // Start BeamNode first so it registers selective gossip
                    // topic handlers; EthLibp2p.run() then derives the
                    // gossipsub subscribe set from those handlers (instead of
                    // joining every attestation subnet). See
                    // pkgs/network/src/ethlibp2p.zig run() for the rationale.
                    try self.beam_node.run();

                    if (self.network) |net| {
                        try net.run();
                    }
                    self.started = true;

                    std.debug.print("=== NODE 3 STARTED - will now sync via STATUS and parent block requests ===\n\n", .{});
                }
            };

            var delayed_runner = DelayedNodeRunner{
                .beam_node = &beam_node_3,
                .reference_node = &beam_node_1,
                .network = if (!mock_network) network3 else null,
            };
            const delayed_cb = try allocator.create(node_lib.utils.OnIntervalCbWrapper);
            delayed_cb.* = .{
                .ptr = &delayed_runner,
                .onIntervalCb = DelayedNodeRunner.onInterval,
            };

            // Start the rust libp2p networks BEFORE the beam nodes:
            // `BeamNode.run()` calls `gossip.subscribe(...)`, which now
            // enqueues `SwarmCommand::SubscribeGossip` on the per-network
            // command channel. That channel only exists after
            // `EthLibp2p.run()` returns from `wait_for_network_ready`, so
            // any earlier subscribe would be dropped with a hard error.
            if (!mock_network) {
                try network1.run();
                try network2.run();
                // network3.run() is called in DelayedNodeRunner.onInterval
                // to ensure node3 joins fresh without pre-cached gossip blocks
            }

            // Start nodes 1, 2 immediately (node 3 starts delayed after finalization)
            try beam_node_1.run();
            try beam_node_2.run();

            // Register delayed runner callback with clock
            try clock.subscribeOnSlot(delayed_cb);

            try clock.run();
        },
        .prometheus => |prometheus| switch (prometheus.__commands__) {
            .genconfig => |genconfig| {
                const generated_config = generatePrometheusConfig(allocator, genconfig.@"metrics-port") catch |err| {
                    ErrorHandler.logErrorWithOperation(err, "generate Prometheus config");
                    return err;
                };
                defer allocator.free(generated_config);

                const config_file = std.Io.Dir.cwd().createFile(init.io, genconfig.filename, .{ .truncate = true }) catch |err| {
                    ErrorHandler.logErrorWithDetails(err, "create Prometheus config file", .{ .filename = genconfig.filename });
                    return err;
                };
                defer config_file.close(init.io);
                var write_buf: [4096]u8 = undefined;
                var writer = config_file.writer(init.io, &write_buf);
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
            std.Io.Dir.cwd().createDirPath(init.io, leancmd.@"data-dir") catch |err| {
                ErrorHandler.logErrorWithDetails(err, "create data directory", .{ .path = leancmd.@"data-dir" });
                return err;
            };

            var zeam_logger_config = utils_lib.getLoggerConfig(console_log_level, utils_lib.FileBehaviourParams{ .fileActiveLevel = log_file_active_level, .filePath = leancmd.@"data-dir", .fileName = log_filename });

            // Create empty node registry upfront to avoid undefined pointer in error paths
            const node_registry = try allocator.create(node_lib.NodeNameRegistry);
            node_registry.* = node_lib.NodeNameRegistry.init(allocator);

            var start_options: node.NodeOptions = .{
                .network_id = leancmd.@"network-id",
                .node_key = leancmd.@"node-id",
                .validator_config = leancmd.@"validator-config",
                .node_key_index = undefined,
                .metrics_enable = leancmd.@"metrics-enable",
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
                .db_backend = leancmd.@"db-backend",
            };

            defer start_options.deinit(allocator);

            node.buildStartOptions(allocator, leancmd, &start_options) catch |err| {
                ErrorHandler.logErrorWithDetails(err, "build node start options", .{
                    .node_id = leancmd.@"node-id",
                    .validator_config = leancmd.@"validator-config",
                    .custom_genesis = leancmd.@"custom-genesis",
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
    @import("std").testing.refAllDecls(@This());
}
