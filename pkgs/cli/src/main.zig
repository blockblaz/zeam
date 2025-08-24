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

const configs = @import("@zeam/configs");
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;

const utilsLib = @import("@zeam/utils");

const sftFactory = @import("@zeam/state-transition");
const metrics = @import("@zeam/metrics");

const networks = @import("@zeam/network");

const ZeamArgs = struct {
    genesis: u64 = 1234,
    num_validators: u64 = 4,
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
        generate_prometheus_config: struct {
            help: bool = false,
            metricsPort: u16 = 9667,
            output: []const u8 = "pkgs/metrics/prometheus/prometheus.yml",
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

        pub const __messages__ = .{
            .clock = "Run the clock service for slot timing",
            .beam = "Run a full Beam node",
            .generate_prometheus_config = "Generate a Prometheus configuration file",
            .prove = "Generate and verify ZK proofs for state transitions on a mock chain",
        };
    },

    pub const __messages__ = .{
        .genesis = "Genesis time for the chain",
        .num_validators = "Number of validators",
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
            const logger = utilsLib.getLogger(null);

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
            try metrics.startListener(allocator, beamcmd.metricsPort);
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

            var backend1: networks.NetworkInterface = undefined;
            var backend2: networks.NetworkInterface = undefined;
            if (mock_network) {
                var network: *networks.Mock = try allocator.create(networks.Mock);
                network.* = try networks.Mock.init(allocator, loop);
                backend1 = network.getNetworkInterface();
                backend2 = network.getNetworkInterface();
                std.debug.print("---\n\n mock gossip {any}\n\n", .{backend1.gossip});
            } else {
                // TODO: right now EthLibp2p act as a mock network
                // however convert it into libp2p network by using rust bridge and create 2 separate networks
                var network1: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);
                network1.* = try networks.EthLibp2p.init(allocator, loop, .{ .networkId = 0, .port = 9001, .peers = -1 });
                try network1.run();
                backend1 = network1.getNetworkInterface();

                // init a new lib2p network here to connect with network1
                var network2: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);
                network2.* = try networks.EthLibp2p.init(allocator, loop, .{ .networkId = 1, .port = 9002, .peers = 9001 });
                try network2.run();
                backend2 = network2.getNetworkInterface();
                std.debug.print("---\n\n mock gossip {any}\n\n", .{backend1.gossip});
            }

            var clock = try allocator.create(Clock);
            clock.* = try Clock.init(allocator, chain_config.genesis.genesis_time, loop);

            var validator_ids_1 = [_]usize{1};
            var validator_ids_2 = [_]usize{2};

            const logger1 = utilsLib.getScopedLogger(.n1, .debug);
            const logger2 = utilsLib.getScopedLogger(.n2, .debug);

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
        .generate_prometheus_config => |configcmd| {
            const config_content = try metrics.generatePrometheusConfig(allocator, configcmd.metricsPort);
            defer allocator.free(config_content);
            
            if (std.mem.eql(u8, configcmd.output, "-")) {
                // Output to stdout
                try std.io.getStdOut().writeAll(config_content);
            } else {
                // Write to file
                const file = try std.fs.cwd().createFile(configcmd.output, .{});
                defer file.close();
                try file.writeAll(config_content);
                std.debug.print("Prometheus configuration written to {s}\n", .{configcmd.output});
            }
        },
    }
}
