const std = @import("std");
const enr_lib = @import("enr");
const ENR = enr_lib.ENR;
const utils_lib = @import("@zeam/utils");
const Yaml = @import("yaml").Yaml;
const configs = @import("@zeam/configs");
const metrics = @import("@zeam/metrics");
const metrics_server = @import("metrics_server.zig");
const json = std.json;
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;
const sft = @import("@zeam/state-transition");
const xev = @import("xev");
const networks = @import("@zeam/network");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;
const node_lib = @import("@zeam/node");
const Clock = node_lib.Clock;
const BeamNode = node_lib.BeamNode;
const types = @import("@zeam/types");
const LoggerConfig = utils_lib.ZeamLoggerConfig;
const NodeCommand = @import("main.zig").NodeCommand;
const zeam_utils = @import("@zeam/utils");

const prefix = "zeam_";

pub const NodeOptions = struct {
    node_id: u32,
    bootnodes: []const []const u8,
    validator_indices: []usize,
    genesis_spec: types.GenesisSpec,
    metrics_enable: bool,
    metrics_port: u16,
    local_priv_key: []const u8,
    logger_config: *LoggerConfig,

    pub fn deinit(self: *NodeOptions, allocator: std.mem.Allocator) void {
        for (self.bootnodes) |b| allocator.free(b);
        allocator.free(self.bootnodes);
        allocator.free(self.validator_indices);
        allocator.free(self.local_priv_key);
    }
};

/// A Node that encapsulates the networking, blockchain, and validator functionalities.
/// It manages the event loop, network interface, clock, and beam node.
pub const Node = struct {
    loop: xev.Loop,
    network: networks.EthLibp2p,
    beam_node: BeamNode,
    clock: Clock,
    enr: ENR,
    options: *const NodeOptions,
    allocator: std.mem.Allocator,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();

    pub fn init(self: *Self, allocator: std.mem.Allocator, options: *const NodeOptions) !void {
        self.allocator = allocator;
        self.options = options;

        const node_id = options.node_id;

        if (options.metrics_enable) {
            try metrics.init(allocator);
            try metrics_server.startMetricsServer(allocator, options.metrics_port);
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

        chain_options.genesis_time = options.genesis_spec.genesis_time;
        chain_options.num_validators = options.genesis_spec.num_validators;
        const chain_config = try ChainConfig.init(Chain.custom, chain_options);
        var anchorState = try sft.genGenesisState(allocator, chain_config.genesis);
        errdefer anchorState.deinit(allocator);

        // TODO we seem to be needing one loop because then the events added to loop are not being fired
        // in the order to which they have been added even with the an appropriate delay added
        // behavior of this further needs to be investigated but for now we will share the same loop
        self.loop = try xev.Loop.init(.{});

        const addresses = try self.constructMultiaddrs();
        self.network = try networks.EthLibp2p.init(allocator, &self.loop, .{ .networkId = 0, .listen_addresses = addresses.listen_addresses, .connect_peers = addresses.connect_peers, .local_private_key = options.local_priv_key }, options.logger_config.logger(.network));
        errdefer self.network.deinit();
        self.clock = try Clock.init(allocator, chain_config.genesis.genesis_time, &self.loop);
        errdefer self.clock.deinit(allocator);

        self.beam_node = try BeamNode.init(allocator, .{
            // options
            .nodeId = node_id,
            .config = chain_config,
            .anchorState = &anchorState,
            .backend = self.network.getNetworkInterface(),
            .clock = &self.clock,
            .db = .{},
            .validator_ids = options.validator_indices,
            .logger_config = options.logger_config,
        });

        self.logger = options.logger_config.logger(.node);
    }

    pub fn deinit(self: *Self) void {
        self.clock.deinit(self.allocator);
        self.beam_node.deinit();
        self.network.deinit();
        self.enr.deinit();
        self.loop.deinit();
    }

    pub fn run(self: *Node) !void {
        try self.network.run();
        try self.beam_node.run();

        const ascii_art =
            \\
            \\  ███████╗███████╗ █████╗ ███╗   ███╗
            \\  ╚══███╔╝██╔════╝██╔══██╗████╗ ████║
            \\    ███╔╝ █████╗  ███████║██╔████╔██║
            \\   ███╔╝  ██╔══╝  ██╔══██║██║╚██╔╝██║
            \\  ███████╗███████╗██║  ██║██║ ╚═╝ ██║
            \\  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
            \\
            \\ a blazing fast lean consensus client
        ;

        var encoded_txt_buf: [1000]u8 = undefined;
        const encoded_txt = try self.enr.encodeToTxt(&encoded_txt_buf);

        const quic_port = try self.enr.getQUIC();

        // Use logger.info instead of std.debug.print
        self.logger.info("\n{s}", .{ascii_art});
        self.logger.info("════════════════════════════════════════════════════════", .{});
        self.logger.info("  🚀 Zeam Lean Node Started Successfully!", .{});
        self.logger.info("════════════════════════════════════════════════════════", .{});
        self.logger.info("  Node ID: {d}", .{self.options.node_id});
        self.logger.info("  Listening on QUIC port: {?d}", .{quic_port});
        self.logger.info("  ENR: {s}", .{encoded_txt});
        self.logger.info("────────────────────────────────────────────────────────", .{});

        try self.clock.run();
    }

    fn constructMultiaddrs(self: *Self) !struct { listen_addresses: []const Multiaddr, connect_peers: []const Multiaddr } {
        const self_node_index = self.options.validator_indices[0];
        try ENR.decodeTxtInto(&self.enr, self.options.bootnodes[self_node_index]);

        // Overriding the IP to 0.0.0.0 to listen on all interfaces
        try self.enr.kvs.put("ip", "\x00\x00\x00\x00");

        var node_multiaddrs = try self.enr.multiaddrP2PQUIC(self.allocator);
        defer node_multiaddrs.deinit(self.allocator);
        // move the ownership to the `EthLibp2p`, will be freed in its deinit
        const listen_addresses = try node_multiaddrs.toOwnedSlice(self.allocator);
        errdefer {
            for (listen_addresses) |addr| addr.deinit();
            self.allocator.free(listen_addresses);
        }
        var connect_peer_list: std.ArrayListUnmanaged(Multiaddr) = .empty;
        defer connect_peer_list.deinit(self.allocator);

        for (self.options.bootnodes, 0..) |n, i| {
            if (i != self_node_index) {
                var n_enr: ENR = undefined;
                try ENR.decodeTxtInto(&n_enr, n);
                var peer_multiaddr_list = try n_enr.multiaddrP2PQUIC(self.allocator);
                defer peer_multiaddr_list.deinit(self.allocator);
                const peer_multiaddrs = try peer_multiaddr_list.toOwnedSlice(self.allocator);
                defer self.allocator.free(peer_multiaddrs);
                try connect_peer_list.appendSlice(self.allocator, peer_multiaddrs);
            }
        }

        // move the ownership to the `EthLibp2p`, will be freed in its deinit
        const connect_peers = try connect_peer_list.toOwnedSlice(self.allocator);
        errdefer {
            for (connect_peers) |addr| addr.deinit();
            self.allocator.free(connect_peers);
        }

        return .{ .listen_addresses = listen_addresses, .connect_peers = connect_peers };
    }
};

/// Builds the start options for a node based on the provided command and options.
/// It loads the necessary configuration files, parses them, and populates the
/// `StartNodeOptions` structure.
/// The caller is responsible for freeing the allocated resources in `StartNodeOptions`.
pub fn buildStartOptions(allocator: std.mem.Allocator, node_cmd: NodeCommand, opts: *NodeOptions) !void {
    try utils_lib.checkDIRExists(node_cmd.custom_genesis);

    const config_filepath = try std.mem.concat(allocator, u8, &[_][]const u8{ node_cmd.custom_genesis, "/config.yaml" });
    defer allocator.free(config_filepath);
    const bootnodes_filepath = try std.mem.concat(allocator, u8, &[_][]const u8{ node_cmd.custom_genesis, "/nodes.yaml" });
    defer allocator.free(bootnodes_filepath);
    const validators_filepath = try std.mem.concat(allocator, u8, &[_][]const u8{ node_cmd.custom_genesis, "/validators.yaml" });
    defer allocator.free(validators_filepath);
    // TODO: support genesis file loading when ssz library supports it
    // const genesis_filepath = try std.mem.concat(allocator, &[_][]const u8{custom_genesis, "/genesis.ssz"});
    // defer allocator.free(genesis_filepath);

    var parsed_bootnodes = try utils_lib.loadFromYAMLFile(allocator, bootnodes_filepath);
    defer parsed_bootnodes.deinit(allocator);

    var parsed_config = try utils_lib.loadFromYAMLFile(allocator, config_filepath);
    defer parsed_config.deinit(allocator);

    var parsed_validators = try utils_lib.loadFromYAMLFile(allocator, validators_filepath);
    defer parsed_validators.deinit(allocator);

    const bootnodes = try nodesFromYAML(allocator, parsed_bootnodes);
    errdefer {
        for (bootnodes) |b| allocator.free(b);
        allocator.free(bootnodes);
    }
    if (bootnodes.len == 0) {
        return error.InvalidNodesConfig;
    }
    const genesis_spec = try configs.genesisConfigFromYAML(parsed_config, node_cmd.override_genesis_time);

    const validator_indices = try validatorIndicesFromYAML(allocator, opts.node_id, parsed_validators);
    errdefer allocator.free(validator_indices);
    if (validator_indices.len == 0) {
        return error.InvalidValidatorConfig;
    }
    try utils_lib.checkDIRExists(node_cmd.network_dir);
    const local_priv_key_filepath = try std.mem.concat(allocator, u8, &[_][]const u8{ node_cmd.network_dir, "/key" });
    defer allocator.free(local_priv_key_filepath);
    const local_priv_key = try utils_lib.readFileToEndAlloc(allocator, local_priv_key_filepath, 512);

    opts.bootnodes = bootnodes;
    opts.validator_indices = validator_indices;
    opts.local_priv_key = local_priv_key;
    opts.genesis_spec = genesis_spec;
}

/// Parses the nodes from a YAML configuration.
/// Expects a YAML structure like:
/// ```yaml
///   - enr1...
///   - enr2...
/// ```
/// Returns a set of ENR strings. The caller is responsible for freeing the returned slice.
fn nodesFromYAML(allocator: std.mem.Allocator, nodes_config: Yaml) ![]const []const u8 {
    const temp_nodes = try nodes_config.parse(allocator, [][]const u8);
    defer allocator.free(temp_nodes);

    var nodes = try allocator.alloc([]const u8, temp_nodes.len);
    errdefer {
        for (nodes) |node| allocator.free(node);
        allocator.free(nodes);
    }

    for (temp_nodes, 0..) |temp_node, i| {
        nodes[i] = try allocator.dupe(u8, temp_node);
    }

    return nodes;
}

/// Parses the validator indices for a given node from a YAML configuration.
/// Expects a YAML structure like:
/// ```yaml
/// node_0:
///   - 0
///   - 1
/// node_1:
///   - 2
///   - 3
/// ```
/// where `node_{node_id}` is the key for the node's validator indices.
/// Returns a set of validator indices. The caller is responsible for freeing the returned slice.
fn validatorIndicesFromYAML(allocator: std.mem.Allocator, node_id: u32, validators_config: Yaml) ![]usize {
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
    var config1 = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/src/test/fixtures/config.yaml");
    defer config1.deinit(std.testing.allocator);
    const genesis_spec = try configs.genesisConfigFromYAML(config1, null);
    try std.testing.expectEqual(9, genesis_spec.num_validators);
    try std.testing.expectEqual(1704085200, genesis_spec.genesis_time);

    var config2 = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/src/test/fixtures/validators.yaml");
    defer config2.deinit(std.testing.allocator);
    const validator_indices = try validatorIndicesFromYAML(std.testing.allocator, 0, config2);
    defer std.testing.allocator.free(validator_indices);
    try std.testing.expectEqual(3, validator_indices.len);
    try std.testing.expectEqual(1, validator_indices[0]);
    try std.testing.expectEqual(4, validator_indices[1]);
    try std.testing.expectEqual(7, validator_indices[2]);

    var config3 = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/src/test/fixtures/nodes.yaml");
    defer config3.deinit(std.testing.allocator);
    const nodes = try nodesFromYAML(std.testing.allocator, config3);
    defer {
        for (nodes) |node| std.testing.allocator.free(node);
        std.testing.allocator.free(nodes);
    }
    try std.testing.expectEqual(3, nodes.len);
    try std.testing.expectEqualStrings("enr:-IW4QA0pljjdLfxS_EyUxNAxJSoGCwmOVNJauYWsTiYHyWG5Bky-7yCEktSvu_w-PWUrmzbc8vYL_Mx5pgsAix2OfOMBgmlkgnY0gmlwhKwUAAGEcXVpY4IfkIlzZWNwMjU2azGhA6mw8mfwe-3TpjMMSk7GHe3cURhOn9-ufyAqy40wEyui", nodes[0]);
    try std.testing.expectEqualStrings("enr:-IW4QNx7F6OKXCmx9igmSwOAOdUEiQ9Et73HNygWV1BbuFgkXZLMslJVgpLYmKAzBF-AO0qJYq40TtqvtFkfeh2jzqYBgmlkgnY0gmlwhKwUAAKEcXVpY4IfkIlzZWNwMjU2azGhA2hqUIfSG58w4lGPMiPp9llh1pjFuoSRUuoHmwNdHELw", nodes[1]);
    try std.testing.expectEqualStrings("enr:-IW4QOh370UNQipE8qYlVRK3MpT7I0hcOmrTgLO9agIxuPS2B485Se8LTQZ4Rhgo6eUuEXgMAa66Wt7lRYNHQo9zk8QBgmlkgnY0gmlwhKwUAAOEcXVpY4IfkIlzZWNwMjU2azGhA7NTxgfOmGE2EQa4HhsXxFOeHdTLYIc2MEBczymm9IUN", nodes[2]);
}
