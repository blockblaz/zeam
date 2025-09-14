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
const Logger = utils_lib.ZeamLogger;

const prefix = "zeam_";

pub const StartNodeOptions = struct {
    node_id: u32,
    bootnodes: []const []const u8,
    validator_indices: []usize,
    genesis_spec: types.GenesisSpec,
    metrics_enable: bool,
    metrics_port: u16,
    logger: *Logger,
};

/// Starts a node with the given options.
/// This function does not return until the node is stopped.
/// It initializes the metrics server if enabled, sets up the network,
/// and starts the Beam node with the provided configuration.
pub fn startNode(allocator: std.mem.Allocator, options: StartNodeOptions) !void {
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
    const anchorState = try sft.genGenesisState(allocator, chain_config.genesis);

    // TODO we seem to be needing one loop because then the events added to loop are not being fired
    // in the order to which they have been added even with the an appropriate delay added
    // behavior of this further needs to be investigated but for now we will share the same loop
    const loop = try allocator.create(xev.Loop);
    loop.* = try xev.Loop.init(.{});

    const self_node_index = options.validator_indices[0];
    var network = try allocator.create(networks.EthLibp2p);
    var node_enr: ENR = undefined;
    defer node_enr.deinit();
    try ENR.decodeTxtInto(&node_enr, options.bootnodes[self_node_index]);

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

    for (options.bootnodes, 0..) |n, i| {
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

    network.* = try networks.EthLibp2p.init(allocator, loop, .{ .networkId = 0, .listen_addresses = listen_addresses, .connect_peers = connect_peers }, options.logger);
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
        .validator_ids = options.validator_indices,
        .logger = options.logger,
    });

    try beam_node.run();
    std.debug.print("Lean node {d} listened on {?d}\n", .{ node_id, try node_enr.getQUIC() });
    try clock.run();
}

/// Parses the nodes from a YAML configuration.
/// Expects a YAML structure like:
/// ```yaml
///   - enr1...
///   - enr2...
/// ```
/// Returns a set of ENR strings. The caller is responsible for freeing the returned slice.
pub fn nodesFromYAML(allocator: std.mem.Allocator, nodes_config: Yaml) ![]const []const u8 {
    return try nodes_config.parse(allocator, [][]const u8);
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
pub fn validatorIndicesFromYAML(allocator: std.mem.Allocator, node_id: u32, validators_config: Yaml) ![]usize {
    var validator_indices: std.ArrayListUnmanaged(usize) = .empty;
    defer validator_indices.deinit(allocator);

    var node_key_buf: [prefix.len + 4]u8 = undefined;
    const node_key = try std.fmt.bufPrint(&node_key_buf, "{s}{d}", .{ prefix, node_id });
    for (validators_config.docs.items[0].map.get(node_key).?.list) |item| {
        try validator_indices.append(allocator, @intCast(item.int));
    }
    return try validator_indices.toOwnedSlice(allocator);
}
