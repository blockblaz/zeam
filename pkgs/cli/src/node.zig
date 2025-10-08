const std = @import("std");
const enr_lib = @import("enr");
const ENR = enr_lib.ENR;
const utils_lib = @import("@zeam/utils");
const Yaml = @import("yaml").Yaml;
const configs = @import("@zeam/configs");
const api = @import("@zeam/api");
const api_server = @import("api_server.zig");
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
const constants = @import("constants.zig");
const database = @import("@zeam/database");

const prefix = "zeam_";

// Structure to hold parsed ENR fields from validator-config.yaml
const EnrFields = struct {
    ip: ?[]const u8 = null,
    ip6: ?[]const u8 = null,
    tcp: ?u16 = null,
    udp: ?u16 = null,
    quic: ?u16 = null,
    seq: ?u64 = null,
    // Allow for custom fields
    custom_fields: std.StringHashMap([]const u8),

    pub fn deinit(self: *EnrFields, allocator: std.mem.Allocator) void {
        if (self.ip) |ip_str| allocator.free(ip_str);
        if (self.ip6) |ip6_str| allocator.free(ip6_str);
        var iterator = self.custom_fields.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.custom_fields.deinit();
    }
};

pub const NodeOptions = struct {
    network_id: u32,
    node_key: []const u8,
    node_key_index: usize,
    // 1. a special value of "genesis_bootnode" for validator config means its a genesis bootnode and so
    //   the configuration is to be picked from genesis
    // 2. otherwise validator_config is dir path to this nodes's validator_config.yaml and validatrs.yaml
    //   and one must use all the nodes in genesis nodes.yaml as peers
    validator_config: []const u8,
    bootnodes: []const []const u8,
    validator_indices: []usize,
    genesis_spec: types.GenesisSpec,
    metrics_enable: bool,
    metrics_port: u16,
    local_priv_key: []const u8,
    logger_config: *LoggerConfig,
    database_path: []const u8,

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
    db: database.Db,

    const Self = @This();

    pub fn init(self: *Self, allocator: std.mem.Allocator, options: *const NodeOptions) !void {
        self.allocator = allocator;
        self.options = options;

        if (options.metrics_enable) {
            try api.init(allocator);
            try api_server.startAPIServer(allocator, options.metrics_port);
        }

        // some base mainnet spec would be loaded to build this up
        const chain_spec =
            \\{"preset": "mainnet", "name": "devnet0"}
        ;
        const json_options = json.ParseOptions{
            .ignore_unknown_fields = true,
            .allocate = .alloc_if_needed,
        };
        var chain_options = (try json.parseFromSlice(ChainOptions, allocator, chain_spec, json_options)).value;
        chain_options.genesis_time = options.genesis_spec.genesis_time;
        chain_options.num_validators = options.genesis_spec.num_validators;
        // transfer ownership of the chain_options to ChainConfig
        const chain_config = try ChainConfig.init(Chain.custom, chain_options);
        var anchorState: types.BeamState = undefined;
        try anchorState.genGenesisState(allocator, chain_config.genesis);
        errdefer anchorState.deinit();

        // TODO we seem to be needing one loop because then the events added to loop are not being fired
        // in the order to which they have been added even with the an appropriate delay added
        // behavior of this further needs to be investigated but for now we will share the same loop
        self.loop = try xev.Loop.init(.{});

        const addresses = try self.constructMultiaddrs();

        self.network = try networks.EthLibp2p.init(allocator, &self.loop, .{
            .networkId = options.network_id,
            .network_name = chain_config.spec.name,
            .listen_addresses = addresses.listen_addresses,
            .connect_peers = addresses.connect_peers,
            .local_private_key = options.local_priv_key,
        }, options.logger_config.logger(.network));
        errdefer self.network.deinit();
        self.clock = try Clock.init(allocator, chain_config.genesis.genesis_time, &self.loop);
        errdefer self.clock.deinit(allocator);

        var db = try database.Db.open(allocator, options.logger_config.logger(.database), options.database_path);
        errdefer db.deinit();

        try self.beam_node.init(allocator, .{
            .nodeId = @intCast(options.node_key_index),
            .config = chain_config,
            .anchorState = &anchorState,
            .backend = self.network.getNetworkInterface(),
            .clock = &self.clock,
            .validator_ids = options.validator_indices,
            .db = db,
            .logger_config = options.logger_config,
        });

        self.logger = options.logger_config.logger(.node);
    }

    pub fn deinit(self: *Self) void {
        self.clock.deinit(self.allocator);
        self.beam_node.deinit();
        self.network.deinit();
        self.enr.deinit();
        self.db.deinit();
        self.loop.deinit();
    }

    pub fn run(self: *Node) !void {
        try self.network.run();
        try self.beam_node.run();

        const ascii_art =
            \\  ███████████████████████████████████████████████████████
            \\  ██████████████                         ████  ██████████
            \\  ███████████        ████████████████       █████████████
            \\  █████████      ████████████████████████     ███████████
            \\  ██████    █████████████████████████████████     ███████
            \\  █████    █████████████████████  █████████████    ██████
            \\  ███     ██████████       █   █████   █████████    █████
            \\  ███    ███████████  █████ █ █ █ ███████████████     ███
            \\  ██    ██████████ ██ ██ ████ ███ ██    ██████████   ████
            \\  ██   ██████████         ███ ████       █████████    ███
            \\  ██   ███████████  █  ██████ ████        █████████   ███
            \\  █    █████████ ████ █████     █████ █████████████   ███
            \\  █    ██████████ █   ████     ██   █████   ███████   ███
            \\  ██   ██████████       ████████ ██    █    ██████    ███
            \\  ██    █████████       ███████ █       ██████████    ███
            \\  ███   ██████████      ███   ███       █████████    █ ██
            \\  ███    ████████████ ███ ██ ███ █     █ ███████    █████
            \\  ███     ████████████ ████   █████   █████████    ██████
            \\  █████     █████████   ███   █████   ████████    ███████
            \\  ████████      ██████████████████████████     ██████████
            \\  ████████  █      ████████████████████      ████████████
            \\  █████  ██████         ██████████         ██████████████
            \\  █████████████████                    ██████████████████
            \\  ███████████████████████████████████████████████████████
            \\
            \\           ███████╗███████╗ █████╗ ███╗   ███╗
            \\           ╚══███╔╝██╔════╝██╔══██╗████╗ ████║
            \\             ███╔╝ █████╗  ███████║██╔████╔██║
            \\            ███╔╝  ██╔══╝  ██╔══██║██║╚██╔╝██║
            \\           ███████╗███████╗██║  ██║██║ ╚═╝ ██║
            \\           ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
            \\
            \\          A blazing fast lean consensus client
        ;

        var encoded_txt_buf: [1000]u8 = undefined;
        const encoded_txt = try self.enr.encodeToTxt(&encoded_txt_buf);

        const quic_port = try self.enr.getQUIC();

        // Use logger.info instead of std.debug.print
        self.logger.info("\n{s}", .{ascii_art});
        self.logger.info("════════════════════════════════════════════════════════", .{});
        self.logger.info("  🚀 Zeam Lean Node Started Successfully!", .{});
        self.logger.info("════════════════════════════════════════════════════════", .{});
        self.logger.info("  Node ID: {d}", .{self.options.node_key_index});
        self.logger.info("  Listening on QUIC port: {?d}", .{quic_port});
        self.logger.info("  ENR: {s}", .{encoded_txt});
        self.logger.info("────────────────────────────────────────────────────────", .{});

        try self.clock.run();
    }

    fn constructMultiaddrs(self: *Self) !struct { listen_addresses: []const Multiaddr, connect_peers: []const Multiaddr } {
        if (std.mem.eql(u8, self.options.validator_config, "genesis_bootnode")) {
            try ENR.decodeTxtInto(&self.enr, self.options.bootnodes[self.options.node_key_index]);
        } else {
            // Parse validator config to get ENR fields
            const validator_config_filepath = try std.mem.concat(self.allocator, u8, &[_][]const u8{
                self.options.validator_config,
                "/validator-config.yaml",
            });
            defer self.allocator.free(validator_config_filepath);

            var parsed_validator_config = try utils_lib.loadFromYAMLFile(self.allocator, validator_config_filepath);
            defer parsed_validator_config.deinit(self.allocator);

            // Get ENR fields from validator config
            var enr_fields = try getEnrFieldsFromValidatorConfig(self.allocator, self.options.node_key, parsed_validator_config);
            defer enr_fields.deinit(self.allocator);

            // Construct ENR from fields and private key
            self.enr = try constructENRFromFields(self.allocator, self.options.local_priv_key, enr_fields);
        }

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
            // don't exclude any entry from nodes.yaml if this is not a genesis bootnode
            if (i != self.options.node_key_index or !std.mem.eql(u8, self.options.validator_config, "genesis_bootnode")) {
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
    const validators_filepath = try std.mem.concat(allocator, u8, &[_][]const u8{
        if (std.mem.eql(u8, node_cmd.validator_config, "genesis_bootnode"))
            //
            node_cmd.custom_genesis
        else
            node_cmd.validator_config,
        "/validators.yaml",
    });
    defer allocator.free(validators_filepath);
    const validator_config_filepath = try std.mem.concat(allocator, u8, &[_][]const u8{
        if (std.mem.eql(u8, node_cmd.validator_config, "genesis_bootnode"))
            //
            node_cmd.custom_genesis
        else
            node_cmd.validator_config,
        "/validator-config.yaml",
    });
    defer allocator.free(validator_config_filepath);
    // TODO: support genesis file loading when ssz library supports it
    // const genesis_filepath = try std.mem.concat(allocator, &[_][]const u8{custom_genesis, "/genesis.ssz"});
    // defer allocator.free(genesis_filepath);

    var parsed_bootnodes = try utils_lib.loadFromYAMLFile(allocator, bootnodes_filepath);
    defer parsed_bootnodes.deinit(allocator);

    var parsed_config = try utils_lib.loadFromYAMLFile(allocator, config_filepath);
    defer parsed_config.deinit(allocator);

    var parsed_validators = try utils_lib.loadFromYAMLFile(allocator, validators_filepath);
    defer parsed_validators.deinit(allocator);

    var parsed_validator_config = try utils_lib.loadFromYAMLFile(allocator, validator_config_filepath);
    defer parsed_validator_config.deinit(allocator);

    const bootnodes = try nodesFromYAML(allocator, parsed_bootnodes);
    errdefer {
        for (bootnodes) |b| allocator.free(b);
        allocator.free(bootnodes);
    }
    if (bootnodes.len == 0) {
        return error.InvalidNodesConfig;
    }
    const genesis_spec = try configs.genesisConfigFromYAML(parsed_config, node_cmd.override_genesis_time);

    const validator_indices = try validatorIndicesFromYAML(allocator, opts.node_key, parsed_validators);
    errdefer allocator.free(validator_indices);
    if (validator_indices.len == 0) {
        return error.InvalidValidatorConfig;
    }
    const local_priv_key = try getPrivateKeyFromValidatorConfig(allocator, opts.node_key, parsed_validator_config);

    opts.bootnodes = bootnodes;
    opts.validator_indices = validator_indices;
    opts.local_priv_key = local_priv_key;
    opts.genesis_spec = genesis_spec;
    opts.node_key_index = try nodeKeyIndexFromYaml(opts.node_key, parsed_validator_config);
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
fn validatorIndicesFromYAML(allocator: std.mem.Allocator, node_key: []const u8, validators: Yaml) ![]usize {
    var validator_indices: std.ArrayListUnmanaged(usize) = .empty;
    defer validator_indices.deinit(allocator);

    for (validators.docs.items[0].map.get(node_key).?.list) |item| {
        try validator_indices.append(allocator, @intCast(item.int));
    }
    return try validator_indices.toOwnedSlice(allocator);
}

// Parses the index for a given node key from a YAML configuration.
// ```yaml
// shuffle: roundrobin
// validators:
//   - name: "zeam_0"
//     # node id 7d0904dc6d8d7130e0e68d5d3175d0c3cf470f8725f67bd8320882f5b9753cc0
//     # peer id 16Uiu2HAkvi2sxT75Bpq1c7yV2FjnSQJJ432d6jeshbmfdJss1i6f
//     privkey: "bdf953adc161873ba026330c56450453f582e3c4ee6cb713644794bcfdd85fe5"
//     enrFields:
//       # verify /ip4/127.0.0.1/udp/9000/quic-v1/p2p/16Uiu2HAkvi2sxT75Bpq1c7yV2FjnSQJJ432d6jeshbmfdJss1i6f
//       ip: "127.0.0.1"
//       quic: 9000
//     count: 1 # number of indices for this node
//```

fn nodeKeyIndexFromYaml(node_key: []const u8, validator_config: Yaml) !usize {
    var index: usize = 0;
    for (validator_config.docs.items[0].map.get("validators").?.list) |entry| {
        const name_value = entry.map.get("name").?;
        if (name_value == .string and std.mem.eql(u8, name_value.string, node_key)) {
            return index;
        }
        index += 1;
    }
    return error.InvalidNodeKey;
}

fn getPrivateKeyFromValidatorConfig(allocator: std.mem.Allocator, node_key: []const u8, validator_config: Yaml) ![]const u8 {
    for (validator_config.docs.items[0].map.get("validators").?.list) |entry| {
        const name_value = entry.map.get("name").?;
        if (name_value == .string and std.mem.eql(u8, name_value.string, node_key)) {
            const privkey_value = entry.map.get("privkey").?;
            if (privkey_value == .string) {
                return try allocator.dupe(u8, privkey_value.string);
            } else {
                return error.InvalidPrivateKeyFormat;
            }
        }
    }
    return error.InvalidNodeKey;
}

fn getEnrFieldsFromValidatorConfig(allocator: std.mem.Allocator, node_key: []const u8, validator_config: Yaml) !EnrFields {
    for (validator_config.docs.items[0].map.get("validators").?.list) |entry| {
        const name_value = entry.map.get("name").?;
        if (name_value == .string and std.mem.eql(u8, name_value.string, node_key)) {
            const enr_fields_value = entry.map.get("enrFields");
            if (enr_fields_value == null) {
                return error.MissingEnrFields;
            }

            var enr_fields = EnrFields{
                .custom_fields = std.StringHashMap([]const u8).init(allocator),
            };
            errdefer enr_fields.deinit(allocator);

            const fields_map = enr_fields_value.?.map;

            // Parse known fields
            if (fields_map.get("ip")) |ip_value| {
                if (ip_value == .string) {
                    enr_fields.ip = try allocator.dupe(u8, ip_value.string);
                }
            }

            if (fields_map.get("ip6")) |ip6_value| {
                if (ip6_value == .string) {
                    enr_fields.ip6 = try allocator.dupe(u8, ip6_value.string);
                }
            }

            if (fields_map.get("tcp")) |tcp_value| {
                if (tcp_value == .int) {
                    enr_fields.tcp = @intCast(tcp_value.int);
                }
            }

            if (fields_map.get("udp")) |udp_value| {
                if (udp_value == .int) {
                    enr_fields.udp = @intCast(udp_value.int);
                }
            }

            if (fields_map.get("quic")) |quic_value| {
                if (quic_value == .int) {
                    enr_fields.quic = @intCast(quic_value.int);
                }
            }

            if (fields_map.get("seq")) |seq_value| {
                if (seq_value == .int) {
                    enr_fields.seq = @intCast(seq_value.int);
                }
            }

            // Parse custom fields
            var iterator = fields_map.iterator();
            while (iterator.next()) |kv| {
                const key = kv.key_ptr.*;
                const value = kv.value_ptr.*;

                // Skip known fields
                if (std.mem.eql(u8, key, "ip") or
                    std.mem.eql(u8, key, "ip6") or
                    std.mem.eql(u8, key, "tcp") or
                    std.mem.eql(u8, key, "udp") or
                    std.mem.eql(u8, key, "quic") or
                    std.mem.eql(u8, key, "seq"))
                {
                    continue;
                }

                // Handle custom field based on type
                if (value == .string) {
                    const key_copy = try allocator.dupe(u8, key);
                    const value_copy = try allocator.dupe(u8, value.string);
                    try enr_fields.custom_fields.put(key_copy, value_copy);
                } else if (value == .int) {
                    // Convert integer to string for custom fields with proper padding
                    const value_str = try std.fmt.allocPrint(allocator, "0x{x:0>8}", .{@as(u32, @intCast(value.int))});
                    const key_copy = try allocator.dupe(u8, key);
                    try enr_fields.custom_fields.put(key_copy, value_str);
                }
            }

            return enr_fields;
        }
    }
    return error.InvalidNodeKey;
}

fn constructENRFromFields(allocator: std.mem.Allocator, private_key: []const u8, enr_fields: EnrFields) !ENR {
    // Clean up private key (remove 0x prefix if present)
    const secret_key_str = if (std.mem.startsWith(u8, private_key, "0x"))
        private_key[2..]
    else
        private_key;

    if (secret_key_str.len != 64) {
        return error.InvalidSecretKeyLength;
    }

    // Create SignableENR from private key
    var signable_enr = enr_lib.SignableENR.fromSecretKeyString(secret_key_str) catch {
        return error.ENRCreationFailed;
    };

    // Set IP address (IPv4)
    if (enr_fields.ip) |ip_str| {
        const ip_addr = std.net.Ip4Address.parse(ip_str, 0) catch {
            return error.InvalidIPAddress;
        };
        const ip_addr_bytes = std.mem.asBytes(&ip_addr.sa.addr);
        signable_enr.set("ip", ip_addr_bytes) catch {
            return error.ENRSetIPFailed;
        };
    }

    // Set IP address (IPv6)
    if (enr_fields.ip6) |ip6_str| {
        const ip6_addr = std.net.Ip6Address.parse(ip6_str, 0) catch {
            return error.InvalidIP6Address;
        };
        const ip6_addr_bytes = std.mem.asBytes(&ip6_addr.sa.addr);
        signable_enr.set("ip6", ip6_addr_bytes) catch {
            return error.ENRSetIP6Failed;
        };
    }

    // Set TCP port
    if (enr_fields.tcp) |tcp_port| {
        var tcp_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &tcp_bytes, tcp_port, .big);
        signable_enr.set("tcp", &tcp_bytes) catch {
            return error.ENRSetTCPFailed;
        };
    }

    // Set UDP port
    if (enr_fields.udp) |udp_port| {
        var udp_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &udp_bytes, udp_port, .big);
        signable_enr.set("udp", &udp_bytes) catch {
            return error.ENRSetUDPFailed;
        };
    }

    // Set QUIC port
    if (enr_fields.quic) |quic_port| {
        var quic_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &quic_bytes, quic_port, .big);
        signable_enr.set("quic", &quic_bytes) catch {
            return error.ENRSetQUICFailed;
        };
    }

    // Set sequence number
    if (enr_fields.seq) |seq_num| {
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, seq_num, .big);
        signable_enr.set("seq", &seq_bytes) catch {
            return error.ENRSetSEQFailed;
        };
    }

    // Set custom fields
    var custom_iterator = enr_fields.custom_fields.iterator();
    while (custom_iterator.next()) |kv| {
        const key = kv.key_ptr.*;
        const value = kv.value_ptr.*;

        // Try to parse as hex if it starts with 0x
        if (std.mem.startsWith(u8, value, "0x")) {
            const hex_value = value[2..];
            if (hex_value.len % 2 != 0) {
                return error.InvalidHexValue;
            }
            const bytes = try allocator.alloc(u8, hex_value.len / 2);
            defer allocator.free(bytes);

            _ = std.fmt.hexToBytes(bytes, hex_value) catch {
                return error.InvalidHexFormat;
            };

            signable_enr.set(key, bytes) catch {
                return error.ENRSetCustomFieldFailed;
            };
        } else {
            // Treat as string
            signable_enr.set(key, value) catch {
                return error.ENRSetCustomFieldFailed;
            };
        }
    }

    // Convert SignableENR to ENR
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try enr_lib.writeSignableENR(writer, &signable_enr);
    const enr_text = fbs.getWritten();

    var enr: ENR = undefined;
    try ENR.decodeTxtInto(&enr, enr_text);

    return enr;
}

test "config yaml parsing" {
    var config1 = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/config.yaml");
    defer config1.deinit(std.testing.allocator);
    const genesis_spec = try configs.genesisConfigFromYAML(config1, null);
    try std.testing.expectEqual(9, genesis_spec.num_validators);
    try std.testing.expectEqual(1704085200, genesis_spec.genesis_time);

    var config2 = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/validators.yaml");
    defer config2.deinit(std.testing.allocator);
    const validator_indices = try validatorIndicesFromYAML(std.testing.allocator, "zeam_0", config2);
    defer std.testing.allocator.free(validator_indices);
    try std.testing.expectEqual(3, validator_indices.len);
    try std.testing.expectEqual(1, validator_indices[0]);
    try std.testing.expectEqual(4, validator_indices[1]);
    try std.testing.expectEqual(7, validator_indices[2]);

    var config3 = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/nodes.yaml");
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

test "ENR fields parsing from validator config" {
    var validator_config = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/validator-config.yaml");
    defer validator_config.deinit(std.testing.allocator);

    // Test parsing ENR fields for zeam_0
    var enr_fields = try getEnrFieldsFromValidatorConfig(std.testing.allocator, "zeam_0", validator_config);
    defer enr_fields.deinit(std.testing.allocator);

    // Verify the parsed fields match expected values
    try std.testing.expectEqualStrings("172.20.0.100", enr_fields.ip.?);
    try std.testing.expectEqual(@as(u16, 9000), enr_fields.tcp.?);
    try std.testing.expectEqual(@as(u16, 9001), enr_fields.quic.?);
    try std.testing.expectEqual(@as(u64, 1), enr_fields.seq.?);

    // Test parsing ENR fields for quadrivium_0
    var enr_fields_1 = try getEnrFieldsFromValidatorConfig(std.testing.allocator, "quadrivium_0", validator_config);
    defer enr_fields_1.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("2001:db8:85a3::8a2e:370:7334", enr_fields_1.ip6.?);
    try std.testing.expectEqual(@as(u16, 30303), enr_fields_1.tcp.?);
    try std.testing.expectEqual(@as(u16, 8080), enr_fields_1.quic.?);
    try std.testing.expectEqual(@as(u64, 1), enr_fields_1.seq.?);

    // Test custom field parsing
    // Check if the custom field exists
    const whatever_field = enr_fields.custom_fields.get("whatever");
    if (whatever_field) |value| {
        try std.testing.expectEqualStrings("0x01000000", value);
    } else {
        // If the field doesn't exist, that's also a test failure
        try std.testing.expect(false);
    }
    // quadrivium_0 doesn't have custom fields, so just verify the custom_fields map is empty
    try std.testing.expectEqual(@as(usize, 0), enr_fields_1.custom_fields.count());
}

test "ENR construction from fields" {
    var validator_config = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/validator-config.yaml");
    defer validator_config.deinit(std.testing.allocator);

    // Get ENR fields for zeam_0
    var enr_fields = try getEnrFieldsFromValidatorConfig(std.testing.allocator, "zeam_0", validator_config);
    defer enr_fields.deinit(std.testing.allocator);

    // Get private key for zeam_0
    const private_key = try getPrivateKeyFromValidatorConfig(std.testing.allocator, "zeam_0", validator_config);
    defer std.testing.allocator.free(private_key);

    // Construct ENR from fields
    const constructed_enr = try constructENRFromFields(std.testing.allocator, private_key, enr_fields);

    // Verify the ENR was constructed successfully
    // We can't easily verify the exact ENR content without knowing the exact signature,
    // but we can verify that specific fields are present in the constructed ENR
    try std.testing.expect(constructed_enr.kvs.get("ip") != null);
    try std.testing.expect(constructed_enr.kvs.get("quic") != null);
    try std.testing.expect(constructed_enr.kvs.get("tcp") != null);
    try std.testing.expect(constructed_enr.kvs.get("seq") != null);
}
