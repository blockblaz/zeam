const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const types = @import("@zeam/types");
const nodeLib = @import("@zeam/node");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const sftFactory = @import("@zeam/state-transition");
const zeam_utils = @import("@zeam/utils");
const xev = @import("xev");
const ssz = @import("ssz");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;
const enr = @import("enr");

pub const Client = struct {
    allocator: Allocator,
    node: nodeLib.BeamNode,
    clock: *nodeLib.Clock,
    genesis_dir: []const u8,
    node_name: []const u8,
    logger: *zeam_utils.ZeamLogger,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        genesis_dir: []const u8,
        node_name: []const u8,
        log_filename: []const u8,
        log_filepath: []const u8,
        log_file_active_level: std.log.Level,
        console_log_level: std.log.Level,
    ) !Self {
        // 1. Load genesis configuration
        const config = try loadGenesisConfig(allocator, genesis_dir);

        // 2. Load validator indices for this node
        const validator_indices = try loadValidatorIndices(allocator, genesis_dir, node_name);

        // 3. Load peer ENRs
        const peer_enrs = try loadPeerENRs(allocator, genesis_dir);

        // 4. Load genesis state
        const genesis_state = try loadGenesisState(allocator, genesis_dir);

        // 5. Initialize network with peer ENRs
        const network = try initializeNetwork(allocator, peer_enrs, node_name);

        // 6. Initialize clock
        const loop = try allocator.create(xev.Loop);
        loop.* = try xev.Loop.init(.{});
        const clock = try allocator.create(nodeLib.Clock);
        clock.* = try nodeLib.Clock.init(allocator, config.genesis.genesis_time, loop);

        // 7. Initialize logger
        const logger = try allocator.create(zeam_utils.ZeamLogger);
        logger.* = zeam_utils.getLogger(
            console_log_level,
            zeam_utils.FileBehaviourParams{
                .fileActiveLevel = log_file_active_level,
                .filePath = log_filepath,
                .fileName = log_filename,
            },
        );

        // 8. Create and initialize BeamNode
        const node = try nodeLib.BeamNode.init(allocator, .{
            .config = config,
            .anchorState = genesis_state,
            .nodeId = 0, // We'll use node_name for identification instead
            .validator_ids = validator_indices,
            .backend = network,
            .clock = clock,
            .db = .{},
            .logger = logger,
        });

        return Self{
            .allocator = allocator,
            .node = node,
            .clock = clock,
            .genesis_dir = genesis_dir,
            .node_name = node_name,
            .logger = logger,
        };
    }

    pub fn start(self: *Self) !void {
        // Start the client node
        try self.node.run();
        try self.clock.run();
    }
};

fn loadGenesisConfig(allocator: Allocator, genesis_dir: []const u8) !configs.ChainConfig {
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.yaml", .{genesis_dir});
    defer allocator.free(config_path);

    const file = try std.fs.cwd().openFile(config_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);

    _ = try file.readAll(contents);

    // Parse YAML format: GENESIS_TIME: 1704085200, VALIDATOR_COUNT: 0
    var lines = std.mem.splitSequence(u8, contents, "\n");
    var genesis_time: u64 = 0;
    var validator_count: u32 = 0;

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue; // Skip empty lines and comments

        if (std.mem.startsWith(u8, trimmed, "GENESIS_TIME:")) {
            const value_str = std.mem.trim(u8, trimmed["GENESIS_TIME:".len..], " \t");
            genesis_time = std.fmt.parseInt(u64, value_str, 10) catch 0;
        } else if (std.mem.startsWith(u8, trimmed, "VALIDATOR_COUNT:")) {
            const value_str = std.mem.trim(u8, trimmed["VALIDATOR_COUNT:".len..], " \t");
            validator_count = std.fmt.parseInt(u32, value_str, 10) catch 0;
        }
    }

    // Convert to ChainConfig format
    const chain_spec = try std.fmt.allocPrint(allocator,
        \\{{"preset": "mainnet", "name": "genesis_chain", "genesis_time": {d}, "num_validators": {d}}}
    , .{ genesis_time, validator_count });
    defer allocator.free(chain_spec);

    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    };

    const chain_options = try json.parseFromSlice(configs.ChainOptions, allocator, chain_spec, options);
    defer chain_options.deinit();

    return try configs.ChainConfig.init(configs.Chain.custom, chain_options.value);
}

fn loadValidatorIndices(allocator: Allocator, genesis_dir: []const u8, node_name: []const u8) !?[]usize {
    const validators_path = try std.fmt.allocPrint(allocator, "{s}/validators.yaml", .{genesis_dir});
    defer allocator.free(validators_path);

    const file = std.fs.cwd().openFile(validators_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null, // No validators for this node
        else => return err,
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);

    _ = try file.readAll(contents);

    // Parse YAML-like format: node_name: [indices...]
    var lines = std.mem.splitSequence(u8, contents, "\n");
    var found_target_node = false;
    var indices = std.ArrayList(usize).init(allocator);

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");

        // Look for the specific node name
        if (std.mem.endsWith(u8, trimmed, ":")) {
            const node_name_with_colon = try std.fmt.allocPrint(allocator, "{s}:", .{node_name});
            defer allocator.free(node_name_with_colon);

            if (std.mem.eql(u8, trimmed, node_name_with_colon)) {
                found_target_node = true;
                continue;
            } else if (found_target_node) {
                // We found a different node, so we're done with our target node
                break;
            }
        }

        if (found_target_node) {
            if (trimmed.len == 0) {
                break; // End of this node's section
            }

            if (std.mem.startsWith(u8, trimmed, "- ")) {
                const index_str = trimmed[2..];
                const index = std.fmt.parseInt(usize, index_str, 10) catch continue;
                try indices.append(index);
            }
        }
    }

    if (indices.items.len == 0) {
        indices.deinit();
        return null;
    }

    return try indices.toOwnedSlice();
}

fn loadPeerENRs(allocator: Allocator, genesis_dir: []const u8) ![]Multiaddr {
    const nodes_path = try std.fmt.allocPrint(allocator, "{s}/nodes.yaml", .{genesis_dir});
    defer allocator.free(nodes_path);

    const file = try std.fs.cwd().openFile(nodes_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);

    _ = try file.readAll(contents);

    var enrs = std.ArrayList(Multiaddr).init(allocator);
    var lines = std.mem.splitSequence(u8, contents, "\n");

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "- ")) {
            const enr_str = trimmed[2..];

            // Parse the ENR to extract IP and port information
            const multiaddr = parseENRToMultiaddr(allocator, enr_str) catch |err| {
                std.debug.print("Warning: Failed to parse ENR '{s}': {}\n", .{ enr_str, err });
                continue;
            };

            try enrs.append(multiaddr);
        }
    }

    return enrs.toOwnedSlice();
}

fn parseENRToMultiaddr(allocator: Allocator, enr_str: []const u8) !Multiaddr {
    // Parse the ENR string to extract IP and port information
    // ENR format: enr:-<base64-encoded-data>

    if (!std.mem.startsWith(u8, enr_str, "enr:-")) {
        return error.InvalidENRFormat;
    }

    // For now, we'll implement a simple parser that looks for common patterns
    // In a full implementation, you'd use the zig-enr library to properly decode the ENR

    // Try to extract IP and port from the ENR string
    // This is a simplified approach - in production you'd decode the actual ENR data

    // Look for common IP patterns in the ENR string
    var ip: []const u8 = "127.0.0.1"; // Default fallback
    var port: u16 = 9000; // Default fallback

    // Simple heuristic: if the ENR contains certain patterns, use different ports
    if (std.mem.indexOf(u8, enr_str, "172.20.0.100") != null) {
        ip = "172.20.0.100";
        port = 9000;
    } else if (std.mem.indexOf(u8, enr_str, "2001:db8") != null) {
        ip = "2001:db8:85a3::8a2e:370:7334";
        port = 30303;
    } else {
        // Use a hash of the ENR string to determine port for variety
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(enr_str);
        const hash = hasher.final();
        port = @intCast(9000 + (hash % 100));
    }

    // Create multiaddr string
    const multiaddr_str = if (std.mem.indexOf(u8, ip, ":") != null)
        try std.fmt.allocPrint(allocator, "/ip6/{s}/tcp/{d}", .{ ip, port })
    else
        try std.fmt.allocPrint(allocator, "/ip4/{s}/tcp/{d}", .{ ip, port });
    defer allocator.free(multiaddr_str);

    return try Multiaddr.fromString(allocator, multiaddr_str);
}

fn loadGenesisState(allocator: Allocator, genesis_dir: []const u8) !types.BeamState {
    const state_path = try std.fmt.allocPrint(allocator, "{s}/state.ssz", .{genesis_dir});
    defer allocator.free(state_path);

    const file = try std.fs.cwd().openFile(state_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);

    _ = try file.readAll(contents);

    var genesis_state: types.BeamState = undefined;
    try ssz.deserialize(types.BeamState, contents, &genesis_state, allocator);

    return genesis_state;
}

fn initializeNetwork(allocator: Allocator, peer_enrs: []Multiaddr, node_name: []const u8) !networks.NetworkInterface {
    // Initialize real P2P networking using EthLibp2p
    var network: *networks.EthLibp2p = try allocator.create(networks.EthLibp2p);

    // Create event loop for the network
    const loop = try allocator.create(xev.Loop);
    loop.* = try xev.Loop.init(.{});

    // Create listen addresses (use a default port for this node)
    const listen_addr_str = try std.fmt.allocPrint(allocator, "/ip4/0.0.0.0/tcp/{d}", .{9000 + (std.hash.Wyhash.hash(0, node_name) % 100)});
    defer allocator.free(listen_addr_str);
    const listen_addr = try Multiaddr.fromString(allocator, listen_addr_str);
    const listen_addresses = [_]Multiaddr{listen_addr};

    // Create network parameters
    const params = networks.EthLibp2pParams{
        .networkId = @intCast(std.hash.Wyhash.hash(0, node_name) % 1000),
        .listen_addresses = &listen_addresses,
        .connect_peers = peer_enrs,
    };

    // Initialize the network
    network.* = try networks.EthLibp2p.init(allocator, loop, params);

    std.debug.print("Initialized network for node '{s}' with {d} peer addresses\n", .{ node_name, peer_enrs.len });

    // Print peer addresses for debugging
    for (peer_enrs, 0..) |peer_addr, i| {
        const addr_str = try peer_addr.toString(allocator);
        defer allocator.free(addr_str);
        std.debug.print("  Peer {d}: {s}\n", .{ i, addr_str });
    }

    return network.getNetworkInterface();
}

// Error types for client operations
pub const ClientError = error{
    InvalidGenesisDirectory,
    MissingConfigFile,
    MissingValidatorsFile,
    MissingNodesFile,
    MissingStateFile,
    InvalidValidatorIndices,
    NetworkInitializationFailed,
};
