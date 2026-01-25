const std = @import("std");
const enr_lib = @import("enr");
const ENR = enr_lib.ENR;
const utils_lib = @import("@zeam/utils");
const Yaml = @import("yaml").Yaml;
const configs = @import("@zeam/configs");
const api = @import("@zeam/api");
const api_server = @import("api_server.zig");
const event_broadcaster = api.event_broadcaster;
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;
const sft = @import("@zeam/state-transition");
const xev = @import("xev");
const networks = @import("@zeam/network");
const Multiaddr = @import("multiformats").multiaddr.Multiaddr;
const node_lib = @import("@zeam/node");
const key_manager_lib = @import("@zeam/key-manager");
const xmss = @import("@zeam/xmss");
const Clock = node_lib.Clock;
const BeamNode = node_lib.BeamNode;
const types = @import("@zeam/types");
const LoggerConfig = utils_lib.ZeamLoggerConfig;
const NodeCommand = @import("main.zig").NodeCommand;
const zeam_utils = @import("@zeam/utils");
const constants = @import("constants.zig");
const database = @import("@zeam/database");
const json = std.json;
const utils = @import("@zeam/utils");
const ssz = @import("ssz");
const zeam_metrics = @import("@zeam/metrics");
const build_options = @import("build_options");

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

/// Represents a validator assignment from annotated_validators.yaml
pub const ValidatorAssignment = struct {
    index: usize,
    pubkey_hex: []const u8,
    privkey_file: []const u8,

    pub fn deinit(self: *ValidatorAssignment, allocator: std.mem.Allocator) void {
        allocator.free(self.pubkey_hex);
        allocator.free(self.privkey_file);
    }
};

pub const NodeOptions = struct {
    network_id: u32,
    node_key: []const u8,
    node_key_index: usize,
    // 1. a special value of "genesis_bootnode" for validator config means its a genesis bootnode and so
    //   the configuration is to be picked from genesis
    // 2. otherwise validator_config is dir path to this nodes's validator_config.yaml and annotated_validators.yaml
    //   and one must use all the nodes in genesis nodes.yaml as peers
    validator_config: []const u8,
    bootnodes: []const []const u8,
    validator_assignments: []ValidatorAssignment,
    genesis_spec: types.GenesisSpec,
    metrics_enable: bool,
    api_port: u16,
    local_priv_key: []const u8,
    logger_config: *LoggerConfig,
    database_path: []const u8,
    hash_sig_key_dir: []const u8,
    node_registry: *node_lib.NodeNameRegistry,
    checkpoint_sync_url: ?[]const u8 = null,

    pub fn deinit(self: *NodeOptions, allocator: std.mem.Allocator) void {
        for (self.bootnodes) |b| allocator.free(b);
        allocator.free(self.bootnodes);
        for (self.validator_assignments) |*assignment| {
            @constCast(assignment).deinit(allocator);
        }
        allocator.free(self.validator_assignments);
        allocator.free(self.local_priv_key);
        allocator.free(self.hash_sig_key_dir);
        self.node_registry.deinit();
        allocator.destroy(self.node_registry);
    }

    pub fn getValidatorIndices(self: *const NodeOptions, allocator: std.mem.Allocator) ![]usize {
        var indices = try allocator.alloc(usize, self.validator_assignments.len);
        for (self.validator_assignments, 0..) |assignment, i| {
            indices[i] = assignment.index;
        }
        return indices;
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
    key_manager: key_manager_lib.KeyManager,
    anchor_state: *types.BeamState,

    const Self = @This();

    pub fn init(
        self: *Self,
        allocator: std.mem.Allocator,
        options: *const NodeOptions,
    ) !void {
        self.allocator = allocator;
        self.options = options;

        // Initialize event broadcaster
        try event_broadcaster.initGlobalBroadcaster(allocator);

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

        // Set validator_pubkeys from genesis_spec (read from config.yaml via genesisConfigFromYAML)
        chain_options.validator_pubkeys = options.genesis_spec.validator_pubkeys;

        // transfer ownership of the chain_options to ChainConfig
        const chain_config = try ChainConfig.init(Chain.custom, chain_options);

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
            .node_registry = options.node_registry,
        }, options.logger_config.logger(.network));
        errdefer self.network.deinit();
        self.clock = try Clock.init(allocator, chain_config.genesis.genesis_time, &self.loop);
        errdefer self.clock.deinit(allocator);

        var db = try database.Db.open(allocator, options.logger_config.logger(.database), options.database_path);
        errdefer db.deinit();

        self.logger = options.logger_config.logger(.node);

        const anchorState: *types.BeamState = try allocator.create(types.BeamState);
        errdefer allocator.destroy(anchorState);
        self.anchor_state = anchorState;

        // Initialize anchor state with priority: checkpoint URL > database > genesis
        var checkpoint_sync_succeeded = false;
        if (options.checkpoint_sync_url) |checkpoint_url| {
            self.logger.info("checkpoint sync enabled, downloading state from: {s}", .{checkpoint_url});

            // Try checkpoint sync, fall back to database/genesis on failure
            if (downloadCheckpointState(allocator, checkpoint_url, self.logger)) |downloaded_state| {
                self.anchor_state.* = downloaded_state;

                // Verify state against genesis config
                if (verifyCheckpointState(allocator, self.anchor_state, &chain_config.genesis, self.logger)) {
                    self.logger.info("checkpoint sync completed successfully, using state at slot {d} as anchor", .{self.anchor_state.slot});
                    checkpoint_sync_succeeded = true;
                } else |verify_err| {
                    self.logger.warn("checkpoint state verification failed: {}, falling back to database/genesis", .{verify_err});
                    self.anchor_state.deinit();
                }
            } else |download_err| {
                self.logger.warn("checkpoint sync failed: {}, falling back to database/genesis", .{download_err});
            }
        }

        // Fall back to database/genesis if checkpoint sync was not attempted or failed
        if (!checkpoint_sync_succeeded) {
            // Try to load the latest finalized state from the database, fallback to genesis
            db.loadLatestFinalizedState(self.anchor_state) catch |err| {
                self.logger.warn("failed to load latest finalized state from database: {any}", .{err});
                try self.anchor_state.genGenesisState(allocator, chain_config.genesis);
            };
        }
        errdefer self.anchor_state.deinit();

        const num_validators: usize = @intCast(chain_config.genesis.numValidators());
        self.key_manager = key_manager_lib.KeyManager.init(allocator);
        errdefer self.key_manager.deinit();

        try self.loadValidatorKeypairs(num_validators);

        const validator_ids = try options.getValidatorIndices(allocator);
        errdefer allocator.free(validator_ids);

        try self.beam_node.init(allocator, .{
            .nodeId = @intCast(options.node_key_index),
            .config = chain_config,
            .anchorState = self.anchor_state,
            .backend = self.network.getNetworkInterface(),
            .clock = &self.clock,
            .validator_ids = validator_ids,
            .key_manager = &self.key_manager,
            .db = db,
            .logger_config = options.logger_config,
            .node_registry = options.node_registry,
        });

        // Start API server after chain is initialized so we can pass the chain pointer
        if (options.metrics_enable) {
            try api.init(allocator);
            // Set node lifecycle metrics
            zeam_metrics.metrics.lean_node_info.set(.{ .name = "zeam", .version = build_options.version }, 1) catch {};
            zeam_metrics.metrics.lean_node_start_time_seconds.set(@intCast(std.time.timestamp()));
            try api_server.startAPIServer(allocator, options.api_port, options.logger_config, self.beam_node.chain);
        }
    }

    pub fn deinit(self: *Self) void {
        self.clock.deinit(self.allocator);
        self.beam_node.deinit();
        self.key_manager.deinit();
        self.network.deinit();
        self.enr.deinit();
        self.db.deinit();
        self.loop.deinit();
        event_broadcaster.deinitGlobalBroadcaster();
        self.anchor_state.deinit();
        self.allocator.destroy(self.anchor_state);
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

    fn loadValidatorKeypairs(
        self: *Self,
        num_validators: usize,
    ) !void {
        if (self.options.validator_assignments.len == 0) {
            return error.NoValidatorAssignments;
        }

        const hash_sig_key_dir = self.options.hash_sig_key_dir;

        for (self.options.validator_assignments) |assignment| {
            if (assignment.index >= num_validators) {
                return error.HashSigValidatorIndexOutOfRange;
            }

            const privkey_file = assignment.privkey_file;

            if (!std.mem.endsWith(u8, privkey_file, "_sk.ssz")) {
                return error.InvalidPrivkeyFileFormat;
            }

            const base = privkey_file[0 .. privkey_file.len - 7]; // Remove "_sk.ssz"
            const sk_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}_sk.ssz", .{ hash_sig_key_dir, base });
            defer self.allocator.free(sk_path);
            const pk_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}_pk.ssz", .{ hash_sig_key_dir, base });
            defer self.allocator.free(pk_path);

            // Read secret key
            var sk_file = std.fs.cwd().openFile(sk_path, .{}) catch |err| switch (err) {
                error.FileNotFound => return error.HashSigSecretKeyMissing,
                else => return err,
            };
            defer sk_file.close();
            const secret_ssz = try sk_file.readToEndAlloc(self.allocator, constants.MAX_HASH_SIG_ENCODED_KEY_SIZE);
            defer self.allocator.free(secret_ssz);

            // Read public key
            var pk_file = std.fs.cwd().openFile(pk_path, .{}) catch |err| switch (err) {
                error.FileNotFound => return error.HashSigPublicKeyMissing,
                else => return err,
            };
            defer pk_file.close();
            const public_ssz = try pk_file.readToEndAlloc(self.allocator, constants.MAX_HASH_SIG_ENCODED_KEY_SIZE);
            defer self.allocator.free(public_ssz);

            var keypair = try xmss.KeyPair.fromSsz(
                self.allocator,
                secret_ssz,
                public_ssz,
            );
            errdefer keypair.deinit();

            try self.key_manager.addKeypair(assignment.index, keypair);
        }
    }
};

/// Builds the start options for a node based on the provided command and options.
/// It loads the necessary configuration files, parses them, and populates the
/// `StartNodeOptions` structure.
/// The caller is responsible for freeing the allocated resources in `StartNodeOptions`.
pub fn buildStartOptions(
    allocator: std.mem.Allocator,
    node_cmd: NodeCommand,
    opts: *NodeOptions,
) !void {
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
        "/annotated_validators.yaml",
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
    const genesis_spec = try configs.genesisConfigFromYAML(allocator, parsed_config, node_cmd.override_genesis_time);

    const validator_assignments = try validatorAssignmentsFromYAML(allocator, opts.node_key, parsed_validators);
    errdefer {
        for (validator_assignments) |*a| {
            @constCast(a).deinit(allocator);
        }
        allocator.free(validator_assignments);
    }
    if (validator_assignments.len == 0) {
        return error.InvalidValidatorConfig;
    }
    const local_priv_key = try getPrivateKeyFromValidatorConfig(allocator, opts.node_key, parsed_validator_config);

    const node_key_index = try nodeKeyIndexFromYaml(opts.node_key, parsed_validator_config);

    const hash_sig_key_dir = try std.mem.concat(allocator, u8, &[_][]const u8{
        node_cmd.custom_genesis,
        "/",
        node_cmd.@"sig-keys-dir",
    });

    // Populate node name registry with peer information
    populateNodeNameRegistry(allocator, opts.node_registry, validator_config_filepath, validators_filepath) catch |err| {
        std.log.warn("Failed to populate node name registry: {any}", .{err});
    };

    opts.bootnodes = bootnodes;
    opts.validator_assignments = validator_assignments;
    opts.local_priv_key = local_priv_key;
    opts.genesis_spec = genesis_spec;
    opts.node_key_index = node_key_index;
    opts.hash_sig_key_dir = hash_sig_key_dir;
    opts.checkpoint_sync_url = node_cmd.@"checkpoint-sync-url";
}

/// Downloads finalized checkpoint state from the given URL and deserializes it
/// Returns the deserialized state. The caller is responsible for calling deinit on it.
fn downloadCheckpointState(
    allocator: std.mem.Allocator,
    url: []const u8,
    logger: zeam_utils.ModuleLogger,
) !types.BeamState {
    logger.info("downloading checkpoint state from: {s}", .{url});

    // Parse URL using std.Uri
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;

    // Initialize HTTP client
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Buffer for server response headers
    var server_header_buffer: [16 * 1024]u8 = undefined;

    // Open HTTP request
    var req = client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
    }) catch |err| {
        logger.err("failed to open HTTP connection: {}", .{err});
        return error.ConnectionFailed;
    };
    defer req.deinit();

    // Send the request
    req.send() catch |err| {
        logger.err("failed to send HTTP request: {}", .{err});
        return error.RequestFailed;
    };

    // Wait for response
    req.wait() catch |err| {
        logger.err("failed to receive HTTP response: {}", .{err});
        return error.ResponseFailed;
    };

    // Check HTTP status
    if (req.response.status != .ok) {
        logger.err("checkpoint sync failed: HTTP {d}", .{@intFromEnum(req.response.status)});
        return error.HttpError;
    }

    // Read response body
    var ssz_data = std.ArrayList(u8).init(allocator);
    errdefer ssz_data.deinit();

    var buffer: [8192]u8 = undefined;
    while (true) {
        const bytes_read = req.reader().read(&buffer) catch |err| {
            logger.err("failed to read response body: {}", .{err});
            return error.ReadFailed;
        };
        if (bytes_read == 0) break;
        try ssz_data.appendSlice(buffer[0..bytes_read]);
    }

    logger.info("downloaded checkpoint state: {d} bytes", .{ssz_data.items.len});

    // Deserialize SSZ state
    // Use arena allocator for deserialization as SSZ types may allocate
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var checkpoint_state: types.BeamState = undefined;
    try ssz.deserialize(types.BeamState, ssz_data.items, &checkpoint_state, arena.allocator());

    logger.info("successfully deserialized checkpoint state at slot {d}", .{checkpoint_state.slot});

    // Clone the state to move it out of the arena using the proper cloning function
    var cloned_state: types.BeamState = undefined;
    try types.sszClone(allocator, types.BeamState, checkpoint_state, &cloned_state);

    return cloned_state;
}

/// Verifies checkpoint state against the genesis configuration
/// Validates that the downloaded state is consistent with expected genesis parameters
/// Also computes and logs the state root and block root
fn verifyCheckpointState(
    allocator: std.mem.Allocator,
    state: *const types.BeamState,
    genesis_spec: *const types.GenesisSpec,
    logger: zeam_utils.ModuleLogger,
) !void {
    // Verify genesis timestamp matches
    if (state.config.genesis_time != genesis_spec.genesis_time) {
        logger.err("checkpoint state verification failed: genesis time mismatch (expected={d}, got={d})", .{
            genesis_spec.genesis_time,
            state.config.genesis_time,
        });
        return error.GenesisTimeMismatch;
    }

    // Verify number of validators matches genesis config
    const expected_validators = genesis_spec.numValidators();
    const actual_validators = state.validators.len();
    if (actual_validators != expected_validators) {
        logger.err("checkpoint state verification failed: validator count mismatch (expected={d}, got={d})", .{
            expected_validators,
            actual_validators,
        });
        return error.ValidatorCountMismatch;
    }

    // Verify state has validators
    if (actual_validators == 0) {
        logger.err("checkpoint state verification failed: no validators in state", .{});
        return error.NoValidators;
    }

    // Verify each validator pubkey matches genesis config
    const state_validators = state.validators.constSlice();
    for (genesis_spec.validator_pubkeys, 0..) |expected_pubkey, i| {
        const actual_pubkey = state_validators[i].pubkey;
        if (!std.mem.eql(u8, &expected_pubkey, &actual_pubkey)) {
            logger.err("checkpoint state verification failed: validator pubkey mismatch at index {d}", .{i});
            return error.ValidatorPubkeyMismatch;
        }
    }

    // Generate state block header with correct state_root
    // (latest_block_header.state_root is zero; genStateBlockHeader computes and sets it)
    const state_block_header = try state.genStateBlockHeader(allocator);

    // Calculate the block root from the properly constructed block header
    var block_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlockHeader, state_block_header, &block_root, allocator);

    logger.info("checkpoint state verified: slot={d}, genesis_time={d}, validators={d}, state_root=0x{s}, block_root=0x{s}", .{
        state.slot,
        state.config.genesis_time,
        actual_validators,
        std.fmt.fmtSliceHexLower(&state_block_header.state_root),
        std.fmt.fmtSliceHexLower(&block_root),
    });
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
/// Parses the validator assignments for a given node from a YAML configuration.
/// Expects a YAML structure like:
/// ```yaml
/// zeam_0:
///   - index: 0
///     pubkey_hex: 812f8540481ce70515d43b451cedcf6b4e3177312821fa541df6375c20ced55196ad245a00335d425e86817bdbde75536c986c25
///     privkey_file: validator_0_sk.json
///   - index: 3
///     pubkey_hex: a47e01144cd43e3efddef56da069f418d9aac406c29589314f74b00158437375e51b1213ecbbf23d47fd9e05933cfb24ac84e72d
///     privkey_file: validator_3_sk.json
/// ```
/// where `node_key` (e.g., "zeam_0") is the key for the node's validator assignments.
/// Returns a slice of ValidatorAssignment. The caller is responsible for freeing the returned slice.
fn validatorAssignmentsFromYAML(allocator: std.mem.Allocator, node_key: []const u8, validators: Yaml) ![]ValidatorAssignment {
    var assignments: std.ArrayListUnmanaged(ValidatorAssignment) = .empty;
    defer assignments.deinit(allocator);
    errdefer {
        for (assignments.items) |*a| {
            @constCast(a).deinit(allocator);
        }
    }

    const node_validators = validators.docs.items[0].map.get(node_key) orelse return error.InvalidNodeKey;
    if (node_validators != .list) return error.InvalidValidatorConfig;

    for (node_validators.list) |item| {
        if (item != .map) return error.InvalidValidatorConfig;

        const index_value = item.map.get("index") orelse return error.InvalidValidatorConfig;
        if (index_value != .int) return error.InvalidValidatorConfig;

        const pubkey_value = item.map.get("pubkey_hex") orelse return error.InvalidValidatorConfig;
        if (pubkey_value != .string) return error.InvalidValidatorConfig;

        const privkey_value = item.map.get("privkey_file") orelse return error.InvalidValidatorConfig;
        if (privkey_value != .string) return error.InvalidValidatorConfig;

        const assignment = ValidatorAssignment{
            .index = @intCast(index_value.int),
            .pubkey_hex = try allocator.dupe(u8, pubkey_value.string),
            .privkey_file = try allocator.dupe(u8, privkey_value.string),
        };
        try assignments.append(allocator, assignment);
    }
    return try assignments.toOwnedSlice(allocator);
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

/// Populate a NodeNameRegistry from validator-config.yaml and validators.yaml
/// This creates mappings from peer IDs and validator indices to node names
pub fn populateNodeNameRegistry(
    allocator: std.mem.Allocator,
    registry: *node_lib.NodeNameRegistry,
    validator_config_path: []const u8,
    validators_path: []const u8,
) !void {

    // Parse validator-config.yaml to get node names and their ENRs/privkeys
    var parsed_validator_config = try utils_lib.loadFromYAMLFile(allocator, validator_config_path);
    defer parsed_validator_config.deinit(allocator);

    // Parse validators.yaml to get validator indices for each node
    var parsed_validators = try utils_lib.loadFromYAMLFile(allocator, validators_path);
    defer parsed_validators.deinit(allocator);

    const validators_list = parsed_validator_config.docs.items[0].map.get("validators");
    if (validators_list == null) return;

    for (validators_list.?.list) |entry| {
        const name_value = entry.map.get("name");
        if (name_value == null or name_value.? != .string) continue;
        const node_name = name_value.?.string;

        // Get peer ID from ENR or private key
        const peer_id_str = blk: {
            var peer_id_buf: [256]u8 = undefined;
            // Try to get ENR first
            if (entry.map.get("enr")) |enr_value| {
                if (enr_value == .string) {
                    var enr: ENR = undefined;
                    ENR.decodeTxtInto(&enr, enr_value.string) catch break :blk null;
                    const pid = enr.peerId(allocator) catch break :blk null;
                    const pid_str_slice = pid.toBase58(&peer_id_buf) catch break :blk null;
                    const pid_str = allocator.dupe(u8, pid_str_slice) catch break :blk null;
                    break :blk pid_str;
                }
            }

            // Try to construct ENR from privkey and enrFields
            if (entry.map.get("privkey")) |privkey_value| {
                if (privkey_value == .string) {
                    const enr_fields_value = entry.map.get("enrFields");
                    if (enr_fields_value != null) {
                        var enr_fields = getEnrFieldsFromValidatorConfig(allocator, node_name, parsed_validator_config) catch break :blk null;
                        defer enr_fields.deinit(allocator);
                        var enr = constructENRFromFields(allocator, privkey_value.string, enr_fields) catch break :blk null;
                        defer enr.deinit();
                        const pid = enr.peerId(allocator) catch break :blk null;
                        const pid_str_slice = pid.toBase58(&peer_id_buf) catch break :blk null;
                        const pid_str = allocator.dupe(u8, pid_str_slice) catch break :blk null;
                        break :blk pid_str;
                    }
                }
            }
            break :blk null;
        };

        // Add peer ID mapping if we got a valid peer ID string
        if (peer_id_str) |pid_str| {
            defer allocator.free(pid_str);
            registry.addPeerMapping(pid_str, node_name) catch |err| {
                std.log.warn("Failed to add peer mapping for node {s}: {any}", .{ node_name, err });
            };
        }

        // Add validator index mappings
        const node_validators = parsed_validators.docs.items[0].map.get(node_name);
        if (node_validators) |validators| {
            if (validators == .list) {
                for (validators.list) |item| {
                    if (item == .int) {
                        const validator_index: usize = @intCast(item.int);
                        registry.addValidatorMapping(validator_index, node_name) catch |err| {
                            std.log.warn("Failed to add validator mapping for node {s} index {d}: {any}", .{ node_name, validator_index, err });
                        };
                    }
                }
            }
        }
    }
}

test "configs yaml parsing" {
    var config_file = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/config.yaml");
    defer config_file.deinit(std.testing.allocator);
    const genesis_spec = try configs.genesisConfigFromYAML(std.testing.allocator, config_file, null);
    defer std.testing.allocator.free(genesis_spec.validator_pubkeys);
    try std.testing.expectEqual(@as(u64, 9), genesis_spec.numValidators());
    try std.testing.expectEqual(@as(u64, 1704085200), genesis_spec.genesis_time);

    var validators_file = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/annotated_validators.yaml");
    defer validators_file.deinit(std.testing.allocator);
    const validator_assignments = try validatorAssignmentsFromYAML(std.testing.allocator, "zeam_0", validators_file);
    defer {
        for (validator_assignments) |*a| {
            @constCast(a).deinit(std.testing.allocator);
        }
        std.testing.allocator.free(validator_assignments);
    }
    try std.testing.expectEqual(3, validator_assignments.len);
    try std.testing.expectEqual(1, validator_assignments[0].index);
    try std.testing.expectEqual(4, validator_assignments[1].index);
    try std.testing.expectEqual(7, validator_assignments[2].index);

    var nodes_file = try utils_lib.loadFromYAMLFile(std.testing.allocator, "pkgs/cli/test/fixtures/nodes.yaml");
    defer nodes_file.deinit(std.testing.allocator);
    const nodes = try nodesFromYAML(std.testing.allocator, nodes_file);
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

test "compare roots from genGensisBlock and genGenesisState and genStateBlockHeader" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Load config.yaml from test fixtures
    const config_filepath = "pkgs/cli/test/fixtures/config.yaml";
    var parsed_config = try utils.loadFromYAMLFile(allocator, config_filepath);
    defer parsed_config.deinit(allocator);

    // Parse genesis config from YAML
    const genesis_spec = try configs.genesisConfigFromYAML(allocator, parsed_config, null);
    defer allocator.free(genesis_spec.validator_pubkeys);

    // Generate genesis state
    var genesis_state: types.BeamState = undefined;
    try genesis_state.genGenesisState(allocator, genesis_spec);
    defer genesis_state.deinit();

    std.debug.print("\nGenesis state: {s}\n", .{try genesis_state.toJsonString(allocator)});

    // Generate genesis block using genGenesisBlock
    var genesis_block: types.BeamBlock = undefined;
    try genesis_state.genGenesisBlock(allocator, &genesis_block);
    defer genesis_block.deinit();

    // Get state root by hashing the state directly
    var state_root_from_genesis: [32]u8 = undefined;
    try zeam_utils.hashTreeRoot(types.BeamState, genesis_state, &state_root_from_genesis, allocator);

    // Generate block header using genStateBlockHeader
    const state_block_header = try genesis_state.genStateBlockHeader(allocator);
    const state_root_from_block_header = state_block_header.state_root;

    // Compare the roots - they should be equal
    try std.testing.expect(std.mem.eql(u8, &genesis_block.state_root, &state_root_from_block_header));
    try std.testing.expect(std.mem.eql(u8, &state_root_from_genesis, &state_root_from_block_header));

    // Verify the state root matches the expected value
    const state_root_from_genesis_hex = try std.fmt.allocPrint(allocator, "0x{s}", .{std.fmt.fmtSliceHexLower(&state_root_from_genesis)});
    defer allocator.free(state_root_from_genesis_hex);
    try std.testing.expectEqualStrings(state_root_from_genesis_hex, "0xdda67dde8a468b0087881f6d8f1cd159ca4c2e82f780156744dc920049515cb1");
}

test "populateNodeNameRegistry" {
    const allocator = std.testing.allocator;

    const validator_config_path = "pkgs/cli/test/fixtures/validator-config.yaml";
    const validators_path = "pkgs/cli/test/fixtures/validators.yaml";

    // Create an empty registry and populate it from test fixtures
    var registry = node_lib.NodeNameRegistry.init(allocator);
    defer registry.deinit();
    try populateNodeNameRegistry(allocator, &registry, validator_config_path, validators_path);

    try std.testing.expectEqual(@as(usize, 9), registry.validator_index_to_name.count());
    try std.testing.expectEqual(@as(usize, 3), registry.peer_id_to_name.count());

    try std.testing.expectEqualStrings("zeam_0", registry.getNodeNameFromValidatorIndex(1).name.?);
    try std.testing.expectEqualStrings("zeam_0", registry.getNodeNameFromValidatorIndex(4).name.?);
    try std.testing.expectEqualStrings("zeam_0", registry.getNodeNameFromValidatorIndex(7).name.?);

    try std.testing.expectEqualStrings("ream_0", registry.getNodeNameFromValidatorIndex(0).name.?);
    try std.testing.expectEqualStrings("ream_0", registry.getNodeNameFromValidatorIndex(3).name.?);
    try std.testing.expectEqualStrings("ream_0", registry.getNodeNameFromValidatorIndex(6).name.?);

    try std.testing.expectEqualStrings("quadrivium_0", registry.getNodeNameFromValidatorIndex(2).name.?);
    try std.testing.expectEqualStrings("quadrivium_0", registry.getNodeNameFromValidatorIndex(5).name.?);
    try std.testing.expectEqualStrings("quadrivium_0", registry.getNodeNameFromValidatorIndex(8).name.?);

    try std.testing.expectEqualStrings("zeam_0", registry.getNodeNameFromPeerId("16Uiu2HAmKgamysJowVqBeftDWr3XBETpmwvjcusbcuai17uWFgLf").name.?);
    try std.testing.expectEqualStrings("ream_0", registry.getNodeNameFromPeerId("16Uiu2HAmSH2XVgZqYHWucap5kuPzLnt2TsNQkoppVxB5eJGvaXwm").name.?);
    try std.testing.expectEqualStrings("quadrivium_0", registry.getNodeNameFromPeerId("16Uiu2HAmQj1RDNAxopeeeCFPRr3zhJYmH6DEPHYKmxLViLahWcFE").name.?);
}

test "checkpoint-sync-url parameter is optional" {
    // Verify that the NodeCommand struct has checkpoint-sync-url as optional
    const node_cmd = NodeCommand{
        .custom_genesis = "test",
        .@"node-id" = "test",
        .validator_config = "test",
        .override_genesis_time = null,
        .@"checkpoint-sync-url" = null, // Should compile and work with null
    };

    try std.testing.expect(node_cmd.@"checkpoint-sync-url" == null);

    const node_cmd_with_url = NodeCommand{
        .custom_genesis = "test",
        .@"node-id" = "test",
        .validator_config = "test",
        .override_genesis_time = null,
        .@"checkpoint-sync-url" = "http://localhost:5052/lean/v0/states/finalized",
    };

    try std.testing.expect(node_cmd_with_url.@"checkpoint-sync-url" != null);
    try std.testing.expectEqualStrings(node_cmd_with_url.@"checkpoint-sync-url".?, "http://localhost:5052/lean/v0/states/finalized");
}

test "NodeOptions checkpoint_sync_url field is optional" {
    // Verify NodeOptions can be created with null checkpoint_sync_url
    const allocator = std.testing.allocator;

    // Create a minimal NodeOptions structure for testing
    var registry = node_lib.NodeNameRegistry.init(allocator);
    defer registry.deinit();

    var logger_config = utils_lib.getLoggerConfig(null, null);

    // Create a minimal genesis spec for testing
    const genesis_spec = types.GenesisSpec{
        .genesis_time = 1000,
        .validator_pubkeys = try allocator.alloc(types.Bytes52, 0),
    };
    defer allocator.free(genesis_spec.validator_pubkeys);

    var node_options = NodeOptions{
        .network_id = 0,
        .node_key = "test",
        .node_key_index = 0,
        .validator_config = "test",
        .bootnodes = &[_][]const u8{},
        .validator_assignments = &[_]ValidatorAssignment{},
        .genesis_spec = genesis_spec,
        .metrics_enable = false,
        .api_port = 5052,
        .local_priv_key = try allocator.dupe(u8, "test"),
        .logger_config = &logger_config,
        .database_path = "test",
        .hash_sig_key_dir = try allocator.dupe(u8, "test"),
        .node_registry = &registry,
        .checkpoint_sync_url = null, // Should work with null
    };
    defer {
        allocator.free(node_options.local_priv_key);
        allocator.free(node_options.hash_sig_key_dir);
    }

    try std.testing.expect(node_options.checkpoint_sync_url == null);

    // Test with a URL
    node_options.checkpoint_sync_url = "http://localhost:5052/lean/v0/states/finalized";
    try std.testing.expect(node_options.checkpoint_sync_url != null);
}
