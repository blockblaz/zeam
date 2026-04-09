const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");
const Allocator = std.mem.Allocator;

const KeyManagerError = error{
    AttestationKeyNotFound,
    ProposalKeyNotFound,
};

pub const ValidatorKeys = struct {
    attestation_keypair: xmss.KeyPair,
    proposal_keypair: xmss.KeyPair,

    pub fn deinit(self: *ValidatorKeys) void {
        self.attestation_keypair.deinit();
        self.proposal_keypair.deinit();
    }
};

const CachedKeyPair = struct {
    attestation_keypair: xmss.KeyPair,
    proposal_keypair: xmss.KeyPair,
    num_active_epochs: usize,
};
var global_test_key_pair_cache: ?std.AutoHashMap(usize, CachedKeyPair) = null;
const cache_allocator = std.heap.page_allocator;

fn getOrCreateCachedKeyPair(
    validator_id: usize,
    num_active_epochs: usize,
) !ValidatorKeys {
    if (global_test_key_pair_cache == null) {
        global_test_key_pair_cache = std.AutoHashMap(usize, CachedKeyPair).init(cache_allocator);
    }
    var cache = &global_test_key_pair_cache.?;

    if (cache.get(validator_id)) |cached| {
        if (cached.num_active_epochs >= num_active_epochs) {
            std.debug.print("CACHE HIT: validator {d}\n", .{validator_id});
            return ValidatorKeys{
                .attestation_keypair = cached.attestation_keypair,
                .proposal_keypair = cached.proposal_keypair,
            };
        }
        // Not enough epochs, remove old key pair and regenerate
        var old = cache.fetchRemove(validator_id).?.value;
        old.attestation_keypair.deinit();
        old.proposal_keypair.deinit();
    }
    std.debug.print("CACHE MISS: generating validator {d}\n", .{validator_id});
    const att_seed = try std.fmt.allocPrint(cache_allocator, "test_validator_{d}_attestation", .{validator_id});
    defer cache_allocator.free(att_seed);

    var attestation_keypair = try xmss.KeyPair.generate(
        cache_allocator,
        att_seed,
        0,
        num_active_epochs,
    );
    errdefer attestation_keypair.deinit();

    const prop_seed = try std.fmt.allocPrint(cache_allocator, "test_validator_{d}_proposal", .{validator_id});
    defer cache_allocator.free(prop_seed);

    const proposal_keypair = try xmss.KeyPair.generate(
        cache_allocator,
        prop_seed,
        0,
        num_active_epochs,
    );

    try cache.put(validator_id, CachedKeyPair{
        .attestation_keypair = attestation_keypair,
        .proposal_keypair = proposal_keypair,
        .num_active_epochs = num_active_epochs,
    });
    return ValidatorKeys{
        .attestation_keypair = attestation_keypair,
        .proposal_keypair = proposal_keypair,
    };
}

pub const KeyManager = struct {
    keys: std.AutoHashMap(usize, ValidatorKeys),
    allocator: Allocator,
    /// Tracks which keypairs are owned (allocated by us) vs borrowed (cached).
    owned_keys: std.AutoHashMap(usize, void),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .keys = std.AutoHashMap(usize, ValidatorKeys).init(allocator),
            .allocator = allocator,
            .owned_keys = std.AutoHashMap(usize, void).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            if (self.owned_keys.contains(entry.key_ptr.*)) {
                entry.value_ptr.deinit();
            }
        }
        self.keys.deinit();
        self.owned_keys.deinit();
    }

    /// Add an owned keypair that will be freed on deinit.
    pub fn addKeypair(self: *Self, validator_id: usize, validator_keys: ValidatorKeys) !void {
        try self.keys.put(validator_id, validator_keys);
        try self.owned_keys.put(validator_id, {});
    }

    /// Add a cached/borrowed keypair that will NOT be freed on deinit.
    pub fn addCachedKeypair(self: *Self, validator_id: usize, validator_keys: ValidatorKeys) !void {
        try self.keys.put(validator_id, validator_keys);
    }

    pub fn loadFromKeypairDir(_: *Self, _: []const u8) !void {
        // Dummy function for now
        return;
    }

    pub fn signAttestation(
        self: *const Self,
        attestation: *const types.Attestation,
        allocator: Allocator,
    ) !types.SIGBYTES {
        var signature = try self.signAttestationWithHandle(attestation, allocator);
        defer signature.deinit();

        var sig_buffer: types.SIGBYTES = undefined;
        const bytes_written = try signature.toBytes(&sig_buffer);

        if (bytes_written < types.SIGSIZE) {
            @memset(sig_buffer[bytes_written..], 0);
        }

        return sig_buffer;
    }

    pub fn getAttestationPubkeyBytes(
        self: *const Self,
        validator_index: usize,
        buffer: []u8,
    ) !usize {
        const validator_keys = self.keys.get(validator_index) orelse return KeyManagerError.AttestationKeyNotFound;
        return try validator_keys.attestation_keypair.pubkeyToBytes(buffer);
    }

    pub fn getProposalPubkeyBytes(
        self: *const Self,
        validator_index: usize,
        buffer: []u8,
    ) !usize {
        const validator_keys = self.keys.get(validator_index) orelse return KeyManagerError.ProposalKeyNotFound;
        return try validator_keys.proposal_keypair.pubkeyToBytes(buffer);
    }

    pub const AllPubkeys = struct {
        attestation_pubkeys: []types.Bytes52,
        proposal_pubkeys: []types.Bytes52,
    };

    /// Extract all validator public keys into dual arrays (attestation + proposal)
    /// Caller owns the returned slices and must free them
    pub fn getAllPubkeys(
        self: *const Self,
        allocator: Allocator,
        num_validators: usize,
    ) !AllPubkeys {
        const att_pubkeys = try allocator.alloc(types.Bytes52, num_validators);
        errdefer allocator.free(att_pubkeys);
        const prop_pubkeys = try allocator.alloc(types.Bytes52, num_validators);
        errdefer allocator.free(prop_pubkeys);

        for (0..num_validators) |i| {
            _ = try self.getAttestationPubkeyBytes(i, &att_pubkeys[i]);
            _ = try self.getProposalPubkeyBytes(i, &prop_pubkeys[i]);
        }

        return AllPubkeys{ .attestation_pubkeys = att_pubkeys, .proposal_pubkeys = prop_pubkeys };
    }

    /// Get the raw attestation public key handle for a validator (for aggregation)
    pub fn getAttestationPubkeyHandle(
        self: *const Self,
        validator_index: usize,
    ) !*const xmss.HashSigPublicKey {
        const validator_keys = self.keys.get(validator_index) orelse return KeyManagerError.AttestationKeyNotFound;
        return validator_keys.attestation_keypair.public_key;
    }

    /// Sign an attestation and return the raw signature handle (for aggregation)
    /// Caller must call deinit on the returned signature when done
    pub fn signAttestationWithHandle(
        self: *const Self,
        attestation: *const types.Attestation,
        allocator: Allocator,
    ) !xmss.Signature {
        zeam_metrics.metrics.lean_pq_sig_attestation_signatures_total.incr();

        const validator_index: usize = @intCast(attestation.validator_id);
        const validator_keys = self.keys.get(validator_index) orelse return KeyManagerError.AttestationKeyNotFound;

        const signing_timer = zeam_metrics.lean_pq_sig_attestation_signing_time_seconds.start();
        var message: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, attestation.data, &message, allocator);

        const epoch: u32 = @intCast(attestation.data.slot);
        const signature = try validator_keys.attestation_keypair.sign(&message, epoch);
        _ = signing_timer.observe();

        return signature;
    }

    pub fn signBlockRoot(
        self: *const Self,
        proposer_index: usize,
        block_root: *const [32]u8,
        slot: u32,
    ) !types.SIGBYTES {
        const validator_keys = self.keys.get(proposer_index) orelse return KeyManagerError.ProposalKeyNotFound;
        var signature = try validator_keys.proposal_keypair.sign(block_root, slot);
        defer signature.deinit();
        var sig_buffer: types.SIGBYTES = undefined;
        const bytes_written = try signature.toBytes(&sig_buffer);
        if (bytes_written < types.SIGSIZE) {
            @memset(sig_buffer[bytes_written..], 0);
        }
        return sig_buffer;
    }
};

/// Maximum size of a serialized XMSS private key (20MB).
pub const MAX_SK_SIZE = 1024 * 1024 * 20;

/// Maximum size of a serialized XMSS public key (256 bytes).
pub const MAX_PK_SIZE = 256;

/// Load an XMSS keypair from SSZ files on disk.
///
/// `sk_path` must point to the secret key SSZ file (`*_sk.ssz`).
/// `pk_path` must point to the public key SSZ file (`*_pk.ssz`).
///
/// Returns a fully initialised `xmss.KeyPair`. The caller owns the keypair
/// and must call `keypair.deinit()` when it is no longer needed.
pub fn loadKeypairFromFiles(
    allocator: Allocator,
    sk_path: []const u8,
    pk_path: []const u8,
) !xmss.KeyPair {
    var sk_file = std.fs.cwd().openFile(sk_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SecretKeyFileNotFound,
        else => return err,
    };
    defer sk_file.close();
    const sk_data = try sk_file.readToEndAlloc(allocator, MAX_SK_SIZE);
    defer allocator.free(sk_data);

    var pk_file = std.fs.cwd().openFile(pk_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.PublicKeyFileNotFound,
        else => return err,
    };
    defer pk_file.close();
    const pk_data = try pk_file.readToEndAlloc(allocator, MAX_PK_SIZE);
    defer allocator.free(pk_data);

    return xmss.KeyPair.fromSsz(allocator, sk_data, pk_data);
}

/// Number of pre-generated test keys available in the test-keys submodule.
const NUM_PREGENERATED_KEYS: usize = 32;

const build_options = @import("build_options");

/// Find the test-keys directory using the repo root path injected by build.zig.
fn findTestKeysDir() ?[]const u8 {
    const keys_path = build_options.test_keys_path;
    if (keys_path.len == 0) return null;

    // Verify it actually exists at runtime
    if (std.fs.cwd().openDir(keys_path, .{})) |dir| {
        var d = dir;
        d.close();
        return keys_path;
    } else |_| {}

    return null;
}

/// Load a ValidatorKeys pair from SSZ files on disk.
/// Reads the key files once and constructs two independent keypairs
/// (attestation + proposal) from the same SSZ bytes.
/// TODO: load separate proposal key files when available.
pub fn loadValidatorKeysFromFiles(
    allocator: Allocator,
    sk_path: []const u8,
    pk_path: []const u8,
) !ValidatorKeys {
    // Read files once
    var sk_file = std.fs.cwd().openFile(sk_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SecretKeyFileNotFound,
        else => return err,
    };
    defer sk_file.close();
    const sk_data = try sk_file.readToEndAlloc(allocator, MAX_SK_SIZE);
    defer allocator.free(sk_data);

    var pk_file = std.fs.cwd().openFile(pk_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.PublicKeyFileNotFound,
        else => return err,
    };
    defer pk_file.close();
    const pk_data = try pk_file.readToEndAlloc(allocator, MAX_PK_SIZE);
    defer allocator.free(pk_data);

    // Construct two independent keypairs from the same bytes
    var att_keypair = try xmss.KeyPair.fromSsz(allocator, sk_data, pk_data);
    errdefer att_keypair.deinit();
    const prop_keypair = try xmss.KeyPair.fromSsz(allocator, sk_data, pk_data);
    return ValidatorKeys{ .attestation_keypair = att_keypair, .proposal_keypair = prop_keypair };
}

fn loadPreGeneratedKey(
    allocator: Allocator,
    keys_dir: []const u8,
    index: usize,
) !ValidatorKeys {
    var sk_path_buf: [512]u8 = undefined;
    const sk_path = std.fmt.bufPrint(&sk_path_buf, "{s}/validator_{d}_sk.ssz", .{ keys_dir, index }) catch unreachable;

    var pk_path_buf: [512]u8 = undefined;
    const pk_path = std.fmt.bufPrint(&pk_path_buf, "{s}/validator_{d}_pk.ssz", .{ keys_dir, index }) catch unreachable;

    return loadValidatorKeysFromFiles(allocator, sk_path, pk_path);
}

pub fn getTestKeyManager(
    allocator: Allocator,
    num_validators: usize,
    max_slot: usize,
) !KeyManager {
    var key_manager = KeyManager.init(allocator);
    errdefer key_manager.deinit();

    // Determine how many keys we can load from pre-generated files
    const keys_dir = findTestKeysDir();
    const num_preloaded = if (keys_dir != null)
        @min(num_validators, NUM_PREGENERATED_KEYS)
    else
        0;

    // Load pre-generated keys (fast path: near-instant from SSZ files)
    var actually_loaded: usize = 0;
    if (keys_dir) |dir| {
        for (0..num_preloaded) |i| {
            const validator_keys = loadPreGeneratedKey(allocator, dir, i) catch |err| {
                std.debug.print("Failed to load pre-generated key {d}: {}\n", .{ i, err });
                break;
            };
            key_manager.addKeypair(i, validator_keys) catch |err| {
                std.debug.print("Failed to add pre-generated key {d}: {}\n", .{ i, err });
                break;
            };
            actually_loaded += 1;
        }
        std.debug.print("Loaded {d} pre-generated test keys from {s}\n", .{ actually_loaded, dir });
    } else {
        std.debug.print("Pre-generated keys not found, generating all keys at runtime\n", .{});
    }

    // Generate remaining keys at runtime (for validators beyond the loaded set)
    if (num_validators > actually_loaded) {
        var num_active_epochs = max_slot + 1;
        if (num_active_epochs < 10) num_active_epochs = 10;

        for (actually_loaded..num_validators) |i| {
            const validator_keys = try getOrCreateCachedKeyPair(i, num_active_epochs);
            try key_manager.addCachedKeypair(i, validator_keys);
        }
        std.debug.print("Generated {d} additional keys at runtime\n", .{num_validators - actually_loaded});
    }

    return key_manager;
}
