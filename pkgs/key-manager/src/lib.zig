const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");
const Allocator = std.mem.Allocator;
const JsonValue = std.json.Value;

pub const XmssTestConfig = struct {
    scheme: xmss.HashSigScheme,
    signature_ssz_len: usize,
    allow_placeholder_aggregated_proof: bool,

    pub fn fromLeanEnv(lean_env: ?[]const u8) XmssTestConfig {
        const scheme = schemeFromLeanEnv(lean_env);
        return .{
            .scheme = scheme,
            .signature_ssz_len = xmss.signatureSszLenForScheme(scheme),
            .allow_placeholder_aggregated_proof = scheme == .@"test",
        };
    }
};

pub const FixtureKeyError = error{
    DuplicateKeyIndex,
    InvalidKeyFile,
    InvalidKeyIndex,
    InvalidPublicKey,
    NoKeysFound,
};

fn schemeFromLeanEnv(lean_env: ?[]const u8) xmss.HashSigScheme {
    const env = lean_env orelse return .prod;
    if (std.ascii.eqlIgnoreCase(env, "test")) return .@"test";
    return .prod;
}

fn parseKeyIndex(file_name: []const u8) !usize {
    if (!std.mem.endsWith(u8, file_name, ".json")) {
        return FixtureKeyError.InvalidKeyIndex;
    }
    const stem = file_name[0 .. file_name.len - ".json".len];
    if (stem.len == 0) {
        return FixtureKeyError.InvalidKeyIndex;
    }
    return std.fmt.parseInt(usize, stem, 10) catch FixtureKeyError.InvalidKeyIndex;
}

const fixture_key_file_max_bytes: usize = 2 * 1024 * 1024;

fn readPublicKeyFromJson(
    allocator: Allocator,
    dir: std.fs.Dir,
    file_name: []const u8,
) !types.Bytes52 {
    const payload = dir.readFileAlloc(allocator, file_name, fixture_key_file_max_bytes) catch {
        return FixtureKeyError.InvalidKeyFile;
    };
    defer allocator.free(payload);

    var parsed = std.json.parseFromSlice(JsonValue, allocator, payload, .{ .ignore_unknown_fields = true }) catch {
        return FixtureKeyError.InvalidKeyFile;
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |map| map,
        else => return FixtureKeyError.InvalidKeyFile,
    };
    const pub_val = obj.get("public") orelse return FixtureKeyError.InvalidKeyFile;
    const pub_hex = switch (pub_val) {
        .string => |s| s,
        else => return FixtureKeyError.InvalidKeyFile,
    };

    return parsePublicKeyHex(pub_hex);
}

fn parsePublicKeyHex(input: []const u8) !types.Bytes52 {
    const public_key_hex_len: usize = 2 * @sizeOf(types.Bytes52);
    const hex_str = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    if (hex_str.len != public_key_hex_len) {
        return FixtureKeyError.InvalidPublicKey;
    }
    var bytes: types.Bytes52 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex_str) catch {
        return FixtureKeyError.InvalidPublicKey;
    };
    return bytes;
}

const KeyManagerError = error{
    ValidatorKeyNotFound,
    PrivateKeyMissing,
    PublicKeyBufferTooSmall,
};

const PublicKeyEntry = struct {
    bytes: types.Bytes52,
    public_key: xmss.PublicKey,
};

const KeyEntry = union(enum) {
    keypair: xmss.KeyPair,
    public_key: PublicKeyEntry,
};

const CachedKeyPair = struct {
    keypair: xmss.KeyPair,
    num_active_epochs: usize,
};
var global_test_key_pair_cache: ?std.AutoHashMap(usize, CachedKeyPair) = null;
const cache_allocator = std.heap.page_allocator;

fn getOrCreateCachedKeyPair(
    validator_id: usize,
    num_active_epochs: usize,
) !xmss.KeyPair {
    if (global_test_key_pair_cache == null) {
        global_test_key_pair_cache = std.AutoHashMap(usize, CachedKeyPair).init(cache_allocator);
    }
    var cache = &global_test_key_pair_cache.?;

    if (cache.get(validator_id)) |cached| {
        if (cached.num_active_epochs >= num_active_epochs) {
            std.debug.print("CACHE HIT: validator {d}\n", .{validator_id});
            return cached.keypair;
        }
        // Not enough epochs, remove old key pair and regenerate
        var old = cache.fetchRemove(validator_id).?.value;
        old.keypair.deinit();
    }
    std.debug.print("CACHE MISS: generating validator {d}\n", .{validator_id});
    const seed = try std.fmt.allocPrint(cache_allocator, "test_validator_{d}", .{validator_id});
    defer cache_allocator.free(seed);

    const keypair = try xmss.KeyPair.generate(
        cache_allocator,
        seed,
        0,
        num_active_epochs,
    );

    try cache.put(validator_id, CachedKeyPair{
        .keypair = keypair,
        .num_active_epochs = num_active_epochs,
    });
    return keypair;
}

pub const KeyManager = struct {
    keys: std.AutoHashMap(usize, KeyEntry),
    allocator: Allocator,
    owns_keypairs: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .keys = std.AutoHashMap(usize, KeyEntry).init(allocator),
            .allocator = allocator,
            .owns_keypairs = true,
        };
    }

    pub fn deinit(self: *Self) void {
        self.clearEntries();
        self.keys.deinit();
    }

    pub fn addKeypair(self: *Self, validator_id: usize, keypair: xmss.KeyPair) !void {
        if (self.keys.getPtr(validator_id)) |entry| {
            self.deinitEntry(entry);
            entry.* = .{ .keypair = keypair };
            return;
        }
        try self.keys.put(validator_id, .{ .keypair = keypair });
    }

    pub fn addPublicKey(self: *Self, validator_id: usize, pubkey_bytes: types.Bytes52) !void {
        var public_key = try xmss.PublicKey.fromBytes(pubkey_bytes[0..]);
        errdefer public_key.deinit();

        const entry_value = PublicKeyEntry{ .bytes = pubkey_bytes, .public_key = public_key };
        if (self.keys.getPtr(validator_id)) |entry| {
            self.deinitEntry(entry);
            entry.* = .{ .public_key = entry_value };
            return;
        }
        try self.keys.put(validator_id, .{ .public_key = entry_value });
    }

    pub fn loadLeanSpecKeys(self: *Self, keys_root: []const u8, lean_env: ?[]const u8) !void {
        const scheme_dir_name = switch (schemeFromLeanEnv(lean_env)) {
            .@"test" => "test_scheme",
            .prod => "prod_scheme",
        };
        const scheme_dir_path = try std.fs.path.join(self.allocator, &.{ keys_root, scheme_dir_name });
        defer self.allocator.free(scheme_dir_path);
        try self.loadKeysFromDir(scheme_dir_path);
    }

    pub fn loadKeysFromDir(self: *Self, keys_dir_path: []const u8) !void {
        var dir = try std.fs.cwd().openDir(keys_dir_path, .{ .iterate = true });
        defer dir.close();

        self.clearEntries();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            const index = parseKeyIndex(entry.name) catch continue;
            const pubkey = try readPublicKeyFromJson(self.allocator, dir, entry.name);
            if (self.keys.get(index) != null) {
                return FixtureKeyError.DuplicateKeyIndex;
            }
            self.addPublicKey(index, pubkey) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return FixtureKeyError.InvalidPublicKey,
            };
        }

        if (self.keys.count() == 0) {
            return FixtureKeyError.NoKeysFound;
        }
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

    pub fn getPublicKeyBytes(
        self: *const Self,
        validator_index: usize,
        buffer: []u8,
    ) !usize {
        const entry = self.keys.getPtr(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;
        return switch (entry.*) {
            .keypair => |keypair| try keypair.pubkeyToBytes(buffer),
            .public_key => |pubkey| blk: {
                if (buffer.len < pubkey.bytes.len) {
                    return KeyManagerError.PublicKeyBufferTooSmall;
                }
                @memcpy(buffer[0..pubkey.bytes.len], pubkey.bytes[0..]);
                break :blk pubkey.bytes.len;
            },
        };
    }

    /// Extract all validator public keys into an array
    /// Caller owns the returned slice and must free it
    pub fn getAllPubkeys(
        self: *const Self,
        allocator: Allocator,
        num_validators: usize,
    ) ![]types.Bytes52 {
        const pubkeys = try allocator.alloc(types.Bytes52, num_validators);
        errdefer allocator.free(pubkeys);

        // XMSS public keys are always exactly 52 bytes
        for (0..num_validators) |i| {
            _ = try self.getPublicKeyBytes(i, &pubkeys[i]);
        }

        return pubkeys;
    }

    /// Get the raw public key handle for a validator (for aggregation)
    pub fn getPublicKeyHandle(
        self: *const Self,
        validator_index: usize,
    ) !*const xmss.HashSigPublicKey {
        const entry = self.keys.getPtr(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;
        return switch (entry.*) {
            .keypair => |keypair| keypair.public_key,
            .public_key => |pubkey| pubkey.public_key.handle,
        };
    }

    /// Sign an attestation and return the raw signature handle (for aggregation)
    /// Caller must call deinit on the returned signature when done
    pub fn signAttestationWithHandle(
        self: *const Self,
        attestation: *const types.Attestation,
        allocator: Allocator,
    ) !xmss.Signature {
        const validator_index: usize = @intCast(attestation.validator_id);
        const entry = self.keys.getPtr(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;
        const keypair = switch (entry.*) {
            .keypair => |*kp| kp,
            .public_key => return KeyManagerError.PrivateKeyMissing,
        };

        const signing_timer = zeam_metrics.lean_pq_signature_attestation_signing_time_seconds.start();
        var message: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, attestation.data, &message, allocator);

        const epoch: u32 = @intCast(attestation.data.slot);
        const signature = try keypair.sign(&message, epoch);
        _ = signing_timer.observe();

        return signature;
    }

    fn clearEntries(self: *Self) void {
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            self.deinitEntry(entry.value_ptr);
        }
        self.keys.clearRetainingCapacity();
    }

    fn deinitEntry(self: *Self, entry: *KeyEntry) void {
        switch (entry.*) {
            .keypair => |*keypair| {
                if (self.owns_keypairs) {
                    keypair.deinit();
                }
            },
            .public_key => |*pubkey| pubkey.public_key.deinit(),
        }
    }
};

pub fn getTestKeyManager(
    allocator: Allocator,
    num_validators: usize,
    max_slot: usize,
) !KeyManager {
    var key_manager = KeyManager.init(allocator);
    key_manager.owns_keypairs = false;
    errdefer key_manager.deinit();

    var num_active_epochs = max_slot + 1;
    // to reuse cached keypairs, gen for 10 since most tests ask for < 10 max slot including
    // building mock chain for tests. otherwise getOrCreateCachedKeyPair might cleanup previous
    //  key generated for smaller life time
    if (num_active_epochs < 10) num_active_epochs = 10;

    for (0..num_validators) |i| {
        const keypair = try getOrCreateCachedKeyPair(i, num_active_epochs);
        try key_manager.addKeypair(i, keypair);
    }

    return key_manager;
}
