const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");
const Allocator = std.mem.Allocator;

const KeyManagerError = error{
    ValidatorKeyNotFound,
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
    keys: std.AutoHashMap(usize, xmss.KeyPair),
    allocator: Allocator,
    owns_keypairs: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .keys = std.AutoHashMap(usize, xmss.KeyPair).init(allocator),
            .allocator = allocator,
            .owns_keypairs = true,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owns_keypairs) {
            var it = self.keys.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
        }
        self.keys.deinit();
    }

    pub fn addKeypair(self: *Self, validator_id: usize, keypair: xmss.KeyPair) !void {
        try self.keys.put(validator_id, keypair);
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
        const keypair = self.keys.get(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;
        return try keypair.pubkeyToBytes(buffer);
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
        const keypair = self.keys.get(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;
        return keypair.public_key;
    }

    /// Sign an attestation and return the raw signature handle (for aggregation)
    /// Caller must call deinit on the returned signature when done
    pub fn signAttestationWithHandle(
        self: *const Self,
        attestation: *const types.Attestation,
        allocator: Allocator,
    ) !xmss.Signature {
        const validator_index: usize = @intCast(attestation.validator_id);
        const keypair = self.keys.get(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;

        const signing_timer = zeam_metrics.lean_pq_signature_attestation_signing_time_seconds.start();
        var message: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, attestation.data, &message, allocator);

        const epoch: u32 = @intCast(attestation.data.slot);
        const signature = try keypair.sign(&message, epoch);
        _ = signing_timer.observe();

        return signature;
    }
};

/// Maximum size of a serialized XMSS private key (20MB).
const MAX_SK_SIZE = 1024 * 1024 * 20;

/// Maximum size of a serialized XMSS public key (256 bytes).
const MAX_PK_SIZE = 256;

/// Try to load pre-generated test keys from the test-keys submodule.
///
/// Keys are stored as SSZ-encoded files at test-keys/hash-sig-keys/validator_{i}_sk.ssz
/// and validator_{i}_pk.ssz. Loading from disk is near-instant compared to generating
/// XMSS keys at runtime (which takes minutes for 32 validators).
fn loadPreGeneratedKeys(
    allocator: Allocator,
    num_validators: usize,
) !KeyManager {
    var key_manager = KeyManager.init(allocator);
    errdefer key_manager.deinit();

    for (0..num_validators) |i| {
        // Build file paths
        var sk_path_buf: [256]u8 = undefined;
        const sk_path = std.fmt.bufPrint(&sk_path_buf, "test-keys/hash-sig-keys/validator_{d}_sk.ssz", .{i}) catch unreachable;

        var pk_path_buf: [256]u8 = undefined;
        const pk_path = std.fmt.bufPrint(&pk_path_buf, "test-keys/hash-sig-keys/validator_{d}_pk.ssz", .{i}) catch unreachable;

        // Read private key
        var sk_file = std.fs.cwd().openFile(sk_path, .{}) catch {
            return error.KeyGenerationFailed;
        };
        defer sk_file.close();
        const sk_data = sk_file.readToEndAlloc(allocator, MAX_SK_SIZE) catch {
            return error.KeyGenerationFailed;
        };
        defer allocator.free(sk_data);

        // Read public key
        var pk_file = std.fs.cwd().openFile(pk_path, .{}) catch {
            return error.KeyGenerationFailed;
        };
        defer pk_file.close();
        const pk_data = pk_file.readToEndAlloc(allocator, MAX_PK_SIZE) catch {
            return error.KeyGenerationFailed;
        };
        defer allocator.free(pk_data);

        // Reconstruct keypair from SSZ
        var keypair = xmss.KeyPair.fromSsz(allocator, sk_data, pk_data) catch {
            return error.KeyGenerationFailed;
        };
        errdefer keypair.deinit();

        try key_manager.addKeypair(i, keypair);
    }

    std.debug.print("Loaded {d} pre-generated test keys from test-keys/\n", .{num_validators});
    return key_manager;
}

pub fn getTestKeyManager(
    allocator: Allocator,
    num_validators: usize,
    max_slot: usize,
) !KeyManager {
    // Try loading pre-generated keys first (fast path).
    // Falls back to runtime generation if files don't exist.
    if (num_validators <= 32) {
        if (loadPreGeneratedKeys(allocator, num_validators)) |km| {
            return km;
        } else |_| {
            std.debug.print("Pre-generated keys not found, falling back to runtime generation\n", .{});
        }
    }

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
