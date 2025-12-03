const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const Allocator = std.mem.Allocator;

const KeyManagerError = error{
    ValidatorKeyNotFound,
    SignatureMismatch,
};

const CachedKeyPair = struct {
    keypair: xmss.KeyPair,
    num_active_epochs: usize,
};
var global_test_key_pair_cache: ?std.AutoHashMap(usize, CachedKeyPair) = null;
var cache_mutex: std.Thread.Mutex = .{};
const cache_allocator = std.heap.page_allocator;

fn getOrCreateCachedKeyPair(
    validator_id: usize,
    num_active_epochs: usize,
) !xmss.KeyPair {
    cache_mutex.lock();
    defer cache_mutex.unlock();

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
        const validator_index: usize = @intCast(attestation.validator_id);

        const keypair = self.keys.get(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;

        var message: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.Attestation, attestation.*, &message, allocator);

        const epoch: u32 = @intCast(attestation.data.slot);
        var signature = try keypair.sign(&message, epoch);
        defer signature.deinit();

        var sig_buffer: types.SIGBYTES = undefined;
        const bytes_written = try signature.toBytes(&sig_buffer);

        std.debug.print("[SIGN-DEBUG] Signature serialized: bytes_written={d}, SIGSIZE={d}\n", .{ bytes_written, types.SIGSIZE });

        if (bytes_written < types.SIGSIZE) {
            std.debug.print("[SIGN-DEBUG] Zero-padding {d} bytes\n", .{types.SIGSIZE - bytes_written});
            @memset(sig_buffer[bytes_written..], 0);
        } else if (bytes_written > types.SIGSIZE) {
            std.debug.print("[SIGN-DEBUG] ERROR: Signature too large! bytes_written={d} > SIGSIZE={d}\n", .{ bytes_written, types.SIGSIZE });
            return KeyManagerError.SignatureMismatch;
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
    // For tests, use minimum of 256 epochs (sufficient for test scenarios)
    // This balances key generation time with test coverage
    if (num_active_epochs < 256) num_active_epochs = 256;

    // Parallelize key generation for multiple validators
    if (num_validators > 1) {
        // Create threads for parallel key generation
        const KeyGenContext = struct {
            validator_id: usize,
            num_active_epochs: usize,
            result: ?xmss.KeyPair = null,
            err: ?anyerror = null,
        };

        var contexts = try allocator.alloc(KeyGenContext, num_validators);
        defer allocator.free(contexts);

        for (contexts, 0..) |*ctx, i| {
            ctx.* = KeyGenContext{
                .validator_id = i,
                .num_active_epochs = num_active_epochs,
            };
        }

        const threads = try allocator.alloc(std.Thread, num_validators);
        defer allocator.free(threads);

        // Spawn threads for parallel key generation
        for (threads, 0..) |*thread, i| {
            thread.* = try std.Thread.spawn(.{}, struct {
                fn run(ctx: *KeyGenContext) void {
                    ctx.result = getOrCreateCachedKeyPair(ctx.validator_id, ctx.num_active_epochs) catch |err| {
                        ctx.err = err;
                        return;
                    };
                }
            }.run, .{&contexts[i]});
        }

        // Wait for all threads to complete
        for (threads) |thread| {
            thread.join();
        }

        // Collect results and check for errors
        for (contexts) |ctx| {
            if (ctx.err) |err| {
                return err;
            }
            if (ctx.result) |keypair| {
                try key_manager.addKeypair(ctx.validator_id, keypair);
            } else {
                return error.KeyGenerationFailed;
            }
        }
    } else {
        // Single validator - no need for parallelization
        for (0..num_validators) |i| {
            const keypair = try getOrCreateCachedKeyPair(i, num_active_epochs);
            try key_manager.addKeypair(i, keypair);
        }
    }

    return key_manager;
}
