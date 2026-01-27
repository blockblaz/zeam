const std = @import("std");
const Allocator = std.mem.Allocator;

const aggregate = @import("aggregation.zig");
pub const MAX_AGGREGATE_SIGNATURE_SIZE = aggregate.MAX_AGGREGATE_SIGNATURE_SIZE;
pub const ByteListMiB = aggregate.ByteListMiB;
pub const AggregationError = aggregate.AggregationError;
pub const setupProver = aggregate.setupProver;
pub const setupVerifier = aggregate.setupVerifier;
pub const aggregateSignatures = aggregate.aggregateSignatures;
pub const verifyAggregatedPayload = aggregate.verifyAggregatedPayload;
pub const aggregate_module = aggregate;

const hashsig = @import("hashsig.zig");
pub const KeyPair = hashsig.KeyPair;
pub const Signature = hashsig.Signature;
pub const PublicKey = hashsig.PublicKey;
pub const HashSigError = hashsig.HashSigError;
pub const verifySsz = hashsig.verifySsz;
pub const HashSigKeyPair = hashsig.HashSigKeyPair;
pub const HashSigSignature = hashsig.HashSigSignature;
pub const HashSigPublicKey = hashsig.HashSigPublicKey;
pub const HashSigPrivateKey = hashsig.HashSigPrivateKey;

/// Cache for validator public keys to avoid repeated SSZ deserialization.
/// Maps validator index to the deserialized public key handle.
/// Thread-safety: NOT thread-safe. Use one cache per chain instance.
pub const PublicKeyCache = struct {
    cache: std.AutoHashMap(usize, PublicKey),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .cache = std.AutoHashMap(usize, PublicKey).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all cached public key handles
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            var pk = entry.value_ptr.*;
            pk.deinit();
        }
        self.cache.deinit();
    }

    /// Get a cached public key handle, deserializing from bytes if not cached.
    /// Returns the raw HashSigPublicKey pointer for FFI use.
    pub fn getOrPut(self: *Self, validator_index: usize, pubkey_bytes: []const u8) HashSigError!*const HashSigPublicKey {
        if (self.cache.get(validator_index)) |cached| {
            return cached.handle;
        }

        // Deserialize and cache
        var pubkey = try PublicKey.fromBytes(pubkey_bytes);
        errdefer pubkey.deinit(); // Free the Rust handle if cache.put fails
        try self.cache.put(validator_index, pubkey);

        // Return the handle from the newly cached entry
        return self.cache.get(validator_index).?.handle;
    }

    /// Check if a validator's public key is already cached
    pub fn contains(self: *const Self, validator_index: usize) bool {
        return self.cache.contains(validator_index);
    }

    /// Get the number of cached public keys
    pub fn count(self: *const Self) usize {
        return self.cache.count();
    }
};

test "get tests" {
    @import("std").testing.refAllDeclsRecursive(@This());
}

test "PublicKeyCache basic operations" {
    const allocator = std.testing.allocator;

    var cache = PublicKeyCache.init(allocator);
    defer cache.deinit();

    try std.testing.expect(cache.count() == 0);
    try std.testing.expect(!cache.contains(0));
}
