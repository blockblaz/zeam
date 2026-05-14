const std = @import("std");
const Allocator = std.mem.Allocator;

const aggregate = @import("aggregation.zig");
pub const MAX_AGGREGATE_SIGNATURE_SIZE = aggregate.MAX_AGGREGATE_SIGNATURE_SIZE;
pub const ByteListMiB = aggregate.ByteListMiB;
pub const AggregationError = aggregate.AggregationError;
pub const setRayonThreads = aggregate.setRayonThreads;
pub const setupProver = aggregate.setupProver;
pub const setupVerifier = aggregate.setupVerifier;
pub const aggregateSignatures = aggregate.aggregateSignatures;
pub const verifyAggregatedPayload = aggregate.verifyAggregatedPayload;
pub const verifyAggregatedPayloadBatch = aggregate.verifyAggregatedPayloadBatch;
pub const AggregatedPayloadVerifyBatch = aggregate.AggregatedPayloadVerifyBatch;
pub const aggregate_module = aggregate;

const hashsig = @import("hashsig.zig");
pub const KeyPair = hashsig.KeyPair;
pub const Signature = hashsig.Signature;
pub const PublicKey = hashsig.PublicKey;
pub const HashSigError = hashsig.HashSigError;
pub const verifySsz = hashsig.verifySsz;
pub const verifySszTest = hashsig.verifySszTest;
pub const HashSigKeyPair = hashsig.HashSigKeyPair;
pub const HashSigSignature = hashsig.HashSigSignature;
pub const HashSigPublicKey = hashsig.HashSigPublicKey;
pub const HashSigPrivateKey = hashsig.HashSigPrivateKey;

/// Lock-free cache for validator public keys, indexed by validator index.
///
/// Each slot is a single `usize` atomic holding `*HashSigPublicKey` (cast
/// to `usize`); 0 is the empty sentinel. Reads are a single atomic load
/// — no mutex on the hot path. Population is lazy: a miss runs
/// `PublicKey.fromBytes` and CAS-installs the handle; lost-race writers
/// free their handle and adopt the winner's.
///
/// Replaces the previous `std.AutoHashMap` + `pubkey_cache_lock` design
/// (P1 of #863). The cache backing is sized to `numValidators()` at
/// chain init; out-of-range indices fall through to a non-cached
/// deserialise. Validator-set growth (post-genesis additions) is not
/// supported here yet — we expect that when leanSpec adds it, the
/// fork-boundary handler will rebuild the cache with the new size.
pub const PublicKeyCache = struct {
    /// One atomic per validator index; stores `@intFromPtr(handle)` or 0.
    slots: []std.atomic.Value(usize),
    allocator: Allocator,

    const Self = @This();
    const EMPTY: usize = 0;

    pub fn init(allocator: Allocator, capacity: usize) !Self {
        const slots = try allocator.alloc(std.atomic.Value(usize), capacity);
        for (slots) |*s| s.* = std.atomic.Value(usize).init(EMPTY);
        return .{ .slots = slots, .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        for (self.slots) |*s| {
            const ptr_int = s.load(.monotonic);
            if (ptr_int != EMPTY) {
                var pk = PublicKey{ .handle = @ptrFromInt(ptr_int) };
                pk.deinit();
            }
        }
        self.allocator.free(self.slots);
    }

    /// Get a cached public key handle, deserialising from bytes on miss
    /// and CAS-installing the result. Returns the raw
    /// `*const HashSigPublicKey` for FFI use.
    ///
    /// Out-of-range indices (validator_index >= capacity) deserialise
    /// each call — slow but correct, never fails because the cache
    /// is undersized.
    pub fn getOrPut(self: *Self, validator_index: usize, pubkey_bytes: []const u8) HashSigError!*const HashSigPublicKey {
        if (validator_index >= self.slots.len) {
            // Slow uncached path. Caller leaks the handle — same shape
            // the old code had on cache-miss; this is rare enough that
            // we accept the leak rather than thread an ownership flag
            // through every caller. The arena-allocator-backed STF
            // path frees its own scratch on completion.
            const pk = try PublicKey.fromBytes(pubkey_bytes);
            return pk.handle;
        }

        const slot = &self.slots[validator_index];
        const existing = slot.load(.acquire);
        if (existing != EMPTY) return @ptrFromInt(existing);

        var pk = try PublicKey.fromBytes(pubkey_bytes);
        const new_int = @intFromPtr(pk.handle);

        if (slot.cmpxchgStrong(EMPTY, new_int, .release, .acquire)) |loser| {
            // Another thread populated this slot first. Free our
            // freshly-deserialised handle and adopt the winner's.
            pk.deinit();
            return @ptrFromInt(loser);
        }
        return pk.handle;
    }

    /// Check if a validator's public key is already cached. Atomic
    /// read; safe to call concurrently with `getOrPut`.
    pub fn contains(self: *const Self, validator_index: usize) bool {
        if (validator_index >= self.slots.len) return false;
        return self.slots[validator_index].load(.monotonic) != EMPTY;
    }

    /// Best-effort count of populated slots. Walks the array atomically
    /// — value can drift under concurrent populations, OK for diagnostics.
    pub fn count(self: *const Self) usize {
        var n: usize = 0;
        for (self.slots) |*s| {
            if (s.load(.monotonic) != EMPTY) n += 1;
        }
        return n;
    }
};

test "get tests" {
    @import("std").testing.refAllDecls(@This());
}

test "PublicKeyCache basic operations" {
    const allocator = std.testing.allocator;

    var cache = try PublicKeyCache.init(allocator, 4);
    defer cache.deinit();

    try std.testing.expect(cache.count() == 0);
    try std.testing.expect(!cache.contains(0));
}

test "PublicKeyCache contains is false for out-of-range index" {
    const allocator = std.testing.allocator;

    var cache = try PublicKeyCache.init(allocator, 4);
    defer cache.deinit();

    try std.testing.expect(!cache.contains(99));
}

test "PublicKeyCache zero-capacity is initialisable and empty" {
    const allocator = std.testing.allocator;

    var cache = try PublicKeyCache.init(allocator, 0);
    defer cache.deinit();

    try std.testing.expect(cache.count() == 0);
    try std.testing.expect(!cache.contains(0));
}
