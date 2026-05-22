const std = @import("std");
const Allocator = std.mem.Allocator;

const aggregate = @import("aggregation.zig");
pub const MAX_AGGREGATE_PROOF_SIZE = aggregate.MAX_AGGREGATE_PROOF_SIZE;
pub const ByteList512KiB = aggregate.ByteList512KiB;
pub const MessageBinding = aggregate.MessageBinding;
pub const AggregationError = aggregate.AggregationError;
pub const setRayonThreads = aggregate.setRayonThreads;
pub const setupProver = aggregate.setupProver;
pub const setupVerifier = aggregate.setupVerifier;
pub const aggregateType1 = aggregate.aggregateType1;
pub const verifyType1 = aggregate.verifyType1;
pub const mergeType1ToType2 = aggregate.mergeType1ToType2;
pub const splitType2ByMessage = aggregate.splitType2ByMessage;
pub const verifyType2 = aggregate.verifyType2;
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
    /// `*const HashSigPublicKey` for FFI use; the cache retains
    /// ownership of the handle for its full lifetime.
    ///
    /// Returns `HashSigError.ValidatorIndexOutOfRange` when
    /// `validator_index >= capacity`. The cache is sized at
    /// `BeamChain.init` from `genesis.numValidators()`; lean spec does
    /// not currently grow the validator set after genesis. If/when
    /// post-genesis growth lands, the fork-boundary handler must
    /// rebuild the cache with the new size — until then we fail loudly
    /// rather than fall back to a leaky uncached deserialise (PR #884
    /// review by @zclawz).
    pub fn getOrPut(self: *Self, validator_index: usize, pubkey_bytes: []const u8) HashSigError!*const HashSigPublicKey {
        if (validator_index >= self.slots.len) {
            return HashSigError.ValidatorIndexOutOfRange;
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

test "PublicKeyCache getOrPut populates on miss and returns same handle on hit" {
    const allocator = std.testing.allocator;

    // Generate one real keypair so we have valid SSZ pubkey bytes.
    var keypair = try KeyPair.generate(allocator, "cache_test_seed", 0, 2);
    defer keypair.deinit();

    var pk_buf: [256]u8 = undefined;
    const pk_len = try keypair.pubkeyToBytes(&pk_buf);
    const pk_bytes = pk_buf[0..pk_len];

    var cache = try PublicKeyCache.init(allocator, 4);
    defer cache.deinit();

    try std.testing.expect(!cache.contains(2));
    const first = try cache.getOrPut(2, pk_bytes);
    try std.testing.expect(cache.contains(2));
    try std.testing.expect(cache.count() == 1);

    // Second lookup must return the SAME handle pointer — the
    // population path is invoked at most once per slot.
    const second = try cache.getOrPut(2, pk_bytes);
    try std.testing.expectEqual(first, second);
    try std.testing.expect(cache.count() == 1);
}

test "PublicKeyCache getOrPut returns ValidatorIndexOutOfRange past capacity" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "oor_test_seed", 0, 2);
    defer keypair.deinit();
    var pk_buf: [256]u8 = undefined;
    const pk_len = try keypair.pubkeyToBytes(&pk_buf);
    const pk_bytes = pk_buf[0..pk_len];

    var cache = try PublicKeyCache.init(allocator, 3);
    defer cache.deinit();

    try std.testing.expectError(
        HashSigError.ValidatorIndexOutOfRange,
        cache.getOrPut(3, pk_bytes),
    );
    try std.testing.expectError(
        HashSigError.ValidatorIndexOutOfRange,
        cache.getOrPut(99, pk_bytes),
    );
}

test "PublicKeyCache concurrent getOrPut for same slot installs exactly one handle" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "cas_test_seed", 0, 2);
    defer keypair.deinit();
    var pk_buf: [256]u8 = undefined;
    const pk_len = try keypair.pubkeyToBytes(&pk_buf);
    const pk_bytes = pk_buf[0..pk_len];

    var cache = try PublicKeyCache.init(allocator, 8);
    // No defer deinit yet — we want to inspect post-race state first;
    // freed at the end after the assertions.

    const NUM_THREADS = 8;
    const SLOT: usize = 4;

    const Worker = struct {
        fn run(c: *PublicKeyCache, idx: usize, bytes: []const u8, out: *?*const HashSigPublicKey) void {
            out.* = c.getOrPut(idx, bytes) catch null;
        }
    };

    var threads: [NUM_THREADS]std.Thread = undefined;
    var results: [NUM_THREADS]?*const HashSigPublicKey = .{null} ** NUM_THREADS;

    for (0..NUM_THREADS) |i| {
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ &cache, SLOT, pk_bytes, &results[i] });
    }
    for (&threads) |*t| t.join();

    // All threads must observe the SAME winning handle. The cache
    // slot's atomic load is the single source of truth post-race.
    const winner = results[0] orelse return error.TestUnexpectedResult;
    for (results) |r| {
        try std.testing.expectEqual(winner, r orelse return error.TestUnexpectedResult);
    }
    try std.testing.expect(cache.count() == 1);

    // Sanity: the installed handle must round-trip via the slot's
    // atomic load (i.e. it really is in the cache, not a leaked
    // loser that some thread is still holding).
    const post = try cache.getOrPut(SLOT, pk_bytes);
    try std.testing.expectEqual(winner, post);

    // deinit frees the installed handle exactly once. If the CAS
    // protocol leaked a loser's handle the testing allocator would
    // surface it on process exit; the contract here is that
    // PublicKeyCache.deinit suffices to release every handle the
    // cache ever held.
    cache.deinit();
}
