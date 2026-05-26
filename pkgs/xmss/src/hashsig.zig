const std = @import("std");
const Allocator = std.mem.Allocator;

pub const aggregate = @import("aggregation.zig");

// Opaque Zig types that map to the corresponding Rust structs.
// Zig never looks inside these; sizes come from the hashsig_sizeof_* queries.
pub const HashSigKeyPair = opaque {};
pub const HashSigSignature = opaque {};
pub const HashSigPublicKey = opaque {};
pub const HashSigPrivateKey = opaque {};

// ─── Layout queries ────────────────────────────────────────────────────────────
// Rust exports these so Zig can pre-allocate the right amount of space.
// Call once at startup (or comptime-cache them); values are stable for the
// lifetime of a given Rust build.

extern fn hashsig_sizeof_keypair() callconv(.c) usize;
extern fn hashsig_alignof_keypair() callconv(.c) usize;
extern fn hashsig_sizeof_signature() callconv(.c) usize;
extern fn hashsig_alignof_signature() callconv(.c) usize;
extern fn hashsig_sizeof_public_key() callconv(.c) usize;
extern fn hashsig_alignof_public_key() callconv(.c) usize;

// ─── Placement-init (no Rust Box allocation) ──────────────────────────────────
// Each `_into` function writes a fully-initialised struct into caller-supplied
// storage (allocated by Zig/C malloc, which always satisfies Rust's alignment).
// The matching `_deinit` runs Rust Drop in-place WITHOUT freeing the buffer;
// the caller owns the buffer and must free it afterwards.

extern fn hashsig_keypair_generate_into(
    out: *HashSigKeyPair,
    seed_phrase: [*:0]const u8,
    activation_epoch: usize,
    num_active_epochs: usize,
) callconv(.c) c_int;

extern fn hashsig_keypair_from_ssz_into(
    out: *HashSigKeyPair,
    private_key_ssz: [*]const u8,
    private_key_len: usize,
    public_key_ssz: [*]const u8,
    public_key_len: usize,
) callconv(.c) c_int;

/// Destroy the KeyPair in-place (runs Rust Drop). Does NOT free the buffer.
extern fn hashsig_keypair_deinit(kp: *HashSigKeyPair) callconv(.c) void;

extern fn hashsig_sign_into(
    out: *HashSigSignature,
    private_key: *const HashSigPrivateKey,
    message_ptr: [*]const u8,
    epoch: u32,
) callconv(.c) c_int;

/// Destroy the Signature in-place. Does NOT free the buffer.
extern fn hashsig_signature_deinit(sig: *HashSigSignature) callconv(.c) void;

extern fn hashsig_signature_from_ssz_into(
    out: *HashSigSignature,
    sig_bytes: [*]const u8,
    sig_len: usize,
) callconv(.c) c_int;

extern fn hashsig_public_key_from_ssz_into(
    out: *HashSigPublicKey,
    pubkey_bytes: [*]const u8,
    pubkey_len: usize,
) callconv(.c) c_int;

/// Destroy the PublicKey in-place. Does NOT free the buffer.
extern fn hashsig_public_key_deinit(pk: *HashSigPublicKey) callconv(.c) void;

// ─── Accessor / sub-key views ─────────────────────────────────────────────────
// These return pointers INTO the caller-owned KeyPair buffer.  Valid for the
// lifetime of that buffer.

extern fn hashsig_keypair_get_public_key(keypair: *const HashSigKeyPair) callconv(.c) ?*const HashSigPublicKey;
extern fn hashsig_keypair_get_private_key(keypair: *const HashSigKeyPair) callconv(.c) ?*const HashSigPrivateKey;

// ─── Serialisation (caller-supplies-output, unchanged) ────────────────────────

extern fn hashsig_public_key_to_bytes(
    public_key: *const HashSigPublicKey,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.c) usize;

extern fn hashsig_private_key_to_bytes(
    private_key: *const HashSigPrivateKey,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.c) usize;

extern fn hashsig_signature_to_bytes(
    signature: *const HashSigSignature,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.c) usize;

// ─── Verify ───────────────────────────────────────────────────────────────────

extern fn hashsig_verify(
    public_key: *const HashSigPublicKey,
    message_ptr: [*]const u8,
    epoch: u32,
    signature: *const HashSigSignature,
) callconv(.c) i32;

extern fn hashsig_verify_ssz(
    pubkey_bytes: [*]const u8,
    pubkey_len: usize,
    message: [*]const u8,
    epoch: u32,
    signature_bytes: [*]const u8,
    signature_len: usize,
) callconv(.c) i32;

extern fn hashsig_test_verify_ssz(
    pubkey_bytes: [*]const u8,
    pubkey_len: usize,
    message: [*]const u8,
    epoch: u32,
    signature_bytes: [*]const u8,
    signature_len: usize,
) callconv(.c) i32;

extern fn hashsig_message_length() callconv(.c) usize;

// ─── Error set ────────────────────────────────────────────────────────────────

pub const HashSigError = error{
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    InvalidSignature,
    SerializationFailed,
    InvalidMessageLength,
    DeserializationFailed,
    OutOfMemory,
    ValidatorIndexOutOfRange,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Allocate `sz` bytes from the C heap (malloc).  C malloc always returns
/// memory aligned to at least max_align_t (≥8 bytes on LP64), which satisfies
/// the alignment of any Rust `#[repr(C)]` type used in hashsig-glue.
fn cAlloc(sz: usize) HashSigError![*]u8 {
    const raw = std.c.malloc(sz) orelse return HashSigError.OutOfMemory;
    return @ptrCast(raw);
}

fn cFree(ptr: [*]u8) void {
    std.c.free(@ptrCast(ptr));
}

// ─── Byte-level verify helpers ────────────────────────────────────────────────

/// Verify signature using SSZ-encoded bytes (no object allocation).
pub fn verifySsz(
    pubkey_bytes: []const u8,
    message: []const u8,
    epoch: u32,
    signature_bytes: []const u8,
) HashSigError!void {
    if (message.len != 32) return HashSigError.InvalidMessageLength;
    switch (hashsig_verify_ssz(
        pubkey_bytes.ptr,
        pubkey_bytes.len,
        message.ptr,
        epoch,
        signature_bytes.ptr,
        signature_bytes.len,
    )) {
        1 => {},
        0 => return HashSigError.VerificationFailed,
        -1 => return HashSigError.InvalidSignature,
        else => return HashSigError.VerificationFailed,
    }
}

/// Verify signature against the leanSpec test scheme (LOG_LIFETIME=8).
pub fn verifySszTest(
    pubkey_bytes: []const u8,
    message: []const u8,
    epoch: u32,
    signature_bytes: []const u8,
) HashSigError!void {
    if (message.len != 32) return HashSigError.InvalidMessageLength;
    switch (hashsig_test_verify_ssz(
        pubkey_bytes.ptr,
        pubkey_bytes.len,
        message.ptr,
        epoch,
        signature_bytes.ptr,
        signature_bytes.len,
    )) {
        1 => {},
        0 => return HashSigError.VerificationFailed,
        -1 => return HashSigError.InvalidSignature,
        else => return HashSigError.VerificationFailed,
    }
}

// ─── KeyPair ─────────────────────────────────────────────────────────────────

/// Wrapper for the XMSS key pair.
///
/// The Rust `KeyPair` struct lives in a C-heap buffer owned by this wrapper;
/// Rust never Box-allocates it.  `deinit` runs Rust Drop in-place then frees
/// the buffer.
pub const KeyPair = struct {
    /// C-heap buffer holding the Rust KeyPair struct.
    _buf: [*]u8,
    /// Pointer into `_buf` for the embedded public key.
    public_key: *const HashSigPublicKey,
    /// Pointer into `_buf` for the embedded private key.
    private_key: *const HashSigPrivateKey,
    /// Zig allocator used for ephemeral work (e.g. null-terminated seed string).
    allocator: Allocator,

    const Self = @This();

    /// Generate a new key pair.
    pub fn generate(
        allocator: Allocator,
        seed_phrase: []const u8,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) HashSigError!Self {
        const buf = try cAlloc(hashsig_sizeof_keypair());
        errdefer cFree(buf);

        const kp: *HashSigKeyPair = @ptrCast(buf);

        const c_seed = allocator.dupeZ(u8, seed_phrase) catch return HashSigError.OutOfMemory;
        defer allocator.free(c_seed);

        if (hashsig_keypair_generate_into(kp, c_seed.ptr, activation_epoch, num_active_epochs) != 0)
            return HashSigError.KeyGenerationFailed;

        const public_key = hashsig_keypair_get_public_key(kp) orelse {
            hashsig_keypair_deinit(kp);
            return HashSigError.KeyGenerationFailed;
        };
        const private_key = hashsig_keypair_get_private_key(kp) orelse {
            hashsig_keypair_deinit(kp);
            return HashSigError.KeyGenerationFailed;
        };

        return Self{
            ._buf = buf,
            .public_key = public_key,
            .private_key = private_key,
            .allocator = allocator,
        };
    }

    /// Reconstruct a key pair from SSZ-encoded bytes.
    pub fn fromSsz(
        allocator: Allocator,
        private_key_ssz: []const u8,
        public_key_ssz: []const u8,
    ) HashSigError!Self {
        if (private_key_ssz.len == 0 or public_key_ssz.len == 0)
            return HashSigError.DeserializationFailed;

        const buf = try cAlloc(hashsig_sizeof_keypair());
        errdefer cFree(buf);

        const kp: *HashSigKeyPair = @ptrCast(buf);

        if (hashsig_keypair_from_ssz_into(
            kp,
            private_key_ssz.ptr,
            private_key_ssz.len,
            public_key_ssz.ptr,
            public_key_ssz.len,
        ) != 0) return HashSigError.DeserializationFailed;

        const public_key = hashsig_keypair_get_public_key(kp) orelse {
            hashsig_keypair_deinit(kp);
            return HashSigError.DeserializationFailed;
        };
        const private_key = hashsig_keypair_get_private_key(kp) orelse {
            hashsig_keypair_deinit(kp);
            return HashSigError.DeserializationFailed;
        };

        return Self{
            ._buf = buf,
            .public_key = public_key,
            .private_key = private_key,
            .allocator = allocator,
        };
    }

    /// Sign a message.  Caller owns the returned `Signature` and must call
    /// `Signature.deinit` when done.
    pub fn sign(self: *const Self, message: []const u8, epoch: u32) HashSigError!Signature {
        if (message.len != hashsig_message_length()) return HashSigError.InvalidMessageLength;
        return Signature.fromPrivKey(self.private_key, message, epoch);
    }

    /// Verify a signature.
    pub fn verify(self: *const Self, message: []const u8, signature: *const Signature, epoch: u32) HashSigError!void {
        if (message.len != hashsig_message_length()) return HashSigError.InvalidMessageLength;
        switch (hashsig_verify(self.public_key, message.ptr, epoch, signature.handle)) {
            1 => {},
            else => return HashSigError.VerificationFailed,
        }
    }

    /// Get the required message length.
    pub fn messageLength() usize {
        return hashsig_message_length();
    }

    /// Serialize the public key to SSZ bytes.
    pub fn pubkeyToBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const n = hashsig_public_key_to_bytes(self.public_key, buffer.ptr, buffer.len);
        if (n == 0) return HashSigError.SerializationFailed;
        return n;
    }

    /// Serialize the private key to SSZ bytes.
    pub fn privkeyToBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const n = hashsig_private_key_to_bytes(self.private_key, buffer.ptr, buffer.len);
        if (n == 0) return HashSigError.SerializationFailed;
        return n;
    }

    /// Destroy the key pair and free its storage.
    pub fn deinit(self: *Self) void {
        hashsig_keypair_deinit(@ptrCast(self._buf));
        cFree(self._buf);
    }
};

// ─── Signature ───────────────────────────────────────────────────────────────

/// Wrapper for an XMSS signature.
///
/// The Rust `Signature` struct lives in a C-heap buffer owned by this wrapper.
/// `handle` is an opaque pointer into that buffer, used for FFI calls.
pub const Signature = struct {
    /// C-heap buffer holding the Rust Signature struct.
    _buf: [*]u8,
    /// Opaque FFI view of the struct for use in verify / aggregate calls.
    handle: *HashSigSignature,

    const Self = @This();

    /// Sign with a private key; returns a Signature owning its own storage.
    /// Internal helper used by `KeyPair.sign`.
    fn fromPrivKey(private_key: *const HashSigPrivateKey, message: []const u8, epoch: u32) HashSigError!Self {
        const buf = try cAlloc(hashsig_sizeof_signature());
        errdefer cFree(buf);

        const sig: *HashSigSignature = @ptrCast(buf);

        if (hashsig_sign_into(sig, private_key, message.ptr, epoch) != 0)
            return HashSigError.SigningFailed;

        return Self{ ._buf = buf, .handle = sig };
    }

    /// Deserialize a Signature from SSZ bytes.
    pub fn fromBytes(bytes: []const u8) HashSigError!Self {
        if (bytes.len == 0) return HashSigError.DeserializationFailed;

        const buf = try cAlloc(hashsig_sizeof_signature());
        errdefer cFree(buf);

        const sig: *HashSigSignature = @ptrCast(buf);

        if (hashsig_signature_from_ssz_into(sig, bytes.ptr, bytes.len) != 0)
            return HashSigError.DeserializationFailed;

        return Self{ ._buf = buf, .handle = sig };
    }

    /// Serialize the signature to SSZ bytes.
    pub fn toBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const n = hashsig_signature_to_bytes(self.handle, buffer.ptr, buffer.len);
        if (n == 0) return HashSigError.SerializationFailed;
        return n;
    }

    /// Destroy the signature and free its storage.
    pub fn deinit(self: *Self) void {
        hashsig_signature_deinit(self.handle);
        cFree(self._buf);
    }
};

// ─── PublicKey ────────────────────────────────────────────────────────────────

/// Wrapper for a standalone XMSS public key (e.g. deserialized for cache use).
///
/// `handle` is an opaque pointer into the C-heap buffer for FFI calls.
pub const PublicKey = struct {
    /// C-heap buffer holding the Rust PublicKey struct.
    _buf: [*]u8,
    /// Opaque FFI view of the struct.
    handle: *HashSigPublicKey,

    const Self = @This();

    /// Deserialize a public key from SSZ bytes.
    pub fn fromBytes(bytes: []const u8) HashSigError!Self {
        if (bytes.len == 0) return HashSigError.DeserializationFailed;

        const buf = try cAlloc(hashsig_sizeof_public_key());
        errdefer cFree(buf);

        const pk: *HashSigPublicKey = @ptrCast(buf);

        if (hashsig_public_key_from_ssz_into(pk, bytes.ptr, bytes.len) != 0)
            return HashSigError.DeserializationFailed;

        return Self{ ._buf = buf, .handle = pk };
    }

    /// Destroy the public key and free its storage.
    pub fn deinit(self: *Self) void {
        hashsig_public_key_deinit(self.handle);
        cFree(self._buf);
    }
};

// ─── PublicKeyCache ──────────────────────────────────────────────────────────

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
                // `handle` and `_buf` both point to the same C-heap allocation
                // (handle = @ptrCast(_buf) at construction time).
                const raw: [*]u8 = @ptrFromInt(ptr_int);
                var pk = PublicKey{
                    ._buf = raw,
                    .handle = @ptrCast(raw),
                };
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
        // The `handle` == `_buf` (both point to the start of the C-heap allocation
        // for the Rust PublicKey struct), so storing `handle` as the atomic value
        // is sufficient to reconstruct both fields in `deinit`.
        const new_int = @intFromPtr(pk.handle);

        if (slot.cmpxchgStrong(EMPTY, new_int, .release, .acquire)) |loser| {
            // Another thread populated this slot first. Free our
            // freshly-deserialised handle and adopt the winner's.
            pk.deinit();
            return @ptrFromInt(loser);
        }
        return pk.handle;
    }

    /// Check if a validator's public key is already cached.
    pub fn contains(self: *const Self, validator_index: usize) bool {
        if (validator_index >= self.slots.len) return false;
        return self.slots[validator_index].load(.monotonic) != EMPTY;
    }

    /// Best-effort count of populated slots.
    pub fn count(self: *const Self) usize {
        var n: usize = 0;
        for (self.slots) |*s| {
            if (s.load(.monotonic) != EMPTY) n += 1;
        }
        return n;
    }
};

// ─── Tests ────────────────────────────────────────────────────────────────────

test "HashSig: generate keypair" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    try std.testing.expect(@intFromPtr(keypair.public_key) != 0);
    try std.testing.expect(@intFromPtr(keypair.private_key) != 0);
}

test "HashSig: SSZ keypair roundtrip" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_ssz_roundtrip", 0, 5);
    defer keypair.deinit();

    var pk_buffer: [256]u8 = undefined;
    const pk_len = try keypair.pubkeyToBytes(&pk_buffer);

    const sk_buffer = try allocator.alloc(u8, 1024 * 1024 * 10);
    defer allocator.free(sk_buffer);
    const sk_len = try keypair.privkeyToBytes(sk_buffer);

    std.debug.print("\nPK size: {d}, SK size: {d}\n", .{ pk_len, sk_len });

    var restored_keypair = try KeyPair.fromSsz(
        allocator,
        sk_buffer[0..sk_len],
        pk_buffer[0..pk_len],
    );
    defer restored_keypair.deinit();

    const message = [_]u8{42} ** 32;
    const epoch: u32 = 0;

    var signature = try restored_keypair.sign(&message, epoch);
    defer signature.deinit();

    try keypair.verify(&message, &signature, epoch);
}

test "HashSig: sign and verify" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    const msg_len = KeyPair.messageLength();
    const message = try allocator.alloc(u8, msg_len);
    defer allocator.free(message);

    for (message, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    const epoch: u32 = 0;

    var signature = try keypair.sign(message, epoch);
    defer signature.deinit();

    try keypair.verify(message, &signature, epoch);

    keypair.verify(message, &signature, epoch + 100) catch |err| {
        try std.testing.expect(err == HashSigError.VerificationFailed);
    };

    message[0] = message[0] + 1;
    keypair.verify(message, &signature, epoch) catch |err| {
        try std.testing.expect(err == HashSigError.VerificationFailed);
    };
}

test "HashSig: invalid message length" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    const wrong_message = try allocator.alloc(u8, 10);
    defer allocator.free(wrong_message);

    const result = keypair.sign(wrong_message, 0);
    try std.testing.expectError(HashSigError.InvalidMessageLength, result);
}

test "HashSig: SSZ serialize and verify" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 10);
    defer keypair.deinit();

    const message = [_]u8{1} ** 32;
    const epoch: u32 = 0;

    var signature = try keypair.sign(&message, epoch);
    defer signature.deinit();

    var sig_buffer: [4000]u8 = undefined;
    const sig_size = try signature.toBytes(&sig_buffer);
    std.debug.print("\nSignature size: {d} bytes\n", .{sig_size});

    var pubkey_buffer: [256]u8 = undefined;
    const pubkey_size = try keypair.pubkeyToBytes(&pubkey_buffer);
    std.debug.print("Public key size: {d} bytes\n", .{pubkey_size});

    try verifySsz(
        pubkey_buffer[0..pubkey_size],
        &message,
        epoch,
        sig_buffer[0..sig_size],
    );

    std.debug.print("Verification succeeded!\n", .{});
}

test "HashSig: verify fails with zero signature" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 10);
    defer keypair.deinit();

    const message = [_]u8{1} ** 32;
    const epoch: u32 = 0;

    var pubkey_buffer: [256]u8 = undefined;
    const pubkey_size = try keypair.pubkeyToBytes(&pubkey_buffer);

    var signature_buffer: [4000]u8 = undefined;

    var signature = try keypair.sign(&message, epoch);
    defer signature.deinit();

    const signature_size = try signature.toBytes(&signature_buffer);

    var zero_sig_buffer = [_]u8{0} ** 4000;

    const invalid_signature_result = verifySsz(
        pubkey_buffer[0..pubkey_size],
        &message,
        epoch,
        &zero_sig_buffer,
    );

    try std.testing.expectError(HashSigError.InvalidSignature, invalid_signature_result);

    const invalid_message = [_]u8{2} ** 32;
    const verification_failed_result = verifySsz(
        pubkey_buffer[0..pubkey_size],
        &invalid_message,
        epoch,
        signature_buffer[0..signature_size],
    );

    try std.testing.expectError(HashSigError.VerificationFailed, verification_failed_result);
}
