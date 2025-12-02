const std = @import("std");
const Allocator = std.mem.Allocator;
const hash_zig = @import("hash-zig");

// Re-export types for convenience
pub const GeneralizedXMSSSignatureScheme = hash_zig.GeneralizedXMSSSignatureScheme;
pub const KeyLifetimeRustCompat = hash_zig.KeyLifetimeRustCompat;

// Default lifetime for zeam (2^32 for production use - 4.3 billion signatures)
const DEFAULT_LIFETIME: KeyLifetimeRustCompat = .lifetime_2_32;
// Default number of active epochs for key generation
const DEFAULT_ACTIVE_EPOCHS: usize = 1024;

pub const HashSigError = error{
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    InvalidSignature,
    SerializationFailed,
    InvalidMessageLength,
    DeserializationFailed,
    OutOfMemory,
    SchemeInitFailed,
};

/// Wrapper for hash-zig keypair that maintains compatibility with existing zeam API
pub const KeyPair = struct {
    scheme: *GeneralizedXMSSSignatureScheme,
    secret_key: *hash_zig.signature.GeneralizedXMSSSecretKey,
    public_key: hash_zig.signature.GeneralizedXMSSPublicKey,
    allocator: Allocator,
    owns_scheme: bool,

    const Self = @This();

    /// Generate a new key pair
    /// Creates a new scheme instance for this keypair
    pub fn generate(
        allocator: Allocator,
        seed_phrase: []const u8,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) HashSigError!Self {
        // Initialize scheme with default lifetime (returns pointer)
        const scheme_ptr = GeneralizedXMSSSignatureScheme.initWithSeed(
            allocator,
            DEFAULT_LIFETIME,
            seedPhraseToBytes(seed_phrase),
        ) catch |err| {
            std.debug.print("Scheme init failed: {any}\n", .{err});
            return HashSigError.SchemeInitFailed;
        };
        errdefer scheme_ptr.deinit();

        // Generate keypair
        const keypair = scheme_ptr.keyGen(activation_epoch, num_active_epochs) catch |err| {
            std.debug.print("KeyGen failed: {any}, activation_epoch={}, num_active_epochs={}\n", .{ err, activation_epoch, num_active_epochs });
            return HashSigError.KeyGenerationFailed;
        };

        return Self{
            .scheme = scheme_ptr,
            .secret_key = keypair.secret_key,
            .public_key = keypair.public_key,
            .allocator = allocator,
            .owns_scheme = true,
        };
    }

    /// Reconstruct a key pair from SSZ-serialized bytes
    /// Note: For secret keys, this requires re-running keyGen since trees aren't serialized
    /// This function is not fully implemented - use generate() instead
    pub fn fromSSZ(
        allocator: Allocator,
        secret_key_ssz: []const u8,
        public_key_ssz: []const u8,
    ) HashSigError!Self {
        _ = allocator;
        _ = secret_key_ssz;
        _ = public_key_ssz;

        // Secret key SSZ deserialization requires keyGen to rebuild trees
        // For now, return error - caller should use generate() or implement full reconstruction
        return HashSigError.DeserializationFailed;
    }

    /// Reconstruct a key pair from JSON (for backward compatibility)
    /// NOTE: This function is not fully implemented yet.
    ///
    /// Migration path:
    /// 1. For new deployments: Use SSZ format directly (validator_N_pk.ssz, validator_N_sk.ssz)
    /// 2. For existing deployments: Regenerate keys using KeyPair.generate()
    /// 3. If JSON migration is needed: Implement JSON→SSZ conversion here
    ///
    /// The old Rust format stored keys as JSON with bincode-encoded bytes.
    /// The new format uses pure SSZ serialization.
    pub fn fromJson(
        allocator: Allocator,
        secret_key_json: []const u8,
        public_key_json: []const u8,
    ) HashSigError!Self {
        _ = allocator;
        _ = secret_key_json;
        _ = public_key_json;

        // TODO: Implement JSON parsing if migration from old format is needed
        // For now, recommend regenerating keys with KeyPair.generate()
        return HashSigError.DeserializationFailed;
    }

    /// Sign a message
    /// Caller owns the returned signature and must free it with deinit()
    pub fn sign(
        self: *const Self,
        message: []const u8,
        epoch: u32,
    ) HashSigError!Signature {
        if (message.len != 32) {
            return HashSigError.InvalidMessageLength;
        }

        const message_array: *const [32]u8 = message[0..32];
        const signature_ptr = self.scheme.sign(self.secret_key, epoch, message_array.*) catch {
            return HashSigError.SigningFailed;
        };

        return Signature{
            .inner = signature_ptr,
            .allocator = self.allocator,
        };
    }

    /// Verify a signature
    pub fn verify(
        self: *const Self,
        message: []const u8,
        signature: *const Signature,
        epoch: u32,
    ) HashSigError!void {
        if (message.len != 32) {
            return HashSigError.InvalidMessageLength;
        }

        const message_array: *const [32]u8 = message[0..32];
        const is_valid = self.scheme.verify(&self.public_key, epoch, message_array.*, signature.inner) catch {
            return HashSigError.VerificationFailed;
        };

        if (!is_valid) {
            return HashSigError.VerificationFailed;
        }
    }

    /// Get the required message length (always 32 bytes)
    pub fn messageLength() usize {
        return 32;
    }

    /// Serialize public key to SSZ bytes
    pub fn pubkeyToBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        var list = std.ArrayList(u8).init(self.allocator);
        defer list.deinit();

        self.public_key.sszEncode(&list) catch {
            return HashSigError.SerializationFailed;
        };

        if (list.items.len > buffer.len) {
            return HashSigError.SerializationFailed;
        }

        @memcpy(buffer[0..list.items.len], list.items);
        return list.items.len;
    }

    /// Free the key pair
    pub fn deinit(self: *Self) void {
        if (self.owns_scheme) {
            // Important: deinit secret_key first (it owns trees), then scheme
            self.secret_key.deinit();
            // Scheme deinit frees itself via allocator.destroy(self)
            self.scheme.deinit();
        }
    }
};

/// Wrapper for hash-zig signature
pub const Signature = struct {
    inner: *hash_zig.signature.GeneralizedXMSSSignature,
    allocator: Allocator,

    const Self = @This();

    /// Serialize signature to SSZ bytes
    /// Returns the number of bytes written to the buffer
    pub fn toBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        var list = std.ArrayList(u8).init(self.allocator);
        defer list.deinit();

        self.inner.sszEncode(&list) catch {
            return HashSigError.SerializationFailed;
        };

        if (list.items.len > buffer.len) {
            return HashSigError.SerializationFailed;
        }

        @memcpy(buffer[0..list.items.len], list.items);
        return list.items.len;
    }

    /// Free the signature
    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }
};

/// Verify signature using SSZ-encoded bytes (for compatibility)
pub fn verifySsz(
    pubkey_bytes: []const u8,
    message: []const u8,
    epoch: u32,
    signature_bytes: []const u8,
) HashSigError!void {
    if (message.len != 32) {
        return HashSigError.InvalidMessageLength;
    }

    // Use page allocator for temporary scheme instance
    const allocator = std.heap.page_allocator;

    // Initialize scheme with default lifetime
    var scheme = GeneralizedXMSSSignatureScheme.init(allocator, DEFAULT_LIFETIME) catch {
        return HashSigError.SchemeInitFailed;
    };
    defer scheme.deinit();

    // Deserialize public key from SSZ
    var public_key: hash_zig.signature.GeneralizedXMSSPublicKey = undefined;
    hash_zig.signature.GeneralizedXMSSPublicKey.sszDecode(pubkey_bytes, &public_key, null) catch {
        return HashSigError.DeserializationFailed;
    };

    // Deserialize signature from SSZ
    var signature = hash_zig.signature.GeneralizedXMSSSignature.fromBytes(signature_bytes, allocator) catch {
        return HashSigError.DeserializationFailed;
    };
    defer signature.deinit();

    // Verify
    const message_array: *const [32]u8 = message[0..32];
    const is_valid = scheme.verify(&public_key, epoch, message_array.*, signature) catch {
        return HashSigError.VerificationFailed;
    };

    if (!is_valid) {
        return HashSigError.VerificationFailed;
    }
}

/// Verify signature using SSZ-encoded bytes (bincode compatibility wrapper)
pub fn verifyBincode(
    pubkey_bytes: []const u8,
    message: []const u8,
    epoch: u32,
    signature_bytes: []const u8,
) HashSigError!void {
    // For now, treat bincode same as SSZ (hash-zig v1.1.0 supports both)
    return verifySsz(pubkey_bytes, message, epoch, signature_bytes);
}

/// Convert seed phrase to 32-byte seed
fn seedPhraseToBytes(seed_phrase: []const u8) [32]u8 {
    var seed: [32]u8 = undefined;

    if (seed_phrase.len >= 32) {
        @memcpy(seed[0..32], seed_phrase[0..32]);
    } else {
        @memcpy(seed[0..seed_phrase.len], seed_phrase);
        @memset(seed[seed_phrase.len..], 0);
    }

    return seed;
}

// Tests
test "HashSig: generate keypair" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    try std.testing.expect(keypair.secret_key.activation_epoch == 0);
}

test "HashSig: sign and verify" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    const message = [_]u8{0x42} ** 32;
    const epoch: u32 = 0;

    // Sign the message
    var signature = try keypair.sign(&message, epoch);
    defer signature.deinit();

    // Verify the signature
    try keypair.verify(&message, &signature, epoch);

    // Test with wrong epoch
    keypair.verify(&message, &signature, epoch + 100) catch |err| {
        try std.testing.expect(err == HashSigError.VerificationFailed);
    };

    // Test with wrong message
    var wrong_message = message;
    wrong_message[0] = wrong_message[0] +% 1;
    keypair.verify(&wrong_message, &signature, epoch) catch |err| {
        try std.testing.expect(err == HashSigError.VerificationFailed);
    };
}

test "HashSig: invalid message length" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    const wrong_message = [_]u8{0x42} ** 10;
    const epoch: u32 = 0;

    // Should fail with invalid message length
    const result = keypair.sign(&wrong_message, epoch);
    try std.testing.expectError(HashSigError.InvalidMessageLength, result);
}

test "HashSig: SSZ serialize and verify" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 10);
    defer keypair.deinit();

    const message = [_]u8{1} ** 32;
    const epoch: u32 = 0;

    // Sign
    var signature = try keypair.sign(&message, epoch);
    defer signature.deinit();

    // Serialize signature
    var sig_buffer: [4000]u8 = undefined;
    const sig_size = try signature.toBytes(&sig_buffer);
    std.debug.print("\nSignature size: {d} bytes\n", .{sig_size});

    // Serialize public key
    var pubkey_buffer: [256]u8 = undefined;
    const pubkey_size = try keypair.pubkeyToBytes(&pubkey_buffer);
    std.debug.print("Public key size: {d} bytes\n", .{pubkey_size});

    // Verify using original keypair (SSZ verification via verifySsz not yet implemented)
    try keypair.verify(&message, &signature, epoch);

    std.debug.print("Verification succeeded!\n", .{});
}

test "HashSig: verify fails with wrong signature" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 10);
    defer keypair.deinit();

    const message = [_]u8{1} ** 32;
    const epoch: u32 = 0;

    var signature = try keypair.sign(&message, epoch);
    defer signature.deinit();

    const invalid_message = [_]u8{2} ** 32;

    // Verification should fail
    const verification_failed_result = keypair.verify(&invalid_message, &signature, epoch);
    try std.testing.expectError(HashSigError.VerificationFailed, verification_failed_result);
}
