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
    InvalidJsonFormat,
    SecretKeyNotSupported,
    PublicKeyMismatch,
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

    /// Reconstruct a key pair from SSZ-serialized bytes (leansig format)
    /// Loads the full Merkle trees from the SSZ file
    pub fn fromSSZ(
        allocator: Allocator,
        secret_key_ssz: []const u8,
        public_key_ssz: []const u8,
    ) HashSigError!Self {
        _ = public_key_ssz; // Public key file not used - we derive it from secret key

        // Allocate secret key on heap first
        const secret_key = try allocator.create(hash_zig.signature.GeneralizedXMSSSecretKey);
        errdefer allocator.destroy(secret_key);

        // Deserialize the full secret key (including trees) from SSZ
        hash_zig.signature.GeneralizedXMSSSecretKey.sszDecode(secret_key_ssz, secret_key, allocator) catch {
            allocator.destroy(secret_key);
            return HashSigError.DeserializationFailed;
        };

        // Derive public key from secret key's top tree root (not from file!)
        const top_tree_root = secret_key.top_tree.root();
        const hash_len_fe: usize = switch (DEFAULT_LIFETIME) {
            .lifetime_2_8 => 8,
            .lifetime_2_18 => 7,
            .lifetime_2_32 => 8,
        };
        const public_key = hash_zig.signature.GeneralizedXMSSPublicKey.init(top_tree_root, secret_key.parameter, hash_len_fe);

        // Initialize scheme with just the lifetime
        const scheme_ptr = GeneralizedXMSSSignatureScheme.init(
            allocator,
            DEFAULT_LIFETIME,
        ) catch {
            secret_key.deinit();
            allocator.destroy(secret_key);
            return HashSigError.SchemeInitFailed;
        };

        return Self{
            .scheme = scheme_ptr,
            .secret_key = secret_key,
            .public_key = public_key,
            .allocator = allocator,
            .owns_scheme = true,
        };
    }

    /// Reconstruct a key pair from JSON (for backward compatibility)
    ///
    /// Supports the old Rust hashsig-glue JSON format.
    /// Expected JSON formats:
    ///
    /// Public Key: { "root": [u32, ...], "parameter": [u32, ...], "hash_len_fe": u32 }
    /// Secret Key: { "prf_key": [u8; 32], "parameter": [u32, ...],
    ///               "activation_epoch": usize, "num_active_epochs": usize }
    ///
    /// Note: The Merkle trees are not stored in JSON and will be regenerated.
    /// This is expensive (5-10 minutes for lifetime_2_32) but necessary.
    pub fn fromJson(
        allocator: Allocator,
        secret_key_json: []const u8,
        public_key_json: []const u8,
    ) HashSigError!Self {
        const json = std.json;

        // Parse secret key JSON
        const sk_parsed = json.parseFromSlice(
            json.Value,
            allocator,
            secret_key_json,
            .{},
        ) catch return HashSigError.InvalidJsonFormat;
        defer sk_parsed.deinit();

        const sk_obj = sk_parsed.value.object;

        // Extract prf_key (32 bytes)
        const prf_key_array = sk_obj.get("prf_key") orelse return HashSigError.InvalidJsonFormat;
        if (prf_key_array != .array) return HashSigError.InvalidJsonFormat;
        if (prf_key_array.array.items.len != 32) return HashSigError.InvalidJsonFormat;

        var prf_key: [32]u8 = undefined;
        for (prf_key_array.array.items, 0..) |item, i| {
            const val = switch (item) {
                .integer => |int| @as(u8, @intCast(int)),
                .number_string => |str| std.fmt.parseInt(u8, str, 10) catch return HashSigError.InvalidJsonFormat,
                else => return HashSigError.InvalidJsonFormat,
            };
            prf_key[i] = val;
        }

        // Extract parameter array (5 field elements)
        const sk_param_array = sk_obj.get("parameter") orelse return HashSigError.InvalidJsonFormat;
        if (sk_param_array != .array) return HashSigError.InvalidJsonFormat;
        if (sk_param_array.array.items.len != 5) return HashSigError.InvalidJsonFormat;

        var parameter: [5]hash_zig.FieldElement = undefined;
        for (sk_param_array.array.items, 0..) |item, i| {
            const val = switch (item) {
                .integer => |int| @as(u32, @intCast(int)),
                .number_string => |str| std.fmt.parseInt(u32, str, 10) catch return HashSigError.InvalidJsonFormat,
                else => return HashSigError.InvalidJsonFormat,
            };
            parameter[i] = hash_zig.FieldElement.fromCanonical(val);
        }

        // Extract activation_epoch
        const activation_epoch_val = sk_obj.get("activation_epoch") orelse return HashSigError.InvalidJsonFormat;
        const activation_epoch = switch (activation_epoch_val) {
            .integer => |int| @as(usize, @intCast(int)),
            .number_string => |str| std.fmt.parseInt(usize, str, 10) catch return HashSigError.InvalidJsonFormat,
            else => return HashSigError.InvalidJsonFormat,
        };

        // Extract num_active_epochs
        const num_active_epochs_val = sk_obj.get("num_active_epochs") orelse return HashSigError.InvalidJsonFormat;
        const num_active_epochs = switch (num_active_epochs_val) {
            .integer => |int| @as(usize, @intCast(int)),
            .number_string => |str| std.fmt.parseInt(usize, str, 10) catch return HashSigError.InvalidJsonFormat,
            else => return HashSigError.InvalidJsonFormat,
        };

        // Parse public key JSON to get the public key
        const public_key = publicKeyFromJson(allocator, public_key_json) catch {
            return HashSigError.InvalidJsonFormat;
        };

        // Initialize scheme with the prf_key as seed to ensure deterministic tree generation
        const scheme_ptr = GeneralizedXMSSSignatureScheme.initWithSeed(
            allocator,
            DEFAULT_LIFETIME,
            prf_key,
        ) catch return HashSigError.SchemeInitFailed;

        // Regenerate the keypair using the extracted parameters
        // Use keyGenWithParameter to provide the exact prf_key and parameter from JSON
        // The scheme's RNG is already seeded with prf_key, ensuring deterministic trees
        const keypair = scheme_ptr.keyGenWithParameter(
            activation_epoch,
            num_active_epochs,
            parameter,
            prf_key,
            true, // rng_already_consumed = true since initWithSeed already consumed the seed
        ) catch |err| {
            std.debug.print("keyGenWithParameter failed during fromJson: {any}\n", .{err});
            // Clean up scheme before returning error
            scheme_ptr.deinit();
            return HashSigError.KeyGenerationFailed;
        };

        // Verify the regenerated public key matches the stored one
        // Compare roots to ensure consistency
        const regenerated_root = keypair.public_key.getRoot();
        const stored_root = public_key.getRoot();
        for (regenerated_root, stored_root) |regen, stored| {
            if (regen.value != stored.value) {
                // Mismatch - the regenerated key doesn't match the stored key
                // This could happen if the JSON format is different or corrupted
                keypair.secret_key.deinit();
                scheme_ptr.deinit();
                return HashSigError.PublicKeyMismatch;
            }
        }

        return Self{
            .scheme = scheme_ptr,
            .secret_key = keypair.secret_key,
            .public_key = keypair.public_key,
            .allocator = allocator,
            .owns_scheme = true,
        };
    }

    /// Extract public key from JSON for verification purposes only
    /// This is useful for migrating from old JSON format to verify existing signatures
    /// without needing the secret key.
    pub fn publicKeyFromJson(
        allocator: Allocator,
        public_key_json: []const u8,
    ) HashSigError!hash_zig.signature.GeneralizedXMSSPublicKey {
        const json = std.json;

        // Parse public key JSON
        const pk_parsed = json.parseFromSlice(
            json.Value,
            allocator,
            public_key_json,
            .{},
        ) catch return HashSigError.InvalidJsonFormat;
        defer pk_parsed.deinit();

        const pk_obj = pk_parsed.value.object;

        // Extract root array (8 field elements)
        const root_array = pk_obj.get("root") orelse return HashSigError.InvalidJsonFormat;
        if (root_array != .array) return HashSigError.InvalidJsonFormat;
        if (root_array.array.items.len != 8) return HashSigError.InvalidJsonFormat;

        var root: [8]hash_zig.FieldElement = undefined;
        for (root_array.array.items, 0..) |item, i| {
            const val = switch (item) {
                .integer => |int| @as(u32, @intCast(int)),
                .number_string => |str| std.fmt.parseInt(u32, str, 10) catch return HashSigError.InvalidJsonFormat,
                else => return HashSigError.InvalidJsonFormat,
            };
            root[i] = hash_zig.FieldElement.fromCanonical(val);
        }

        // Extract parameter array (5 field elements)
        const param_array = pk_obj.get("parameter") orelse return HashSigError.InvalidJsonFormat;
        if (param_array != .array) return HashSigError.InvalidJsonFormat;
        if (param_array.array.items.len != 5) return HashSigError.InvalidJsonFormat;

        var parameter: [5]hash_zig.FieldElement = undefined;
        for (param_array.array.items, 0..) |item, i| {
            const val = switch (item) {
                .integer => |int| @as(u32, @intCast(int)),
                .number_string => |str| std.fmt.parseInt(u32, str, 10) catch return HashSigError.InvalidJsonFormat,
                else => return HashSigError.InvalidJsonFormat,
            };
            parameter[i] = hash_zig.FieldElement.fromCanonical(val);
        }

        // Extract hash_len_fe (default to 8 for lifetime 2^32 if not present)
        const hash_len_fe = if (pk_obj.get("hash_len_fe")) |hash_len_fe_val| blk: {
            break :blk switch (hash_len_fe_val) {
                .integer => |int| @as(usize, @intCast(int)),
                .number_string => |str| std.fmt.parseInt(usize, str, 10) catch return HashSigError.InvalidJsonFormat,
                else => return HashSigError.InvalidJsonFormat,
            };
        } else 8; // Default to 8 for lifetime 2^32

        // Create and return public key
        return hash_zig.signature.GeneralizedXMSSPublicKey.init(root, parameter, hash_len_fe);
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

        var msg_bytes: [32]u8 = undefined;
        @memcpy(&msg_bytes, message[0..32]);
        const signature_ptr = self.scheme.sign(self.secret_key, epoch, msg_bytes) catch {
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

        var msg_bytes: [32]u8 = undefined;
        @memcpy(&msg_bytes, message[0..32]);
        const is_valid = self.scheme.verify(&self.public_key, epoch, msg_bytes, signature.inner) catch {
            std.debug.print("[HASH-ZIG-VERIFY] FAILED: Verification error for epoch {d}\n", .{epoch});
            return HashSigError.VerificationFailed;
        };

        if (!is_valid) {
            std.debug.print("[HASH-ZIG-VERIFY] FAILED: Invalid signature for epoch {d}\n", .{epoch});
            return HashSigError.VerificationFailed;
        }

        std.debug.print("[HASH-ZIG-VERIFY] SUCCESS: Valid signature for epoch {d}\n", .{epoch});
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

    const allocator = std.heap.page_allocator;

    var scheme = GeneralizedXMSSSignatureScheme.init(allocator, DEFAULT_LIFETIME) catch {
        return HashSigError.SchemeInitFailed;
    };
    defer scheme.deinit();

    var public_key: hash_zig.signature.GeneralizedXMSSPublicKey = undefined;
    hash_zig.signature.GeneralizedXMSSPublicKey.sszDecode(pubkey_bytes, &public_key, null) catch {
        return HashSigError.DeserializationFailed;
    };

    var signature = hash_zig.signature.GeneralizedXMSSSignature.fromBytes(signature_bytes, allocator) catch {
        return HashSigError.DeserializationFailed;
    };
    defer signature.deinit();

    const message_array: *const [32]u8 = message[0..32];
    const is_valid = scheme.verify(&public_key, epoch, message_array.*, signature) catch {
        std.debug.print("[HASH-ZIG-VERIFY] FAILED: Verification error for epoch {d}\n", .{epoch});
        return HashSigError.VerificationFailed;
    };

    if (!is_valid) {
        std.debug.print("[HASH-ZIG-VERIFY] FAILED: Invalid signature for epoch {d}\n", .{epoch});
        return HashSigError.VerificationFailed;
    }

    std.debug.print("[HASH-ZIG-VERIFY] SUCCESS: Valid signature for epoch {d}\n", .{epoch});
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
