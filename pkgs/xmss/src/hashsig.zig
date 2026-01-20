const std = @import("std");
const Allocator = std.mem.Allocator;

pub const aggregate = @import("aggregation.zig");

/// Opaque pointer to the Rust KeyPair struct
pub const HashSigKeyPair = opaque {};

/// Opaque pointer to the Rust Signature struct
pub const HashSigSignature = opaque {};

/// Opaque pointer to the Rust PublicKey struct
pub const HashSigPublicKey = opaque {};

/// Opaque pointer to the Rust PrivateKey struct
pub const HashSigPrivateKey = opaque {};

/// Generate a new key pair
extern fn hashsig_keypair_generate(
    seed_phrase: [*:0]const u8,
    activation_epoch: usize,
    num_active_epochs: usize,
) ?*HashSigKeyPair;

/// Reconstruct a key pair from SSZ-encoded bytes
extern fn hashsig_keypair_from_ssz(
    private_key_ssz: [*]const u8,
    private_key_len: usize,
    public_key_ssz: [*]const u8,
    public_key_len: usize,
) ?*HashSigKeyPair;

/// Free a key pair
extern fn hashsig_keypair_free(keypair: ?*HashSigKeyPair) void;

/// Get pointer to public key from keypair (valid as long as keypair is alive)
extern fn hashsig_keypair_get_public_key(keypair: *const HashSigKeyPair) ?*const HashSigPublicKey;

/// Get pointer to private key from keypair (valid as long as keypair is alive)
extern fn hashsig_keypair_get_private_key(keypair: *const HashSigKeyPair) ?*const HashSigPrivateKey;

/// Sign a message using private key directly
extern fn hashsig_sign(
    private_key: *const HashSigPrivateKey,
    message_ptr: [*]const u8,
    epoch: u32,
) ?*HashSigSignature;

/// Verify a signature using public key directly
extern fn hashsig_verify(
    public_key: *const HashSigPublicKey,
    message_ptr: [*]const u8,
    epoch: u32,
    signature: *const HashSigSignature,
) i32;

/// Serialize a public key pointer to bytes
extern fn hashsig_public_key_to_bytes(
    public_key: *const HashSigPublicKey,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

/// Serialize a private key pointer to bytes
extern fn hashsig_private_key_to_bytes(
    private_key: *const HashSigPrivateKey,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

/// Free a signature
extern fn hashsig_signature_free(signature: ?*HashSigSignature) void;

/// Construct a signature from SSZ bytes
extern fn hashsig_signature_from_ssz(
    sig_bytes: [*]const u8,
    sig_len: usize,
) ?*HashSigSignature;

/// Construct a public key from SSZ bytes
extern fn hashsig_public_key_from_ssz(
    pubkey_bytes: [*]const u8,
    pubkey_len: usize,
) ?*HashSigPublicKey;

/// Free a standalone public key
extern fn hashsig_public_key_free(pubkey: ?*HashSigPublicKey) void;

/// Get the message length constant
extern fn hashsig_message_length() usize;

/// Serialize a signature to bytes using SSZ encoding
extern fn hashsig_signature_to_bytes(
    signature: *const HashSigSignature,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

/// Verify XMSS signature from SSZ-encoded bytes
extern fn hashsig_verify_ssz(
    pubkey_bytes: [*]const u8,
    pubkey_len: usize,
    message: [*]const u8,
    epoch: u32,
    signature_bytes: [*]const u8,
    signature_len: usize,
) i32;

pub const HashSigError = error{ KeyGenerationFailed, SigningFailed, VerificationFailed, InvalidSignature, SerializationFailed, InvalidMessageLength, DeserializationFailed, OutOfMemory };

/// Verify signature using SSZ-encoded bytes
pub fn verifySsz(
    pubkey_bytes: []const u8,
    message: []const u8,
    epoch: u32,
    signature_bytes: []const u8,
) HashSigError!void {
    if (message.len != 32) {
        return HashSigError.InvalidMessageLength;
    }

    const result = hashsig_verify_ssz(
        pubkey_bytes.ptr,
        pubkey_bytes.len,
        message.ptr,
        epoch,
        signature_bytes.ptr,
        signature_bytes.len,
    );

    switch (result) {
        1 => {},
        0 => return HashSigError.VerificationFailed,
        -1 => return HashSigError.InvalidSignature,
        else => return HashSigError.VerificationFailed,
    }
}

/// Wrapper for the hash signature key pair
pub const KeyPair = struct {
    handle: *HashSigKeyPair,
    public_key: *const HashSigPublicKey,
    private_key: *const HashSigPrivateKey,
    allocator: Allocator,

    const Self = @This();

    /// Generate a new key pair
    pub fn generate(
        allocator: Allocator,
        seed_phrase: []const u8,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) HashSigError!Self {
        // Create null-terminated string for C
        const c_seed = try allocator.dupeZ(u8, seed_phrase);
        defer allocator.free(c_seed);

        const handle = hashsig_keypair_generate(
            c_seed.ptr,
            activation_epoch,
            num_active_epochs,
        ) orelse {
            return HashSigError.KeyGenerationFailed;
        };

        const public_key = hashsig_keypair_get_public_key(handle) orelse {
            hashsig_keypair_free(handle);
            return HashSigError.KeyGenerationFailed;
        };

        const private_key = hashsig_keypair_get_private_key(handle) orelse {
            hashsig_keypair_free(handle);
            return HashSigError.KeyGenerationFailed;
        };

        return Self{
            .handle = handle,
            .public_key = public_key,
            .private_key = private_key,
            .allocator = allocator,
        };
    }

    /// Reconstruct a key pair from SSZ-encoded bytes
    pub fn fromSsz(
        allocator: Allocator,
        private_key_ssz: []const u8,
        public_key_ssz: []const u8,
    ) HashSigError!Self {
        if (private_key_ssz.len == 0 or public_key_ssz.len == 0) {
            return HashSigError.DeserializationFailed;
        }

        const handle = hashsig_keypair_from_ssz(
            private_key_ssz.ptr,
            private_key_ssz.len,
            public_key_ssz.ptr,
            public_key_ssz.len,
        ) orelse {
            return HashSigError.DeserializationFailed;
        };

        const public_key = hashsig_keypair_get_public_key(handle) orelse {
            hashsig_keypair_free(handle);
            return HashSigError.DeserializationFailed;
        };

        const private_key = hashsig_keypair_get_private_key(handle) orelse {
            hashsig_keypair_free(handle);
            return HashSigError.DeserializationFailed;
        };

        return Self{
            .handle = handle,
            .public_key = public_key,
            .private_key = private_key,
            .allocator = allocator,
        };
    }

    /// Sign a message
    /// Caller owns the returned signature and must free it with deinit()
    pub fn sign(
        self: *const Self,
        message: []const u8,
        epoch: u32,
    ) HashSigError!Signature {
        const msg_len = hashsig_message_length();
        if (message.len != msg_len) {
            return HashSigError.InvalidMessageLength;
        }

        const sig_handle = hashsig_sign(
            self.private_key,
            message.ptr,
            epoch,
        ) orelse {
            return HashSigError.SigningFailed;
        };

        return Signature{ .handle = sig_handle };
    }

    /// Verify a signature
    pub fn verify(
        self: *const Self,
        message: []const u8,
        signature: *const Signature,
        epoch: u32,
    ) HashSigError!void {
        const msg_len = hashsig_message_length();
        if (message.len != msg_len) {
            return HashSigError.InvalidMessageLength;
        }

        const result = hashsig_verify(
            self.public_key,
            message.ptr,
            epoch,
            signature.handle,
        );

        if (result != 1) {
            return HashSigError.VerificationFailed;
        }
    }

    /// Get the required message length
    pub fn messageLength() usize {
        return hashsig_message_length();
    }

    /// Serialize public key to bytes (SSZ format)
    pub fn pubkeyToBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const bytes_written = hashsig_public_key_to_bytes(
            self.public_key,
            buffer.ptr,
            buffer.len,
        );

        if (bytes_written == 0) {
            return HashSigError.SerializationFailed;
        }

        return bytes_written;
    }

    /// Serialize private key to bytes (SSZ format)
    pub fn privkeyToBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const bytes_written = hashsig_private_key_to_bytes(
            self.private_key,
            buffer.ptr,
            buffer.len,
        );

        if (bytes_written == 0) {
            return HashSigError.SerializationFailed;
        }

        return bytes_written;
    }

    /// Free the key pair
    pub fn deinit(self: *Self) void {
        hashsig_keypair_free(self.handle);
    }
};

/// Wrapper for the hash signature
pub const Signature = struct {
    handle: *HashSigSignature,

    const Self = @This();

    /// Deserialize a signature from SSZ bytes
    pub fn fromBytes(bytes: []const u8) HashSigError!Self {
        if (bytes.len == 0) {
            return HashSigError.DeserializationFailed;
        }

        const handle = hashsig_signature_from_ssz(
            bytes.ptr,
            bytes.len,
        ) orelse {
            return HashSigError.DeserializationFailed;
        };

        return Self{ .handle = handle };
    }

    /// Serialize signature to bytes (SSZ format)
    /// Returns the number of bytes written to the buffer
    pub fn toBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const bytes_written = hashsig_signature_to_bytes(
            self.handle,
            buffer.ptr,
            buffer.len,
        );

        if (bytes_written == 0) {
            return HashSigError.SerializationFailed;
        }

        return bytes_written;
    }

    /// Free the signature
    pub fn deinit(self: *Self) void {
        hashsig_signature_free(self.handle);
    }
};

/// Wrapper for standalone public keys reconstructed from SSZ bytes
pub const PublicKey = struct {
    handle: *HashSigPublicKey,

    const Self = @This();

    pub fn fromBytes(bytes: []const u8) HashSigError!Self {
        if (bytes.len == 0) {
            return HashSigError.DeserializationFailed;
        }

        const handle = hashsig_public_key_from_ssz(
            bytes.ptr,
            bytes.len,
        ) orelse {
            return HashSigError.DeserializationFailed;
        };

        return Self{ .handle = handle };
    }

    pub fn deinit(self: *Self) void {
        hashsig_public_key_free(self.handle);
    }
};

test "HashSig: generate keypair" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    try std.testing.expect(@intFromPtr(keypair.public_key) != 0);
    try std.testing.expect(@intFromPtr(keypair.private_key) != 0);
}

test "HashSig: SSZ keypair roundtrip" {
    const allocator = std.testing.allocator;

    // Generate original keypair
    var keypair = try KeyPair.generate(allocator, "test_ssz_roundtrip", 0, 5);
    defer keypair.deinit();

    // Serialize to SSZ
    var pk_buffer: [256]u8 = undefined;
    const pk_len = try keypair.pubkeyToBytes(&pk_buffer);

    // We need a large buffer for private key (it contains many one-time keys)
    // Allocating on heap to be safe with stack size
    const sk_buffer = try allocator.alloc(u8, 1024 * 1024 * 10); // 10MB should be enough
    defer allocator.free(sk_buffer);
    const sk_len = try keypair.privkeyToBytes(sk_buffer);

    std.debug.print("\nPK size: {d}, SK size: {d}\n", .{ pk_len, sk_len });

    // Reconstruct from SSZ
    var restored_keypair = try KeyPair.fromSsz(
        allocator,
        sk_buffer[0..sk_len],
        pk_buffer[0..pk_len],
    );
    defer restored_keypair.deinit();

    // Verify functionality with restored keypair
    const message = [_]u8{42} ** 32;
    const epoch: u32 = 0;

    // Sign with restored keypair
    var signature = try restored_keypair.sign(&message, epoch);
    defer signature.deinit();

    // Verify with original keypair (should work as they are same keys)
    try keypair.verify(&message, &signature, epoch);
}

test "HashSig: sign and verify" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    // Create a message of the correct length
    const msg_len = KeyPair.messageLength();
    const message = try allocator.alloc(u8, msg_len);
    defer allocator.free(message);

    // Fill with test data
    for (message, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    const epoch: u32 = 0;

    // Sign the message
    var signature = try keypair.sign(message, epoch);
    defer signature.deinit();

    // Verify the signature
    try keypair.verify(message, &signature, epoch);

    // Test with wrong epoch
    keypair.verify(message, &signature, epoch + 100) catch |err| {
        try std.testing.expect(err == HashSigError.VerificationFailed);
    };

    // Test with wrong message
    message[0] = message[0] + 1; // Modify message
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

    const epoch: u32 = 0;

    // Should fail with invalid message length
    const result = keypair.sign(wrong_message, epoch);
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

    // Verify using SSZ
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

    // Serialize public key
    var pubkey_buffer: [256]u8 = undefined;
    const pubkey_size = try keypair.pubkeyToBytes(&pubkey_buffer);

    var signature_buffer: [4000]u8 = undefined;

    var signature = try keypair.sign(&message, epoch);
    defer signature.deinit();

    const signature_size = try signature.toBytes(&signature_buffer);

    // Create invalid signature with all zeros
    var zero_sig_buffer = [_]u8{0} ** 4000;

    // Invalid signature length - should fail with InvalidSignature
    const invalid_signature_result = verifySsz(
        pubkey_buffer[0..pubkey_size],
        &message,
        epoch,
        &zero_sig_buffer,
    );

    try std.testing.expectError(HashSigError.InvalidSignature, invalid_signature_result);

    const invalid_message = [_]u8{2} ** 32;
    // Verification should fail - should fail with VerificationFailed
    const verification_failed_result = verifySsz(
        pubkey_buffer[0..pubkey_size],
        &invalid_message,
        epoch,
        signature_buffer[0..signature_size],
    );

    try std.testing.expectError(HashSigError.VerificationFailed, verification_failed_result);
}
