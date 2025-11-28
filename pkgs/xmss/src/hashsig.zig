const std = @import("std");
const Allocator = std.mem.Allocator;

/// Opaque pointer to the Rust KeyPair struct
pub const HashSigKeyPair = opaque {};

/// Opaque pointer to the Rust Signature struct
pub const HashSigSignature = opaque {};

/// Generate a new key pair
extern fn hashsig_keypair_generate(
    seed_phrase: [*:0]const u8,
    activation_epoch: usize,
    num_active_epochs: usize,
) ?*HashSigKeyPair;

/// Reconstruct a key pair from serialized JSON
extern fn hashsig_keypair_from_json(
    secret_key_json: [*]const u8,
    secret_key_len: usize,
    public_key_json: [*]const u8,
    public_key_len: usize,
) ?*HashSigKeyPair;

/// Free a key pair
extern fn hashsig_keypair_free(keypair: ?*HashSigKeyPair) void;

/// Sign a message
/// Returns pointer to Signature on success, null on error
extern fn hashsig_sign(
    keypair: *const HashSigKeyPair,
    message_ptr: [*]const u8,
    epoch: u32,
) ?*HashSigSignature;

/// Free a signature
extern fn hashsig_signature_free(signature: ?*HashSigSignature) void;

/// Verify a signature
/// Returns 1 if valid, 0 if invalid, -1 on error
extern fn hashsig_verify(
    keypair: *const HashSigKeyPair,
    message_ptr: [*]const u8,
    epoch: u32,
    signature: *const HashSigSignature,
) i32;

/// Get the message length constant
extern fn hashsig_message_length() usize;

/// Serialize a signature to bytes using bincode
extern fn hashsig_signature_to_bytes(
    signature: *const HashSigSignature,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

/// Serialize a public key to bytes using bincode
extern fn hashsig_pubkey_to_bytes(
    keypair: *const HashSigKeyPair,
    buffer: [*]u8,
    buffer_len: usize,
) usize;

/// Verify XMSS signature from bincode-serialized bytes
extern fn hashsig_verify_bincode(
    pubkey_bytes: [*]const u8,
    pubkey_len: usize,
    message: [*]const u8,
    epoch: u32,
    signature_bytes: [*]const u8,
    signature_len: usize,
) i32;

pub const HashSigError = error{ KeyGenerationFailed, SigningFailed, VerificationFailed, InvalidSignature, SerializationFailed, InvalidMessageLength, DeserializationFailed, OutOfMemory };

/// Verify signature using bincode-serialized bytes
pub fn verifyBincode(
    pubkey_bytes: []const u8,
    message: []const u8,
    epoch: u32,
    signature_bytes: []const u8,
) HashSigError!void {
    if (message.len != 32) {
        return HashSigError.InvalidMessageLength;
    }

    const result = hashsig_verify_bincode(
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

        return Self{
            .handle = handle,
            .allocator = allocator,
        };
    }

    /// Reconstruct a key pair from serialized JSON blobs
    pub fn fromJson(
        allocator: Allocator,
        secret_key_json: []const u8,
        public_key_json: []const u8,
    ) HashSigError!Self {
        if (secret_key_json.len == 0 or public_key_json.len == 0) {
            return HashSigError.DeserializationFailed;
        }

        const handle = hashsig_keypair_from_json(
            secret_key_json.ptr,
            secret_key_json.len,
            public_key_json.ptr,
            public_key_json.len,
        ) orelse {
            return HashSigError.DeserializationFailed;
        };

        return Self{
            .handle = handle,
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
            self.handle,
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
            self.handle,
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

    /// Serialize public key to bytes (bincode format)
    pub fn pubkeyToBytes(self: *const Self, buffer: []u8) HashSigError!usize {
        const bytes_written = hashsig_pubkey_to_bytes(
            self.handle,
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

    /// Serialize signature to bytes (bincode format)
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

test "HashSig: generate keypair" {
    const allocator = std.testing.allocator;

    var keypair = try KeyPair.generate(allocator, "test_seed", 0, 2);
    defer keypair.deinit();

    try std.testing.expect(@intFromPtr(keypair.handle) != 0);
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

test "HashSig: bincode serialize and verify" {
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

    // Verify using bincode
    try verifyBincode(
        pubkey_buffer[0..pubkey_size],
        &message,
        epoch,
        &sig_buffer,
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

    // Create invalid signature with all zeros
    var zero_sig_buffer = [_]u8{0} ** 4000;

    // Verification should fail
    const result = verifyBincode(
        pubkey_buffer[0..pubkey_size],
        &message,
        epoch,
        &zero_sig_buffer,
    );

    try std.testing.expectError(HashSigError.VerificationFailed, result);
}
