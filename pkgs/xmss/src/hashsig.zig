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

pub const HashSigError = error{ KeyGenerationFailed, SigningFailed, VerificationFailed, InvalidSignature, SerializationFailed, InvalidMessageLength, OutOfMemory };

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
    ) HashSigError!bool {
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

        return switch (result) {
            1 => true,
            0 => false,
            else => HashSigError.VerificationFailed,
        };
    }

    /// Get the required message length
    pub fn messageLength() usize {
        return hashsig_message_length();
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

    /// Free the signature
    pub fn deinit(self: *Self) void {
        hashsig_signature_free(self.handle);
    }
};
