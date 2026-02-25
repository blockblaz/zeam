const std = @import("std");
const Allocator = std.mem.Allocator;
const xmss = @import("@zeam/xmss");
const signature = @import("./signature.zig");

pub const XmssSignature = signature.Signature;

/// Maximum size for signature SSZ encoding buffer
pub const MAX_SSZ_SIZE: usize = xmss.Signature.MAX_SSZ_SIZE;

/// Convert an opaque Rust Signature (from @zeam/xmss) to the Zig XmssSignature Container type.
/// This enables proper SSZ hash_tree_root computation as a Container.
/// Caller owns the returned XmssSignature and must call deinit().
pub fn fromOpaqueSignature(opaque_sig: *const xmss.Signature, allocator: Allocator) !XmssSignature {
    // Serialize to SSZ bytes using Rust FFI
    var buffer: [MAX_SSZ_SIZE]u8 = undefined;
    const sig_len = try opaque_sig.toBytes(&buffer);

    // Deserialize into Zig XmssSignature Container type
    return try XmssSignature.fromSszBytes(buffer[0..sig_len], allocator);
}

// Tests
test "XmssSignature deserialization from opaque" {
    const allocator = std.testing.allocator;

    var keypair = try xmss.KeyPair.generate(allocator, "test_xmss_conversion", 0, 10);
    defer keypair.deinit();

    const message = [_]u8{42} ** 32;
    const epoch: u32 = 0;

    // Sign the message
    var opaque_sig = try keypair.sign(&message, epoch);
    defer opaque_sig.deinit();

    // Convert to XmssSignature Container type (Rust SSZ → Zig struct)
    var xmss_sig = try fromOpaqueSignature(&opaque_sig, allocator);
    defer xmss_sig.deinit();

    // Verify XmssSignature has valid structure
    // For XMSS with LOG_LIFETIME=32: path has ~32 siblings, hashes has ~64 entries
    try std.testing.expect(xmss_sig.path.siblings.len() > 0);
    try std.testing.expect(xmss_sig.hashes.len() > 0);

    // Verify rho has non-zero values (randomness should not be all zeros)
    var rho_has_nonzero = false;
    for (xmss_sig.rho) |val| {
        if (val != 0) {
            rho_has_nonzero = true;
            break;
        }
    }
    try std.testing.expect(rho_has_nonzero);

    // The original opaque signature can still be used for verification
    try keypair.verify(&message, &opaque_sig, epoch);
}

test "XmssSignature hash_tree_root" {
    const allocator = std.testing.allocator;

    var keypair = try xmss.KeyPair.generate(allocator, "test_hash_tree_root", 0, 10);
    defer keypair.deinit();

    const message = [_]u8{123} ** 32;
    const epoch: u32 = 0;

    // Sign the message
    var opaque_sig = try keypair.sign(&message, epoch);
    defer opaque_sig.deinit();

    // Convert to XmssSignature Container type
    var xmss_sig = try fromOpaqueSignature(&opaque_sig, allocator);
    defer xmss_sig.deinit();

    // Compute hash_tree_root as proper SSZ Container
    const root = try xmss_sig.sszRoot(allocator);

    // Verify root is non-zero
    var is_zero = true;
    for (root) |byte| {
        if (byte != 0) {
            is_zero = false;
            break;
        }
    }
    try std.testing.expect(!is_zero);
}
