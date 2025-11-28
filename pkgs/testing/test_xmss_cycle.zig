const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const ssz = @import("ssz");

const testing = @import("signature_helpers.zig");

test "XMSS full cycle: generate, sign, verify" {
    const allocator = std.testing.allocator;

    // Generate a keypair
    var keypair = try xmss.KeyPair.generate(allocator, "test_seed", 0, 10);
    defer keypair.deinit();

    // Create a message
    const message = [_]u8{1} ** 32;

    // Sign the message
    var signature = try keypair.sign(&message, 0);
    defer signature.deinit();

    // Serialize signature
    var sig_buffer: types.SIGBYTES = undefined;
    const sig_size = try signature.toBytes(&sig_buffer);
    std.debug.print("\nSignature size: {d} bytes\n", .{sig_size});

    // Serialize public key
    var pubkey_buffer: [256]u8 = undefined;
    const pubkey_size = try keypair.pubkeyToBytes(&pubkey_buffer);
    std.debug.print("Public key size: {d} bytes\n", .{pubkey_size});

    // Verify using bincode
    try xmss.verifyBincode(
        pubkey_buffer[0..pubkey_size],
        &message,
        0,
        &sig_buffer,
    );

    std.debug.print("Verification succeeded!\n", .{});
}

test "TestKeyManager: sign and verify attestation" {
    const allocator = std.testing.allocator;

    var key_manager = try testing.TestKeyManager.init(allocator, 2, 10);
    defer key_manager.deinit();

    // Create an attestation
    const attestation = types.Attestation{
        .validator_id = 0,
        .data = types.AttestationData{
            .slot = 1,
            .head = .{ .root = [_]u8{0} ** 32, .slot = 0 },
            .target = .{ .root = [_]u8{0} ** 32, .slot = 0 },
            .source = .{ .root = [_]u8{0} ** 32, .slot = 0 },
        },
    };

    // Sign the attestation
    const signature = try key_manager.signAttestation(&attestation, allocator);
    std.debug.print("\nAttestation signature generated\n", .{});

    // Get public key
    var pubkey_buffer: [256]u8 = undefined;
    const pubkey_size = try key_manager.getPublicKeyBytes(0, &pubkey_buffer);
    std.debug.print("Public key size: {d} bytes\n", .{pubkey_size});

    // Hash the attestation
    var message: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.Attestation, attestation, &message, allocator);

    // Verify
    try xmss.verifyBincode(
        pubkey_buffer[0..pubkey_size],
        &message,
        1, // epoch = slot
        &signature,
    );

    std.debug.print("Attestation verification succeeded!\n", .{});
}
