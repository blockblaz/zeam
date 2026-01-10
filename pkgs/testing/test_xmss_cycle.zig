const std = @import("std");
const hash_zig = @import("hash-zig");
const PoseidonHasher = hash_zig.ssz.SszHasher;
const xmss = @import("@zeam/xmss");
const keymanager = @import("@zeam/key-manager");
const types = @import("@zeam/types");
const ssz = @import("ssz");

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

    // Verify using SSZ
    try xmss.verifySsz(
        pubkey_buffer[0..pubkey_size],
        &message,
        0,
        &sig_buffer,
    );

    std.debug.print("Verification succeeded!\n", .{});
}

test "TestKeyManager: sign and verify attestation" {
    const allocator = std.testing.allocator;

    var key_manager = try keymanager.getTestKeyManager(allocator, 2, 10);
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
    try ssz.hashTreeRoot(PoseidonHasher, types.Attestation, attestation, &message, allocator);

    // Verify
    try xmss.verifySsz(
        pubkey_buffer[0..pubkey_size],
        &message,
        1, // epoch = slot
        &signature,
    );

    std.debug.print("Attestation verification succeeded!\n", .{});
}

test "XMSS aggregation via Zig FFI (phony signatures)" {
    const allocator = std.testing.allocator;

    const log_lifetimes = [_]usize{ 2, 3 };
    const pub_keys = try allocator.alloc(xmss.aggregate.CXmssPublicKey, log_lifetimes.len);
    defer allocator.free(pub_keys);
    const signatures = try allocator.alloc(xmss.aggregate.CXmssSignature, log_lifetimes.len);
    defer allocator.free(signatures);

    var total_merkle_words: usize = 0;
    for (log_lifetimes) |ll| {
        total_merkle_words += ll * 8;
    }
    const merkle_buf = try allocator.alloc(u32, total_merkle_words);
    defer allocator.free(merkle_buf);

    var message_hash: [8]u32 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const slot: u64 = 42;

    try xmss.aggregate.generatePhonySignatures(
        &log_lifetimes,
        &message_hash,
        slot,
        pub_keys,
        signatures,
        merkle_buf,
    );

    xmss.aggregate.setupProver();
    xmss.aggregate.setupVerifier();

    const proof_capacity: usize = 1024 * 1024;
    var proof_buf = try allocator.alloc(u8, proof_capacity);
    defer allocator.free(proof_buf);

    var proof_len: usize = 0;
    try xmss.aggregate.aggregate(
        pub_keys,
        signatures,
        &message_hash,
        slot,
        proof_buf,
        &proof_len,
    );

    try xmss.aggregate.verifyAggregated(
        pub_keys,
        &message_hash,
        proof_buf[0..proof_len],
        slot,
    );
}

test "XMSS aggregation: invalid proof fails" {
    const allocator = std.testing.allocator;

    const log_lifetimes = [_]usize{ 2, 3 };
    const pub_keys = try allocator.alloc(xmss.aggregate.CXmssPublicKey, log_lifetimes.len);
    defer allocator.free(pub_keys);
    const signatures = try allocator.alloc(xmss.aggregate.CXmssSignature, log_lifetimes.len);
    defer allocator.free(signatures);

    var total_merkle_words: usize = 0;
    for (log_lifetimes) |ll| {
        total_merkle_words += ll * 8;
    }
    const merkle_buf = try allocator.alloc(u32, total_merkle_words);
    defer allocator.free(merkle_buf);

    var message_hash: [8]u32 = .{ 7, 6, 5, 4, 3, 2, 1, 0 };
    const slot: u64 = 42;

    try xmss.aggregate.generatePhonySignatures(
        &log_lifetimes,
        &message_hash,
        slot,
        pub_keys,
        signatures,
        merkle_buf,
    );

    xmss.aggregate.setupProver();
    xmss.aggregate.setupVerifier();

    const proof_capacity: usize = 1024 * 1024;
    var proof_buf = try allocator.alloc(u8, proof_capacity);
    defer allocator.free(proof_buf);

    var proof_len: usize = 0;
    try xmss.aggregate.aggregate(
        pub_keys,
        signatures,
        &message_hash,
        slot,
        proof_buf,
        &proof_len,
    );
    try std.testing.expect(proof_len > 0);
    proof_buf[0] ^= 0x01;

    const verify_result = xmss.aggregate.verifyAggregated(
        pub_keys,
        &message_hash,
        proof_buf[0..proof_len],
        slot,
    );
    if (verify_result) |_| {
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expect(
            err == xmss.aggregate.AggregationError.InvalidSignature or
                err == xmss.aggregate.AggregationError.VerificationFailed,
        );
    }
}

test "XMSS aggregation: mismatched counts fail" {
    const allocator = std.testing.allocator;

    const log_lifetimes = [_]usize{ 2, 3 };
    const pub_keys = try allocator.alloc(xmss.aggregate.CXmssPublicKey, log_lifetimes.len);
    defer allocator.free(pub_keys);
    const signatures = try allocator.alloc(xmss.aggregate.CXmssSignature, log_lifetimes.len);
    defer allocator.free(signatures);

    var total_merkle_words: usize = 0;
    for (log_lifetimes) |ll| {
        total_merkle_words += ll * 8;
    }
    const merkle_buf = try allocator.alloc(u32, total_merkle_words);
    defer allocator.free(merkle_buf);

    var message_hash: [8]u32 = .{ 10, 11, 12, 13, 14, 15, 16, 17 };
    const slot: u64 = 100;

    try xmss.aggregate.generatePhonySignatures(
        &log_lifetimes,
        &message_hash,
        slot,
        pub_keys,
        signatures,
        merkle_buf,
    );

    xmss.aggregate.setupProver();
    const proof_capacity: usize = 1024 * 1024;
    const proof_buf = try allocator.alloc(u8, proof_capacity);
    defer allocator.free(proof_buf);
    var proof_len: usize = 0;

    try std.testing.expectError(
        xmss.aggregate.AggregationError.AggregationFailed,
        xmss.aggregate.aggregate(
            pub_keys,
            signatures[0..1],
            &message_hash,
            slot,
            proof_buf,
            &proof_len,
        ),
    );
}

test "XMSS aggregation: invalid log lifetime rejected" {
    const allocator = std.testing.allocator;

    const log_lifetimes = [_]usize{1};
    const pub_keys = try allocator.alloc(xmss.aggregate.CXmssPublicKey, log_lifetimes.len);
    defer allocator.free(pub_keys);
    const signatures = try allocator.alloc(xmss.aggregate.CXmssSignature, log_lifetimes.len);
    defer allocator.free(signatures);
    const merkle_buf = try allocator.alloc(u32, 8);
    defer allocator.free(merkle_buf);

    var message_hash: [8]u32 = .{ 1, 1, 1, 1, 1, 1, 1, 1 };
    const slot: u64 = 1;

    try std.testing.expectError(
        xmss.aggregate.AggregationError.GenerationFailed,
        xmss.aggregate.generatePhonySignatures(
            &log_lifetimes,
            &message_hash,
            slot,
            pub_keys,
            signatures,
            merkle_buf,
        ),
    );
}
