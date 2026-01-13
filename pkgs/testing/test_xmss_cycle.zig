const std = @import("std");
const xmss = @import("@zeam/xmss");
const keymanager = @import("@zeam/key-manager");
const types = @import("@zeam/types");
const ssz = @import("ssz");

const ZERO_HASH = types.ZERO_HASH;

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
            .head = .{ .root = ZERO_HASH, .slot = 0 },
            .target = .{ .root = ZERO_HASH, .slot = 0 },
            .source = .{ .root = ZERO_HASH, .slot = 0 },
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
    try ssz.hashTreeRoot(types.AttestationData, attestation.data, &message, allocator);

    // Verify
    try xmss.verifySsz(
        pubkey_buffer[0..pubkey_size],
        &message,
        1, // epoch = slot
        &signature,
    );

    std.debug.print("Attestation verification succeeded!\n", .{});
}

test "XMSS aggregation with hashsig-glue signatures" {
    const allocator = std.testing.allocator;

    // Generate multiple keypairs using hashsig-glue
    const num_validators = 3;
    var keypairs = std.ArrayList(xmss.KeyPair).init(allocator);
    defer {
        for (keypairs.items) |*kp| {
            kp.deinit();
        }
        keypairs.deinit();
    }

    // Message to sign
    var message: [32]u8 = [_]u8{42} ** 32;
    const epoch: u32 = 5;

    // Generate keypairs with different seeds
    var i: usize = 0;
    while (i < num_validators) : (i += 1) {
        const seed = try std.fmt.allocPrint(allocator, "validator_{d}", .{i});
        defer allocator.free(seed);

        const kp = try xmss.KeyPair.generate(allocator, seed, 0, 10);
        try keypairs.append(kp);
    }

    // Sign the message with each keypair
    var signatures = std.ArrayList(xmss.Signature).init(allocator);
    defer {
        for (signatures.items) |*sig| {
            sig.deinit();
        }
        signatures.deinit();
    }

    for (keypairs.items) |*kp| {
        const sig = try kp.sign(&message, epoch);
        try signatures.append(sig);
    }

    std.debug.print("\nGenerated {d} signatures with hashsig-glue\n", .{num_validators});

    // Extract keypair and signature handles (opaque pointers)
    var keypair_handles = std.ArrayList(*const anyopaque).init(allocator);
    defer keypair_handles.deinit();
    for (keypairs.items) |*kp| {
        try keypair_handles.append(@ptrCast(kp.handle));
    }

    var signature_handles = std.ArrayList(*const anyopaque).init(allocator);
    defer signature_handles.deinit();
    for (signatures.items) |*sig| {
        try signature_handles.append(@ptrCast(sig.handle));
    }

    std.debug.print("Extracted keypair and signature handles\n", .{});

    // Setup aggregation
    xmss.aggregate.setupProver();
    xmss.aggregate.setupVerifier();

    // Aggregate signatures - returns opaque handle
    const agg_sig = try xmss.aggregate.aggregate(
        keypair_handles.items,
        signature_handles.items,
        &message,
        epoch,
        allocator,
    );
    defer agg_sig.deinit();

    std.debug.print("Aggregated signature (opaque handle, no bytes copied!)\n", .{});

    // Verify aggregated signature - takes opaque handle
    try xmss.aggregate.verifyAggregated(
        keypair_handles.items,
        &message,
        agg_sig,
        epoch,
    );

    std.debug.print("Aggregation verification succeeded!\n", .{});
}

test "XMSS aggregation with hashsig: wrong public keys fail" {
    const allocator = std.testing.allocator;

    // Generate keypairs using hashsig-glue
    const num_validators = 2;
    var keypairs = std.ArrayList(xmss.KeyPair).init(allocator);
    defer {
        for (keypairs.items) |*kp| {
            kp.deinit();
        }
        keypairs.deinit();
    }

    var message: [32]u8 = [_]u8{99} ** 32;
    const epoch: u32 = 3;

    // Generate keypairs and signatures
    var i: usize = 0;
    while (i < num_validators) : (i += 1) {
        const seed = try std.fmt.allocPrint(allocator, "validator_{d}", .{i});
        defer allocator.free(seed);
        const kp = try xmss.KeyPair.generate(allocator, seed, 0, 10);
        try keypairs.append(kp);
    }

    var signatures = std.ArrayList(xmss.Signature).init(allocator);
    defer {
        for (signatures.items) |*sig| {
            sig.deinit();
        }
        signatures.deinit();
    }

    for (keypairs.items) |*kp| {
        const sig = try kp.sign(&message, epoch);
        try signatures.append(sig);
    }

    // Extract keypair and signature handles
    var keypair_handles = std.ArrayList(*const anyopaque).init(allocator);
    defer keypair_handles.deinit();
    for (keypairs.items) |*kp| {
        try keypair_handles.append(@ptrCast(kp.handle));
    }

    var signature_handles = std.ArrayList(*const anyopaque).init(allocator);
    defer signature_handles.deinit();
    for (signatures.items) |*sig| {
        try signature_handles.append(@ptrCast(sig.handle));
    }

    xmss.aggregate.setupProver();
    xmss.aggregate.setupVerifier();

    // Aggregate signatures
    const agg_sig = try xmss.aggregate.aggregate(
        keypair_handles.items,
        signature_handles.items,
        &message,
        epoch,
        allocator,
    );
    defer agg_sig.deinit();

    // Create completely different keypairs that didn't sign this message
    var wrong_keypairs = std.ArrayList(xmss.KeyPair).init(allocator);
    defer {
        for (wrong_keypairs.items) |*kp| {
            kp.deinit();
        }
        wrong_keypairs.deinit();
    }

    i = 0;
    while (i < num_validators) : (i += 1) {
        const seed = try std.fmt.allocPrint(allocator, "wrong_validator_{d}", .{i + 1});
        defer allocator.free(seed);
        const kp = try xmss.KeyPair.generate(allocator, seed, 0, 10);
        try wrong_keypairs.append(kp);
    }

    var wrong_keypair_handles = std.ArrayList(*const anyopaque).init(allocator);
    defer wrong_keypair_handles.deinit();
    for (wrong_keypairs.items) |*kp| {
        try wrong_keypair_handles.append(@ptrCast(kp.handle));
    }

    // Verification should fail with wrong public keys
    var verify_result = xmss.aggregate.verifyAggregated(
        wrong_keypair_handles.items,
        &message,
        agg_sig,
        epoch,
    );

    if (verify_result) |_| {
        std.debug.print("ERROR: Verification succeeded with wrong public keys!\n", .{});
        try std.testing.expect(false); // Should not succeed
    } else |err| {
        std.debug.print("Good: Verification failed with wrong keys: {}\n", .{err});
        try std.testing.expect(
            err == xmss.aggregate.AggregationError.InvalidSignature or
                err == xmss.aggregate.AggregationError.VerificationFailed,
        );
    }

    // Verification should fail with wrong message
    const wrong_message = [_]u8{100} ** 32;
    verify_result = xmss.aggregate.verifyAggregated(
        keypair_handles.items,
        &wrong_message,
        agg_sig,
        epoch,
    );

    if (verify_result) |_| {
        std.debug.print("ERROR: Verification succeeded with wrong message!\n", .{});
        try std.testing.expect(false); // Should not succeed
    } else |err| {
        std.debug.print("Good: Verification failed with wrong message: {}\n", .{err});
        try std.testing.expect(
            err == xmss.aggregate.AggregationError.InvalidSignature or
                err == xmss.aggregate.AggregationError.VerificationFailed,
        );
    }

    // Verification should fail with wrong epoch
    const wrong_epoch = epoch + 1;
    verify_result = xmss.aggregate.verifyAggregated(
        keypair_handles.items,
        &message,
        agg_sig,
        wrong_epoch,
    );

    if (verify_result) |_| {
        std.debug.print("ERROR: Verification succeeded with wrong epoch!\n", .{});
        try std.testing.expect(false); // Should not succeed
    } else |err| {
        std.debug.print("Good: Verification failed with wrong epoch: {}\n", .{err});
        try std.testing.expect(err == xmss.aggregate.AggregationError.InvalidSignature or err == xmss.aggregate.AggregationError.VerificationFailed);
    }
}
