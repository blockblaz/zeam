const libssz = @import("lib.zig");
const utils = libssz.utils;
const serialize = libssz.serialize;
const deserialize = libssz.deserialize;
const hashTreeRoot = libssz.hashTreeRoot;
const std = @import("std");
const ArrayList = std.ArrayList;
const expect = std.testing.expect;
const Sha256 = std.crypto.hash.sha2.Sha256;

// Beacon chain Validator struct for compatibility testing
const Validator = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
};

test "Validator struct serialization" {
    const validator = Validator{
        .pubkey = [_]u8{0xAA} ** 48,
        .withdrawal_credentials = [_]u8{0xBB} ** 32,
        .effective_balance = 32000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 18446744073709551615, // Max u64
        .withdrawable_epoch = 18446744073709551615, // Max u64
    };

    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try serialize(Validator, validator, &list, std.testing.allocator);

    // Verify expected size: 48 + 32 + 8 + 1 + 8 + 8 + 8 + 8 = 121 bytes
    try expect(list.items.len == 121);

    // Test round-trip serialization
    var deserialized: Validator = undefined;
    try deserialize(Validator, list.items, &deserialized, std.testing.allocator);

    try expect(std.mem.eql(u8, &validator.pubkey, &deserialized.pubkey));
    try expect(std.mem.eql(u8, &validator.withdrawal_credentials, &deserialized.withdrawal_credentials));
    try expect(validator.effective_balance == deserialized.effective_balance);
    try expect(validator.slashed == deserialized.slashed);
    try expect(validator.activation_eligibility_epoch == deserialized.activation_eligibility_epoch);
    try expect(validator.activation_epoch == deserialized.activation_epoch);
    try expect(validator.exit_epoch == deserialized.exit_epoch);
    try expect(validator.withdrawable_epoch == deserialized.withdrawable_epoch);
}

test "Validator struct hash tree root" {
    const validator = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x02} ** 32,
        .effective_balance = 32000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    var hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, Validator, validator, &hash, std.testing.allocator);

    // Validate against expected hash
    const expected_validator_hash = [_]u8{ 0x70, 0x68, 0xE5, 0x06, 0xCB, 0xFF, 0xCD, 0x31, 0xBD, 0x2D, 0x13, 0x42, 0x5E, 0x4F, 0xDE, 0x98, 0x6E, 0xF3, 0x5E, 0x6F, 0xB5, 0x0F, 0x35, 0x9D, 0x7A, 0x26, 0xB6, 0x33, 0x2E, 0xE2, 0xCB, 0x94 };
    try expect(std.mem.eql(u8, &hash, &expected_validator_hash));

    // Hash should be deterministic for the same validator
    var hash2: [32]u8 = undefined;
    try hashTreeRoot(Sha256, Validator, validator, &hash2, std.testing.allocator);
    try expect(std.mem.eql(u8, &hash, &hash2));

    // Different validator should produce different hash
    const validator2 = Validator{
        .pubkey = [_]u8{0xFF} ** 48,
        .withdrawal_credentials = [_]u8{0x02} ** 32,
        .effective_balance = 32000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    var hash3: [32]u8 = undefined;
    try hashTreeRoot(Sha256, Validator, validator2, &hash3, std.testing.allocator);
    try expect(!std.mem.eql(u8, &hash, &hash3));
}

test "Individual Validator serialization and hash" {
    // Test individual validator
    const validator = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x02} ** 32,
        .effective_balance = 32000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    // Test serialization
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try serialize(Validator, validator, &list, std.testing.allocator);

    // Validate against expected bytes
    const expected_validator_bytes = [_]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x00, 0x40, 0x59, 0x73, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, list.items, &expected_validator_bytes));

    // Test hash tree root
    var root: [32]u8 = undefined;
    try hashTreeRoot(Sha256, Validator, validator, &root, std.testing.allocator);

    // Validate against expected hash
    const expected_validator_hash = [_]u8{ 0x70, 0x68, 0xE5, 0x06, 0xCB, 0xFF, 0xCD, 0x31, 0xBD, 0x2D, 0x13, 0x42, 0x5E, 0x4F, 0xDE, 0x98, 0x6E, 0xF3, 0x5E, 0x6F, 0xB5, 0x0F, 0x35, 0x9D, 0x7A, 0x26, 0xB6, 0x33, 0x2E, 0xE2, 0xCB, 0x94 };
    try expect(std.mem.eql(u8, &root, &expected_validator_hash));
}

test "List[Validator] serialization and hash tree root" {
    const MAX_VALIDATORS = 100;
    const ValidatorList = utils.List(Validator, MAX_VALIDATORS);

    var validator_list = try ValidatorList.init(std.testing.allocator);
    defer validator_list.deinit();

    // Add test validators
    const validator1 = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x11} ** 32,
        .effective_balance = 32000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 18446744073709551615,
        .withdrawable_epoch = 18446744073709551615,
    };

    const validator2 = Validator{
        .pubkey = [_]u8{0x02} ** 48,
        .withdrawal_credentials = [_]u8{0x22} ** 32,
        .effective_balance = 31000000000,
        .slashed = false,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 1,
        .exit_epoch = 18446744073709551615,
        .withdrawable_epoch = 18446744073709551615,
    };

    try validator_list.append(validator1);
    try validator_list.append(validator2);

    // Test serialization
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try serialize(ValidatorList, validator_list, &list, std.testing.allocator);

    // Validate against expected bytes
    const expected_validator_list_bytes = [_]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x40, 0x59, 0x73, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x76, 0xBE, 0x37, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try expect(std.mem.eql(u8, list.items, &expected_validator_list_bytes));

    // Test deserialization
    var deserialized_list = try ValidatorList.init(std.testing.allocator);
    defer deserialized_list.deinit();
    try deserialize(ValidatorList, list.items, &deserialized_list, std.testing.allocator);

    try expect(validator_list.len() == deserialized_list.len());
    try expect(validator_list.len() == 2);

    // Verify each validator was deserialized correctly
    for (0..validator_list.len()) |i| {
        const orig = try validator_list.get(i);
        const deser = try deserialized_list.get(i);

        try expect(std.mem.eql(u8, &orig.pubkey, &deser.pubkey));
        try expect(std.mem.eql(u8, &orig.withdrawal_credentials, &deser.withdrawal_credentials));
        try expect(orig.effective_balance == deser.effective_balance);
        try expect(orig.slashed == deser.slashed);
        try expect(orig.activation_eligibility_epoch == deser.activation_eligibility_epoch);
        try expect(orig.activation_epoch == deser.activation_epoch);
        try expect(orig.exit_epoch == deser.exit_epoch);
        try expect(orig.withdrawable_epoch == deser.withdrawable_epoch);
    }

    // Test hash tree root
    var hash1: [32]u8 = undefined;
    try hashTreeRoot(Sha256, ValidatorList, validator_list, &hash1, std.testing.allocator);

    // Validate against expected hash
    const expected_validator_list_hash = [_]u8{ 0x54, 0x80, 0xF8, 0x35, 0xD7, 0x52, 0xF7, 0x27, 0xC8, 0xF1, 0xE9, 0xCC, 0x0F, 0x84, 0x2B, 0x25, 0x76, 0xA5, 0x1A, 0xD2, 0xB7, 0xB5, 0x10, 0xF1, 0xA5, 0x39, 0xF7, 0xD8, 0xD0, 0x87, 0xC3, 0xC2 };
    try expect(std.mem.eql(u8, &hash1, &expected_validator_list_hash));

    var hash2: [32]u8 = undefined;
    try hashTreeRoot(Sha256, ValidatorList, deserialized_list, &hash2, std.testing.allocator);

    // Hash should be the same for original and deserialized lists
    try expect(std.mem.eql(u8, &hash1, &hash2));
}

// BeamBlockBody types for testing
const MAX_VALIDATORS_IN_BLOCK = 50;
const ValidatorArray = utils.List(Validator, MAX_VALIDATORS_IN_BLOCK);
const BeamBlockBody = struct {
    validators: ValidatorArray,
};

test "BeamBlockBody with validator array - full cycle" {
    // Create test validators
    const validator1 = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x11} ** 32,
        .effective_balance = 32000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 18446744073709551615,
        .withdrawable_epoch = 18446744073709551615,
    };

    const validator2 = Validator{
        .pubkey = [_]u8{0x02} ** 48,
        .withdrawal_credentials = [_]u8{0x22} ** 32,
        .effective_balance = 31000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    // Create validator array
    var validators = try ValidatorArray.init(std.testing.allocator);
    defer validators.deinit();
    try validators.append(validator1);
    try validators.append(validator2);

    // Create BeamBlockBody
    const beam_block_body = BeamBlockBody{
        .validators = validators,
    };

    // Test serialization
    var serialized_data: ArrayList(u8) = .empty;
    defer serialized_data.deinit(std.testing.allocator);
    try serialize(BeamBlockBody, beam_block_body, &serialized_data, std.testing.allocator);

    // Validate against expected bytes
    const expected_beam_block_body_bytes = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x40, 0x59, 0x73, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x76, 0xBE, 0x37, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, serialized_data.items, &expected_beam_block_body_bytes));

    // Test deserialization
    var deserialized_body: BeamBlockBody = undefined;
    deserialized_body.validators = try ValidatorArray.init(std.testing.allocator);
    defer deserialized_body.validators.deinit();
    try deserialize(BeamBlockBody, serialized_data.items, &deserialized_body, std.testing.allocator);

    // Verify deserialization correctness
    try expect(beam_block_body.validators.len() == deserialized_body.validators.len());
    try expect(beam_block_body.validators.len() == 2);

    for (0..beam_block_body.validators.len()) |i| {
        const orig = try beam_block_body.validators.get(i);
        const deser = try deserialized_body.validators.get(i);

        try expect(std.mem.eql(u8, &orig.pubkey, &deser.pubkey));
        try expect(std.mem.eql(u8, &orig.withdrawal_credentials, &deser.withdrawal_credentials));
        try expect(orig.effective_balance == deser.effective_balance);
        try expect(orig.slashed == deser.slashed);
        try expect(orig.activation_eligibility_epoch == deser.activation_eligibility_epoch);
        try expect(orig.activation_epoch == deser.activation_epoch);
        try expect(orig.exit_epoch == deser.exit_epoch);
        try expect(orig.withdrawable_epoch == deser.withdrawable_epoch);
    }

    // Test hash tree root consistency
    var hash_original: [32]u8 = undefined;
    try hashTreeRoot(Sha256, BeamBlockBody, beam_block_body, &hash_original, std.testing.allocator);

    // Validate against expected hash
    const expected_beam_block_body_hash = [_]u8{ 0x34, 0xF2, 0xBC, 0x58, 0xA0, 0xBF, 0x20, 0x72, 0x43, 0xF8, 0xC2, 0x5E, 0x0F, 0x83, 0x5E, 0x36, 0x90, 0x73, 0xD5, 0xAC, 0x97, 0x1E, 0x9A, 0x53, 0x71, 0x14, 0xA0, 0xFD, 0x1C, 0xC8, 0xD8, 0xE4 };
    try expect(std.mem.eql(u8, &hash_original, &expected_beam_block_body_hash));

    var hash_deserialized: [32]u8 = undefined;
    try hashTreeRoot(Sha256, BeamBlockBody, deserialized_body, &hash_deserialized, std.testing.allocator);

    // Hashes should be identical for original and deserialized data
    try expect(std.mem.eql(u8, &hash_original, &hash_deserialized));

    // Test hash determinism
    var hash_duplicate: [32]u8 = undefined;
    try hashTreeRoot(Sha256, BeamBlockBody, beam_block_body, &hash_duplicate, std.testing.allocator);
    try expect(std.mem.eql(u8, &hash_original, &hash_duplicate));
}

test "Zeam-style List/Bitlist usage with tree root stability" {
    const MAX_VALIDATORS = 2048;
    const MAX_HISTORICAL_BLOCK_HASHES = 4096;

    const Root = [32]u8;

    const Mini3SFCheckpoint = struct {
        root: Root,
        slot: u64,
    };

    const Mini3SFVote = struct {
        validator_id: u64,
        slot: u64,
        head: Mini3SFCheckpoint,
        target: Mini3SFCheckpoint,
        source: Mini3SFCheckpoint,
    };

    const Mini3SFVotes = utils.List(Mini3SFVote, MAX_VALIDATORS);
    const HistoricalBlockHashes = utils.List(Root, MAX_HISTORICAL_BLOCK_HASHES);
    const JustifiedSlots = utils.Bitlist(MAX_HISTORICAL_BLOCK_HASHES);

    const ZeamBeamBlockBody = struct {
        votes: Mini3SFVotes,
    };

    const BeamState = struct {
        slot: u64,
        historical_block_hashes: HistoricalBlockHashes,
        justified_slots: JustifiedSlots,
    };

    var votes = try Mini3SFVotes.init(std.testing.allocator);
    defer votes.deinit();
    try votes.append(Mini3SFVote{
        .validator_id = 1,
        .slot = 10,
        .head = Mini3SFCheckpoint{ .root = [_]u8{1} ** 32, .slot = 10 },
        .target = Mini3SFCheckpoint{ .root = [_]u8{2} ** 32, .slot = 9 },
        .source = Mini3SFCheckpoint{ .root = [_]u8{3} ** 32, .slot = 8 },
    });

    var hashes = try HistoricalBlockHashes.init(std.testing.allocator);
    defer hashes.deinit();
    try hashes.append([_]u8{0xaa} ** 32);
    try hashes.append([_]u8{0xbb} ** 32);

    var bitlist = try JustifiedSlots.init(std.testing.allocator);
    defer bitlist.deinit();
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);

    const body = ZeamBeamBlockBody{ .votes = votes };
    const state = BeamState{
        .slot = 42,
        .historical_block_hashes = hashes,
        .justified_slots = bitlist,
    };

    // Test serialization
    var body_serialized: ArrayList(u8) = .empty;
    defer body_serialized.deinit(std.testing.allocator);
    try serialize(ZeamBeamBlockBody, body, &body_serialized, std.testing.allocator);

    var state_serialized: ArrayList(u8) = .empty;
    defer state_serialized.deinit(std.testing.allocator);
    try serialize(BeamState, state, &state_serialized, std.testing.allocator);

    // Validate against expected bytes
    const expected_zeam_body_bytes = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, body_serialized.items, &expected_zeam_body_bytes));

    const expected_zeam_state_bytes = [_]u8{ 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x0D };

    try expect(std.mem.eql(u8, state_serialized.items, &expected_zeam_state_bytes));

    // Test hash tree root determinism and validate against expected hashes
    var body_hash1: [32]u8 = undefined;
    var body_hash2: [32]u8 = undefined;
    var state_hash1: [32]u8 = undefined;
    var state_hash2: [32]u8 = undefined;

    try hashTreeRoot(Sha256, ZeamBeamBlockBody, body, &body_hash1, std.testing.allocator);
    try hashTreeRoot(Sha256, ZeamBeamBlockBody, body, &body_hash2, std.testing.allocator);
    try hashTreeRoot(Sha256, BeamState, state, &state_hash1, std.testing.allocator);
    try hashTreeRoot(Sha256, BeamState, state, &state_hash2, std.testing.allocator);

    // Validate against expected hashes
    const expected_zeam_body_hash = [_]u8{ 0xAA, 0x2C, 0x76, 0x39, 0x96, 0xA6, 0xDD, 0x26, 0x25, 0x13, 0x12, 0x8D, 0xEA, 0xDF, 0xCB, 0x69, 0xF1, 0xEC, 0xEB, 0x60, 0xA8, 0xFF, 0xAC, 0xC7, 0xA7, 0xE4, 0x28, 0x3C, 0x74, 0xAA, 0x6A, 0xE4 };
    const expected_zeam_state_hash = [_]u8{ 0x3B, 0x61, 0xA7, 0x99, 0x37, 0xF0, 0x69, 0x79, 0x7D, 0x86, 0x41, 0xCA, 0x75, 0x25, 0x26, 0x5D, 0x54, 0x74, 0x5E, 0xB8, 0x2A, 0xA2, 0x1F, 0x20, 0xFA, 0x1D, 0x8A, 0x71, 0x02, 0x87, 0xF9, 0xD7 };

    try expect(std.mem.eql(u8, &body_hash1, &body_hash2));
    try expect(std.mem.eql(u8, &state_hash1, &state_hash2));
    try expect(std.mem.eql(u8, &body_hash1, &expected_zeam_body_hash));
    try expect(std.mem.eql(u8, &state_hash1, &expected_zeam_state_hash));
}

test "BeamState with historical roots - comprehensive test" {
    const MAX_HISTORICAL_ROOTS = 10;

    const Root = [32]u8;

    // BeamState structure with historical roots
    const BeamState = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Root,
        state_root: Root,
        historical_roots: utils.List(Root, MAX_HISTORICAL_ROOTS),
        validator_count: u64,
        justified_checkpoint_root: Root,
        finalized_checkpoint_root: Root,
    };

    var historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer historical_roots.deinit();

    try historical_roots.append([_]u8{0x01} ** 32);
    try historical_roots.append([_]u8{0x02} ** 32);
    try historical_roots.append([_]u8{0x03} ** 32);
    try historical_roots.append([_]u8{0xAA} ** 32);
    try historical_roots.append([_]u8{0xBB} ** 32);
    try historical_roots.append([_]u8{0xCC} ** 32);
    try historical_roots.append([_]u8{0xDD} ** 32);
    try historical_roots.append([_]u8{0xEE} ** 32);
    try historical_roots.append([_]u8{0xFF} ** 32);
    try historical_roots.append([_]u8{0x00} ** 32);

    // Create BeamState instance
    const beam_state = BeamState{
        .slot = 12345,
        .proposer_index = 42,
        .parent_root = [_]u8{0x11} ** 32,
        .state_root = [_]u8{0x22} ** 32,
        .historical_roots = historical_roots,
        .validator_count = 1000,
        .justified_checkpoint_root = [_]u8{0x33} ** 32,
        .finalized_checkpoint_root = [_]u8{0x44} ** 32,
    };

    // Test serialization
    var serialized_data: ArrayList(u8) = .empty;
    defer serialized_data.deinit(std.testing.allocator);
    try serialize(BeamState, beam_state, &serialized_data, std.testing.allocator);

    // Validate against expected bytes
    const expected_comprehensive_beam_state_bytes = [_]u8{ 0x39, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x9C, 0x00, 0x00, 0x00, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, serialized_data.items, &expected_comprehensive_beam_state_bytes));

    // Test hash tree root calculation
    var original_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, BeamState, beam_state, &original_hash, std.testing.allocator);

    // Validate against expected hash
    const expected_comprehensive_beam_state_hash = [_]u8{ 0xBD, 0x36, 0x59, 0x5E, 0x3B, 0x4A, 0x51, 0x9C, 0xF3, 0x5F, 0x4F, 0x96, 0x88, 0x9E, 0x86, 0x10, 0xFF, 0x45, 0x20, 0x49, 0x15, 0xAE, 0x96, 0x2E, 0xF4, 0x0C, 0x81, 0x6B, 0xF7, 0x45, 0x4A, 0x17 };
    try expect(std.mem.eql(u8, &original_hash, &expected_comprehensive_beam_state_hash));

    // Test deserialization
    var deserialized_state: BeamState = undefined;
    deserialized_state.historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer deserialized_state.historical_roots.deinit();
    try deserialize(BeamState, serialized_data.items, &deserialized_state, std.testing.allocator);

    // Verify all fields match
    try expect(beam_state.slot == deserialized_state.slot);
    try expect(beam_state.proposer_index == deserialized_state.proposer_index);
    try expect(beam_state.validator_count == deserialized_state.validator_count);

    // Verify root fields
    try expect(std.mem.eql(u8, &beam_state.parent_root, &deserialized_state.parent_root));
    try expect(std.mem.eql(u8, &beam_state.state_root, &deserialized_state.state_root));
    try expect(std.mem.eql(u8, &beam_state.justified_checkpoint_root, &deserialized_state.justified_checkpoint_root));
    try expect(std.mem.eql(u8, &beam_state.finalized_checkpoint_root, &deserialized_state.finalized_checkpoint_root));

    // Verify historical roots list
    try expect(beam_state.historical_roots.len() == deserialized_state.historical_roots.len());
    try expect(beam_state.historical_roots.len() == 10);

    // Compare each historical root
    for (0..beam_state.historical_roots.len()) |i| {
        const original_root = try beam_state.historical_roots.get(i);
        const deserialized_root = try deserialized_state.historical_roots.get(i);
        try expect(std.mem.eql(u8, &original_root, &deserialized_root));
    }

    // Test hash tree root consistency
    var deserialized_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, BeamState, deserialized_state, &deserialized_hash, std.testing.allocator);

    // Verify hash tree roots are identical
    try expect(std.mem.eql(u8, &original_hash, &deserialized_hash));
}

test "BeamState with empty historical roots" {
    const MAX_HISTORICAL_ROOTS = 8192;

    const Root = [32]u8;

    const SimpleBeamState = struct {
        slot: u64,
        historical_roots: utils.List(Root, MAX_HISTORICAL_ROOTS),
        validator_count: u64,
    };

    // Create BeamState with empty historical roots
    var empty_historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer empty_historical_roots.deinit();

    const beam_state = SimpleBeamState{
        .slot = 0,
        .historical_roots = empty_historical_roots,
        .validator_count = 0,
    };

    // Test serialization
    var serialized_data: ArrayList(u8) = .empty;
    defer serialized_data.deinit(std.testing.allocator);
    try serialize(SimpleBeamState, beam_state, &serialized_data, std.testing.allocator);

    // Validate against expected bytes
    const expected_empty_beam_state_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, serialized_data.items, &expected_empty_beam_state_bytes));

    // Test hash tree root calculation
    var original_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, SimpleBeamState, beam_state, &original_hash, std.testing.allocator);

    // Validate against actual hash
    const expected_empty_beam_state_hash = [_]u8{ 0x58, 0xD2, 0x2B, 0xA0, 0x04, 0x45, 0xE8, 0xB7, 0x39, 0x5E, 0xC3, 0x93, 0x92, 0x45, 0xC6, 0xF1, 0x5A, 0x29, 0x91, 0xA5, 0x70, 0x3F, 0xC5, 0x05, 0x88, 0x10, 0x57, 0xDE, 0x9D, 0xF3, 0x64, 0x10 };

    try expect(std.mem.eql(u8, &original_hash, &expected_empty_beam_state_hash));

    // Test deserialization
    var deserialized_state: SimpleBeamState = undefined;
    deserialized_state.historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer deserialized_state.historical_roots.deinit();
    try deserialize(SimpleBeamState, serialized_data.items, &deserialized_state, std.testing.allocator);

    // Verify all fields match
    try expect(beam_state.slot == deserialized_state.slot);
    try expect(beam_state.validator_count == deserialized_state.validator_count);
    try expect(beam_state.historical_roots.len() == deserialized_state.historical_roots.len());
    try expect(beam_state.historical_roots.len() == 0);

    // Test hash tree root consistency
    var deserialized_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, SimpleBeamState, deserialized_state, &deserialized_hash, std.testing.allocator);

    // Verify hash tree roots are identical
    try expect(std.mem.eql(u8, &original_hash, &deserialized_hash));
}

test "BeamState with maximum historical roots" {
    const MAX_HISTORICAL_ROOTS = 1024;

    const Root = [32]u8;

    const MaxBeamState = struct {
        slot: u64,
        historical_roots: utils.List(Root, MAX_HISTORICAL_ROOTS),
    };

    // Create BeamState with maximum historical roots
    var max_historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer max_historical_roots.deinit();

    // Fill to maximum capacity
    for (0..MAX_HISTORICAL_ROOTS) |i| {
        var root: Root = undefined;
        // Create unique root for each index
        for (0..32) |j| {
            root[j] = @truncate((i * 32 + j) % 256);
        }
        try max_historical_roots.append(root);
    }

    const beam_state = MaxBeamState{
        .slot = 999999,
        .historical_roots = max_historical_roots,
    };

    // Test serialization
    var serialized_data: ArrayList(u8) = .empty;
    defer serialized_data.deinit(std.testing.allocator);
    try serialize(MaxBeamState, beam_state, &serialized_data, std.testing.allocator);

    // Validate against expected bytes (first few bytes)
    const expected_max_beam_state_bytes_start = [_]u8{ 0x3F, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, serialized_data.items[0..12], &expected_max_beam_state_bytes_start));

    // Test hash tree root calculation
    var original_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, MaxBeamState, beam_state, &original_hash, std.testing.allocator);

    // Validate against actual hash
    const expected_max_beam_state_hash = [_]u8{ 0x3F, 0xFC, 0x7A, 0xA4, 0x85, 0x21, 0xD4, 0x02, 0x36, 0x46, 0x19, 0x2E, 0x8D, 0x73, 0xBC, 0x11, 0x3D, 0x1D, 0xE7, 0xF4, 0xDE, 0xC4, 0xD9, 0x6E, 0x94, 0x52, 0xD2, 0xCB, 0x95, 0xE3, 0x22, 0x9A };

    try expect(std.mem.eql(u8, &original_hash, &expected_max_beam_state_hash));

    // Test deserialization
    var deserialized_state: MaxBeamState = undefined;
    deserialized_state.historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer deserialized_state.historical_roots.deinit();
    try deserialize(MaxBeamState, serialized_data.items, &deserialized_state, std.testing.allocator);

    // Verify maximum capacity
    try expect(deserialized_state.historical_roots.len() == MAX_HISTORICAL_ROOTS);
    try expect(beam_state.historical_roots.len() == deserialized_state.historical_roots.len());

    // Compare each root
    for (0..MAX_HISTORICAL_ROOTS) |i| {
        const original_root = try beam_state.historical_roots.get(i);
        const deserialized_root = try deserialized_state.historical_roots.get(i);
        try expect(std.mem.eql(u8, &original_root, &deserialized_root));
    }

    // Test hash tree root consistency
    var deserialized_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, MaxBeamState, deserialized_state, &deserialized_hash, std.testing.allocator);

    try expect(std.mem.eql(u8, &original_hash, &deserialized_hash));
}

test "BeamState historical roots access and comparison" {
    const MAX_HISTORICAL_ROOTS = 50;

    const Root = [32]u8;

    const AccessBeamState = struct {
        slot: u64,
        historical_roots: utils.List(Root, MAX_HISTORICAL_ROOTS),
        metadata: u64,
    };

    var historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer historical_roots.deinit();

    // Add roots with specific patterns
    const test_patterns = [_][32]u8{
        [_]u8{0x00} ** 32,
        [_]u8{0xFF} ** 32,
        [_]u8{0xAA} ** 32,
        [_]u8{0x55} ** 32,
        [_]u8{0x12} ** 32,
        [_]u8{0x34} ** 32,
        [_]u8{0x56} ** 32,
        [_]u8{0x78} ** 32,
        [_]u8{0x9A} ** 32,
        [_]u8{0xBC} ** 32,
    };

    for (test_patterns) |pattern| {
        try historical_roots.append(pattern);
    }

    const beam_state = AccessBeamState{
        .slot = 54321,
        .historical_roots = historical_roots,
        .metadata = 0xDEADBEEF,
    };

    // Test serialization
    var serialized_data: ArrayList(u8) = .empty;
    defer serialized_data.deinit(std.testing.allocator);
    try serialize(AccessBeamState, beam_state, &serialized_data, std.testing.allocator);

    // Validate against expected bytes
    const expected_access_beam_state_bytes = [_]u8{ 0x31, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC };
    try expect(std.mem.eql(u8, serialized_data.items, &expected_access_beam_state_bytes));

    // Test hash tree root calculation
    var original_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, AccessBeamState, beam_state, &original_hash, std.testing.allocator);

    // Validate against expected hash
    const expected_access_beam_state_hash = [_]u8{ 0x22, 0x3E, 0xCB, 0xDD, 0x62, 0x46, 0x7F, 0x7F, 0x0F, 0xA8, 0x2C, 0x91, 0x54, 0x1F, 0xF4, 0xEA, 0xBF, 0x92, 0xB6, 0xB7, 0x67, 0x57, 0x02, 0x67, 0x16, 0xEF, 0x3A, 0xB0, 0x96, 0x4E, 0x91, 0x9E };
    try expect(std.mem.eql(u8, &original_hash, &expected_access_beam_state_hash));

    // Test deserialization
    var deserialized_state: AccessBeamState = undefined;
    deserialized_state.historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer deserialized_state.historical_roots.deinit();
    try deserialize(AccessBeamState, serialized_data.items, &deserialized_state, std.testing.allocator);

    // Test individual root access and comparison
    for (0..test_patterns.len) |i| {
        const original_root = try beam_state.historical_roots.get(i);
        const deserialized_root = try deserialized_state.historical_roots.get(i);
        const expected_pattern = test_patterns[i];

        // Verify root matches expected pattern
        try expect(std.mem.eql(u8, &original_root, &expected_pattern));
        try expect(std.mem.eql(u8, &deserialized_root, &expected_pattern));
        try expect(std.mem.eql(u8, &original_root, &deserialized_root));
    }

    // Test edge cases
    try expect(beam_state.historical_roots.len() == test_patterns.len);
    try expect(deserialized_state.historical_roots.len() == test_patterns.len);

    // Test metadata preservation
    try expect(beam_state.metadata == deserialized_state.metadata);
    try expect(beam_state.slot == deserialized_state.slot);

    // Test hash tree root consistency
    var deserialized_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, AccessBeamState, deserialized_state, &deserialized_hash, std.testing.allocator);

    try expect(std.mem.eql(u8, &original_hash, &deserialized_hash));
}

test "SimpleBeamState with empty historical roots" {
    const MAX_HISTORICAL_ROOTS = 8192;
    const Root = [32]u8;

    const SimpleBeamState = struct {
        slot: u64,
        historical_roots: utils.List(Root, MAX_HISTORICAL_ROOTS),
        validator_count: u64,
    };

    // Create BeamState with empty historical roots
    var empty_historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer empty_historical_roots.deinit();

    const beam_state = SimpleBeamState{
        .slot = 0,
        .historical_roots = empty_historical_roots,
        .validator_count = 0,
    };

    // Test serialization
    var serialized_data: ArrayList(u8) = .empty;
    defer serialized_data.deinit(std.testing.allocator);
    try serialize(SimpleBeamState, beam_state, &serialized_data, std.testing.allocator);

    // Validate against expected bytes
    const expected_simple_beam_state_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, serialized_data.items, &expected_simple_beam_state_bytes));

    // Test hash tree root calculation
    var original_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, SimpleBeamState, beam_state, &original_hash, std.testing.allocator);

    // Validate against actual hash
    const expected_simple_beam_state_hash = [_]u8{ 0x58, 0xD2, 0x2B, 0xA0, 0x04, 0x45, 0xE8, 0xB7, 0x39, 0x5E, 0xC3, 0x93, 0x92, 0x45, 0xC6, 0xF1, 0x5A, 0x29, 0x91, 0xA5, 0x70, 0x3F, 0xC5, 0x05, 0x88, 0x10, 0x57, 0xDE, 0x9D, 0xF3, 0x64, 0x10 };
    try expect(std.mem.eql(u8, &original_hash, &expected_simple_beam_state_hash));

    // Test deserialization
    var deserialized_state: SimpleBeamState = undefined;
    deserialized_state.historical_roots = try utils.List(Root, MAX_HISTORICAL_ROOTS).init(std.testing.allocator);
    defer deserialized_state.historical_roots.deinit();
    try deserialize(SimpleBeamState, serialized_data.items, &deserialized_state, std.testing.allocator);

    // Verify all fields match
    try expect(beam_state.slot == deserialized_state.slot);
    try expect(beam_state.validator_count == deserialized_state.validator_count);
    try expect(beam_state.historical_roots.len() == deserialized_state.historical_roots.len());
    try expect(beam_state.historical_roots.len() == 0);

    // Test hash tree root consistency
    var deserialized_hash: [32]u8 = undefined;
    try hashTreeRoot(Sha256, SimpleBeamState, deserialized_state, &deserialized_hash, std.testing.allocator);

    // Verify hash tree roots are identical
    try expect(std.mem.eql(u8, &original_hash, &deserialized_hash));
}

test "hashTreeRoot for pointer types" {
    var hash: [32]u8 = undefined;

    // Test pointer size .one - SUPPORTED
    {
        var value: u32 = 8;
        try hashTreeRoot(Sha256, *u32, &value, &hash, std.testing.allocator);

        var deserialized: u32 = undefined;
        try deserialize(u32, hash[0..4], &deserialized, std.testing.allocator);
        try expect(deserialized == value);
    }

    // Test pointer to array (size .slice) - SUPPORTED
    {
        var values = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        const values_ptr: *[4]u8 = &values;
        try hashTreeRoot(Sha256, *[4]u8, values_ptr, &hash, std.testing.allocator);

        var deserialized: [4]u8 = undefined;
        try deserialize([4]u8, hash[0..4], &deserialized, std.testing.allocator);
        try expect(std.mem.eql(u8, &deserialized, values_ptr));
    }

    // Test pointer size .many - should return error
    {
        var values = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        const values_ptr: [*]u8 = &values;
        try std.testing.expectError(error.UnSupportedPointerType, hashTreeRoot(Sha256, [*]u8, values_ptr, &hash, std.testing.allocator));
    }

    // Test pointer size .c - should return error
    {
        var values = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        const values_ptr: [*c]u8 = &values;
        try std.testing.expectError(error.UnSupportedPointerType, hashTreeRoot(Sha256, [*c]u8, values_ptr, &hash, std.testing.allocator));
    }
}
