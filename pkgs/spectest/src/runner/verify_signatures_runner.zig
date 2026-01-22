const std = @import("std");

const expect = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;

pub const name = "verify_signatures";

pub const Handler = enum {
    test_invalid_signatures,
    test_valid_signatures,
};

pub const handlers = std.enums.values(Handler);

pub fn handlerLabel(comptime handler: Handler) []const u8 {
    return switch (handler) {
        .test_invalid_signatures => "test_invalid_signatures",
        .test_valid_signatures => "test_valid_signatures",
    };
}

pub fn handlerPath(comptime handler: Handler) []const u8 {
    return handlerLabel(handler);
}

pub fn includeFixtureFile(file_name: []const u8) bool {
    return std.mem.endsWith(u8, file_name, ".json");
}

pub fn baseRelRoot(comptime spec_fork: Fork) []const u8 {
    const kind = FixtureKind.verify_signatures;
    return std.fmt.comptimePrint(
        "consensus/{s}/{s}/{s}",
        .{ kind.runnerModule(), spec_fork.path, kind.handlerSubdir() },
    );
}

const types = @import("@zeam/types");
const state_transition = @import("@zeam/state-transition");
const key_manager = @import("@zeam/key-manager");
const ssz = @import("ssz");
const xmss = @import("@zeam/xmss");

// Signature structure constants from leansig
// path: 8 siblings, each is 8 u32 = 256 bytes
// rho: 7 u32 = 28 bytes
// hashes: 4 elements, each is 8 u32 = 128 bytes
// Total fixed size in fixture: 412 bytes, but actual SIGBYTES is 3112 bytes
// The remaining bytes are likely padding or additional OTS data

const JsonValue = std.json.Value;
const Context = expect.Context;

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 16 * 1024 * 1024; // 16 MiB upper bound per fixture file.

pub fn TestCase(
    comptime spec_fork: Fork,
    comptime rel_path: []const u8,
) type {
    return struct {
        payload: []u8,

        const Self = @This();

        pub fn execute(allocator: std.mem.Allocator, dir: std.fs.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            try tc.run(allocator);
        }

        pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir) RunnerError!Self {
            const payload = try loadFixturePayload(allocator, dir, rel_path);
            return Self{ .payload = payload };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.payload);
        }

        pub fn run(self: *Self, allocator: std.mem.Allocator) RunnerError!void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            try runFixturePayload(spec_fork, arena_allocator, rel_path, self.payload);
        }
    };
}

fn loadFixturePayload(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    rel_path: []const u8,
) RunnerError![]u8 {
    const payload = dir.readFileAlloc(allocator, rel_path, read_max_bytes) catch |err| switch (err) {
        error.FileTooBig => {
            std.debug.print("spectest: fixture {s} exceeds allowed size\n", .{rel_path});
            return RunnerError.IoFailure;
        },
        else => {
            std.debug.print("spectest: failed to read {s}: {s}\n", .{ rel_path, @errorName(err) });
            return RunnerError.IoFailure;
        },
    };
    return payload;
}

pub fn runFixturePayload(
    comptime spec_fork: Fork,
    allocator: std.mem.Allocator,
    fixture_label: []const u8,
    payload: []const u8,
) FixtureError!void {
    _ = spec_fork;
    var parsed = std.json.parseFromSlice(JsonValue, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| {
        std.debug.print("spectest: fixture {s} not valid JSON: {s}\n", .{ fixture_label, @errorName(err) });
        return FixtureError.InvalidFixture;
    };
    defer parsed.deinit();

    const root = parsed.value;
    const obj = switch (root) {
        .object => |map| map,
        else => {
            std.debug.print("spectest: fixture {s} must be JSON object\n", .{fixture_label});
            return FixtureError.InvalidFixture;
        },
    };

    var skipped_cases: usize = 0;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const case_name = entry.key_ptr.*;
        const case_value = entry.value_ptr.*;
        const ctx = Context{ .fixture_label = fixture_label, .case_name = case_name };
        runCase(allocator, ctx, case_value) catch |err| switch (err) {
            FixtureError.SkippedFixture => skipped_cases += 1,
            FixtureError.UnsupportedFixture => {
                std.debug.print(
                    "spectest: skipping unsupported case {s} in {s}\n",
                    .{ case_name, fixture_label },
                );
            },
            else => return err,
        };
    }

    if (skipped_cases > 0) {
        std.debug.print(
            "spectest: skipped {d} case(s) in fixture {s}\n",
            .{ skipped_cases, fixture_label },
        );
    }
}

const AggregatedSignatureProof = struct {
    participants: types.AggregationBits,
    proof_data: []u8,

    pub fn deinit(self: *AggregatedSignatureProof, allocator: std.mem.Allocator) void {
        self.participants.deinit();
        allocator.free(self.proof_data);
    }
};

const ParsedSignedBlockWithAttestation = struct {
    signed_block: types.SignedBlockWithAttestation,
    attestation_proofs: []AggregatedSignatureProof,

    pub fn deinit(self: *ParsedSignedBlockWithAttestation, allocator: std.mem.Allocator) void {
        for (self.attestation_proofs) |*proof| {
            proof.deinit(allocator);
        }
        allocator.free(self.attestation_proofs);
        self.signed_block.deinit();
    }
};

fn runCase(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!void {
    const case_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: expected object\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const lean_env = blk: {
        const lean_env_val = case_obj.get("leanEnv") orelse break :blk null;
        const lean_env_str = switch (lean_env_val) {
            .string => |s| s,
            else => break :blk null,
        };
        break :blk lean_env_str;
    };
    const test_config = key_manager.XmssTestConfig.fromLeanEnv(lean_env);
    const signature_ssz_len: usize = test_config.signature_ssz_len;
    const allow_placeholder_aggregated_proof = test_config.allow_placeholder_aggregated_proof;

    // Parse the anchorState to get validators
    const anchor_state_value = case_obj.get("anchorState") orelse {
        std.debug.print("fixture {s} case {s}: missing anchorState\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    };

    var anchor_state = try buildState(allocator, ctx, anchor_state_value);
    defer anchor_state.deinit();

    // Parse the signedBlockWithAttestation
    const signed_block_value = case_obj.get("signedBlockWithAttestation") orelse {
        std.debug.print("fixture {s} case {s}: missing signedBlockWithAttestation\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    };

    var parsed = try buildSignedBlockWithAttestation(allocator, ctx, signed_block_value);
    defer parsed.deinit(allocator);

    // Determine if we expect failure based on test name/path
    const expect_failure = std.mem.indexOf(u8, ctx.fixture_label, "invalid") != null or
        std.mem.indexOf(u8, ctx.case_name, "invalid") != null;

    // Verify signatures
    const verify_result = verifySignaturesWithFixtureProofs(
        allocator,
        &anchor_state,
        &parsed.signed_block,
        parsed.attestation_proofs,
        signature_ssz_len,
        allow_placeholder_aggregated_proof,
    );

    if (expect_failure) {
        if (verify_result) |_| {
            std.debug.print(
                "fixture {s} case {s}: expected verification to fail but it succeeded\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
            return FixtureError.FixtureMismatch;
        } else |_| {
            // Expected failure
        }
    } else {
        verify_result catch |err| {
            std.debug.print(
                "fixture {s} case {s}: signature verification failed with {s}\n",
                .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
            );
            return FixtureError.FixtureMismatch;
        };
    }
}

fn verifySignaturesWithFixtureProofs(
    allocator: std.mem.Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlockWithAttestation,
    proofs: []const AggregatedSignatureProof,
    signature_ssz_len: usize,
    allow_placeholder_aggregated_proof: bool,
) !void {
    const attestations = signed_block.message.block.body.attestations.constSlice();

    if (attestations.len != proofs.len) {
        return types.StateTransitionError.InvalidBlockSignatures;
    }

    const validators = state.validators.constSlice();

    for (attestations, proofs) |aggregated_attestation, proof| {
        // Ensure the declared participants match the aggregated attestation bitfield.
        if (aggregated_attestation.aggregation_bits.len() != proof.participants.len()) {
            return types.StateTransitionError.InvalidBlockSignatures;
        }
        for (0..aggregated_attestation.aggregation_bits.len()) |i| {
            if (try aggregated_attestation.aggregation_bits.get(i) != try proof.participants.get(i)) {
                return types.StateTransitionError.InvalidBlockSignatures;
            }
        }

        var validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator);
        defer validator_indices.deinit();

        for (validator_indices.items) |validator_index| {
            if (validator_index >= validators.len) {
                return types.StateTransitionError.InvalidValidatorId;
            }
        }

        // NOTE: leanSpec currently serializes a placeholder proof (`0x00`) in test mode.
        // We accept the proof bytes and only validate participant bookkeeping.
        if (allow_placeholder_aggregated_proof) {
            if (proof.proof_data.len == 0) {
                return types.StateTransitionError.InvalidBlockSignatures;
            }
        } else {
            // Future: verify aggregated proofs against leanMultisig once the fixture format
            // provides verifiable proof bytes in non-test environments.
        }
    }

    // Verify proposer attestation signature (standard XMSS signature)
    const proposer_attestation = signed_block.message.proposer_attestation;
    try verifySingleAttestationSignature(
        allocator,
        state,
        @intCast(proposer_attestation.validator_id),
        &proposer_attestation.data,
        &signed_block.signature.proposer_signature,
        signature_ssz_len,
    );
}

fn verifySingleAttestationSignature(
    allocator: std.mem.Allocator,
    state: *const types.BeamState,
    validator_index: usize,
    attestation_data: *const types.AttestationData,
    signature_bytes: *const types.SIGBYTES,
    signature_ssz_len: usize,
) !void {
    if (signature_ssz_len > signature_bytes.len) {
        return types.StateTransitionError.InvalidBlockSignatures;
    }

    const validators = state.validators.constSlice();
    if (validator_index >= validators.len) {
        return types.StateTransitionError.InvalidValidatorId;
    }

    const pubkey = validators[validator_index].getPubkey();

    var message: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.AttestationData, attestation_data.*, &message, allocator);

    const epoch: u32 = @intCast(attestation_data.slot);
    try xmss.verifySsz(pubkey, &message, epoch, signature_bytes.*[0..signature_ssz_len]);
}

fn buildState(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!types.BeamState {
    const pre_obj = try expect.expectObjectValue(FixtureError, value, ctx, "anchorState");

    const config_obj = try expect.expectObject(FixtureError, pre_obj, &.{"config"}, ctx, "config");
    const genesis_time = try expect.expectU64Field(FixtureError, config_obj, &.{"genesisTime"}, ctx, "config.genesisTime");

    const slot = try expect.expectU64Field(FixtureError, pre_obj, &.{"slot"}, ctx, "slot");

    const header_obj = try expect.expectObject(FixtureError, pre_obj, &.{"latestBlockHeader"}, ctx, "latestBlockHeader");
    const latest_block_header = try parseBlockHeader(ctx, header_obj);

    const latest_justified = try parseCheckpoint(ctx, pre_obj, "latestJustified");
    const latest_finalized = try parseCheckpoint(ctx, pre_obj, "latestFinalized");

    var historical = try types.HistoricalBlockHashes.init(allocator);
    errdefer historical.deinit();
    if (pre_obj.get("historicalBlockHashes")) |val| {
        try expect.appendBytesDataField(FixtureError, types.Root, &historical, ctx, val, "historicalBlockHashes");
    }

    var justified_slots = try types.JustifiedSlots.init(allocator);
    errdefer justified_slots.deinit();
    if (pre_obj.get("justifiedSlots")) |val| {
        try expect.appendBoolDataField(FixtureError, &justified_slots, ctx, val, "justifiedSlots");
    }

    var validators = try parseValidators(allocator, ctx, pre_obj);
    errdefer validators.deinit();

    var just_roots = try types.JustificationRoots.init(allocator);
    errdefer just_roots.deinit();
    if (pre_obj.get("justificationsRoots")) |val| {
        try expect.appendBytesDataField(FixtureError, types.Root, &just_roots, ctx, val, "justificationsRoots");
    }

    var just_validators = try types.JustificationValidators.init(allocator);
    errdefer just_validators.deinit();
    if (pre_obj.get("justificationsValidators")) |val| {
        try expect.appendBoolDataField(FixtureError, &just_validators, ctx, val, "justificationsValidators");
    }

    return types.BeamState{
        .config = .{ .genesis_time = genesis_time },
        .slot = slot,
        .latest_block_header = latest_block_header,
        .latest_justified = latest_justified,
        .latest_finalized = latest_finalized,
        .historical_block_hashes = historical,
        .justified_slots = justified_slots,
        .validators = validators,
        .justifications_roots = just_roots,
        .justifications_validators = just_validators,
    };
}

fn parseValidators(
    allocator: std.mem.Allocator,
    ctx: Context,
    pre_obj: std.json.ObjectMap,
) FixtureError!types.Validators {
    var validators = try types.Validators.init(allocator);
    errdefer validators.deinit();

    if (pre_obj.get("validators")) |val| {
        const validators_obj = try expect.expectObjectValue(FixtureError, val, ctx, "validators");
        if (validators_obj.get("data")) |data_val| {
            const arr = try expect.expectArrayValue(FixtureError, data_val, ctx, "validators.data");
            for (arr.items, 0..) |item, idx| {
                var base_label_buf: [64]u8 = undefined;
                const base_label = std.fmt.bufPrint(&base_label_buf, "validators[{d}]", .{idx}) catch "validators";
                const validator_obj = try expect.expectObjectValue(FixtureError, item, ctx, base_label);

                var label_buf: [96]u8 = undefined;
                const pubkey_label = std.fmt.bufPrint(&label_buf, "{s}.pubkey", .{base_label}) catch "validator.pubkey";
                const pubkey = try expect.expectBytesField(FixtureError, types.Bytes52, validator_obj, &.{"pubkey"}, ctx, pubkey_label);

                const validator_index: u64 = blk: {
                    if (validator_obj.get("index")) |index_value| {
                        var index_label_buf: [96]u8 = undefined;
                        const index_label = std.fmt.bufPrint(&index_label_buf, "{s}.index", .{base_label}) catch "validator.index";
                        break :blk try expect.expectU64Value(FixtureError, index_value, ctx, index_label);
                    }
                    break :blk @as(u64, @intCast(idx));
                };

                validators.append(.{ .pubkey = pubkey, .index = validator_index }) catch |err| {
                    std.debug.print(
                        "fixture {s} case {s}: validator #{} append failed: {s}\n",
                        .{ ctx.fixture_label, ctx.case_name, idx, @errorName(err) },
                    );
                    return FixtureError.InvalidFixture;
                };
            }
        }
    }

    return validators;
}

fn buildSignedBlockWithAttestation(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
) FixtureError!ParsedSignedBlockWithAttestation {
    const signed_block_obj = try expect.expectObjectValue(FixtureError, value, ctx, "signedBlockWithAttestation");

    // Parse message
    const message_obj = try expect.expectObject(FixtureError, signed_block_obj, &.{"message"}, ctx, "message");

    // Parse block within message
    const block_obj = try expect.expectObject(FixtureError, message_obj, &.{"block"}, ctx, "message.block");
    const block = try buildBlock(allocator, ctx, block_obj);

    // Parse proposerAttestation
    const proposer_att_obj = try expect.expectObject(FixtureError, message_obj, &.{"proposerAttestation"}, ctx, "message.proposerAttestation");
    const proposer_attestation = try parseProposerAttestation(ctx, proposer_att_obj);

    // Parse signature section
    const signature_obj = try expect.expectObject(FixtureError, signed_block_obj, &.{"signature"}, ctx, "signature");

    // Parse attestation aggregated signature proofs
    var attestation_proofs = std.ArrayList(AggregatedSignatureProof).init(allocator);
    errdefer {
        for (attestation_proofs.items) |*proof| proof.deinit(allocator);
        attestation_proofs.deinit();
    }
    if (signature_obj.get("attestationSignatures")) |att_sigs_val| {
        const att_sigs_obj = try expect.expectObjectValue(FixtureError, att_sigs_val, ctx, "signature.attestationSignatures");
        if (att_sigs_obj.get("data")) |data_val| {
            const arr = try expect.expectArrayValue(FixtureError, data_val, ctx, "signature.attestationSignatures.data");
            for (arr.items, 0..) |item, idx| {
                var label_buf: [96]u8 = undefined;
                const entry_label = std.fmt.bufPrint(&label_buf, "signature.attestationSignatures.data[{d}]", .{idx}) catch "signature.attestationSignatures.data";

                const entry_obj = try expect.expectObjectValue(FixtureError, item, ctx, entry_label);

                const participants_val = entry_obj.get("participants") orelse {
                    std.debug.print(
                        "fixture {s} case {s}: missing participants in {s}\n",
                        .{ ctx.fixture_label, ctx.case_name, entry_label },
                    );
                    return FixtureError.InvalidFixture;
                };
                var participants = try parseAggregationBits(allocator, ctx, participants_val, "participants");

                const proof_val = entry_obj.get("proofData") orelse entry_obj.get("proof_data") orelse {
                    std.debug.print(
                        "fixture {s} case {s}: missing proofData in {s}\n",
                        .{ ctx.fixture_label, ctx.case_name, entry_label },
                    );
                    participants.deinit();
                    return FixtureError.InvalidFixture;
                };
                const proof_data = try parseByteListMiB(allocator, ctx, proof_val, "proofData");

                attestation_proofs.append(.{ .participants = participants, .proof_data = proof_data }) catch |err| {
                    std.debug.print(
                        "fixture {s} case {s}: failed to append attestation proof: {s}\n",
                        .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
                    );
                    participants.deinit();
                    allocator.free(proof_data);
                    return FixtureError.InvalidFixture;
                };
            }
        }
    }

    // Parse proposer_signature
    const proposer_sig = try parseSignature(allocator, ctx, signature_obj, "proposerSignature");

    var signatures = types.createBlockSignatures(allocator, block.body.attestations.len()) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: unable to allocate signature groups: {s}\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };
    signatures.proposer_signature = proposer_sig;

    return ParsedSignedBlockWithAttestation{
        .signed_block = .{
            .message = .{
                .block = block,
                .proposer_attestation = proposer_attestation,
            },
            .signature = signatures,
        },
        .attestation_proofs = attestation_proofs.toOwnedSlice() catch |err| {
            std.debug.print(
                "fixture {s} case {s}: unable to allocate attestation proof list: {s}\n",
                .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
            );
            return FixtureError.InvalidFixture;
        },
    };
}

fn buildBlock(
    allocator: std.mem.Allocator,
    ctx: Context,
    obj: std.json.ObjectMap,
) FixtureError!types.BeamBlock {
    const slot = try expect.expectU64Field(FixtureError, obj, &.{"slot"}, ctx, "slot");
    const proposer_index = try expect.expectU64Field(FixtureError, obj, &.{ "proposer_index", "proposerIndex" }, ctx, "proposer_index");
    const parent_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "parent_root", "parentRoot" }, ctx, "parent_root");
    const state_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "state_root", "stateRoot" }, ctx, "state_root");

    var attestations = try types.AggregatedAttestations.init(allocator);
    errdefer attestations.deinit();

    if (obj.get("body")) |body_val| {
        const body_obj = try expect.expectObjectValue(FixtureError, body_val, ctx, "body");
        if (body_obj.get("attestations")) |att_val| {
            const att_obj = try expect.expectObjectValue(FixtureError, att_val, ctx, "body.attestations");
            if (att_obj.get("data")) |data_val| {
                const arr = try expect.expectArrayValue(FixtureError, data_val, ctx, "body.attestations.data");
                for (arr.items, 0..) |item, idx| {
                    var label_buf: [96]u8 = undefined;
                    const entry_label = std.fmt.bufPrint(&label_buf, "body.attestations.data[{d}]", .{idx}) catch "body.attestations.data";

                    const att_item_obj = try expect.expectObjectValue(FixtureError, item, ctx, entry_label);

                    const bits_val = att_item_obj.get("aggregationBits") orelse {
                        std.debug.print(
                            "fixture {s} case {s}: missing aggregationBits in {s}\n",
                            .{ ctx.fixture_label, ctx.case_name, entry_label },
                        );
                        return FixtureError.InvalidFixture;
                    };
                    var aggregation_bits = try parseAggregationBits(allocator, ctx, bits_val, "aggregationBits");
                    errdefer aggregation_bits.deinit();

                    const data_obj = try expect.expectObject(FixtureError, att_item_obj, &.{"data"}, ctx, "attestation.data");
                    const data = try parseAttestationData(ctx, data_obj);

                    attestations.append(.{ .aggregation_bits = aggregation_bits, .data = data }) catch |err| {
                        std.debug.print(
                            "fixture {s} case {s}: failed to append attestation: {s}\n",
                            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
                        );
                        return FixtureError.InvalidFixture;
                    };
                }
            }
        }
    }

    return types.BeamBlock{
        .slot = slot,
        .proposer_index = proposer_index,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = .{ .attestations = attestations },
    };
}

fn parseAggregationBits(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
    label: []const u8,
) FixtureError!types.AggregationBits {
    const obj = try expect.expectObjectValue(FixtureError, value, ctx, label);
    const arr = try expect.expectArrayField(FixtureError, obj, &.{"data"}, ctx, label);

    var bits = try types.AggregationBits.init(allocator);
    errdefer bits.deinit();

    for (arr.items) |bit_val| {
        const bit = switch (bit_val) {
            .bool => |b| b,
            else => {
                std.debug.print(
                    "fixture {s} case {s}: {s} must contain booleans\n",
                    .{ ctx.fixture_label, ctx.case_name, label },
                );
                return FixtureError.InvalidFixture;
            },
        };
        bits.append(bit) catch |err| {
            std.debug.print(
                "fixture {s} case {s}: failed to append {s} bit: {s}\n",
                .{ ctx.fixture_label, ctx.case_name, label, @errorName(err) },
            );
            return FixtureError.InvalidFixture;
        };
    }

    return bits;
}

fn parseByteListMiB(
    allocator: std.mem.Allocator,
    ctx: Context,
    value: JsonValue,
    label: []const u8,
) FixtureError![]u8 {
    const obj = try expect.expectObjectValue(FixtureError, value, ctx, label);
    const text = try expect.expectStringField(FixtureError, obj, &.{"data"}, ctx, label);

    if (text.len < 2 or !std.mem.eql(u8, text[0..2], "0x")) {
        std.debug.print(
            "fixture {s} case {s}: field {s}.data missing 0x prefix\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    }

    const body = text[2..];
    if (body.len % 2 != 0) {
        std.debug.print(
            "fixture {s} case {s}: field {s}.data has odd hex length\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    }

    const out_len = body.len / 2;
    const out = allocator.alloc(u8, out_len) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: unable to allocate {d} bytes for {s}: {s}\n",
            .{ ctx.fixture_label, ctx.case_name, out_len, label, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, body) catch {
        std.debug.print(
            "fixture {s} case {s}: field {s}.data invalid hex\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    };
    return out;
}

fn parseProposerAttestation(
    ctx: Context,
    obj: std.json.ObjectMap,
) FixtureError!types.Attestation {
    const validator_id = try expect.expectU64Field(FixtureError, obj, &.{"validatorId"}, ctx, "proposerAttestation.validatorId");

    const data_obj = try expect.expectObject(FixtureError, obj, &.{"data"}, ctx, "proposerAttestation.data");
    const data = try parseAttestationData(ctx, data_obj);

    return types.Attestation{
        .validator_id = validator_id,
        .data = data,
    };
}

fn parseAttestationData(
    ctx: Context,
    obj: std.json.ObjectMap,
) FixtureError!types.AttestationData {
    const slot = try expect.expectU64Field(FixtureError, obj, &.{"slot"}, ctx, "data.slot");

    const head_obj = try expect.expectObject(FixtureError, obj, &.{"head"}, ctx, "data.head");
    const head = types.Checkpoint{
        .root = try expect.expectBytesField(FixtureError, types.Root, head_obj, &.{"root"}, ctx, "data.head.root"),
        .slot = try expect.expectU64Field(FixtureError, head_obj, &.{"slot"}, ctx, "data.head.slot"),
    };

    const target_obj = try expect.expectObject(FixtureError, obj, &.{"target"}, ctx, "data.target");
    const target = types.Checkpoint{
        .root = try expect.expectBytesField(FixtureError, types.Root, target_obj, &.{"root"}, ctx, "data.target.root"),
        .slot = try expect.expectU64Field(FixtureError, target_obj, &.{"slot"}, ctx, "data.target.slot"),
    };

    const source_obj = try expect.expectObject(FixtureError, obj, &.{"source"}, ctx, "data.source");
    const source = types.Checkpoint{
        .root = try expect.expectBytesField(FixtureError, types.Root, source_obj, &.{"root"}, ctx, "data.source.root"),
        .slot = try expect.expectU64Field(FixtureError, source_obj, &.{"slot"}, ctx, "data.source.slot"),
    };

    return types.AttestationData{
        .slot = slot,
        .head = head,
        .target = target,
        .source = source,
    };
}

fn parseSignature(
    allocator: std.mem.Allocator,
    ctx: Context,
    obj: std.json.ObjectMap,
    field_name: []const u8,
) FixtureError!types.SIGBYTES {
    const sig_value = obj.get(field_name) orelse {
        std.debug.print(
            "fixture {s} case {s}: missing field {s}\n",
            .{ ctx.fixture_label, ctx.case_name, field_name },
        );
        return FixtureError.InvalidFixture;
    };

    // Re-serialize just the signature object and let Rust parse/SSZ-encode it.
    var json_buf = std.ArrayList(u8).init(allocator);
    defer json_buf.deinit();

    std.json.stringify(sig_value, .{}, json_buf.writer()) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: failed to stringify signature JSON: {s}\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.InvalidFixture;
    };

    var sig_bytes: types.SIGBYTES = std.mem.zeroes(types.SIGBYTES);
    const written = xmss.signatureSszFromJson(json_buf.items, sig_bytes[0..]) catch {
        std.debug.print(
            "fixture {s} case {s}: Rust JSON→SSZ conversion failed\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };

    if (written > sig_bytes.len) {
        std.debug.print(
            "fixture {s} case {s}: Rust JSON→SSZ wrote {d} bytes, max {d}\n",
            .{ ctx.fixture_label, ctx.case_name, written, sig_bytes.len },
        );
        return FixtureError.InvalidFixture;
    }

    return sig_bytes;
}

fn parseU32Array8(
    ctx: Context,
    obj: std.json.ObjectMap,
    label: []const u8,
) FixtureError![8]u32 {
    const data_arr = try expect.expectArrayField(FixtureError, obj, &.{"data"}, ctx, label);
    var result: [8]u32 = undefined;
    for (data_arr.items, 0..) |val, i| {
        if (i >= 8) break;
        result[i] = @intCast(try expect.expectU64Value(FixtureError, val, ctx, label));
    }
    return result;
}

fn parseU32Array7(
    ctx: Context,
    obj: std.json.ObjectMap,
    label: []const u8,
) FixtureError![7]u32 {
    const data_arr = try expect.expectArrayField(FixtureError, obj, &.{"data"}, ctx, label);
    var result: [7]u32 = undefined;
    for (data_arr.items, 0..) |val, i| {
        if (i >= 7) break;
        result[i] = @intCast(try expect.expectU64Value(FixtureError, val, ctx, label));
    }
    return result;
}

fn parseCheckpoint(
    ctx: Context,
    parent: std.json.ObjectMap,
    field_name: []const u8,
) FixtureError!types.Checkpoint {
    const cp_obj = try expect.expectObject(FixtureError, parent, &.{field_name}, ctx, field_name);

    var root_label_buf: [96]u8 = undefined;
    const root_label = std.fmt.bufPrint(&root_label_buf, "{s}.root", .{field_name}) catch field_name;
    var slot_label_buf: [96]u8 = undefined;
    const slot_label = std.fmt.bufPrint(&slot_label_buf, "{s}.slot", .{field_name}) catch field_name;

    return types.Checkpoint{
        .root = try expect.expectBytesField(FixtureError, types.Root, cp_obj, &.{"root"}, ctx, root_label),
        .slot = try expect.expectU64Field(FixtureError, cp_obj, &.{"slot"}, ctx, slot_label),
    };
}

fn parseBlockHeader(
    ctx: Context,
    obj: std.json.ObjectMap,
) FixtureError!types.BeamBlockHeader {
    return types.BeamBlockHeader{
        .slot = try expect.expectU64Field(FixtureError, obj, &.{"slot"}, ctx, "latestBlockHeader.slot"),
        .proposer_index = try expect.expectU64Field(FixtureError, obj, &.{ "proposerIndex", "proposer_index" }, ctx, "latestBlockHeader.proposerIndex"),
        .parent_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "parentRoot", "parent_root" }, ctx, "latestBlockHeader.parentRoot"),
        .state_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "stateRoot", "state_root" }, ctx, "latestBlockHeader.stateRoot"),
        .body_root = try expect.expectBytesField(FixtureError, types.Root, obj, &.{ "bodyRoot", "body_root" }, ctx, "latestBlockHeader.bodyRoot"),
    };
}
