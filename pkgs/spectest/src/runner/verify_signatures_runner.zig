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

    var signed_block = try buildSignedBlockWithAttestation(allocator, ctx, signed_block_value);
    defer signed_block.deinit();

    // Determine if we expect failure based on test name/path
    const expect_failure = std.mem.indexOf(u8, ctx.fixture_label, "invalid") != null or
        std.mem.indexOf(u8, ctx.case_name, "invalid") != null;

    // Verify signatures
    const verify_result = state_transition.verifySignatures(allocator, &anchor_state, &signed_block);

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
) FixtureError!types.SignedBlockWithAttestation {
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

    // Parse attestation_signatures (empty for basic tests)
    var attestation_signatures = try types.AttestationSignatures.init(allocator);
    errdefer attestation_signatures.deinit();

    if (signature_obj.get("attestationSignatures")) |att_sigs_val| {
        const att_sigs_obj = try expect.expectObjectValue(FixtureError, att_sigs_val, ctx, "signature.attestationSignatures");
        if (att_sigs_obj.get("data")) |data_val| {
            const arr = try expect.expectArrayValue(FixtureError, data_val, ctx, "signature.attestationSignatures.data");
            for (arr.items) |_| {
                // TODO: Parse actual attestation signatures if needed
                std.debug.print("fixture {s} case {s}: non-empty attestation signatures not yet supported\n", .{ ctx.fixture_label, ctx.case_name });
                return FixtureError.UnsupportedFixture;
            }
        }
    }

    // Parse proposer_signature
    const proposer_sig = try parseSignature(ctx, signature_obj, "proposerSignature");

    return types.SignedBlockWithAttestation{
        .message = .{
            .block = block,
            .proposer_attestation = proposer_attestation,
        },
        .signature = .{
            .attestation_signatures = attestation_signatures,
            .proposer_signature = proposer_sig,
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
                for (arr.items) |_| {
                    // TODO: Parse actual attestations if needed
                    std.debug.print("fixture {s} case {s}: non-empty attestations not yet supported\n", .{ ctx.fixture_label, ctx.case_name });
                    return FixtureError.UnsupportedFixture;
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
    ctx: Context,
    obj: std.json.ObjectMap,
    field_name: []const u8,
) FixtureError!types.SIGBYTES {
    const sig_obj = try expect.expectObject(FixtureError, obj, &.{field_name}, ctx, field_name);

    // SSZ Container serialization for Signature:
    // Signature = Container(path: HashTreeOpening, rho: Randomness, hashes: HashDigestList)
    //
    // Fixed part (36 bytes):
    //   - offset_path: 4 bytes (offset to path data)
    //   - rho_data: 28 bytes (7 Fp values, each 4 bytes - fixed size Vector)
    //   - offset_hashes: 4 bytes (offset to hashes data)
    //
    // Variable part:
    //   - path data (HashTreeOpening serialized)
    //   - hashes data (HashDigestList serialized)
    //
    // HashTreeOpening = Container(siblings: HashDigestList)
    // Fixed part: 4 bytes (offset to siblings data)
    // Variable part: siblings data
    //
    // HashDigestList = List[HashDigestVector, NODE_LIST_LIMIT]
    // HashDigestVector = Vector[Fp, 8] = 32 bytes (8 * 4 bytes each)
    // Since HashDigestVector is fixed size, the list is serialized as:
    //   - concatenated fixed-size items (no offsets needed)

    var sig_bytes: types.SIGBYTES = std.mem.zeroes(types.SIGBYTES);

    // Parse path siblings
    const path_obj = try expect.expectObject(FixtureError, sig_obj, &.{"path"}, ctx, "path");
    const siblings_obj = try expect.expectObject(FixtureError, path_obj, &.{"siblings"}, ctx, "path.siblings");
    const siblings_data = try expect.expectArrayField(FixtureError, siblings_obj, &.{"data"}, ctx, "path.siblings.data");

    // Parse rho (fixed size: 7 * 4 = 28 bytes)
    const rho_obj = try expect.expectObject(FixtureError, sig_obj, &.{"rho"}, ctx, "rho");
    const rho_arr = try parseU32Array7(ctx, rho_obj, "rho.data");

    // Parse hashes
    const hashes_obj = try expect.expectObject(FixtureError, sig_obj, &.{"hashes"}, ctx, "hashes");
    const hashes_data = try expect.expectArrayField(FixtureError, hashes_obj, &.{"data"}, ctx, "hashes.data");

    // Calculate sizes for SSZ serialization
    const num_siblings = siblings_data.items.len;
    const num_hashes = hashes_data.items.len;

    // Each HashDigestVector = 8 Fp * 4 bytes = 32 bytes
    const sibling_size: usize = 8 * 4; // 32 bytes per sibling
    const hash_size: usize = 8 * 4; // 32 bytes per hash

    // HashTreeOpening SSZ:
    // Fixed part: 4 bytes (offset to siblings)
    // Variable part: siblings data (concatenated HashDigestVectors)
    const path_fixed_part: usize = 4;
    const path_variable_size = num_siblings * sibling_size;
    const path_total_size = path_fixed_part + path_variable_size;

    // HashDigestList SSZ (for hashes): just concatenated fixed-size items
    const hashes_size = num_hashes * hash_size;

    // Signature fixed part: offset_path (4) + rho (28) + offset_hashes (4) = 36 bytes
    const sig_fixed_part: usize = 36;

    // Calculate offsets
    const offset_path: u32 = @intCast(sig_fixed_part); // path starts after fixed part
    const offset_hashes: u32 = @intCast(sig_fixed_part + path_total_size); // hashes start after path

    var write_pos: usize = 0;

    // Write Signature fixed part:
    // 1. offset_path (4 bytes)
    std.mem.writeInt(u32, sig_bytes[write_pos..][0..4], offset_path, .little);
    write_pos += 4;

    // 2. rho data (28 bytes - fixed size)
    for (rho_arr) |val| {
        std.mem.writeInt(u32, sig_bytes[write_pos..][0..4], val, .little);
        write_pos += 4;
    }

    // 3. offset_hashes (4 bytes)
    std.mem.writeInt(u32, sig_bytes[write_pos..][0..4], offset_hashes, .little);
    write_pos += 4;

    // Now write_pos should be at sig_fixed_part (36)

    // Write path (HashTreeOpening):
    // Fixed part: offset to siblings (4 bytes, pointing to byte 4 within path)
    const path_siblings_offset: u32 = 4; // siblings data starts at offset 4 within HashTreeOpening
    std.mem.writeInt(u32, sig_bytes[write_pos..][0..4], path_siblings_offset, .little);
    write_pos += 4;

    // Variable part: siblings data
    for (siblings_data.items) |sibling_val| {
        const sibling_obj = try expect.expectObjectValue(FixtureError, sibling_val, ctx, "sibling");
        const u32_arr = try parseU32Array8(ctx, sibling_obj, "sibling.data");
        for (u32_arr) |val| {
            std.mem.writeInt(u32, sig_bytes[write_pos..][0..4], val, .little);
            write_pos += 4;
        }
    }

    // Write hashes (HashDigestList - just concatenated items since they're fixed size)
    for (hashes_data.items) |hash_val| {
        const hash_obj = try expect.expectObjectValue(FixtureError, hash_val, ctx, "hash");
        const u32_arr = try parseU32Array8(ctx, hash_obj, "hash.data");
        for (u32_arr) |val| {
            std.mem.writeInt(u32, sig_bytes[write_pos..][0..4], val, .little);
            write_pos += 4;
        }
    }

    _ = hashes_size; // Used in offset_hashes calculation

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
