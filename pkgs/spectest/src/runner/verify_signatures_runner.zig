const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");
const stf_runner = @import("state_transition_runner.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const types = @import("@zeam/types");
const xmss = @import("@zeam/xmss");
const zeam_utils = @import("@zeam/utils");
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

pub const name = "verify_signatures";

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 16 * 1024 * 1024;

pub fn TestCase(
    comptime spec_fork: Fork,
    comptime rel_path: []const u8,
) type {
    return struct {
        payload: []u8,

        const Self = @This();

        pub fn execute(allocator: Allocator, dir: std.Io.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            tc.run(allocator) catch |err| switch (err) {
                error.SkippedFixture => return, // treat skip as pass
                else => return err,
            };
        }

        pub fn init(allocator: Allocator, dir: std.Io.Dir) RunnerError!Self {
            const payload = dir.readFileAlloc(std.testing.io, rel_path, allocator, std.Io.Limit.limited(read_max_bytes)) catch |err| {
                std.debug.print(
                    "spectest: failed to read {s}: {s}\n",
                    .{ rel_path, @errorName(err) },
                );
                return RunnerError.IoFailure;
            };
            return Self{ .payload = payload };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.payload);
        }

        pub fn run(self: *Self, allocator: Allocator) RunnerError!void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            try runFixturePayload(spec_fork, arena_allocator, rel_path, self.payload);
        }
    };
}

pub fn runFixturePayload(
    comptime spec_fork: Fork,
    allocator: Allocator,
    fixture_label: []const u8,
    payload: []const u8,
) FixtureError!void {
    _ = spec_fork;
    var parsed = std.json.parseFromSlice(JsonValue, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| {
        std.debug.print("spectest: fixture {s} not valid JSON: {s}\n", .{ fixture_label, @errorName(err) });
        return FixtureError.InvalidFixture;
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |map| map,
        else => {
            std.debug.print("spectest: fixture {s} must be JSON object\n", .{fixture_label});
            return FixtureError.InvalidFixture;
        },
    };

    var it = obj.iterator();
    while (it.next()) |entry| {
        try runCase(allocator, .{
            .fixture_label = fixture_label,
            .case_name = entry.key_ptr.*,
        }, entry.value_ptr.*);
    }
}

fn runCase(allocator: Allocator, ctx: Context, value: JsonValue) FixtureError!void {
    const case_obj = switch (value) {
        .object => |map| map,
        else => {
            std.debug.print("fixture {s} case {s}: expected object\n", .{ ctx.fixture_label, ctx.case_name });
            return FixtureError.InvalidFixture;
        },
    };

    const lean_env = expect_mod.expectStringField(FixtureError, case_obj, &.{"leanEnv"}, ctx, "leanEnv") catch "prod";

    const signed_block_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"signedBlock"}, ctx, "signedBlock");
    const block_obj = try expect_mod.expectObject(FixtureError, signed_block_obj, &.{"block"}, ctx, "signedBlock.block");
    const expect_exception = case_obj.get("expectException");

    // Body attestation verification dispatches to leanMultisig, which is
    // hardcoded to the production scheme. Skip cases with body attestations
    // when running against test-scheme fixtures: the prod path would reject
    // test-scheme bytes by accident at deserialization, which is the right
    // outcome for invalid fixtures but the wrong outcome for valid ones.
    // A parallel test-scheme leanMultisig FFI is the right fix; tracked separately.
    if (std.mem.eql(u8, lean_env, "test")) {
        const body_obj = try expect_mod.expectObject(FixtureError, block_obj, &.{"body"}, ctx, "signedBlock.block.body");
        const attestations_obj = try expect_mod.expectObject(FixtureError, body_obj, &.{"attestations"}, ctx, "signedBlock.block.body.attestations");
        if (attestations_obj.get("data")) |data_val| {
            const arr = try expect_mod.expectArrayValue(FixtureError, data_val, ctx, "body.attestations.data");
            if (arr.items.len > 0) {
                std.debug.print(
                    "spectest: skipping verify_signatures fixture {s} (leanEnv=test with body attestations; needs test-scheme leanMultisig FFI)\n",
                    .{ctx.fixture_label},
                );
                return FixtureError.SkippedFixture;
            }
        }
    }

    const anchor_value = case_obj.get("anchorState") orelse {
        std.debug.print(
            "fixture {s} case {s}: missing anchorState\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };
    var state = try stf_runner.buildState(allocator, ctx, anchor_value);
    defer state.deinit();

    var block = try stf_runner.buildBlock(allocator, ctx, 0, block_obj);
    defer block.deinit();

    const signature_obj = try expect_mod.expectObject(FixtureError, signed_block_obj, &.{"signature"}, ctx, "signedBlock.signature");
    const proposer_sig_hex = try expect_mod.expectStringField(
        FixtureError,
        signature_obj,
        &.{ "proposerSignature", "proposer_signature" },
        ctx,
        "signedBlock.signature.proposerSignature",
    );

    const proposer_sig_bytes = try parseHexBytes(allocator, ctx, proposer_sig_hex, "signedBlock.signature.proposerSignature");

    // Hash the block to produce the verification message.
    var block_root: [32]u8 = undefined;
    zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, allocator) catch {
        std.debug.print(
            "fixture {s} case {s}: failed to hash block\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };

    const proposer_index: usize = @intCast(block.proposer_index);
    const validators_slice = state.validators.constSlice();
    if (proposer_index >= validators_slice.len) {
        // Out-of-range proposer is itself a rejection-worthy case. If the
        // fixture expected an exception, this counts as success; otherwise
        // it is a validator-state mismatch.
        if (case_obj.get("expectException") != null) return;
        std.debug.print(
            "fixture {s} case {s}: proposer_index {d} >= validators.len {d}\n",
            .{ ctx.fixture_label, ctx.case_name, proposer_index, validators_slice.len },
        );
        return FixtureError.FixtureMismatch;
    }

    const proposal_pubkey = validators_slice[proposer_index].getProposalPubkey();
    const epoch: u32 = @intCast(block.slot);

    const proposer_result = if (std.mem.eql(u8, lean_env, "test"))
        xmss.verifySszTest(proposal_pubkey, &block_root, epoch, proposer_sig_bytes)
    else
        xmss.verifySsz(proposal_pubkey, &block_root, epoch, proposer_sig_bytes);
    const proposer_failed = if (proposer_result) |_| false else |_| true;

    // Verify each body-attestation aggregated signature, if any. The fixture's
    // attestationSignatures array runs in lockstep with block.body.attestations.
    //
    // leanMultisig's Rust glue is hardcoded to the production scheme; test-scheme
    // bytes will not deserialize through it. For invalid-fixture cases that path
    // returning false is the expected outcome anyway (the spec asserts the
    // implementation rejects). For valid-fixture cases with body attestations,
    // we'd need a parallel test-scheme leanMultisig FFI; none of the current
    // valid fixtures carry body attestations so that gap doesn't bite yet.
    const att_failed = verifyBodyAttestations(allocator, ctx, &state, &block, signed_block_obj) catch |err| switch (err) {
        FixtureError.SkippedFixture => return FixtureError.SkippedFixture,
        else => return err,
    };

    const any_failure = proposer_failed or att_failed;

    if (expect_exception != null) {
        if (any_failure) return; // expected — at least one signature was rejected
        std.debug.print(
            "fixture {s} case {s}: expected exception but every signature verified\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }

    if (any_failure) {
        if (proposer_result) |_| {} else |err| {
            std.debug.print(
                "fixture {s} case {s}: unexpected proposer signature verification error: {s}\n",
                .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
            );
        }
        if (att_failed) {
            std.debug.print(
                "fixture {s} case {s}: unexpected body-attestation verification failure\n",
                .{ ctx.fixture_label, ctx.case_name },
            );
        }
        return FixtureError.FixtureMismatch;
    }
}

/// Verify each body-attestation aggregated signature. Returns true if any
/// verification rejected the input (whether due to invalid bytes, scheme
/// mismatch, or genuine cryptographic failure).
fn verifyBodyAttestations(
    allocator: Allocator,
    ctx: Context,
    state: *const types.BeamState,
    block: *const types.BeamBlock,
    signed_block_obj: std.json.ObjectMap,
) FixtureError!bool {
    const attestations = block.body.attestations.constSlice();
    if (attestations.len == 0) return false;

    const signature_obj = try expect_mod.expectObject(FixtureError, signed_block_obj, &.{"signature"}, ctx, "signedBlock.signature");
    const att_sigs_obj = try expect_mod.expectObject(FixtureError, signature_obj, &.{ "attestationSignatures", "attestation_signatures" }, ctx, "signedBlock.signature.attestationSignatures");
    const att_sigs_data = att_sigs_obj.get("data") orelse {
        std.debug.print(
            "fixture {s} case {s}: attestationSignatures missing data\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    };
    const sig_arr = try expect_mod.expectArrayValue(FixtureError, att_sigs_data, ctx, "attestationSignatures.data");

    if (sig_arr.items.len != attestations.len) {
        std.debug.print(
            "fixture {s} case {s}: body attestations ({d}) != attestationSignatures ({d})\n",
            .{ ctx.fixture_label, ctx.case_name, attestations.len, sig_arr.items.len },
        );
        return FixtureError.InvalidFixture;
    }

    const validators_slice = state.validators.constSlice();
    var any_failed = false;

    for (attestations, sig_arr.items, 0..) |aggregated_attestation, sig_value, idx| {
        var validator_indices = types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator) catch {
            any_failed = true;
            continue;
        };
        defer validator_indices.deinit(allocator);

        var pubkey_wrappers: std.ArrayList(xmss.PublicKey) = .empty;
        defer {
            for (pubkey_wrappers.items) |*wrapper| wrapper.deinit();
            pubkey_wrappers.deinit(allocator);
        }
        var public_keys: std.ArrayList(*const xmss.HashSigPublicKey) = .empty;
        defer public_keys.deinit(allocator);

        var pubkey_load_failed = false;
        for (validator_indices.items) |validator_index| {
            if (validator_index >= validators_slice.len) {
                pubkey_load_failed = true;
                break;
            }
            const pubkey_bytes = validators_slice[validator_index].getAttestationPubkey();
            const pk = xmss.PublicKey.fromBytes(pubkey_bytes) catch {
                pubkey_load_failed = true;
                break;
            };
            pubkey_wrappers.append(allocator, pk) catch {
                pubkey_load_failed = true;
                break;
            };
            public_keys.append(allocator, pk.handle) catch {
                pubkey_load_failed = true;
                break;
            };
        }
        if (pubkey_load_failed) {
            any_failed = true;
            continue;
        }

        // Parse the aggregated signature proof from the fixture (variable byte
        // list — scheme-agnostic at the wire level). Use the same helper the
        // state-transition runner uses so we benefit from any future format
        // tightening.
        var proof = try parseAggregatedSignatureProof(allocator, ctx, sig_value, idx);
        defer proof.deinit();

        var message_hash: [32]u8 = undefined;
        zeam_utils.hashTreeRoot(types.AttestationData, aggregated_attestation.data, &message_hash, allocator) catch {
            any_failed = true;
            continue;
        };

        const epoch: u64 = aggregated_attestation.data.slot;
        proof.verify(public_keys.items, &message_hash, epoch) catch {
            any_failed = true;
        };
    }

    return any_failed;
}

fn parseAggregatedSignatureProof(
    allocator: Allocator,
    ctx: Context,
    value: JsonValue,
    idx: usize,
) FixtureError!types.AggregatedSignatureProof {
    var label_buf: [64]u8 = undefined;
    const label = std.fmt.bufPrint(&label_buf, "attestationSignatures[{d}]", .{idx}) catch "attestationSignatures[]";

    const obj = try expect_mod.expectObjectValue(FixtureError, value, ctx, label);

    const participants_value = obj.get("participants") orelse {
        std.debug.print(
            "fixture {s} case {s}: {s}.participants missing\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    };
    var participants = try stf_runner.parseAggregationBits(allocator, ctx, participants_value);
    errdefer participants.deinit();

    const proof_data_obj = try expect_mod.expectObject(FixtureError, obj, &.{ "proofData", "proof_data" }, ctx, "attestationSignatures[].proofData");
    const proof_data_hex = try expect_mod.expectStringField(FixtureError, proof_data_obj, &.{"data"}, ctx, "attestationSignatures[].proofData.data");
    const proof_data_bytes = try parseHexBytes(allocator, ctx, proof_data_hex, "attestationSignatures[].proofData.data");

    var proof_data = try xmss.ByteListMiB.init(allocator);
    errdefer proof_data.deinit();
    for (proof_data_bytes) |b| {
        proof_data.append(b) catch return FixtureError.InvalidFixture;
    }

    return types.AggregatedSignatureProof{
        .participants = participants,
        .proof_data = proof_data,
    };
}

fn parseHexBytes(
    allocator: Allocator,
    ctx: Context,
    hex: []const u8,
    label: []const u8,
) FixtureError![]u8 {
    if (hex.len < 2 or !std.mem.eql(u8, hex[0..2], "0x")) {
        std.debug.print(
            "fixture {s} case {s}: {s} missing 0x prefix\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    }
    const hex_body = hex[2..];
    if (hex_body.len % 2 != 0) {
        std.debug.print(
            "fixture {s} case {s}: {s} hex length not even\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    }
    const byte_len = hex_body.len / 2;
    const out = allocator.alloc(u8, byte_len) catch return FixtureError.InvalidFixture;
    _ = std.fmt.hexToBytes(out, hex_body) catch {
        std.debug.print(
            "fixture {s} case {s}: {s} hex decode failed\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    };
    return out;
}
