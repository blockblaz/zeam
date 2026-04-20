const std = @import("std");
const ssz = @import("ssz");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");
const skip = @import("../skip.zig");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const types = @import("@zeam/types");
const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Generic SSZ types exercised by leanSpec's basic-types / xmss-containers
// fixtures. These are not part of zeam's consensus model; they exist purely
// to give the SSZ roundtrip runner something to deserialize/reserialize.
// ---------------------------------------------------------------------------

/// Mersenne-31 field element. SSZ-serialized as Uint32 (4 bytes LE).
const Fp = u32;

// Fixed-size bitvectors — the SSZ library packs `[N]bool` bit-by-bit and
// writes the trailing partial byte when N % 8 != 0.
const SampleBitvector8 = [8]bool;
const SampleBitvector64 = [64]bool;
const AttestationSubnets = [64]bool;
const SyncCommitteeSubnets = [4]bool;

// Fixed-size byte arrays (SSZ ByteVector).
const Bytes4 = [4]u8;
const Bytes64 = [64]u8;

// Fixed-size integer vectors.
const SampleUint16Vector3 = [3]u16;
const SampleUint64Vector4 = [4]u64;

// Variable-size collections.
const SampleBitlist16 = ssz.utils.Bitlist(16);
const SampleBytes32List8 = ssz.utils.List([32]u8, 8);
const SampleUint32List16 = ssz.utils.List(u32, 16);
const ByteListMiB = xmss.ByteListMiB;

// xmss HashTreeOpening: Container{ siblings: List[Vector[Fp, HASH_LEN_FE],
// NODE_LIST_LIMIT] }. For leanEnv=test, HASH_LEN_FE=8 and LOG_LIFETIME=8,
// so NODE_LIST_LIMIT = 1 << (8/2 + 1) = 32.
const TestHashDigestVector = [8]Fp;
const TestHashDigestList = ssz.utils.List(TestHashDigestVector, 32);
const TestHashTreeOpening = struct {
    siblings: TestHashDigestList,

    pub fn deinit(self: *TestHashTreeOpening) void {
        self.siblings.deinit();
    }
};

pub const name = "ssz";

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

// ---------------------------------------------------------------------------
// Test-mode type mirrors: same struct layout as prod types but with [424]u8
// signatures instead of the prod SIGBYTES.  Used for SSZ roundtrip testing
// when fixtures are generated with leanEnv=test (test signature scheme).
// ---------------------------------------------------------------------------

const TEST_SIGSIZE = 424;
const TEST_SIGBYTES = [TEST_SIGSIZE]u8;

/// Mirror of types.SignedAttestation with test-sized signature.
const TestSignedAttestation = struct {
    validator_id: types.ValidatorIndex,
    message: types.AttestationData,
    signature: TEST_SIGBYTES,
};

/// Mirror of types.BlockSignatures with test-sized proposer_signature.
/// attestation_signatures uses AggregatedSignatureProof (ByteListMiB) which
/// has no SIGBYTES dependency, so it stays unchanged.
const TestBlockSignatures = struct {
    attestation_signatures: types.AttestationSignatures,
    proposer_signature: TEST_SIGBYTES,

    pub fn deinit(self: *TestBlockSignatures) void {
        for (self.attestation_signatures.slice()) |*group| {
            group.deinit();
        }
        self.attestation_signatures.deinit();
    }
};

/// Mirror of types.SignedBlock with test-sized BlockSignatures.
const TestSignedBlock = struct {
    block: types.BeamBlock,
    signature: TestBlockSignatures,

    pub fn deinit(self: *TestSignedBlock) void {
        self.block.deinit();
        self.signature.deinit();
    }
};

// ---------------------------------------------------------------------------
// SSZ type map — maps fixture `typeName` to Zig types.
// For entries with test_zig_type != null, the test type is used when
// leanEnv=test so that signatures deserialize at the correct size.
// ---------------------------------------------------------------------------

const SszTypeEntry = struct {
    name: []const u8,
    zig_type: type,
    has_deinit: bool,
    // Optional test-mode type with [424]u8 signatures.
    test_zig_type: ?type = null,
    test_has_deinit: bool = false,
};

const ssz_type_map = [_]SszTypeEntry{
    .{ .name = "Block", .zig_type = types.BeamBlock, .has_deinit = true },
    .{ .name = "BlockBody", .zig_type = types.BeamBlockBody, .has_deinit = true },
    .{ .name = "BlockHeader", .zig_type = types.BeamBlockHeader, .has_deinit = false },
    .{ .name = "Config", .zig_type = types.BeamStateConfig, .has_deinit = false },
    .{ .name = "Checkpoint", .zig_type = types.Checkpoint, .has_deinit = false },
    .{ .name = "Validator", .zig_type = types.Validator, .has_deinit = false },
    .{ .name = "Attestation", .zig_type = types.Attestation, .has_deinit = false },
    .{ .name = "AttestationData", .zig_type = types.AttestationData, .has_deinit = false },
    .{ .name = "AggregatedAttestation", .zig_type = types.AggregatedAttestation, .has_deinit = true },
    .{ .name = "State", .zig_type = types.BeamState, .has_deinit = true },
    .{ .name = "Status", .zig_type = types.Status, .has_deinit = false },
    .{ .name = "BlocksByRootRequest", .zig_type = types.BlockByRootRequest, .has_deinit = false },
    .{ .name = "AggregatedSignatureProof", .zig_type = types.AggregatedSignatureProof, .has_deinit = true },
    .{ .name = "PublicKey", .zig_type = types.Bytes52, .has_deinit = false },
    .{ .name = "SignedBlock", .zig_type = types.SignedBlock, .has_deinit = true, .test_zig_type = TestSignedBlock, .test_has_deinit = true },
    .{ .name = "SignedAttestation", .zig_type = types.SignedAttestation, .has_deinit = false, .test_zig_type = TestSignedAttestation, .test_has_deinit = false },
    .{ .name = "BlockSignatures", .zig_type = types.BlockSignatures, .has_deinit = true, .test_zig_type = TestBlockSignatures, .test_has_deinit = true },
    .{ .name = "Signature", .zig_type = types.SIGBYTES, .has_deinit = false, .test_zig_type = TEST_SIGBYTES, .test_has_deinit = false },
    .{ .name = "SignedAggregatedAttestation", .zig_type = types.SignedAggregatedAttestation, .has_deinit = true },
    // SSZ basic scalar types from leanSpec's test_basic_types fixtures.
    .{ .name = "Boolean", .zig_type = bool, .has_deinit = false },
    .{ .name = "Uint8", .zig_type = u8, .has_deinit = false },
    .{ .name = "Uint16", .zig_type = u16, .has_deinit = false },
    .{ .name = "Uint32", .zig_type = u32, .has_deinit = false },
    .{ .name = "Uint64", .zig_type = u64, .has_deinit = false },
    .{ .name = "Fp", .zig_type = Fp, .has_deinit = false },
    // Fixed-size byte arrays.
    .{ .name = "Bytes4", .zig_type = Bytes4, .has_deinit = false },
    .{ .name = "Bytes32", .zig_type = types.Bytes32, .has_deinit = false },
    .{ .name = "Bytes52", .zig_type = types.Bytes52, .has_deinit = false },
    .{ .name = "Bytes64", .zig_type = Bytes64, .has_deinit = false },
    // Fixed-size bitvectors (serialized bit-packed, trailing partial byte).
    .{ .name = "SampleBitvector8", .zig_type = SampleBitvector8, .has_deinit = false },
    .{ .name = "SampleBitvector64", .zig_type = SampleBitvector64, .has_deinit = false },
    .{ .name = "AttestationSubnets", .zig_type = AttestationSubnets, .has_deinit = false },
    .{ .name = "SyncCommitteeSubnets", .zig_type = SyncCommitteeSubnets, .has_deinit = false },
    // Fixed-size integer vectors.
    .{ .name = "SampleUint16Vector3", .zig_type = SampleUint16Vector3, .has_deinit = false },
    .{ .name = "SampleUint64Vector4", .zig_type = SampleUint64Vector4, .has_deinit = false },
    // Variable-size lists / bitlists.
    .{ .name = "SampleBitlist16", .zig_type = SampleBitlist16, .has_deinit = true },
    .{ .name = "SampleBytes32List8", .zig_type = SampleBytes32List8, .has_deinit = true },
    .{ .name = "SampleUint32List16", .zig_type = SampleUint32List16, .has_deinit = true },
    .{ .name = "ByteListMiB", .zig_type = ByteListMiB, .has_deinit = true },
    // xmss HashTreeOpening (test-env only; prod LOG_LIFETIME differs).
    .{ .name = "HashTreeOpening", .zig_type = TestHashTreeOpening, .has_deinit = true },
};

pub fn TestCase(
    comptime spec_fork: Fork,
    comptime rel_path: []const u8,
) type {
    return struct {
        payload: []u8,

        const Self = @This();

        pub fn execute(allocator: Allocator, dir: std.fs.Dir) RunnerError!void {
            var tc = try Self.init(allocator, dir);
            defer tc.deinit(allocator);
            tc.run(allocator) catch |err| switch (err) {
                error.SkippedFixture => return, // treat skip as pass
                else => return err,
            };
        }

        pub fn init(allocator: Allocator, dir: std.fs.Dir) RunnerError!Self {
            const payload = try loadFixturePayload(allocator, dir, rel_path);
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

fn loadFixturePayload(
    allocator: Allocator,
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

    const root = parsed.value;
    const obj = switch (root) {
        .object => |map| map,
        else => {
            std.debug.print("spectest: fixture {s} must be JSON object\n", .{fixture_label});
            return FixtureError.InvalidFixture;
        },
    };

    var it = obj.iterator();
    while (it.next()) |entry| {
        const case_name = entry.key_ptr.*;
        const case_value = entry.value_ptr.*;
        const ctx = Context{ .fixture_label = fixture_label, .case_name = case_name };
        try runCase(allocator, ctx, case_value);
    }
}

fn runCase(
    allocator: Allocator,
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

    const type_name = try expect_mod.expectStringField(FixtureError, case_obj, &.{"typeName"}, ctx, "typeName");
    const lean_env = try expect_mod.expectStringField(FixtureError, case_obj, &.{"leanEnv"}, ctx, "leanEnv");
    const serialized_hex = try expect_mod.expectStringField(FixtureError, case_obj, &.{"serialized"}, ctx, "serialized");

    // Decode hex to bytes
    if (serialized_hex.len < 2 or !std.mem.eql(u8, serialized_hex[0..2], "0x")) {
        std.debug.print("fixture {s} case {s}: serialized missing 0x prefix\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    }
    const hex_body = serialized_hex[2..];
    if (hex_body.len % 2 != 0) {
        std.debug.print("fixture {s} case {s}: serialized hex length not even\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    }
    const byte_len = hex_body.len / 2;
    const raw_bytes = allocator.alloc(u8, byte_len) catch {
        std.debug.print("fixture {s} case {s}: allocation failed\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    };
    defer allocator.free(raw_bytes);

    _ = std.fmt.hexToBytes(raw_bytes, hex_body) catch {
        std.debug.print("fixture {s} case {s}: invalid hex in serialized\n", .{ ctx.fixture_label, ctx.case_name });
        return FixtureError.InvalidFixture;
    };

    try dispatchSszRoundtrip(allocator, ctx, type_name, lean_env, raw_bytes);
}

/// Types that leanSpec exercises but zeam cannot yet roundtrip:
///   - SSZ Union (new variadic-selector feature; zeam's SSZ library has
///     no `union(enum)` serialization path).
///   - Types embedding `[N]T` where T has size > 1 (e.g. `[3]u16`,
///     `Vector[Fp, 8]`): `ssz.deserialize` for `.array` conflates element
///     index with byte offset, so only out[0] and out[2...] get written,
///     leaving interior elements undefined. Upstream blockblaz/ssz.zig bug.
///     Affected fixture types: SampleUint16Vector3, SampleUint64Vector4,
///     HashTreeOpening (typical payload), HashTreeLayer.
const skip_type_names = [_][]const u8{
    "SampleUnionNone",
    "SampleUnionTypes",
    "SampleUint16Vector3",
    "SampleUint64Vector4",
    "HashTreeLayer",
    "HashTreeOpening",
};

fn shouldSkipType(type_name: []const u8) bool {
    for (skip_type_names) |skip_name| {
        if (std.mem.eql(u8, skip_name, type_name)) return true;
    }
    return false;
}

fn dispatchSszRoundtrip(
    allocator: Allocator,
    ctx: Context,
    type_name: []const u8,
    lean_env: []const u8,
    raw_bytes: []const u8,
) FixtureError!void {
    if (shouldSkipType(type_name)) {
        return FixtureError.SkippedFixture;
    }

    const is_test_env = std.mem.eql(u8, lean_env, "test");

    inline for (ssz_type_map) |entry| {
        if (std.mem.eql(u8, type_name, entry.name)) {
            if (entry.test_zig_type) |TestType| {
                if (is_test_env) {
                    try sszRoundtrip(TestType, entry.test_has_deinit, allocator, ctx, raw_bytes);
                    return;
                }
            }
            try sszRoundtrip(entry.zig_type, entry.has_deinit, allocator, ctx, raw_bytes);
            return;
        }
    }

    std.debug.print(
        "fixture {s} case {s}: unknown SSZ type {s}\n",
        .{ ctx.fixture_label, ctx.case_name, type_name },
    );
    return FixtureError.UnsupportedFixture;
}

fn sszRoundtrip(
    comptime T: type,
    comptime has_deinit: bool,
    allocator: Allocator,
    ctx: Context,
    raw_bytes: []const u8,
) FixtureError!void {
    // Deserialize
    var decoded: T = undefined;
    ssz.deserialize(T, raw_bytes, &decoded, allocator) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: SSZ deserialize failed: {s}\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.FixtureMismatch;
    };
    defer {
        if (has_deinit) {
            decoded.deinit();
        }
    }

    // Re-serialize
    var re_encoded: std.ArrayList(u8) = .empty;
    defer re_encoded.deinit(allocator);

    ssz.serialize(T, decoded, &re_encoded, allocator) catch |err| {
        std.debug.print(
            "fixture {s} case {s}: SSZ re-serialize failed: {s}\n",
            .{ ctx.fixture_label, ctx.case_name, @errorName(err) },
        );
        return FixtureError.FixtureMismatch;
    };

    // Compare
    if (!std.mem.eql(u8, re_encoded.items, raw_bytes)) {
        std.debug.print(
            "fixture {s} case {s}: SSZ roundtrip mismatch (original {d} bytes, re-encoded {d} bytes)\n",
            .{ ctx.fixture_label, ctx.case_name, raw_bytes.len, re_encoded.items.len },
        );
        return FixtureError.FixtureMismatch;
    }
}
