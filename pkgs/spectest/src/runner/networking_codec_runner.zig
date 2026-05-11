// Unified networking_codec runner. leanSpec emits a flat fixture format —
// each case carries a `codecName` plus codec-specific `input`/`output` —
// so the runner dispatches on the codec name and skips families it doesn't
// yet cover (RLP-bound, secp256k1-bound, protobuf-bound). The handlers
// here favour reusing zeam's production codecs (snappyz, snappyframesz,
// multiformats.uvarint, network.GossipTopic) over re-implementing them.
const std = @import("std");

const expect_mod = @import("../json_expect.zig");
const forks = @import("../fork.zig");
const fixture_kind = @import("../fixture_kind.zig");

const network = @import("@zeam/network");
const snappyz = @import("snappyz");
const snappyframesz = @import("snappyframesz");

const Fork = forks.Fork;
const FixtureKind = fixture_kind.FixtureKind;
const JsonValue = std.json.Value;
const Context = expect_mod.Context;
const Allocator = std.mem.Allocator;

pub const name = "networking_codec";

pub const RunnerError = error{
    IoFailure,
} || FixtureError;

pub const FixtureError = error{
    InvalidFixture,
    UnsupportedFixture,
    FixtureMismatch,
    SkippedFixture,
};

const read_max_bytes: usize = 4 * 1024 * 1024;

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
                error.SkippedFixture => return,
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

    const codec = try expect_mod.expectStringField(FixtureError, case_obj, &.{"codecName"}, ctx, "codecName");
    const input_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"input"}, ctx, "input");
    const output_obj = try expect_mod.expectObject(FixtureError, case_obj, &.{"output"}, ctx, "output");

    if (std.mem.eql(u8, codec, "varint")) {
        return runVarint(allocator, ctx, input_obj, output_obj);
    } else if (std.mem.eql(u8, codec, "gossip_topic")) {
        return runGossipTopic(allocator, ctx, input_obj, output_obj);
    } else if (std.mem.eql(u8, codec, "gossip_message_id")) {
        return runGossipMessageId(allocator, ctx, input_obj, output_obj);
    } else if (std.mem.eql(u8, codec, "log2_distance")) {
        return runLog2Distance(allocator, ctx, input_obj, output_obj);
    } else if (std.mem.eql(u8, codec, "xor_distance")) {
        return runXorDistance(allocator, ctx, input_obj, output_obj);
    } else if (std.mem.eql(u8, codec, "snappy_block")) {
        return runSnappyBlock(allocator, ctx, input_obj, output_obj);
    } else if (std.mem.eql(u8, codec, "snappy_frame")) {
        return runSnappyFrame(allocator, ctx, input_obj, output_obj);
    }

    std.debug.print(
        "spectest: skipping networking_codec fixture {s} (codec {s} not yet implemented; needs RLP / protobuf / secp256k1 plumbing)\n",
        .{ ctx.fixture_label, codec },
    );
    return FixtureError.SkippedFixture;
}

fn runVarint(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const value = try expectAnyU64(input_obj, &.{"value"}, ctx, "input.value");
    const expected_hex = try expect_mod.expectStringField(FixtureError, output_obj, &.{"encoded"}, ctx, "output.encoded");
    const expected_len = try expect_mod.expectU64Field(FixtureError, output_obj, &.{ "byteLength", "byte_length" }, ctx, "output.byteLength");

    const expected_bytes = try parseHexBytes(allocator, ctx, expected_hex, "output.encoded");

    var buf: [10]u8 = undefined;
    const encoded = encodeVarint(&buf, value);
    if (encoded.len != expected_len) {
        std.debug.print(
            "fixture {s} case {s}: varint length mismatch (expected {d}, got {d})\n",
            .{ ctx.fixture_label, ctx.case_name, expected_len, encoded.len },
        );
        return FixtureError.FixtureMismatch;
    }
    if (!std.mem.eql(u8, encoded, expected_bytes)) {
        std.debug.print(
            "fixture {s} case {s}: varint bytes mismatch\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn encodeVarint(buf: *[10]u8, value: u64) []u8 {
    var v = value;
    var i: usize = 0;
    while (true) {
        const byte: u8 = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            buf[i] = byte;
            i += 1;
            return buf[0..i];
        } else {
            buf[i] = byte | 0x80;
            i += 1;
        }
    }
}

fn runGossipTopic(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const kind_str = try expect_mod.expectStringField(FixtureError, input_obj, &.{"kind"}, ctx, "input.kind");
    const fork_digest = try expect_mod.expectStringField(FixtureError, input_obj, &.{ "forkDigest", "fork_digest" }, ctx, "input.forkDigest");
    const expected_topic = try expect_mod.expectStringField(FixtureError, output_obj, &.{ "topicString", "topic_string" }, ctx, "output.topicString");

    const gossip_topic: network.GossipTopic = blk: {
        if (std.mem.eql(u8, kind_str, "block")) break :blk .{ .kind = .block };
        if (std.mem.eql(u8, kind_str, "aggregation")) break :blk .{ .kind = .aggregation };
        if (std.mem.eql(u8, kind_str, "attestation")) {
            const subnet = try expect_mod.expectU64Field(FixtureError, input_obj, &.{ "subnetId", "subnet_id" }, ctx, "input.subnetId");
            break :blk .{ .kind = .attestation, .subnet_id = @intCast(subnet) };
        }
        std.debug.print(
            "fixture {s} case {s}: unsupported gossip topic kind {s}\n",
            .{ ctx.fixture_label, ctx.case_name, kind_str },
        );
        return FixtureError.UnsupportedFixture;
    };

    var lean_topic = network.LeanNetworkTopic.init(allocator, gossip_topic, .ssz_snappy, fork_digest) catch return FixtureError.InvalidFixture;
    const actual = lean_topic.encode() catch return FixtureError.InvalidFixture;

    if (!std.mem.eql(u8, actual, expected_topic)) {
        std.debug.print(
            "fixture {s} case {s}: gossip topic mismatch\n  expected: {s}\n  actual:   {s}\n",
            .{ ctx.fixture_label, ctx.case_name, expected_topic, actual },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn runGossipMessageId(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const topic_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{"topic"}, ctx, "input.topic");
    const data_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{"data"}, ctx, "input.data");
    const domain_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{"domain"}, ctx, "input.domain");
    const expected_hex = try expect_mod.expectStringField(FixtureError, output_obj, &.{ "messageId", "message_id" }, ctx, "output.messageId");

    const topic_bytes = try parseHexBytes(allocator, ctx, topic_hex, "input.topic");
    const data_bytes = try parseHexBytes(allocator, ctx, data_hex, "input.data");
    const domain_bytes = try parseHexBytes(allocator, ctx, domain_hex, "input.domain");
    const expected_bytes = try parseHexBytes(allocator, ctx, expected_hex, "output.messageId");

    // Mirror rust/libp2p-glue/src/lib.rs:1601 message_id_fn — but here the
    // runner is given the topic / data / domain post-decompression, so
    // there's no Snappy fallback branch.
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domain_bytes);
    var topic_len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &topic_len_le, topic_bytes.len, .little);
    hasher.update(&topic_len_le);
    hasher.update(topic_bytes);
    hasher.update(data_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    if (expected_bytes.len != 20) {
        std.debug.print(
            "fixture {s} case {s}: expected messageId length {d}, want 20\n",
            .{ ctx.fixture_label, ctx.case_name, expected_bytes.len },
        );
        return FixtureError.InvalidFixture;
    }
    if (!std.mem.eql(u8, digest[0..20], expected_bytes)) {
        std.debug.print(
            "fixture {s} case {s}: gossip message id mismatch\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn runLog2Distance(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const node_a_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{ "nodeA", "node_a" }, ctx, "input.nodeA");
    const node_b_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{ "nodeB", "node_b" }, ctx, "input.nodeB");
    const expected = try expect_mod.expectU64Field(FixtureError, output_obj, &.{"distance"}, ctx, "output.distance");

    const a = try parseHexBytes(allocator, ctx, node_a_hex, "input.nodeA");
    const b = try parseHexBytes(allocator, ctx, node_b_hex, "input.nodeB");
    if (a.len != 32 or b.len != 32) {
        std.debug.print(
            "fixture {s} case {s}: log2_distance node ID must be 32 bytes\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.InvalidFixture;
    }

    // leanSpec log2_distance(a, b) = 0 if a == b, else
    // (256 - leading-zero-bits-of-XOR). Iterate from MSB.
    var lz: u64 = 0;
    var found = false;
    for (a, b) |x, y| {
        const diff = x ^ y;
        if (diff == 0) {
            lz += 8;
            continue;
        }
        lz += @as(u64, @clz(diff));
        found = true;
        break;
    }
    const distance: u64 = if (!found) 0 else 256 - lz;

    if (distance != expected) {
        std.debug.print(
            "fixture {s} case {s}: log2_distance mismatch (expected {d}, got {d})\n",
            .{ ctx.fixture_label, ctx.case_name, expected, distance },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn runXorDistance(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const node_a_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{ "nodeA", "node_a" }, ctx, "input.nodeA");
    const node_b_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{ "nodeB", "node_b" }, ctx, "input.nodeB");
    const expected_hex = try expect_mod.expectStringField(FixtureError, output_obj, &.{"distance"}, ctx, "output.distance");

    const a = try parseHexBytes(allocator, ctx, node_a_hex, "input.nodeA");
    const b = try parseHexBytes(allocator, ctx, node_b_hex, "input.nodeB");
    if (a.len != 32 or b.len != 32) return FixtureError.InvalidFixture;

    var distance_bytes: [32]u8 = undefined;
    for (a, b, 0..) |x, y, i| distance_bytes[i] = x ^ y;

    // leanSpec emits xor_distance as a minimal hex string (leading zeros
    // stripped, but at least a single "0").
    const expected_min = try parseHexMinimal(allocator, ctx, expected_hex, "output.distance");
    const actual_min = stripLeadingZeros(distance_bytes[0..]);

    if (!std.mem.eql(u8, actual_min, expected_min)) {
        std.debug.print(
            "fixture {s} case {s}: xor_distance mismatch\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len - 1 and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

fn parseHexMinimal(allocator: Allocator, ctx: Context, hex: []const u8, label: []const u8) FixtureError![]u8 {
    if (hex.len < 2 or !std.mem.eql(u8, hex[0..2], "0x")) return FixtureError.InvalidFixture;
    var hex_body = hex[2..];
    // Pad to even length so hexToBytes works.
    var padded_buf: [128]u8 = undefined;
    if (hex_body.len % 2 == 1) {
        padded_buf[0] = '0';
        @memcpy(padded_buf[1 .. hex_body.len + 1], hex_body);
        hex_body = padded_buf[0 .. hex_body.len + 1];
    }
    const out = allocator.alloc(u8, hex_body.len / 2) catch return FixtureError.InvalidFixture;
    _ = std.fmt.hexToBytes(out, hex_body) catch {
        std.debug.print(
            "fixture {s} case {s}: {s} hex decode failed\n",
            .{ ctx.fixture_label, ctx.case_name, label },
        );
        return FixtureError.InvalidFixture;
    };
    return out;
}

fn runSnappyBlock(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const data_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{"data"}, ctx, "input.data");
    const expected_hex = try expect_mod.expectStringField(FixtureError, output_obj, &.{"compressed"}, ctx, "output.compressed");

    const data = try parseHexBytes(allocator, ctx, data_hex, "input.data");
    const expected = try parseHexBytes(allocator, ctx, expected_hex, "output.compressed");

    // Snappy block compression is non-canonical: implementations are free
    // to pick between equivalent literal/copy tag sequences. Verify
    // wire-format interop by decoding leanSpec's output and round-tripping
    // zeam's own encode/decode pair, instead of demanding byte equality.
    const decoded_expected = snappyz.decode(allocator, expected) catch {
        std.debug.print(
            "fixture {s} case {s}: snappy_block: zeam decoder failed on leanSpec-emitted bytes\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    };
    if (!std.mem.eql(u8, decoded_expected, data)) {
        std.debug.print(
            "fixture {s} case {s}: snappy_block: leanSpec compressed bytes do not decode to input\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
    const our_encoded = snappyz.encode(allocator, data) catch return FixtureError.InvalidFixture;
    const our_decoded = snappyz.decode(allocator, our_encoded) catch return FixtureError.InvalidFixture;
    if (!std.mem.eql(u8, our_decoded, data)) {
        std.debug.print(
            "fixture {s} case {s}: snappy_block: zeam encode→decode round-trip lost data\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
}

fn runSnappyFrame(allocator: Allocator, ctx: Context, input_obj: std.json.ObjectMap, output_obj: std.json.ObjectMap) FixtureError!void {
    const data_hex = try expect_mod.expectStringField(FixtureError, input_obj, &.{"data"}, ctx, "input.data");
    const expected_hex = try expect_mod.expectStringField(FixtureError, output_obj, &.{"framed"}, ctx, "output.framed");

    const data = try parseHexBytes(allocator, ctx, data_hex, "input.data");
    const expected = try parseHexBytes(allocator, ctx, expected_hex, "output.framed");

    // Same non-canonical-encoder caveat as snappy_block: emitter choices
    // about chunk layout differ between implementations. Validate via
    // round-trip on both sides.
    const decoded_expected = snappyframesz.decode(allocator, expected) catch {
        std.debug.print(
            "fixture {s} case {s}: snappy_frame: zeam decoder failed on leanSpec-emitted bytes\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    };
    if (!std.mem.eql(u8, decoded_expected, data)) {
        std.debug.print(
            "fixture {s} case {s}: snappy_frame: leanSpec framed bytes do not decode to input\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
    const our_encoded = snappyframesz.encode(allocator, data) catch return FixtureError.InvalidFixture;
    const our_decoded = snappyframesz.decode(allocator, our_encoded) catch return FixtureError.InvalidFixture;
    if (!std.mem.eql(u8, our_decoded, data)) {
        std.debug.print(
            "fixture {s} case {s}: snappy_frame: zeam encode→decode round-trip lost data\n",
            .{ ctx.fixture_label, ctx.case_name },
        );
        return FixtureError.FixtureMismatch;
    }
}

/// Like expect_mod.expectU64Field but also accepts `number_string` JSON
/// values (used for u64_max which std.json represents as a string when it
/// overflows the native i64 path).
fn expectAnyU64(
    obj: std.json.ObjectMap,
    field_names: []const []const u8,
    ctx: Context,
    label: []const u8,
) FixtureError!u64 {
    for (field_names) |fname| {
        if (obj.get(fname)) |v| {
            return switch (v) {
                .integer => |i| if (i >= 0) @as(u64, @intCast(i)) else {
                    std.debug.print(
                        "fixture {s} case {s}: {s} negative\n",
                        .{ ctx.fixture_label, ctx.case_name, label },
                    );
                    return FixtureError.InvalidFixture;
                },
                .number_string => |s| std.fmt.parseInt(u64, s, 10) catch {
                    std.debug.print(
                        "fixture {s} case {s}: {s} not parseable as u64 ({s})\n",
                        .{ ctx.fixture_label, ctx.case_name, label, s },
                    );
                    return FixtureError.InvalidFixture;
                },
                else => {
                    std.debug.print(
                        "fixture {s} case {s}: field {s} must be numeric\n",
                        .{ ctx.fixture_label, ctx.case_name, label },
                    );
                    return FixtureError.InvalidFixture;
                },
            };
        }
    }
    std.debug.print(
        "fixture {s} case {s}: missing field {s}\n",
        .{ ctx.fixture_label, ctx.case_name, label },
    );
    return FixtureError.InvalidFixture;
}

fn parseHexBytes(allocator: Allocator, ctx: Context, hex: []const u8, label: []const u8) FixtureError![]u8 {
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
