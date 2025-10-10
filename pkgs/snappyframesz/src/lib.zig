const std = @import("std");
const snappyz = @import("snappyz");

const Allocator = std.mem.Allocator;
const math = std.math;

const FrameError = error{
    UnexpectedEof,
    InvalidStreamIdentifier,
    UnsupportedUnskippableChunkType,
    ChunkTooLarge,
    BadChecksum,
    NotFramed,
    EmptyStream,
};

const stream_identifier = "\xff\x06\x00\x00sNaPpY"; // type + length + "sNaPpY"
const identifier_payload = "sNaPpY";
const masked_crc_constant: u32 = 0xa282ead8;
const max_chunk_len: usize = (1 << 24) - 1; // 24-bit length field
const recommended_chunk: usize = 1 << 16; // 64KiB

pub fn encode(allocator: Allocator, data: []const u8) ![]u8 {
    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();

    try output.ensureTotalCapacityPrecise(stream_identifier.len);
    output.appendSliceAssumeCapacity(stream_identifier);

    if (data.len == 0) {
        return output.toOwnedSlice();
    }

    var chunk_buf = std.ArrayList(u8).init(allocator);
    defer chunk_buf.deinit();

    var index: usize = 0;
    while (index < data.len) {
        const end_index = @min(index + recommended_chunk, data.len);
        const chunk_input = data[index..end_index];

        chunk_buf.clearRetainingCapacity();
        const checksum = maskedChecksum(chunk_input);
        try appendU32le(&chunk_buf, checksum);

        const compressed = try snappyz.encode(allocator, chunk_input);
        defer allocator.free(compressed);
        const use_uncompressed = compressed.len >= chunk_input.len;
        const payload = if (use_uncompressed) chunk_input else compressed;
        const chunk_type: u8 = if (use_uncompressed) 0x01 else 0x00;

        if (payload.len > max_chunk_len - 4) {
            return error.ChunkTooLarge;
        }

        try chunk_buf.appendSlice(payload);

        try appendChunk(&output, chunk_type, chunk_buf.items);

        index = end_index;
    }

    return output.toOwnedSlice();
}

pub fn encodeToWriter(allocator: Allocator, reader: anytype, writer: anytype) !void {
    try writer.writeAll(stream_identifier);

    var chunk_input_buffer = try allocator.alloc(u8, recommended_chunk);
    defer allocator.free(chunk_input_buffer);

    while (true) {
        const read_len = try reader.read(chunk_input_buffer);
        if (read_len == 0) break;

        const chunk_input = chunk_input_buffer[0..read_len];
        const checksum = maskedChecksum(chunk_input);

        const compressed = try snappyz.encode(allocator, chunk_input);
        defer allocator.free(compressed);

        const use_uncompressed = compressed.len >= chunk_input.len;
        const payload_len = if (use_uncompressed) chunk_input.len else compressed.len;
        const chunk_type: u8 = if (use_uncompressed) 0x01 else 0x00;

        if (payload_len > max_chunk_len - 4) {
            return error.ChunkTooLarge;
        }

        try writeChunkHeader(writer, chunk_type, payload_len + 4);

        var checksum_bytes: [4]u8 = undefined;
        std.mem.writeIntLittle(u32, checksum_bytes[0..], checksum);
        try writer.writeAll(&checksum_bytes);
        if (use_uncompressed) {
            try writer.writeAll(chunk_input);
        } else {
            try writer.writeAll(compressed);
        }
    }
}

pub fn decode(allocator: Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) {
        return error.EmptyStream;
    }

    return decodeFramed(allocator, data) catch |err| switch (err) {
        FrameError.NotFramed, FrameError.EmptyStream => snappyz.decode(allocator, data),
        else => |e| return e,
    };
}

pub fn decodeFromReader(allocator: Allocator, reader: anytype, writer: anytype) !void {
    var chunk_buf = std.ArrayList(u8).init(allocator);
    defer chunk_buf.deinit();

    var processed_any_chunk = false;
    var saw_stream_identifier = false;
    var saw_data_chunk = false;

    var header: [4]u8 = undefined;

    while (true) {
        const maybe_first = try readByte(reader);
        if (maybe_first == null) break;

        const is_first_chunk = !processed_any_chunk;
        processed_any_chunk = true;
        header[0] = maybe_first.?;
        try readExact(reader, header[1..]);

        const chunk_type = header[0];
        const length = readChunkLength(header[1..4]);

        if (length > max_chunk_len) return FrameError.ChunkTooLarge;

        try chunk_buf.resize(length);
        try readExact(reader, chunk_buf.items);

        const chunk_data = chunk_buf.items;

        switch (chunk_type) {
            0xff => {
                if (length != identifier_payload.len) return FrameError.InvalidStreamIdentifier;
                if (!std.mem.eql(u8, chunk_data, identifier_payload)) {
                    return FrameError.InvalidStreamIdentifier;
                }
                saw_stream_identifier = true;
            },
            0x00 => {
                if (length < 4) return FrameError.UnexpectedEof;
                const expected_checksum = readU32le(chunk_data[0..4]);
                const compressed_payload = chunk_data[4..];
                const decoded = try snappyz.decode(allocator, compressed_payload);
                defer allocator.free(decoded);
                try validateChecksum(decoded, expected_checksum);
                try writer.writeAll(decoded);
                saw_data_chunk = true;
            },
            0x01 => {
                if (length < 4) return FrameError.UnexpectedEof;
                const expected_checksum = readU32le(chunk_data[0..4]);
                const raw_payload = chunk_data[4..];
                try validateChecksum(raw_payload, expected_checksum);
                try writer.writeAll(raw_payload);
                saw_data_chunk = true;
            },
            else => {
                if (chunk_type >= 0x80 and chunk_type <= 0xfe) {
                    // skippable chunk
                } else if (!saw_stream_identifier and !saw_data_chunk and is_first_chunk) {
                    return FrameError.NotFramed;
                } else {
                    return FrameError.UnsupportedUnskippableChunkType;
                }
            },
        }

        chunk_buf.clearRetainingCapacity();
    }

    if (!saw_data_chunk) return FrameError.NotFramed;
}

fn decodeFramed(allocator: Allocator, data: []const u8) ![]u8 {
    if (data.len < 4) return FrameError.NotFramed;

    var cursor: usize = 0;
    var saw_data_chunk = false;
    var saw_stream_identifier = false;

    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();

    while (cursor < data.len) {
        if (data.len - cursor < 4) return FrameError.UnexpectedEof;
        const chunk_type = data[cursor];
        const length = readChunkLength(data[cursor + 1 .. cursor + 4]);
        cursor += 4;

        if (length > max_chunk_len) return FrameError.ChunkTooLarge;
        if (cursor + length > data.len) return FrameError.UnexpectedEof;

        const chunk_data = data[cursor .. cursor + length];
        cursor += length;

        switch (chunk_type) {
            0xff => {
                if (length != identifier_payload.len) return FrameError.InvalidStreamIdentifier;
                if (!std.mem.eql(u8, chunk_data, identifier_payload)) {
                    return FrameError.InvalidStreamIdentifier;
                }
                saw_stream_identifier = true;
            },
            0x00 => {
                if (length < 4) return FrameError.UnexpectedEof;
                const expected_checksum = readU32le(chunk_data[0..4]);
                const compressed_payload = chunk_data[4..];
                const decoded = try snappyz.decode(allocator, compressed_payload);
                defer allocator.free(decoded);
                try validateChecksum(decoded, expected_checksum);
                try output.appendSlice(decoded);
                saw_data_chunk = true;
            },
            0x01 => {
                if (length < 4) return FrameError.UnexpectedEof;
                const expected_checksum = readU32le(chunk_data[0..4]);
                const raw_payload = chunk_data[4..];
                try validateChecksum(raw_payload, expected_checksum);
                try output.appendSlice(raw_payload);
                saw_data_chunk = true;
            },
            else => {
                if (chunk_type >= 0x80 and chunk_type <= 0xfe) {
                    continue; // skippable chunk
                }
                if (!saw_stream_identifier and output.items.len == 0 and cursor == length + 4) {
                    // the first chunk is not a recognized frame chunk, treat as not framed
                    return FrameError.NotFramed;
                }
                return FrameError.UnsupportedUnskippableChunkType;
            },
        }
    }

    if (!saw_data_chunk) return FrameError.NotFramed;

    // Some producers may omit the identifier. Only enforce when data present with mismatched chunk.
    return output.toOwnedSlice();
}

fn appendChunk(output: *std.ArrayList(u8), chunk_type: u8, payload: []const u8) !void {
    if (payload.len > max_chunk_len) return FrameError.ChunkTooLarge;
    try output.ensureUnusedCapacity(4 + payload.len);
    output.appendAssumeCapacity(chunk_type);
    const byte0: u8 = @intCast(payload.len & 0xff);
    const byte1: u8 = @intCast((payload.len >> 8) & 0xff);
    const byte2: u8 = @intCast((payload.len >> 16) & 0xff);
    output.appendAssumeCapacity(byte0);
    output.appendAssumeCapacity(byte1);
    output.appendAssumeCapacity(byte2);
    output.appendSliceAssumeCapacity(payload);
}

fn writeChunkHeader(writer: anytype, chunk_type: u8, payload_len: usize) !void {
    if (payload_len > max_chunk_len) return FrameError.ChunkTooLarge;
    const byte0: u8 = @intCast(payload_len & 0xff);
    const byte1: u8 = @intCast((payload_len >> 8) & 0xff);
    const byte2: u8 = @intCast((payload_len >> 16) & 0xff);
    const header = [_]u8{
        chunk_type,
        byte0,
        byte1,
        byte2,
    };
    try writer.writeAll(&header);
}

fn readChunkLength(bytes: []const u8) usize {
    return @as(usize, bytes[0]) |
        (@as(usize, bytes[1]) << 8) |
        (@as(usize, bytes[2]) << 16);
}

fn appendU32le(list: *std.ArrayList(u8), value: u32) !void {
    try list.ensureUnusedCapacity(4);
    const byte0: u8 = @intCast(value & 0xff);
    const byte1: u8 = @intCast((value >> 8) & 0xff);
    const byte2: u8 = @intCast((value >> 16) & 0xff);
    const byte3: u8 = @intCast((value >> 24) & 0xff);
    list.appendAssumeCapacity(byte0);
    list.appendAssumeCapacity(byte1);
    list.appendAssumeCapacity(byte2);
    list.appendAssumeCapacity(byte3);
}

fn readU32le(bytes: []const u8) u32 {
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn maskedChecksum(data: []const u8) u32 {
    const crc = crc32c(data);
    const rotated = math.rotr(u32, crc, 15);
    return rotated +% masked_crc_constant;
}

fn validateChecksum(data: []const u8, expected_masked: u32) !void {
    const computed = maskedChecksum(data);
    if (computed != expected_masked) {
        return FrameError.BadChecksum;
    }
}

fn crc32c(data: []const u8) u32 {
    return std.hash.crc.Crc32Iscsi.hash(data);
}

fn readExact(reader: anytype, buffer: []u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        const read_len = try reader.read(buffer[index..]);
        if (read_len == 0) return FrameError.UnexpectedEof;
        index += read_len;
    }
}

fn readByte(reader: anytype) !?u8 {
    var byte: [1]u8 = undefined;
    const read_len = try reader.read(&byte);
    if (read_len == 0) return null;
    return byte[0];
}

const go_writer_golden_frame =
    "\xff\x06\x00\x00sNaPpY" ++
    "\x01\x08\x00\x00" ++
    "\x68\x10\xe6\xb6" ++
    "\x61\x62\x63\x64" ++
    "\x00\x11\x00\x00" ++
    "\x5f\xeb\xf2\x10" ++
    "\x96\x01" ++
    "\x00\x41" ++
    "\xfe\x01\x00" ++
    "\xfe\x01\x00" ++
    "\x52\x01\x00" ++
    "\x00\x18\x00\x00" ++
    "\x30\x85\x69\xeb" ++
    "\x70" ++
    "\x00\x42" ++
    "\xee\x01\x00" ++
    "\x0d\x01" ++
    "\x08\x65\x66\x43" ++
    "\x4e\x01\x00" ++
    "\x4e\x5a\x00" ++
    "\x00\x67";

test "encodeToWriter matches encode" {
    const allocator = std.testing.allocator;
    const sample = "frame-streaming-testframe-streaming-test";

    const direct = try encode(allocator, sample);
    defer allocator.free(direct);

    var reader_stream = std.io.FixedBufferStream([]const u8).init(sample);
    var encoded_buffer = std.ArrayList(u8).init(allocator);
    defer encoded_buffer.deinit();

    try encodeToWriter(allocator, reader_stream.reader(), encoded_buffer.writer());

    try std.testing.expectEqualSlices(u8, direct, encoded_buffer.items);
}

test "decodeFromReader matches decode" {
    const allocator = std.testing.allocator;
    const sample = "thissNaPpYYYYYYYYYYYYYYYYYYYY";

    const encoded = try encode(allocator, sample);
    defer allocator.free(encoded);

    var reader_stream = std.io.FixedBufferStream([]const u8).init(encoded);
    var decoded_buffer = std.ArrayList(u8).init(allocator);
    defer decoded_buffer.deinit();

    try decodeFromReader(allocator, reader_stream.reader(), decoded_buffer.writer());

    try std.testing.expectEqualSlices(u8, sample, decoded_buffer.items);
}

test "frame roundtrip samples" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "",
        "a",
        "hello snappy",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0123456789abcdefghijklmnopqrstuvwxyz",
    };

    for (cases) |case_data| {
        const encoded = try encode(allocator, case_data);
        defer allocator.free(encoded);

        const decoded = decode(allocator, encoded) catch |err| {
            std.debug.print("decode failed for case '{s}' with error={any}\n", .{ case_data, err });
            return err;
        };
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, case_data, decoded);
    }
}

test "frame encode splits large payload into multiple chunks" {
    const allocator = std.testing.allocator;
    const large_len = (recommended_chunk * 2) + 123;
    const large_data = try allocator.alloc(u8, large_len);
    defer allocator.free(large_data);

    for (large_data, 0..) |*byte, idx| {
        byte.* = @intCast((idx * 31) % 251);
    }

    const encoded = try encode(allocator, large_data);
    defer allocator.free(encoded);

    var chunk_count: usize = 0;
    var cursor: usize = stream_identifier.len;
    while (cursor + 4 <= encoded.len) {
        chunk_count += 1;
        const length = readChunkLength(encoded[cursor + 1 .. cursor + 4]);
        cursor += 4 + length;
    }

    try std.testing.expect(chunk_count >= 2);

    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, large_data, decoded);
}

test "decode falls back to raw snappy payloads" {
    const allocator = std.testing.allocator;
    const sample = "raw snappy payload";
    const raw = try snappyz.encode(allocator, sample);
    defer allocator.free(raw);

    const decoded = try decode(allocator, raw);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, sample, decoded);
}

test "decode rejects invalid stream identifier" {
    const allocator = std.testing.allocator;
    const sample = "identifier";
    const encoded = try encode(allocator, sample);
    defer allocator.free(encoded);

    var invalid = try allocator.dupe(u8, encoded);
    defer allocator.free(invalid);
    invalid[4] ^= 0xff; // corrupt the identifier payload

    try std.testing.expectError(FrameError.InvalidStreamIdentifier, decode(allocator, invalid));
}

test "decode detects checksum mismatch" {
    const allocator = std.testing.allocator;
    const sample = "checksum";
    const encoded = try encode(allocator, sample);
    defer allocator.free(encoded);

    var corrupted = try allocator.dupe(u8, encoded);
    defer allocator.free(corrupted);

    const first_chunk = stream_identifier.len;
    corrupted[first_chunk + 4] ^= 0xff; // flip a checksum byte

    try std.testing.expectError(FrameError.BadChecksum, decode(allocator, corrupted));
}

test "decode compatibility with go snappy writer golden output" {
    const allocator = std.testing.allocator;
    const decoded = try decode(allocator, go_writer_golden_frame);
    defer allocator.free(decoded);

    const expected_total_len = 4 + 150 + 68 + 3 + 20 + 20 + 1;
    try std.testing.expectEqual(@as(usize, expected_total_len), decoded.len);
    try std.testing.expectEqualSlices(u8, "abcd", decoded[0..4]);

    var cursor: usize = 4;
    try std.testing.expect(std.mem.allEqual(u8, 'A', decoded[cursor .. cursor + 150]));
    cursor += 150;
    try std.testing.expect(std.mem.allEqual(u8, 'B', decoded[cursor .. cursor + 68]));
    cursor += 68;
    try std.testing.expectEqualSlices(u8, "efC", decoded[cursor .. cursor + 3]);
    cursor += 3;
    try std.testing.expect(std.mem.allEqual(u8, 'C', decoded[cursor .. cursor + 20]));
    cursor += 20;
    try std.testing.expect(std.mem.allEqual(u8, 'B', decoded[cursor .. cursor + 20]));
    cursor += 20;
    try std.testing.expectEqual(@as(u8, 'g'), decoded[cursor]);
}

test "encode compatibility with go snappy writer golden output" {
    const allocator = std.testing.allocator;

    const SegmentSpec = union(enum) {
        literal: []const u8,
        repeat: struct { ch: u8, len: usize },
    };

    const segment_specs = [_]SegmentSpec{
        SegmentSpec{ .literal = "abcd" },
        SegmentSpec{ .repeat = .{ .ch = @as(u8, 'A'), .len = 150 } },
        SegmentSpec{ .repeat = .{ .ch = @as(u8, 'B'), .len = 68 } },
        SegmentSpec{ .literal = "efC" },
        SegmentSpec{ .repeat = .{ .ch = @as(u8, 'C'), .len = 20 } },
        SegmentSpec{ .repeat = .{ .ch = @as(u8, 'B'), .len = 20 } },
        SegmentSpec{ .literal = "g" },
    };

    var payload_builder = std.ArrayList(u8).init(allocator);
    defer payload_builder.deinit();

    for (segment_specs) |spec| switch (spec) {
        .literal => |lit| try payload_builder.appendSlice(lit),
        .repeat => |rep| {
            try payload_builder.ensureUnusedCapacity(rep.len);
            var i: usize = 0;
            while (i < rep.len) : (i += 1) try payload_builder.append(rep.ch);
        },
    };

    const payload = try payload_builder.toOwnedSlice();
    defer allocator.free(payload);

    const segments = try allocator.alloc([]const u8, segment_specs.len);
    defer allocator.free(segments);

    var offset: usize = 0;
    for (segment_specs, 0..) |spec, idx| {
        const len = switch (spec) {
            .literal => |lit| lit.len,
            .repeat => |rep| rep.len,
        };
        segments[idx] = payload[offset .. offset + len];
        offset += len;
    }

    const SegmentedReader = struct {
        segments: []const []const u8,
        index: usize = 0,

        pub fn read(self: *@This(), buffer: []u8) !usize {
            if (self.index >= self.segments.len) return 0;
            const segment = self.segments[self.index];
            std.debug.assert(buffer.len >= segment.len);
            std.mem.copy(u8, buffer[0..segment.len], segment);
            self.index += 1;
            return segment.len;
        }
    };

    var segmented_reader = SegmentedReader{ .segments = segments };
    var encoded = std.ArrayList(u8).init(allocator);
    defer encoded.deinit();

    try encodeToWriter(allocator, &segmented_reader, encoded.writer());

    try std.testing.expectEqualSlices(u8, go_writer_golden_frame, encoded.items);
}
