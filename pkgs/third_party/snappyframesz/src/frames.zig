/// Snappy framing encode/decode utilities with compatibility helpers for external producers.
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

const ChunkType = enum(u8) {
    stream_identifier = 0xff,
    compressed = 0x00,
    uncompressed = 0x01,

    pub const ParseError = error{InvalidValue};

    pub fn fromByte(value: u8) ParseError!ChunkType {
        return std.enums.fromInt(ChunkType, value) orelse ParseError.InvalidValue;
    }

    pub fn toByte(self: ChunkType) u8 {
        return @intFromEnum(self);
    }
};

/// Stateful encoder for emitting Snappy frames chunk-by-chunk.
pub const FrameEncoder = struct {
    allocator: Allocator,
    wrote_stream_identifier: bool = false,
    wrote_data_chunk: bool = false,
    checksum_buf: [4]u8 = undefined,

    /// Create a new encoder that writes chunks into the provided allocator-backed writer.
    pub fn init(allocator: Allocator) FrameEncoder {
        return .{ .allocator = allocator };
    }

    fn ensureStreamIdentifier(self: *FrameEncoder, writer: anytype) !void {
        if (self.wrote_stream_identifier) return;
        try writer.writeAll(stream_identifier);
        self.wrote_stream_identifier = true;
    }

    /// Compress and emit a chunk; large chunks may be stored uncompressed per Snappy framing heuristics.
    pub fn writeChunk(self: *FrameEncoder, writer: anytype, chunk_input: []const u8) !void {
        if (chunk_input.len == 0) return;

        try self.ensureStreamIdentifier(writer);

        const checksum = maskedChecksum(chunk_input);
        std.mem.writeInt(u32, self.checksum_buf[0..], checksum, .little);

        const compressed = try snappyz.encode(self.allocator, chunk_input);
        defer self.allocator.free(compressed);

        const compress_threshold = chunk_input.len - (chunk_input.len / 8);
        const use_uncompressed = compressed.len >= compress_threshold;
        const payload_len = if (use_uncompressed) chunk_input.len else compressed.len;
        if (payload_len > max_chunk_len - 4) return FrameError.ChunkTooLarge;

        const chunk_type: ChunkType = if (use_uncompressed) .uncompressed else .compressed;
        try writeChunkHeader(writer, chunk_type, payload_len + 4);
        try writer.writeAll(&self.checksum_buf);
        if (use_uncompressed) {
            try writer.writeAll(chunk_input);
        } else {
            try writer.writeAll(compressed);
        }

        self.wrote_data_chunk = true;
    }

    fn writeEmptyChunk(self: *FrameEncoder, writer: anytype) !void {
        try self.ensureStreamIdentifier(writer);
        const checksum = maskedChecksum(&[_]u8{});
        std.mem.writeInt(u32, self.checksum_buf[0..], checksum, .little);
        try writeChunkHeader(writer, .uncompressed, 4);
        try writer.writeAll(&self.checksum_buf);
        self.wrote_data_chunk = true;
    }

    /// Finalize the stream, writing an empty chunk if no data was provided.
    pub fn finish(self: *FrameEncoder, writer: anytype) !void {
        if (!self.wrote_data_chunk) {
            try self.writeEmptyChunk(writer);
        }
    }
};

/// Encode all data into a fresh Snappy frame stored in an owned slice.
pub fn encode(allocator: Allocator, data: []const u8) ![]u8 {
    var allocating = std.Io.Writer.Allocating.init(allocator);
    errdefer allocating.deinit();

    var encoder = FrameEncoder.init(allocator);

    var index: usize = 0;
    while (index < data.len) {
        const end_index = @min(index + recommended_chunk, data.len);
        const chunk_input = data[index..end_index];
        try encoder.writeChunk(&allocating.writer, chunk_input);
        index = end_index;
    }

    try encoder.finish(&allocating.writer);

    return allocating.toOwnedSlice();
}

/// Stream input from `reader` into the frame writer without buffering the entire payload.
pub fn encodeToWriter(allocator: Allocator, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    var encoder = FrameEncoder.init(allocator);

    var chunk_input_buffer = try allocator.alloc(u8, recommended_chunk);
    defer allocator.free(chunk_input_buffer);

    while (true) {
        const read_len = try reader.readSliceShort(chunk_input_buffer);
        if (read_len == 0) break;

        try encoder.writeChunk(writer, chunk_input_buffer[0..read_len]);
    }

    try encoder.finish(writer);
}

/// Decode either a framed Snappy payload or raw Snappy buffer into newly allocated bytes.
pub fn decode(allocator: Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) {
        return error.EmptyStream;
    }

    return decodeFramed(allocator, data) catch |err| switch (err) {
        FrameError.NotFramed, FrameError.EmptyStream => snappyz.decode(allocator, data),
        else => |e| return e,
    };
}

/// Decode framed input from `reader`, writing decompressed output into `writer`.
pub fn decodeFromReader(allocator: Allocator, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    var chunk_buf: std.ArrayList(u8) = .empty;
    defer chunk_buf.deinit(allocator);

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

        const chunk_type_byte = header[0];
        const length = readChunkLength(header[1..4]);

        if (length > max_chunk_len) return FrameError.ChunkTooLarge;

        try chunk_buf.resize(allocator, length);
        try readExact(reader, chunk_buf.items);

        const chunk_data = chunk_buf.items;

        const maybe_chunk_type = ChunkType.fromByte(chunk_type_byte) catch null;

        if (maybe_chunk_type) |chunk_type| {
            switch (chunk_type) {
                .stream_identifier => {
                    try ensureStreamIdentifier(chunk_data);
                    saw_stream_identifier = true;
                },
                .compressed => {
                    try writeCompressedChunk(allocator, writer, chunk_data);
                    saw_data_chunk = true;
                },
                .uncompressed => {
                    try writeUncompressedChunk(writer, chunk_data);
                    saw_data_chunk = true;
                },
            }
        } else {
            if (chunk_type_byte >= 0x80 and chunk_type_byte <= 0xfd) {
                chunk_buf.clearRetainingCapacity();
                continue;
            }
            if (!saw_stream_identifier and !saw_data_chunk and is_first_chunk) {
                return FrameError.NotFramed;
            }
            return FrameError.UnsupportedUnskippableChunkType;
        }

        chunk_buf.clearRetainingCapacity();
    }

    // A stream that contained the identifier but no data chunks is a valid
    // empty payload per the Snappy framing spec. Only treat the input as
    // unframed when neither was seen. (Upstream blockblaz/snappyframesz#8.)
    if (!saw_stream_identifier and !saw_data_chunk) return FrameError.NotFramed;
}

fn decodeFramed(allocator: Allocator, data: []const u8) ![]u8 {
    if (data.len < 4) return FrameError.NotFramed;

    var cursor: usize = 0;
    var saw_data_chunk = false;
    var saw_stream_identifier = false;

    var allocating = std.Io.Writer.Allocating.init(allocator);
    errdefer allocating.deinit();

    while (cursor < data.len) {
        if (data.len - cursor < 4) return FrameError.UnexpectedEof;
        const chunk_start = cursor;
        const chunk_type_byte = data[cursor];
        const is_first_chunk = !saw_stream_identifier and !saw_data_chunk and chunk_start == 0;
        const maybe_chunk_type = ChunkType.fromByte(chunk_type_byte) catch null;
        if (is_first_chunk and maybe_chunk_type == null and !(chunk_type_byte >= 0x80 and chunk_type_byte <= 0xfd)) {
            return FrameError.NotFramed;
        }

        const length = readChunkLength(data[cursor + 1 .. cursor + 4]);
        cursor += 4;

        if (length > max_chunk_len) return FrameError.ChunkTooLarge;
        if (cursor + length > data.len) return FrameError.UnexpectedEof;

        const chunk_data = data[cursor .. cursor + length];
        cursor += length;

        if (maybe_chunk_type) |chunk_type| {
            switch (chunk_type) {
                .stream_identifier => {
                    try ensureStreamIdentifier(chunk_data);
                    saw_stream_identifier = true;
                },
                .compressed => {
                    try writeCompressedChunk(allocator, &allocating.writer, chunk_data);
                    saw_data_chunk = true;
                },
                .uncompressed => {
                    try writeUncompressedChunk(&allocating.writer, chunk_data);
                    saw_data_chunk = true;
                },
            }
            continue;
        }

        if (chunk_type_byte >= 0x80 and chunk_type_byte <= 0xfd) {
            continue; // skippable chunk
        }

        if (is_first_chunk) return FrameError.NotFramed;

        return FrameError.UnsupportedUnskippableChunkType;
    }

    // A stream that contained the identifier but no data chunks is a valid
    // empty payload per the Snappy framing spec. Only treat the input as
    // unframed when neither was seen. (Upstream blockblaz/snappyframesz#8.)
    if (!saw_stream_identifier and !saw_data_chunk) return FrameError.NotFramed;

    // Some producers may omit the identifier. Only enforce when data present with mismatched chunk.
    return allocating.toOwnedSlice();
}

fn ensureStreamIdentifier(chunk_payload: []const u8) !void {
    if (chunk_payload.len != identifier_payload.len) return FrameError.InvalidStreamIdentifier;
    if (!std.mem.eql(u8, chunk_payload, identifier_payload)) {
        return FrameError.InvalidStreamIdentifier;
    }
}

fn writeUncompressedChunk(writer: *std.Io.Writer, chunk_payload: []const u8) !void {
    if (chunk_payload.len < 4) return FrameError.UnexpectedEof;
    const expected_checksum = readU32le(chunk_payload[0..4]);
    const raw_payload = chunk_payload[4..];
    try validateChecksum(raw_payload, expected_checksum);
    try writer.writeAll(raw_payload);
}

fn writeCompressedChunk(allocator: Allocator, writer: *std.Io.Writer, chunk_payload: []const u8) !void {
    if (chunk_payload.len < 4) return FrameError.UnexpectedEof;
    const expected_checksum = readU32le(chunk_payload[0..4]);
    const compressed_payload = chunk_payload[4..];
    const decoded = try snappyz.decode(allocator, compressed_payload);
    defer allocator.free(decoded);
    try validateChecksum(decoded, expected_checksum);
    try writer.writeAll(decoded);
}

fn writeChunkHeader(writer: *std.Io.Writer, chunk_type: ChunkType, payload_len: usize) !void {
    if (payload_len > max_chunk_len) return FrameError.ChunkTooLarge;
    const chunk_type_byte: u8 = chunk_type.toByte();
    const byte0: u8 = @intCast(payload_len & 0xff);
    const byte1: u8 = @intCast((payload_len >> 8) & 0xff);
    const byte2: u8 = @intCast((payload_len >> 16) & 0xff);
    const header = [_]u8{
        chunk_type_byte,
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

fn readExact(reader: *std.Io.Reader, buffer: []u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        const read_len = try reader.readSliceShort(buffer[index..]);
        if (read_len == 0) return FrameError.UnexpectedEof;
        index += read_len;
    }
}

fn readByte(reader: *std.Io.Reader) !?u8 {
    var byte: [1]u8 = undefined;
    const read_len = try reader.readSliceShort(&byte);
    if (read_len == 0) return null;
    return byte[0];
}

fn loadFileAlloc(allocator: Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .unlimited);
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

    var reader_stream: std.Io.Reader = .fixed(sample);
    var encoded_buffer = std.Io.Writer.Allocating.init(allocator);
    defer encoded_buffer.deinit();

    try encodeToWriter(allocator, &reader_stream, &encoded_buffer.writer);

    try std.testing.expectEqualSlices(u8, direct, encoded_buffer.written());
}

test "FrameEncoder manual streaming API" {
    const allocator = std.testing.allocator;
    const parts = [_][]const u8{ "frame-", "encoder-", "stream" };

    var encoder = FrameEncoder.init(allocator);
    var encoded = std.Io.Writer.Allocating.init(allocator);
    defer encoded.deinit();

    var i: usize = 0;
    while (i < parts.len) : (i += 1) {
        try encoder.writeChunk(&encoded.writer, parts[i]);
    }

    try encoder.finish(&encoded.writer);

    var combined_builder: std.ArrayList(u8) = .empty;
    defer combined_builder.deinit(allocator);
    for (parts) |segment| {
        try combined_builder.appendSlice(allocator, segment);
    }
    const combined = try combined_builder.toOwnedSlice(allocator);
    defer allocator.free(combined);

    const encoded_bytes = encoded.written();
    const decoded_manual = try decode(allocator, encoded_bytes);
    defer allocator.free(decoded_manual);

    try std.testing.expectEqualSlices(u8, combined, decoded_manual);

    try std.testing.expect(std.mem.startsWith(u8, encoded_bytes, stream_identifier));
}

test "decodeFromReader matches decode" {
    const allocator = std.testing.allocator;
    const sample = "thissNaPpYYYYYYYYYYYYYYYYYYYY";

    const encoded = try encode(allocator, sample);
    defer allocator.free(encoded);

    var reader_stream: std.Io.Reader = .fixed(encoded);
    var decoded_buffer = std.Io.Writer.Allocating.init(allocator);
    defer decoded_buffer.deinit();

    try decodeFromReader(allocator, &reader_stream, &decoded_buffer.writer);

    try std.testing.expectEqualSlices(u8, sample, decoded_buffer.written());
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
    try std.testing.expect(std.mem.allEqual(u8, decoded[cursor .. cursor + 150], 'A'));
    cursor += 150;
    try std.testing.expect(std.mem.allEqual(u8, decoded[cursor .. cursor + 68], 'B'));
    cursor += 68;
    try std.testing.expectEqualSlices(u8, "efC", decoded[cursor .. cursor + 3]);
    cursor += 3;
    try std.testing.expect(std.mem.allEqual(u8, decoded[cursor .. cursor + 20], 'C'));
    cursor += 20;
    try std.testing.expect(std.mem.allEqual(u8, decoded[cursor .. cursor + 20], 'B'));
    cursor += 20;
    try std.testing.expectEqual(@as(u8, 'g'), decoded[cursor]);
}

test "decode compatibility with rust snappy frame alice29" {
    const allocator = std.testing.allocator;
    const rust_frame_path = "src/testdata/alice29.frame";
    const rust_source_path = "src/testdata/alice29.txt";

    const frame_bytes = try loadFileAlloc(allocator, rust_frame_path);
    defer allocator.free(frame_bytes);

    const original = try loadFileAlloc(allocator, rust_source_path);
    defer allocator.free(original);

    const decoded = try decode(allocator, frame_bytes);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, original, decoded);
}

test "encode compatibility with rust snappy frame alice29" {
    const allocator = std.testing.allocator;
    const rust_frame_path = "src/testdata/alice29.frame";
    const rust_source_path = "src/testdata/alice29.txt";

    const original = try loadFileAlloc(allocator, rust_source_path);
    defer allocator.free(original);

    const expected_frame = try loadFileAlloc(allocator, rust_frame_path);
    defer allocator.free(expected_frame);

    const encoded = try encode(allocator, original);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, expected_frame, encoded);
}
