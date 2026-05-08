const std = @import("std");
const lib = @import("./lib.zig");

// Zig compiler configuration
const serialize = lib.serialize;
const deserialize = lib.deserialize;
const isFixedSizeObject = lib.isFixedSizeObject;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const hashes_of_zero = @import("./zeros.zig").hashes_of_zero;

// SSZ specification constants
const BYTES_PER_CHUNK = 32;
const chunk = [BYTES_PER_CHUNK]u8;
const zero_chunk: chunk = [_]u8{0} ** BYTES_PER_CHUNK;

/// Implements the SSZ `List[N]` container.
pub fn List(T: type, comptime N: usize) type {
    // Compile-time check: List[bool, N] is not allowed, use Bitlist[N] instead
    if (T == bool) {
        @compileError("List[bool, N] is not supported. Use Bitlist(" ++ std.fmt.comptimePrint("{}", .{N}) ++ ") instead for boolean lists.");
    }

    return struct {
        const Self = @This();
        const Item = T;
        const Inner = std.ArrayList(T);

        const OFFSET_SIZE = 4;

        inner: Inner,
        allocator: Allocator,

        pub fn sszEncode(self: *const Self, l: *ArrayList(u8), allocator: Allocator) !void {
            try serialize([]const Item, self.constSlice(), l, allocator);
        }

        pub fn isFixedSizeObject() bool {
            return false;
        }

        /// Maximum serialized byte length for List(T, N) with at most N elements.
        pub fn maxInLength() !usize {
            if (try lib.isFixedSizeObject(Item)) {
                return N * try lib.serializedFixedSize(Item);
            }
            return N * @sizeOf(u32) + N * try lib.maxInLength(Item);
        }

        /// Minimum serialized byte length for List(T, N) (empty list).
        pub fn minInLength() usize {
            return 0;
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, allocator: ?Allocator) !void {
            // BitList[N] or regular List[N]?
            const alloc = allocator orelse return error.AllocatorRequired;
            out.* = try init(alloc);

            // FastSSZ-style capacity optimization: pre-allocate based on input size
            // TODO: replace this with the definite value, taken from the list
            if (serialized.len > 0) {
                const estimated_capacity = if (try lib.isFixedSizeObject(Self.Item))
                    serialized.len / (try lib.serializedFixedSize(Self.Item))
                else
                    serialized.len / 8; // Conservative estimate for dynamic types
                try out.inner.ensureTotalCapacity(alloc, estimated_capacity);
            }

            if (Self.Item == bool) {
                @panic("Use the optimized utils.Bitlist(N) instead of utils.List(bool, N)");
            } else if (try lib.isFixedSizeObject(Self.Item)) {
                const pitch = try lib.serializedFixedSize(Self.Item);
                if (serialized.len % pitch != 0) return error.OffsetOrdering;
                const n_items = serialized.len / pitch;
                if (n_items > N) return error.OffsetExceedsSize;

                for (0..n_items) |i| {
                    var item: Self.Item = undefined;
                    try deserialize(Self.Item, serialized[i * pitch .. (i + 1) * pitch], &item, allocator);
                    try out.append(item);
                }
            } else {
                // Validate and decode dynamic list length
                const size = try Self.decodeDynamicLength(serialized);
                const prefix_len = @as(usize, size) * 4;
                if (prefix_len > serialized.len) return error.OffsetExceedsSize;

                const indices = std.mem.bytesAsSlice(u32, serialized[0..prefix_len]);
                var i = @as(usize, 0);
                while (i < size) : (i += 1) {
                    const end = if (i < size - 1) indices[i + 1] else serialized.len;
                    const start = indices[i];
                    if (start > serialized.len or end > serialized.len) {
                        return error.OffsetExceedsSize;
                    }
                    if (start > end) return error.OffsetOrdering;
                    if (i > 0 and start < indices[i - 1]) {
                        return error.OffsetOrdering;
                    }
                    const item = try out.inner.addOne(alloc);
                    try deserialize(Self.Item, serialized[start..end], item, allocator);
                }
            }
        }

        pub fn init(allocator: Allocator) !Self {
            return .{ .inner = .empty, .allocator = allocator };
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            if (self.len() != other.len()) return false;

            const self_slice = self.constSlice();
            const other_slice = other.constSlice();

            // For struct/array types, use std.meta.eql for proper deep comparison
            if (@typeInfo(Self.Item) == .@"struct" or @typeInfo(Self.Item) == .array) {
                return std.meta.eql(self_slice, other_slice);
            } else {
                // For a slice of primitive types, it's faster to do a memory
                // comparison.
                return std.mem.eql(Self.Item, self_slice, other_slice);
            }
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit(self.allocator);
        }

        pub fn append(self: *Self, item: Self.Item) error{ Overflow, OutOfMemory }!void {
            if (self.inner.items.len >= N) return error.Overflow;
            return self.inner.append(self.allocator, item);
        }

        pub fn slice(self: *Self) []T {
            return self.inner.items;
        }

        pub fn constSlice(self: *const Self) []const T {
            return self.inner.items;
        }

        pub fn fromSlice(allocator: Allocator, m: []const T) !Self {
            if (m.len > N) return error.Overflow;
            var inner: Inner = .empty;
            try inner.appendSlice(allocator, m);
            return .{ .inner = inner, .allocator = allocator };
        }

        pub fn get(self: Self, i: usize) error{IndexOutOfBounds}!T {
            if (i >= self.inner.items.len) return error.IndexOutOfBounds;
            return self.inner.items[i];
        }

        pub fn set(self: *Self, i: usize, item: T) error{IndexOutOfBounds}!void {
            if (i >= self.inner.items.len) return error.IndexOutOfBounds;
            self.inner.items[i] = item;
        }

        pub fn len(self: *const Self) usize {
            return self.inner.items.len;
        }

        pub fn serializedSize(self: *const Self) !usize {
            const inner_slice = self.constSlice();
            return lib.serializedSize(@TypeOf(inner_slice), inner_slice);
        }

        pub fn hashTreeRoot(self: *const Self, Hasher: type, out: *[32]u8, allocator: Allocator) !void {
            const items = self.constSlice();

            switch (@typeInfo(Item)) {
                .int => {
                    var list: ArrayList(u8) = .empty;
                    defer list.deinit(allocator);
                    const chunks = try lib.pack([]const Item, items, &list, allocator);

                    const bytes_per_item = @sizeOf(Item);
                    const items_per_chunk = BYTES_PER_CHUNK / bytes_per_item;
                    const chunks_for_max_capacity = (N + items_per_chunk - 1) / items_per_chunk;
                    var tmp: chunk = undefined;
                    try lib.merkleize(Hasher, chunks, chunks_for_max_capacity, &tmp);
                    lib.mixInLength2(Hasher, tmp, items.len, out);
                },
                else => {
                    var chunks: ArrayList(chunk) = .empty;
                    defer chunks.deinit(allocator);
                    var tmp: chunk = undefined;
                    for (items) |item| {
                        try lib.hashTreeRoot(Hasher, Item, item, &tmp, allocator);
                        try chunks.append(allocator, tmp);
                    }
                    // Always use N (max capacity) for merkleization, even when empty
                    // This ensures proper tree depth according to SSZ specification
                    try lib.merkleize(Hasher, chunks.items, N, &tmp);
                    lib.mixInLength2(Hasher, tmp, items.len, out);
                },
            }
        }

        /// Decodes and validates the length from dynamic input
        pub fn decodeDynamicLength(buf: []const u8) !u32 {
            if (buf.len == 0) {
                return 0;
            }
            if (buf.len < 4) {
                return error.DynamicLengthTooShort;
            }

            const offset = std.mem.readInt(u32, buf[0..4], std.builtin.Endian.little);
            if (offset % OFFSET_SIZE != 0 or offset == 0) {
                return error.DynamicLengthNotOffsetSized;
            }

            const length = offset / OFFSET_SIZE;
            if (length > N) {
                return error.DynamicLengthExceedsMax;
            }

            return length;
        }
    };
}

/// Implements the SSZ `Bitlist[N]` container
pub fn Bitlist(comptime N: usize) type {
    return struct {
        const Self = @This();
        // stores list without sentinel
        const Inner = std.ArrayList(u8);

        inner: Inner,
        allocator: Allocator,
        length: usize,

        pub fn sszEncode(self: *const Self, l: *ArrayList(u8), allocator: Allocator) !void {
            if (self.length == 0) {
                try l.append(allocator, @as(u8, 1));
                return;
            }

            // slice has at least one byte, appends all
            // non-terminal bytes.
            const sl = self.inner.items;
            try l.appendSlice(allocator, sl[0 .. sl.len - 1]);

            if (self.length % 8 == 0) {
                // sentinel is extra byte
                try l.append(allocator, sl[sl.len - 1]);
                try l.append(allocator, 1);
            } else {
                try l.append(allocator, sl[sl.len - 1] | @shlExact(@as(u8, 1), @truncate(self.length % 8)));
            }
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, allocator: ?std.mem.Allocator) !void {
            const alloc = allocator orelse return error.AllocatorRequired;
            out.* = try init(alloc);

            // Comprehensive validation (handles empty, trailing zero, size limits)
            try Self.validateBitlist(serialized);

            // FastSSZ-style capacity optimization: pre-allocate based on input size
            const byte_capacity = serialized.len;
            if (byte_capacity > 0) {
                try out.inner.ensureTotalCapacity(alloc, byte_capacity);
            }

            // Find sentinel bit position using @clz (count leading zeros)
            const last_byte = serialized[serialized.len - 1];
            const msb_pos = @as(usize, 8) - @clz(last_byte);
            const bit_length = 8 * (serialized.len - 1) + (msb_pos - 1);

            // Calculate how many full bytes we need (excluding sentinel)
            const full_bytes = bit_length / 8;
            const remaining_bits = bit_length % 8;

            // Copy all full bytes
            if (full_bytes > 0) {
                try out.*.inner.appendSlice(alloc, serialized[0..full_bytes]);
            }

            // Handle remaining bits in the last byte (if any)
            if (remaining_bits > 0) {
                // The last byte contains both data bits and the sentinel bit
                // We need to mask out the sentinel bit and any bits after it
                const mask = (@as(u8, 1) << @truncate(remaining_bits)) - 1;
                try out.*.inner.append(alloc, serialized[full_bytes] & mask);
            }

            out.*.length = bit_length;
        }

        pub fn isFixedSizeObject() bool {
            return false;
        }

        /// Maximum serialized byte length for Bitlist(N) (N bits + sentinel).
        pub fn maxInLength() usize {
            return (N + 7 + 1) / 8;
        }

        /// Minimum serialized byte length for Bitlist(N) (empty bitlist: one byte with sentinel).
        pub fn minInLength() usize {
            return 1;
        }

        pub fn init(allocator: Allocator) !Self {
            return .{ .inner = .empty, .allocator = allocator, .length = 0 };
        }

        pub fn get(self: Self, i: usize) error{IndexOutOfBounds}!bool {
            if (i >= self.length) return error.IndexOutOfBounds;
            return self.inner.items[i / 8] & @shlExact(@as(u8, 1), @truncate(i % 8)) != 0;
        }

        pub fn set(self: *Self, i: usize, bit: bool) error{IndexOutOfBounds}!void {
            if (i >= self.length) return error.IndexOutOfBounds;
            const mask = ~@shlExact(@as(u8, 1), @truncate(i % 8));
            const b = if (bit) @shlExact(@as(u8, 1), @truncate(i % 8)) else 0;
            self.inner.items[i / 8] = @truncate((self.inner.items[i / 8] & mask) | b);
        }

        pub fn append(self: *Self, item: bool) error{ Overflow, OutOfMemory, IndexOutOfBounds }!void {
            if (self.length >= N) return error.Overflow;
            if (self.length % 8 == 0) {
                try self.inner.append(self.allocator, 0);
            }
            self.length += 1;
            try self.set(self.length - 1, item);
        }

        pub fn len(self: *const Self) usize {
            return self.length;
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit(self.allocator);
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            return (self.length == other.length) and std.mem.eql(u8, self.inner.items, other.inner.items);
        }

        pub fn serializedSize(self: *const Self) usize {
            // Size is number of bytes needed plus one bit for the sentinel
            return (self.length + 7 + 1) / 8;
        }

        pub fn hashTreeRoot(self: *const Self, Hasher: type, out: *[32]u8, allocator: Allocator) !void {
            const bit_length = self.length;

            var bitfield_bytes: ArrayList(u8) = .empty;
            defer bitfield_bytes.deinit(allocator);

            if (bit_length > 0) {
                // Get the internal bit data since we don't store delimiter
                const sl = self.inner.items;
                try bitfield_bytes.appendSlice(allocator, sl[0..sl.len]);

                // Remove trailing zeros but keep at least one byte
                // This avoids the wasteful pattern of removing all zeros then adding back a chunk
                while (bitfield_bytes.items.len > 1 and bitfield_bytes.items[bitfield_bytes.items.len - 1] == 0) {
                    _ = bitfield_bytes.pop();
                }
            }

            // Pack bits into chunks (pad to chunk boundary)
            const padding_size = (BYTES_PER_CHUNK - bitfield_bytes.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
            _ = try bitfield_bytes.appendSlice(allocator, zero_chunk[0..padding_size]);

            const chunks = std.mem.bytesAsSlice(chunk, bitfield_bytes.items);
            var tmp: chunk = undefined;

            // Use chunk_count limit as per SSZ specification
            const chunk_count_limit = (N + 255) / 256;
            try lib.merkleize(Hasher, chunks, chunk_count_limit, &tmp);
            lib.mixInLength2(Hasher, tmp, bit_length, out);
        }

        /// Validates that the bitlist is correctly formed
        pub fn validateBitlist(buf: []const u8) !void {
            const byte_len = buf.len;

            // Empty buffer is invalid, at least sentinel bit should exist
            if (byte_len == 0) return error.InvalidBitlistEncoding;

            // Maximum possible bytes in a bitlist with provided bitlimit.
            const max_bytes = ((N + 7 + 1) >> 3);
            if (byte_len > max_bytes) {
                return error.BitlistTooManyBytes;
            }

            // The most significant bit is present in the last byte in the array.
            const last = buf[byte_len - 1];
            if (last == 0) {
                return error.BitlistTrailingByteZero;
            }

            // Determine the position of the most significant bit.
            // Find most significant bit position
            const msb_pos = if (last == 0) 0 else 8 - @clz(last);

            // The absolute position of the most significant bit will be the number of
            // bits in the preceding bytes plus the position of the most significant
            // bit. Subtract this value by 1 to determine the length of the bitlist.
            const num_of_bits: u64 = @intCast(8 * (byte_len - 1) + msb_pos - 1);

            if (num_of_bits > N) {
                return error.BitlistTooManyBits;
            }
        }
    };
}
