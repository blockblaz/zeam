//! This module provides functions for serializing and deserializing
//! data structures with the SSZ method.

const std = @import("std");
pub const utils = @import("./utils.zig");
pub const zeros = @import("./zeros.zig");
const ArrayList = std.ArrayList;
const builtin = std.builtin;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Number of bytes per chunk.
const BYTES_PER_CHUNK = 32;

pub fn serializedFixedSize(T: type) !usize {
    const info = @typeInfo(T);
    return switch (info) {
        .int => @sizeOf(T),
        .bool => @sizeOf(T),
        .array => info.array.len * try serializedFixedSize(info.array.child),
        .pointer => switch (info.pointer.size) {
            .slice => error.NoSerializedFixedSizeAvailable,
            // or should we just throw error for all of pointer
            else => serializedFixedSize(info.pointer.child),
        },
        .optional => error.NoSerializedFixedSizeAvailable,
        .null => @as(usize, 0),
        .@"struct" => |str| size: {
            var size: usize = 0;
            inline for (str.fields) |field| {
                size += try serializedFixedSize(field.type);
            }
            break :size size;
        },
        else => error.NoSerializedFixedSizeAvailable,
    };
}

// Determine the serialized size of an object so that
// the code serializing of variable-size objects can
// determine the offset to the next object.
pub fn serializedSize(T: type, data: T) !usize {
    // Check for custom serializedSize method first for List types
    if (comptime std.meta.hasFn(T, "serializedSize")) {
        return data.serializedSize();
    }

    const info = @typeInfo(T);
    return switch (info) {
        .int => @sizeOf(T),
        .bool => @sizeOf(T),
        .array => size: {
            var size: usize = 0;
            const is_child_fixed = try isFixedSizeObject(info.array.child);
            if (!is_child_fixed) {
                size += 4 * data.len;
            }
            for (0..data.len) |i| {
                size += try serializedSize(info.array.child, data[i]);
            }
            break :size size;
        },
        .pointer => switch (info.pointer.size) {
            .slice => size: {
                var size: usize = 0;
                const is_child_fixed = try isFixedSizeObject(info.pointer.child);
                if (!is_child_fixed) {
                    size += 4 * data.len;
                }
                for (0..data.len) |i| {
                    size += try serializedSize(info.pointer.child, data[i]);
                }
                break :size size;
            },
            else => serializedSize(info.pointer.child, data.*),
        },
        .optional => if (data == null)
            @as(usize, 1)
        else
            1 + try serializedSize(info.optional.child, data.?),
        .null => @as(usize, 0),
        .@"struct" => |str| size: {
            var size: usize = 0;
            inline for (str.fields) |field| {
                const is_field_fixed_size = try isFixedSizeObject(field.type);
                if (is_field_fixed_size == false) {
                    size += 4;
                }
                size += try serializedSize(field.type, @field(data, field.name));
            }
            break :size size;
        },
        else => error.NoSerializedSizeAvailable,
    };
}

/// Returns true if an object is of fixed size
pub fn isFixedSizeObject(T: type) !bool {
    if (comptime std.meta.hasFn(T, "isFixedSizeObject")) {
        return T.isFixedSizeObject();
    }

    const info = @typeInfo(T);
    switch (info) {
        .bool, .int, .null => return true,
        .array => return isFixedSizeObject(info.array.child),
        .@"struct" => |str| inline for (str.fields) |field| {
            if (!try isFixedSizeObject(field.type)) {
                return false;
            }
        },
        .optional => return false,
        .pointer => |ptr| switch (ptr.size) {
            .many, .slice, .c => return false,
            .one => return isFixedSizeObject(info.pointer.child),
        },
        else => return error.UnknownType,
    }
    return true;
}

/// Returns the maximum possible serialized byte length for type `T`.
/// Useful for pre-allocating buffers or validating input bounds.
/// For variable-length types (e.g. slice), use a type that encodes max length (e.g. List(T, N)) or returns error.
pub fn maxInLength(T: type) !usize {
    if (comptime std.meta.hasFn(T, "maxInLength")) {
        return T.maxInLength();
    }

    const info = @typeInfo(T);
    return switch (info) {
        .int => @sizeOf(T),
        .bool => @as(usize, 1),
        .null => @as(usize, 0),
        .array => |array| if (array.child == bool)
            (array.len + 7) / 8
        else blk: {
            const child_max = try maxInLength(array.child);
            if (try isFixedSizeObject(array.child)) {
                break :blk array.len * child_max;
            } else {
                break :blk array.len * child_max + 4 * array.len;
            }
        },
        .optional => 1 + try maxInLength(info.optional.child),
        .pointer => |ptr| switch (ptr.size) {
            .slice => error.NoMaxInLengthAvailable,
            .one => maxInLength(ptr.child),
            else => error.NoMaxInLengthAvailable,
        },
        .@"struct" => |str| blk: {
            var total: usize = 0;
            inline for (str.fields) |field| {
                if (try isFixedSizeObject(field.type)) {
                    total += try maxInLength(field.type);
                } else {
                    total += 4 + try maxInLength(field.type);
                }
            }
            break :blk total;
        },
        .@"union" => |u| blk: {
            if (u.tag_type == null) return error.UnionIsNotTagged;
            var m: usize = 0;
            inline for (u.fields) |f| {
                const n = try maxInLength(f.type);
                if (n > m) m = n;
            }
            break :blk 1 + m;
        },
        else => error.NoMaxInLengthAvailable,
    };
}

/// Returns the minimum possible serialized byte length for type `T`.
/// Used together with maxInLength to validate input bounds before deserializing.
pub fn minInLength(T: type) !usize {
    if (comptime std.meta.hasFn(T, "minInLength")) {
        return T.minInLength();
    }

    const info = @typeInfo(T);
    return switch (info) {
        .int => @sizeOf(T),
        .bool => @as(usize, 1),
        .null => @as(usize, 0),
        .array => |array| if (array.child == bool)
            (array.len + 7) / 8
        else if (try isFixedSizeObject(array.child))
            array.len * try minInLength(array.child)
        else
            array.len * @sizeOf(u32) + array.len * try minInLength(array.child),
        .optional => 1,
        .pointer => |ptr| switch (ptr.size) {
            .slice => error.NoMinInLengthAvailable,
            .one => minInLength(ptr.child),
            else => error.NoMinInLengthAvailable,
        },
        .@"struct" => |str| blk: {
            var total: usize = 0;
            inline for (str.fields) |field| {
                if (try isFixedSizeObject(field.type)) {
                    total += try minInLength(field.type);
                } else {
                    total += 4 + try minInLength(field.type);
                }
            }
            break :blk total;
        },
        .@"union" => |u| blk: {
            if (u.tag_type == null) return error.UnionIsNotTagged;
            var m: usize = std.math.maxInt(usize);
            inline for (u.fields) |f| {
                const n = try minInLength(f.type);
                if (n < m) m = n;
            }
            break :blk 1 + m;
        },
        else => error.NoMinInLengthAvailable,
    };
}

/// Provides the generic serialization of any `data` var to SSZ. The
/// serialization is written to the `ArrayList` `l`.
pub fn serialize(T: type, data: T, l: *ArrayList(u8), allocator: Allocator) !void {
    // shortcut if the type implements its own encode method
    if (comptime std.meta.hasFn(T, "sszEncode")) {
        return data.sszEncode(l, allocator);
    }
    const info = @typeInfo(T);
    switch (info) {
        .array => |array| {
            // Bitvector[N] or vector?
            if (array.child == bool) {
                var byte: u8 = 0;
                for (data, 0..) |bit, index| {
                    if (bit) {
                        byte |= @as(u8, 1) << @truncate(index);
                    }

                    if (index % 8 == 7) {
                        try l.append(allocator, byte);
                        byte = 0;
                    }
                }

                // Write the last byte if the length
                // is not byte-aligned
                if (data.len % 8 != 0) {
                    try l.append(allocator, byte);
                }
            } else {
                // If the item type is fixed-size, serialize inline,
                // otherwise, create an array of offsets and then
                // serialize each object afterwards.
                if (try isFixedSizeObject(array.child)) {
                    for (data) |item| {
                        try serialize(array.child, item, l, allocator);
                    }
                } else {
                    // Size of the buffer before anything is
                    // written to it.
                    const base = l.items.len;
                    var start = base;

                    // Reserve the space for the offset
                    _ = try l.addManyAsSlice(allocator, data.len * @sizeOf(u32));

                    // Now serialize one item after the other
                    // and update the offset list with its location.
                    // The offset is relative to the start of this array's data.
                    for (data) |item| {
                        const relative_offset = l.items.len - base;
                        std.mem.writeInt(u32, l.items[start .. start + 4][0..4], @truncate(relative_offset), std.builtin.Endian.little);
                        _ = try serialize(array.child, item, l, allocator);
                        start += 4;
                    }
                }
            }
        },
        .bool => {
            if (data) {
                try l.append(allocator, 1);
            } else {
                try l.append(allocator, 0);
            }
        },
        .int => |int| {
            switch (int.bits) {
                8, 16, 32, 64, 128, 256 => {},
                else => return error.InvalidSerializedIntLengthType,
            }
            _ = std.mem.writeInt(T, try l.addManyAsArray(allocator, @sizeOf(T)), data, .little);
        },
        .pointer => |pointer| {
            // Bitlist[N] or list?
            switch (pointer.size) {
                .slice => {
                    if (pointer.child == bool) {
                        @panic("use util.Bitlist instead of []bool");
                    }
                    if (@sizeOf(pointer.child) == 1) {
                        _ = try l.appendSlice(allocator, data);
                    } else {
                        if (try isFixedSizeObject(pointer.child)) {
                            for (data) |item| {
                                try serialize(@TypeOf(item), item, l, allocator);
                            }
                        } else {
                            // Size of the buffer before anything is
                            // written to it.
                            const base = l.items.len;
                            var start = base;

                            // Reserve the space for the offset
                            _ = try l.addManyAsSlice(allocator, data.len * @sizeOf(u32));

                            // Now serialize one item after the other
                            // and update the offset list with its location.
                            // The offset is relative to the start of this slice's data.
                            for (data) |item| {
                                const relative_offset = l.items.len - base;
                                std.mem.writeInt(u32, l.items[start .. start + 4][0..4], @truncate(relative_offset), std.builtin.Endian.little);
                                _ = try serialize(pointer.child, item, l, allocator);
                                start += 4;
                            }
                        }
                    }
                },
                .one => try serialize(pointer.child, data.*, l, allocator),
                else => return error.UnSupportedPointerType,
            }
        },
        .@"struct" => {
            // First pass, accumulate the fixed sizes
            comptime var var_start = 0;
            inline for (info.@"struct".fields) |field| {
                comptime {
                    if (@typeInfo(field.type) == .int or @typeInfo(field.type) == .bool) {
                        var_start += @sizeOf(field.type);
                    } else if (try isFixedSizeObject(field.type)) {
                        var_start += try serializedFixedSize(field.type);
                    } else {
                        var_start += 4;
                    }
                }
            }

            // Second pass: intertwine fixed fields and variables offsets
            var var_acc = @as(usize, var_start); // variable part size accumulator
            inline for (info.@"struct".fields) |field| {
                switch (@typeInfo(field.type)) {
                    .int, .bool => {
                        try serialize(field.type, @field(data, field.name), l, allocator);
                    },
                    else => {
                        if (try isFixedSizeObject(field.type)) {
                            try serialize(field.type, @field(data, field.name), l, allocator);
                        } else {
                            try serialize(u32, @truncate(var_acc), l, allocator);
                            var_acc += try serializedSize(field.type, @field(data, field.name));
                        }
                    },
                }
            }

            // Third pass: add variable fields at the end
            if (var_acc > var_start) {
                inline for (info.@"struct".fields) |field| {
                    switch (@typeInfo(field.type)) {
                        .int, .bool => {
                            // skip fixed-size fields
                        },
                        else => {
                            if (!try isFixedSizeObject(field.type)) {
                                try serialize(field.type, @field(data, field.name), l, allocator);
                            }
                        },
                    }
                }
            }
        },
        // Nothing to be added to the payload
        .null => {},
        // Optionals are like unions, but their 0 value has to be 0.
        .optional => {
            if (data != null) {
                _ = try l.append(allocator, 1);
                try serialize(info.optional.child, data.?, l, allocator);
            } else {
                _ = try l.append(allocator, 0);
            }
        },
        .@"union" => {
            if (info.@"union".tag_type == null) {
                return error.UnionIsNotTagged;
            }
            inline for (info.@"union".fields, 0..) |f, index| {
                if (@intFromEnum(data) == index) {
                    _ = std.mem.writeInt(u8, try l.addManyAsArray(allocator, 1), index, .little);
                    try serialize(f.type, @field(data, f.name), l, allocator);
                    return;
                }
            }
        },
        else => {
            return error.UnknownType;
        },
    }
}

/// Takes a byte array containing the serialized payload of type `T` and
/// deserializes it into the `T` object pointed at by `out`.
/// The payload must be within [minInLength, maxInLength] bounds for `T`.
pub fn deserialize(T: type, serialized: []const u8, out: *T, allocator: ?Allocator) !void {
    const has_custom_decode = comptime std.meta.hasFn(T, "sszDecode");
    const enforce_min = !has_custom_decode or comptime std.meta.hasFn(T, "minInLength");
    const enforce_max = !has_custom_decode or comptime std.meta.hasFn(T, "maxInLength");

    // Bounds check: ensure serialized length is within [minInLength, maxInLength]
    const min_len: ?usize = if (enforce_min) blk: {
        const m = minInLength(T) catch break :blk null;
        break :blk m;
    } else null;
    if (min_len) |m| if (serialized.len < m) return error.PayloadTooSmall;

    const max_len: ?usize = if (enforce_max) blk: {
        const m = maxInLength(T) catch break :blk null;
        break :blk m;
    } else null;
    if (max_len) |m| if (serialized.len > m) return error.PayloadTooLarge;

    // shortcut if the type implements its own decode method
    if (has_custom_decode) {
        return T.sszDecode(serialized, out, allocator);
    }

    const info = @typeInfo(T);
    switch (info) {
        .array => {
            // Bitvector[N] or regular vector?
            if (info.array.child == bool) {
                for (serialized, 0..) |byte, bindex| {
                    var i = @as(u8, 0);
                    var b = byte;
                    while (bindex * 8 + i < out.len and i < 8) : (i += 1) {
                        out[bindex * 8 + i] = b & 1 == 1;
                        b >>= 1;
                    }
                }
            } else {
                const U = info.array.child;
                if (try isFixedSizeObject(U)) {
                    const pitch = try comptime serializedFixedSize(U);
                    for (0..out.len) |i| {
                        try deserialize(U, serialized[i * pitch .. (i + 1) * pitch], &out[i], allocator);
                    }
                } else {
                    // first variable index is also the size of the list
                    // of indices. Recast that list as a []const u32.
                    if (serialized.len < 4) return error.OffsetExceedsSize;
                    const offset_prefix = std.mem.readInt(u32, serialized[0..4], std.builtin.Endian.little);
                    if (offset_prefix % @sizeOf(u32) != 0) return error.OffsetOrdering;
                    const size = offset_prefix / @sizeOf(u32);
                    if (size > serialized.len / @sizeOf(u32)) return error.OffsetExceedsSize;
                    if (offset_prefix > serialized.len) return error.OffsetExceedsSize;
                    const indices = std.mem.bytesAsSlice(u32, serialized[0..offset_prefix]);
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
                        try deserialize(U, serialized[start..end], &out[i], allocator);
                    }
                }
            }
        },
        .bool => out.* = (serialized[0] == 1),
        .int => {
            const N = @sizeOf(T);
            out.* = std.mem.readInt(T, serialized[0..N], std.builtin.Endian.little);
        },
        .optional => {
            const index: u8 = serialized[0];
            if (index != 0) {
                var x: info.optional.child = undefined;
                try deserialize(info.optional.child, serialized[1..], &x, allocator);
                out.* = x;
            } else {
                out.* = null;
            }
        },
        .pointer => |ptr| switch (ptr.size) {
            .slice => if (@sizeOf(ptr.child) == 1) {
                // Data is not copied in this function, copy is therefore
                // the responsibility of the caller.
                if (ptr.is_const) {
                    out.* = serialized[0..];
                } else {
                    if (allocator) |alloc| {
                        out.* = try alloc.alloc(ptr.child, serialized.len);
                    }
                    @memcpy(out.*, serialized[0..]);
                }
            } else {
                if (try isFixedSizeObject(ptr.child)) {
                    const pitch = try serializedFixedSize(ptr.child);
                    const n_items = serialized.len / pitch;
                    if (allocator) |alloc| {
                        out.* = try alloc.alloc(ptr.child, n_items);
                    }
                    for (0..n_items) |i| {
                        try deserialize(ptr.child, serialized[i * pitch .. (i + 1) * pitch], &out.*[i], allocator);
                    }
                } else {
                    // read the first index, determine when the "variable size" list ends,
                    // and determine the size of the item as a result.
                    if (serialized.len < 4) return error.OffsetExceedsSize;
                    const first_offset_u32 = std.mem.readInt(u32, serialized[0..4], std.builtin.Endian.little);
                    const first_offset = @as(usize, first_offset_u32);
                    if (first_offset > serialized.len) return error.OffsetExceedsSize;
                    if (first_offset % @sizeOf(u32) != 0) return error.OffsetOrdering;
                    const n_items = first_offset / @sizeOf(u32);
                    if (n_items == 0) return error.OffsetOrdering;

                    var offset: usize = first_offset;
                    var next_offset: usize = if (n_items == 1) serialized.len else blk: {
                        if (serialized.len < 8) return error.OffsetExceedsSize;
                        const n = std.mem.readInt(u32, serialized[4..8], std.builtin.Endian.little);
                        break :blk @as(usize, n);
                    };
                    if (next_offset > serialized.len) return error.OffsetExceedsSize;
                    if (offset > next_offset) return error.OffsetOrdering;

                    if (allocator) |alloc| {
                        out.* = try alloc.alloc(ptr.child, n_items);
                    }
                    for (0..n_items) |i| {
                        try deserialize(ptr.child, serialized[offset..next_offset], &out.*[i], allocator);
                        offset = next_offset;
                        // next offset is either the next entry in the list of offsets,
                        // or the end of the serialized payload.
                        next_offset = if ((i + 2) * 4 >= first_offset)
                            serialized.len
                        else blk: {
                            const rel = (i + 2) * 4;
                            if (rel + 4 > serialized.len) return error.OffsetExceedsSize;
                            const n = std.mem.readInt(u32, serialized[rel..][0..4], std.builtin.Endian.little);
                            break :blk @as(usize, n);
                        };
                        if (next_offset > serialized.len) return error.OffsetExceedsSize;
                        if (offset > next_offset) return error.OffsetOrdering;
                    }
                }
            },
            .one => {
                if (allocator) |alloc| {
                    out.* = try alloc.create(ptr.child);
                }
                return deserialize(ptr.child, serialized, out.*, allocator);
            },
            else => return error.UnSupportedPointerType,
        },
        .@"struct" => {
            // Calculate the number of variable fields in the
            // struct.
            comptime var n_var_fields = 0;
            comptime {
                for (info.@"struct".fields) |field| {
                    switch (@typeInfo(field.type)) {
                        .int, .bool => {},
                        else => {
                            if (!try isFixedSizeObject(field.type)) {
                                n_var_fields += 1;
                            }
                        },
                    }
                }
            }

            // 0 indices array causes compiletime error for places we access indices[]
            // also use n_var_fields instead of indices.len
            var indices: [n_var_fields + 1]u32 = undefined;

            // First pass, read the value of each fixed-size field,
            // and write down the start offset of each variable-sized
            // field.
            var i: usize = 0;
            comptime var variable_field_index = 0;
            inline for (info.@"struct".fields) |field| {
                switch (@typeInfo(field.type)) {
                    .bool, .int => {
                        // Direct deserialize
                        if (i + @sizeOf(field.type) > serialized.len) return error.OffsetExceedsSize;
                        try deserialize(field.type, serialized[i .. i + @sizeOf(field.type)], &@field(out.*, field.name), allocator);
                        i += @sizeOf(field.type);
                    },
                    else => {
                        if (try comptime isFixedSizeObject(field.type)) {
                            // Direct deserialize
                            const field_serialized_size = try serializedFixedSize(field.type);
                            if (i + field_serialized_size > serialized.len) return error.OffsetExceedsSize;
                            try deserialize(field.type, serialized[i .. i + field_serialized_size], &@field(out.*, field.name), allocator);
                            i += field_serialized_size;
                        } else {
                            if (i + 4 > serialized.len) return error.OffsetExceedsSize;
                            try deserialize(u32, serialized[i .. i + 4], &indices[variable_field_index], allocator);
                            i += 4;
                            variable_field_index += 1;
                        }
                    },
                }
            }

            // Second pass, deserialize each variable-sized value
            // now that their offset is known.
            comptime var last_index = 0;
            inline for (info.@"struct".fields) |field| {
                // comptime fields are currently not supported, and it's not even
                // certain that they can ever be without a change in the language.
                if (field.is_comptime) @panic("structure contains comptime field");

                switch (@typeInfo(field.type)) {
                    .bool, .int => {}, // covered by the previous pass
                    else => if (!try comptime isFixedSizeObject(field.type)) {
                        const start = @as(usize, indices[last_index]);
                        const end: usize = if (last_index == n_var_fields - 1) serialized.len else @as(usize, indices[last_index + 1]);
                        if (start > serialized.len or end > serialized.len) return error.OffsetExceedsSize;
                        if (start > end) return error.OffsetOrdering;
                        if (last_index > 0 and start < @as(usize, indices[last_index - 1])) return error.OffsetOrdering;
                        if (last_index == 0 and start != i) return error.OffsetOrdering;
                        try deserialize(field.type, serialized[start..end], &@field(out.*, field.name), allocator);
                        last_index += 1;
                    },
                }
            }
        },
        .@"union" => {
            if (serialized.len < 1) return error.OffsetExceedsSize;
            // Read the type index
            var union_index: u8 = undefined;
            try deserialize(u8, serialized[0..1], &union_index, allocator);

            // Use the index to figure out which type must
            // be deserialized.
            inline for (info.@"union".fields, 0..) |field, index| {
                if (index == union_index) {
                    // &@field(out.*, field.name) can not be used directly,
                    // because this field type hasn't been activated at this
                    // stage.
                    var data: field.type = undefined;
                    try deserialize(field.type, serialized[1..], &data, allocator);
                    out.* = @unionInit(T, field.name, data);
                }
            }
        },
        else => return error.NotImplemented,
    }
}

pub fn mixInLength2(Hasher: type, root: [Hasher.digest_length]u8, length: usize, out: *[Hasher.digest_length]u8) void {
    var hasher = Hasher.init(Hasher.Options{});
    hasher.update(root[0..]);

    var tmp = [_]u8{0} ** 32;
    std.mem.writeInt(@TypeOf(length), tmp[0..@sizeOf(@TypeOf(length))], length, std.builtin.Endian.little);
    hasher.update(tmp[0..]);
    hasher.final(out[0..]);
}

fn mixInLength(Hasher: type, root: [Hasher.digest_length]u8, length: [32]u8, out: *[Hasher.digest_length]u8) void {
    var hasher = Hasher.init(Hasher.Options{});
    hasher.update(root[0..]);
    hasher.update(length[0..]);
    hasher.final(out[0..]);
}

test "mixInLength" {
    var root: [32]u8 = undefined;
    var length: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    var mixin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(root[0..], "2279cf111c15f2d594e7a0055e8735e7409e56ed4250735d6d2f2b0d1bcf8297");
    _ = try std.fmt.hexToBytes(length[0..], "deadbeef00000000000000000000000000000000000000000000000000000000");
    _ = try std.fmt.hexToBytes(expected[0..], "0b665dda6e4c269730bc4bbe3e990a69d37fa82892bac5fe055ca4f02a98c900");
    mixInLength(Sha256, root, length, &mixin);

    try std.testing.expect(std.mem.eql(u8, mixin[0..], expected[0..]));
}

fn mixInSelector(Hasher: type, root: [Hasher.digest_length]u8, comptime selector: usize, out: *[Hasher.digest_length]u8) void {
    var hasher = Hasher.init(Hasher.Options{});
    hasher.update(root[0..]);
    var tmp = [_]u8{0} ** 32;
    std.mem.writeInt(@TypeOf(selector), tmp[0..@sizeOf(@TypeOf(selector))], selector, std.builtin.Endian.little);
    hasher.update(tmp[0..]);
    hasher.final(out[0..]);
}

test "mixInSelector" {
    var root: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    var mixin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(root[0..], "2279cf111c15f2d594e7a0055e8735e7409e56ed4250735d6d2f2b0d1bcf8297");
    _ = try std.fmt.hexToBytes(expected[0..], "c483cb731afcfe9f2c596698eaca1c4e0dcb4a1136297adef74c31c268966eb5");
    mixInSelector(Sha256, root, 25, &mixin);

    try std.testing.expect(std.mem.eql(u8, mixin[0..], expected[0..]));
}

/// Calculates the number of leaves needed for the merkelization
/// of this type.
pub fn chunkCount(T: type) usize {
    const info = @typeInfo(T);
    switch (info) {
        .int, .bool => return 1,
        .pointer => return chunkCount(info.pointer.child),
        // the chunk size of an array depends on its type
        .array => switch (@typeInfo(info.array.child)) {
            // Bitvector[N]
            .bool => return (info.array.len + 255) / 256,
            // Vector[B,N]
            .int => return (info.array.len * @sizeOf(info.array.child) + 31) / 32,
            // Vector[C,N]
            else => return info.array.len,
        },
        .@"struct" => return info.@"struct".fields.len,
        else => return error.NotSupported,
    }
}

const chunk = [BYTES_PER_CHUNK]u8;
const zero_chunk: chunk = [_]u8{0} ** BYTES_PER_CHUNK;

pub fn pack(T: type, values: T, l: *ArrayList(u8), allocator: Allocator) ![]chunk {
    try serialize(T, values, l, allocator);
    const padding_size = (BYTES_PER_CHUNK - l.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
    _ = try l.appendSlice(allocator, zero_chunk[0..padding_size]);
    return std.mem.bytesAsSlice(chunk, l.items);
}

test "pack u32" {
    var expected: [32]u8 = undefined;
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const out = try pack(u32, 0xdeadbeef, &list, std.testing.allocator);

    _ = try std.fmt.hexToBytes(expected[0..], "efbeadde00000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..]));
}

test "pack bool" {
    var expected: [32]u8 = undefined;
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const out = try pack(bool, true, &list, std.testing.allocator);

    _ = try std.fmt.hexToBytes(expected[0..], "0100000000000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..]));
}

test "pack string" {
    var expected: [128]u8 = undefined;
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const out = try pack([]const u8, "a" ** 100, &list, std.testing.allocator);

    _ = try std.fmt.hexToBytes(expected[0..], "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(expected.len == out.len * out[0].len);
    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..32]));
    try std.testing.expect(std.mem.eql(u8, out[1][0..], expected[32..64]));
    try std.testing.expect(std.mem.eql(u8, out[2][0..], expected[64..96]));
    try std.testing.expect(std.mem.eql(u8, out[3][0..], expected[96..]));
}

// merkleize recursively calculates the root hash of a Merkle tree.
pub fn merkleize(Hasher: type, chunks: []chunk, limit: ?usize, out: *[Hasher.digest_length]u8) anyerror!void {
    // Generate zero hashes for this hasher type at comptime
    const hashes_of_zero = comptime zeros.buildHashesOfZero(Hasher, 32, 256);

    // Calculate the number of chunks to be padded, check the limit
    if (limit != null and chunks.len > limit.?) {
        return error.ChunkSizeExceedsLimit;
    }
    const power = limit orelse chunks.len;
    const size = if (power > 0) try std.math.ceilPowerOfTwo(usize, power) else 0;

    // Perform the merkelization
    switch (size) {
        0 => std.mem.copyForwards(u8, out.*[0..], hashes_of_zero[0][0..]),
        1 => std.mem.copyForwards(u8, out.*[0..], (if (chunks.len > 0) chunks[0] else hashes_of_zero[0])[0..]),
        else => {
            // Merkleize the left side. If the number of chunks
            // isn't enough to fill the entire width, complete
            // with zeroes.
            var digest = Hasher.init(Hasher.Options{});
            var buf: [32]u8 = undefined;
            const split = if (size / 2 < chunks.len) size / 2 else chunks.len;
            try merkleize(Hasher, chunks[0..split], size / 2, &buf);
            digest.update(buf[0..]);

            // Merkleize the right side. If the number of chunks only
            // covers the first half, directly input the hashed zero-
            // filled subtrie.
            if (size / 2 < chunks.len) {
                try merkleize(Hasher, chunks[size / 2 ..], size / 2, &buf);
                digest.update(buf[0..]);
            } else {
                // Use depth-based indexing for zero hashes
                // For a subtree of size/2 leaves, we need the zero hash at depth log2(size/2)
                const subtree_size = size / 2;
                const depth = std.math.log2_int(usize, subtree_size);
                digest.update(hashes_of_zero[depth][0..]);
            }
            digest.final(out);
        },
    }
}

test "merkleize an empty slice" {
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const chunks = &[0][32]u8{};
    var out: [32]u8 = undefined;
    try merkleize(Sha256, chunks, null, &out);
    try std.testing.expect(std.mem.eql(u8, out[0..], zero_chunk[0..]));
}

test "merkleize a string" {
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const chunks = try pack([]const u8, "a" ** 100, &list, std.testing.allocator);
    var out: [32]u8 = undefined;
    try merkleize(Sha256, chunks, null, &out);
    // Build the expected tree
    const leaf1 = [_]u8{0x61} ** 32; // "0xaaaaa....aa" 32 times
    var leaf2: [32]u8 = [_]u8{0x61} ** 4 ++ [_]u8{0} ** 28;
    var root: [32]u8 = undefined;
    var internal_left: [32]u8 = undefined;
    var internal_right: [32]u8 = undefined;
    var hasher = Sha256.init(Sha256.Options{});
    hasher.update(leaf1[0..]);
    hasher.update(leaf1[0..]);
    hasher.final(&internal_left);
    hasher = Sha256.init(Sha256.Options{});
    hasher.update(leaf1[0..]);
    hasher.update(leaf2[0..]);
    hasher.final(&internal_right);
    hasher = Sha256.init(Sha256.Options{});
    hasher.update(internal_left[0..]);
    hasher.update(internal_right[0..]);
    hasher.final(&root);

    try std.testing.expect(std.mem.eql(u8, out[0..], root[0..]));
}

test "merkleize a boolean" {
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);

    var chunks = try pack(bool, false, &list, std.testing.allocator);
    var expected = [_]u8{0} ** BYTES_PER_CHUNK;
    var out: [BYTES_PER_CHUNK]u8 = undefined;
    try merkleize(Sha256, chunks, null, &out);

    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));

    var list2: ArrayList(u8) = .empty;
    defer list2.deinit(std.testing.allocator);

    chunks = try pack(bool, true, &list2, std.testing.allocator);
    expected[0] = 1;
    try merkleize(Sha256, chunks, null, &out);
    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));
}

test "merkleize a bytes16 vector with one element" {
    var list: ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    _ = try pack([16]u8, [_]u8{0xaa} ** 16, &list, std.testing.allocator);
    // var expected: [32]u8 = [_]u8{0xaa} ** 16 ++ [_]u8{0x00} ** 16;
    // var out: [32]u8 = undefined;
    // try merkleize(sha256, chunks, null, &out);
    // try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));
}

fn packBits(bits: []const bool, l: *ArrayList(u8), allocator: Allocator) ![]chunk {
    var byte: u8 = 0;
    for (bits, 0..) |bit, bitidx| {
        if (bit) {
            byte |= @as(u8, 1) << @truncate(7 - bitidx % 8);
        }
        if (bitidx % 8 == 7 or bitidx == bits.len - 1) {
            try l.append(allocator, byte);
            byte = 0;
        }
    }

    // pad the last chunk with 0s
    const padding_size = (BYTES_PER_CHUNK - l.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
    _ = try l.appendSlice(allocator, zero_chunk[0..padding_size]);

    return std.mem.bytesAsSlice(chunk, l.items);
}

pub fn hashTreeRoot(Hasher: type, T: type, value: T, out: *[Hasher.digest_length]u8, allocator: Allocator) !void {
    // Check if type has its own hashTreeRoot method at compile time
    if (comptime std.meta.hasFn(T, "hashTreeRoot")) {
        return value.hashTreeRoot(Hasher, out, allocator);
    }

    const type_info = @typeInfo(T);
    switch (type_info) {
        .int, .bool => {
            var list: ArrayList(u8) = .empty;
            defer list.deinit(allocator);
            const chunks = try pack(T, value, &list, allocator);
            try merkleize(Hasher, chunks, null, out);
        },
        .array => |a| {
            // Check if the child is a basic type. If so, return
            // the merkle root of its chunked serialization.
            // Otherwise, it is a composite object and the chunks
            // are the merkle roots of its elements.
            switch (@typeInfo(a.child)) {
                .int => {
                    var list: ArrayList(u8) = .empty;
                    defer list.deinit(allocator);
                    const chunks = try pack(T, value, &list, allocator);
                    try merkleize(Hasher, chunks, null, out);
                },
                .bool => {
                    var list: ArrayList(u8) = .empty;
                    defer list.deinit(allocator);
                    const chunks = try packBits(value[0..], &list, allocator);
                    try merkleize(Hasher, chunks, chunkCount(T), out);
                },
                .array => {
                    var chunks: ArrayList(chunk) = .empty;
                    defer chunks.deinit(allocator);
                    var tmp: chunk = undefined;
                    for (value) |item| {
                        try hashTreeRoot(Hasher, @TypeOf(item), item, &tmp, allocator);
                        try chunks.append(allocator, tmp);
                    }
                    try merkleize(Hasher, chunks.items, null, out);
                },
                else => return error.NotSupported,
            }
        },
        .pointer => |ptr| {
            switch (ptr.size) {
                .one => try hashTreeRoot(Hasher, ptr.child, value.*, out, allocator),
                .slice => {
                    switch (@typeInfo(ptr.child)) {
                        .int => {
                            var list: ArrayList(u8) = .empty;
                            defer list.deinit(allocator);
                            const chunks = try pack(T, value, &list, allocator);
                            var tmp: chunk = undefined;
                            try merkleize(Hasher, chunks, null, &tmp);
                            mixInLength2(Hasher, tmp, value.len, out);
                        },
                        // use bitlist
                        .bool => return error.UnSupportedPointerType,
                        // composite type
                        else => {
                            var chunks: ArrayList(chunk) = .empty;
                            defer chunks.deinit(allocator);
                            var tmp: chunk = undefined;
                            for (value) |item| {
                                try hashTreeRoot(Hasher, @TypeOf(item), item, &tmp, allocator);
                                try chunks.append(allocator, tmp);
                            }
                            try merkleize(Hasher, chunks.items, null, &tmp);
                            mixInLength2(Hasher, tmp, chunks.items.len, out);
                        },
                    }
                },
                else => return error.UnSupportedPointerType,
            }
        },
        .@"struct" => |str| {
            var chunks: ArrayList(chunk) = .empty;
            defer chunks.deinit(allocator);
            var tmp: chunk = undefined;
            inline for (str.fields) |f| {
                try hashTreeRoot(Hasher, f.type, @field(value, f.name), &tmp, allocator);
                try chunks.append(allocator, tmp);
            }
            try merkleize(Hasher, chunks.items, null, out);
        },
        // An optional is a union with `None` as first value.
        .optional => |opt| if (value != null) {
            var tmp: chunk = undefined;
            try hashTreeRoot(Hasher, opt.child, value.?, &tmp, allocator);
            mixInSelector(Hasher, tmp, 1, out);
        } else {
            mixInSelector(Hasher, zero_chunk, 0, out);
        },
        .@"union" => |u| {
            if (u.tag_type == null) {
                return error.UnionIsNotTagged;
            }
            inline for (u.fields, 0..) |f, index| {
                if (@intFromEnum(value) == index) {
                    var tmp: chunk = undefined;
                    try hashTreeRoot(Hasher, f.type, @field(value, f.name), &tmp, allocator);
                    mixInSelector(Hasher, tmp, index, out);
                }
            }
        },
        else => return error.NotSupported,
    }
}

// used at comptime to generate a bitvector from a byte vector
fn bytesToBits(comptime N: usize, src: [N]u8) [N * 8]bool {
    var bitvector: [N * 8]bool = undefined;
    for (src, 0..) |byte, idx| {
        var i = 0;
        while (i < 8) : (i += 1) {
            bitvector[i + idx * 8] = ((byte >> (7 - i)) & 1) == 1;
        }
    }
    return bitvector;
}
