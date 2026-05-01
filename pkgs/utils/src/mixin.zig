const std = @import("std");
pub const Empty = struct {};

inline fn ensureStruct(comptime T: type) ?std.builtin.Type.Struct {
    return switch (@typeInfo(T)) {
        .@"struct" => |s| s,
        else => null,
    };
}

fn indexByName(comptime names: []const []const u8, name: []const u8) ?usize {
    for (names, 0..) |field_name, i| {
        if (std.mem.eql(u8, field_name, name)) return i;
    }
    return null;
}

/// Mixes fields from structure extend into structure super
pub fn MixIn(comptime Super: type, comptime Extend: type) type {
    const superInfo = ensureStruct(Super) orelse @panic("Super type must be a struct");
    const extendInfo = ensureStruct(Extend) orelse @panic("Extend type must be a struct");

    if (extendInfo.layout != superInfo.layout) @compileError("Super and extend struct layouts must be the same");
    if (extendInfo.backing_integer != superInfo.backing_integer) @compileError("Super and extend struct backing integers must be the same");

    var totalFields = superInfo.fields.len;

    for (extendInfo.fields) |field| {
        var found = false;
        for (superInfo.fields) |super_field| {
            if (std.mem.eql(u8, super_field.name, field.name)) {
                found = true;
                break;
            }
        }
        if (!found) totalFields += 1;
    }

    var field_names: [totalFields][]const u8 = undefined;
    var field_types: [totalFields]type = undefined;
    var field_attrs: [totalFields]std.builtin.Type.StructField.Attributes = undefined;

    for (superInfo.fields, 0..) |src, i| {
        field_names[i] = src.name;
        field_types[i] = src.type;
        field_attrs[i] = .{
            .@"comptime" = src.is_comptime,
            .@"align" = src.alignment,
            .default_value_ptr = src.default_value_ptr,
        };
    }

    var next_index: usize = superInfo.fields.len;
    for (extendInfo.fields) |src| {
        const index = indexByName(field_names[0..next_index], src.name) orelse blk: {
            const idx = next_index;
            next_index += 1;
            break :blk idx;
        };

        field_names[index] = src.name;
        field_types[index] = src.type;
        field_attrs[index] = .{
            .@"comptime" = src.is_comptime,
            .@"align" = src.alignment,
            .default_value_ptr = src.default_value_ptr,
        };
    }

    return @Struct(superInfo.layout, superInfo.backing_integer, &field_names, &field_types, &field_attrs);
}

test "mixin" {
    const Type1 = struct {
        a: u8 = 'c',
        z: [3]i32 = [_]i32{ 1, 2, 3 },
    };
    const Type2 = struct { b: isize = 42, a: i32 = 0 };

    const Mixed = MixIn(Type1, Type2);
    const mixed = Mixed{};

    std.debug.print("mixin={any}\n", .{mixed});
    try std.testing.expectEqual(mixed.a, 0);
    try std.testing.expectEqual(mixed.z.len, 3);
    try std.testing.expectEqual(mixed.b, 42);
}
