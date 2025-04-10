const std = @import("std");
/// Constant which represents an empty structure field
pub const Empty = std.builtin.Type.StructField{
    .name = "",
    .type = undefined,
    .default_value_ptr = null,
    .is_comptime = false,
    .alignment = 0,
};

/// Ensures the type matches the wanted type kind
inline fn ensure(comptime T: type, comptime kind: std.builtin.TypeId) ?std.meta.TagPayload(std.builtin.Type, kind) {
    return if (@typeInfo(T) == kind) @field(@typeInfo(T), @tagName(kind)) else null;
}

fn indexByName(comptime fields: []const std.builtin.Type.StructField, name: []const u8) ?usize {
    for (fields, 0..) |field, i| {
        if (std.mem.eql(u8, field.name, name)) return i;
    }
    return null;
}

/// Mixes fields from structure extend into structure super
pub fn MixIn(comptime Super: type, comptime Extend: type) type {
    const superInfo = ensure(Super, .@"struct") orelse @panic("Super type must be a struct");
    const extendInfo = ensure(Extend, .@"struct") orelse @panic("Extend type must be a struct");

    if (extendInfo.layout != superInfo.layout) @compileError("Super and extend struct layouts must be the same");
    if (extendInfo.backing_integer != superInfo.backing_integer) @compileError("Super and extend struct backing integers must be the same");

    var totalFields = superInfo.fields.len;

    for (extendInfo.fields) |field| {
        if (indexByName(superInfo.fields, field.name) == null) totalFields += 1;
    }

    var fields: [totalFields]std.builtin.Type.StructField = [_]std.builtin.Type.StructField{Empty} ** totalFields;

    for (superInfo.fields, 0..) |src, i| {
        fields[i] = src;
    }

    var i: usize = 0;
    for (extendInfo.fields) |src| {
        const index = indexByName(&fields, src.name) orelse blk: {
            i += 1;
            break :blk (i + superInfo.fields.len - 1);
        };

        fields[index] = src;
    }

    return @Type(.{
        .@"struct" = .{
            .layout = superInfo.layout,
            .backing_integer = superInfo.backing_integer,
            .fields = &fields,
            .decls = &.{},
            .is_tuple = false,
        },
    });
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
