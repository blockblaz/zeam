const std = @import("std");

pub fn Partial(comptime T: type) type {
    const info = @typeInfo(T);
    switch (info) {
        .@"struct" => |s| {
            var field_names: [s.fields.len][]const u8 = undefined;
            var field_types: [s.fields.len]type = undefined;
            var field_attrs: [s.fields.len]std.builtin.Type.StructField.Attributes = undefined;

            inline for (s.fields, 0..) |field, i| {
                if (field.is_comptime) {
                    @compileError("Cannot make Partial of " ++ @typeName(T) ++ ", it has a comptime field " ++ field.name);
                }
                const optional_type = switch (@typeInfo(field.type)) {
                    .optional => field.type,
                    else => ?field.type,
                };
                const default_value: optional_type = null;
                field_names[i] = field.name;
                field_types[i] = optional_type;
                field_attrs[i] = .{
                    .@"align" = field.alignment,
                    .default_value_ptr = &default_value,
                };
            }
            return @Struct(s.layout, s.backing_integer, &field_names, &field_types, &field_attrs);
        },
        else => @compileError("Cannot make Partial of " ++ @typeName(T) ++
            ", the type must be a struct"),
    }
    unreachable;
}

test "partial" {
    const PartialObject = Partial(struct {
        foo: []const u8,
        bar: ?[]const u8,
        baz: u32,
    });
    const part = PartialObject{};
    std.debug.print("partial={any}\n", .{part});
    try std.testing.expectEqual(@as(?[]const u8, null), part.foo);
    try std.testing.expectEqual(@as(?[]const u8, null), part.bar);
    try std.testing.expectEqual(@as(?u32, null), part.baz);
}
