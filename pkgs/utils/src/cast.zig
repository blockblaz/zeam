const std = @import("std");

pub fn Cast(To: type, from: anytype) To {
    var result: To = undefined;
    inline for (@typeInfo(To).@"struct".fields) |field| {
        const from_field_value = @field(from, field.name);
        const field_value = switch (@typeInfo(field.type)) {
            .optional => from_field_value,
            else => switch (@typeInfo(@TypeOf(from_field_value))) {
                // TODO: throw error instead of panic?
                .optional => from_field_value orelse @panic("null value for non optional field"),
                else => from_field_value,
            },
        };

        @field(result, field.name) = field_value;
    }
    return result;
}
