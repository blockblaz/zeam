const std = @import("std");

pub fn Cast(To: type, from: anytype) To {
    var result: To = undefined;
    inline for (@typeInfo(To).@"struct".fields) |field| {
        const cast_value = @field(from, field.name);

        const field_value = switch (@typeInfo(field.type)) {
            .optional => cast_value,
            // TODO: throw error instead of panic?
            else => cast_value orelse @panic("optional value for non optional field"),
        };

        @field(result, field.name) = field_value;
    }
    return result;
}
