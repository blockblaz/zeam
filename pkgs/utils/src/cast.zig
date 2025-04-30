const std = @import("std");

pub fn Cast(To: type, from: anytype) To {
    var result: To = undefined;
    inline for (@typeInfo(To).@"struct".fields) |field| {
        const field_value = switch (@typeInfo(field.type)) {
            .optional => @field(from, field.name),
            // TODO: throw error instead of panic?
            else => @field(from, field.name) orelse @panic("optional value for non optional field"),
        };

        @field(result, field.name) = field_value;
    }
    return result;
}
