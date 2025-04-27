const std = @import("std");
const castFactory = @import("./cast.zig");
pub usingnamespace castFactory;

pub fn Extend(To: type, from: anytype, with: anytype) To {
    var result: To = undefined;
    inline for (@typeInfo(To).@"struct".fields) |field| {
        const extend_value = @field(with, field.name) orelse @field(from, field.name);

        const field_value = switch (@typeInfo(field.type)) {
            .optional => extend_value,
            // TODO: throw error instead of panic?
            else => extend_value orelse @panic("optional value for non optional field"),
        };
        @field(result, field.name) = field_value;
    }
    return result;
}
