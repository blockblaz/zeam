const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

/// Helper function to convert JSON value to string
/// Caller is responsible for freeing the returned string
pub fn jsonToString(allocator: Allocator, json_value: json.Value) ![]const u8 {
    var str = std.ArrayList(u8).init(allocator);
    errdefer str.deinit();
    try json.stringify(json_value, .{}, str.writer());
    return str.toOwnedSlice();
}
