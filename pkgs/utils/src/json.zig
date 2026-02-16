const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

/// Helper function to convert JSON value to string
/// Caller is responsible for freeing the returned string
pub fn jsonToString(allocator: Allocator, json_value: json.Value) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{json.fmt(json_value, .{})});
}
