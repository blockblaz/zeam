const std = @import("std");
const Allocator = std.mem.Allocator;

/// Lazily formats a value as JSON when it is actually written to the formatter.
///
/// This is primarily useful for logging: even if `logger.debug(...)` is disabled, Zig evaluates
/// function arguments eagerly. Wrapping a value with `LazyJson(T)` defers the expensive
/// `toJsonString()` allocation/serialization until the log line is really emitted.
///
/// The wrapped type `T` must provide: `pub fn toJsonString(self: *const T, allocator: Allocator) ![]const u8`.
pub fn LazyJson(comptime T: type) type {
    return struct {
        allocator: Allocator,
        value: *const T,

        pub fn init(allocator: Allocator, value: *const T) @This() {
            return .{
                .allocator = allocator,
                .value = value,
            };
        }

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;

            const json_str = self.value.toJsonString(self.allocator) catch |e| {
                try std.fmt.format(writer, "<json error: {any}>", .{e});
                return;
            };
            defer self.allocator.free(json_str);
            try writer.writeAll(json_str);
        }
    };
}

