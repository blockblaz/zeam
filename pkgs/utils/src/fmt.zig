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
                try writer.print("<json error: {any}>", .{e});
                return;
            };
            defer self.allocator.free(json_str);
            try writer.writeAll(json_str);
        }
    };
}

test "LazyJson formats JSON and frees allocation" {
    const allocator = std.testing.allocator;

    const OkJson = struct {
        pub fn toJsonString(self: *const @This(), alloc: Allocator) ![]const u8 {
            _ = self;
            return try alloc.dupe(u8, "{\"ok\":true}");
        }
    };

    const value: OkJson = .{};
    const lazy_json = LazyJson(OkJson).init(allocator, &value);

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    try lazy_json.format("", .{}, buffer.writer(allocator));

    try std.testing.expectEqualStrings("{\"ok\":true}", buffer.items);
}

test "LazyJson formats error on toJsonString failure" {
    const allocator = std.testing.allocator;

    const FailJson = struct {
        pub fn toJsonString(self: *const @This(), alloc: Allocator) ![]const u8 {
            _ = self;
            _ = alloc;
            return error.Failed;
        }
    };

    const value: FailJson = .{};
    const lazy_json = LazyJson(FailJson).init(allocator, &value);

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    try lazy_json.format("", .{}, buffer.writer(allocator));

    try std.testing.expect(std.mem.containsAtLeast(u8, buffer.items, 1, "<json error:"));
}
