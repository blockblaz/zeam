const std = @import("std");
const builtin = @import("builtin");

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn log(comptime scope: @Type(.enum_literal), comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, activeLevel: std.log.Level) !void {
    if (@intFromEnum(level) > @intFromEnum(activeLevel)) {
        return;
    }

    const system_prefix = if (builtin.target.os.tag == .freestanding) "zkvm" else "zeam";

    const scope_prefix = "(" ++ switch (scope) {
        std.log.default_log_scope => system_prefix,
        else => system_prefix ++ "-" ++ @tagName(scope),
    } ++ "): ";
    const prefix = "[" ++ comptime level.asText() ++ "] " ++ scope_prefix;

    if (builtin.target.os.tag == .freestanding) {
        const io = @import("zkvm").io;
        var buf: [512]u8 = undefined;
        io.print_str(try std.fmt.bufPrint(buf[0..], prefix ++ fmt, args));
    } else {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        const stderr = std.io.getStdErr().writer();
        nosuspend stderr.print(prefix ++ fmt, args) catch return;
    }
}

pub fn zeamLog(comptime fmt: []const u8, args: anytype) !void {
    // forcing all logs for now
    try log(std.log.default_log_scope, std.log.Level.debug, fmt, args, std.log.Level.debug);
}
