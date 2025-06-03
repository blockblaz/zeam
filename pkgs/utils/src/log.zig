const std = @import("std");
const builtin = @import("builtin");

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn log(comptime scope: @Type(.enum_literal), activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) !void {
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

// just a handy debugging log used in the project
pub fn zeamLog(comptime fmt: []const u8, args: anytype) !void {
    // forcing all logs for now
    try log(std.log.default_log_scope, std.log.Level.debug, std.log.Level.debug, fmt, args);
}

const ZeamLogger = struct {
    activeLevel: std.log.Level = std.log.Level.debug,
    comptime scope: @Type(.enum_literal) = std.log.default_log_scope,

    const Self = @This();
    pub fn init(comptime scope: @Type(.enum_literal)) Self {
        return Self{
            .scope = scope,
        };
    }

    pub fn setActiveLevel(self: *Self, newLevel: std.log.Level) void {
        self.activeLevel = newLevel;
    }

    pub fn err(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        return log(self.scope, self.activeLevel, .err, fmt, args);
    }

    pub fn warn(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        return log(self.scope, self.activeLevel, .warn, fmt, args);
    }
    pub fn info(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        return log(self.scope, self.activeLevel, .info, fmt, args);
    }

    pub fn debug(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        return log(self.scope, self.activeLevel, .debug, fmt, args);
    }
};

pub fn getScopedLogger(comptime scope: @Type(.enum_literal)) ZeamLogger {
    return ZeamLogger.init(scope);
}

pub fn getLogger() ZeamLogger {
    return ZeamLogger.init(std.log.default_log_scope);
}
