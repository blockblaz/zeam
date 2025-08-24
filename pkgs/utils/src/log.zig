const std = @import("std");
const builtin = @import("builtin");

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn comptTimeLog(comptime scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
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
        var buf: [4096]u8 = undefined;
        // TODO don't throw error because it somehow messes with creation of  noopLogger as noopLog
        // doesn't throw and somehow it can't seem to infer error types as they might not be same
        // across all log fns, figure out in a later PR
        const print_str = std.fmt.bufPrint(buf[0..], prefix ++ fmt ++ "\n", args) catch @panic("error formatting log\n");
        io.print_str(print_str);
    } else {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        const stderr = std.io.getStdErr().writer();
        nosuspend stderr.print(prefix ++ fmt ++ "\n", args) catch return;
    }
}

pub fn log(scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
    switch (scope) {
        .default => return comptTimeLog(.default, activeLevel, level, fmt, args),
        .n1 => return comptTimeLog(.n1, activeLevel, level, fmt, args),
        .n2 => return comptTimeLog(.n2, activeLevel, level, fmt, args),
        .n3 => return comptTimeLog(.n3, activeLevel, level, fmt, args),
    }
}

//
const LoggerScope = enum {
    default,
    n1,
    n2,
    n3,
};

pub const ZeamLogger = struct {
    activeLevel: std.log.Level,
    scope: LoggerScope,

    const Self = @This();
    pub fn init(scope: LoggerScope, activeLevel: std.log.Level) Self {
        return Self{
            .scope = scope,
            .activeLevel = activeLevel,
        };
    }

    pub fn err(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(self.scope, self.activeLevel, .err, fmt, args);
    }

    pub fn warn(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(self.scope, self.activeLevel, .warn, fmt, args);
    }
    pub fn info(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(self.scope, self.activeLevel, .info, fmt, args);
    }

    pub fn debug(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(self.scope, self.activeLevel, .debug, fmt, args);
    }
};

pub fn getScopedLogger(comptime scope: LoggerScope, activeLevel: ?std.log.Level) ZeamLogger {
    return ZeamLogger.init(scope, activeLevel orelse std.log.default_level);
}

pub fn getLogger(activeLevel: ?std.log.Level) ZeamLogger {
    return ZeamLogger.init(std.log.default_log_scope, activeLevel orelse std.log.default_level);
}
