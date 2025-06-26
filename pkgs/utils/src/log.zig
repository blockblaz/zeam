const std = @import("std");
const builtin = @import("builtin");

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn log(comptime scope: @Type(.enum_literal), activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
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

// just a handy debugging log used in the project
pub fn zeamLog(comptime fmt: []const u8, args: anytype) !void {
    // forcing all logs for now
    log(std.log.default_log_scope, std.log.Level.debug, std.log.Level.debug, fmt, args);
}

pub const ZeamLogger = struct {
    activeLevel: std.log.Level = std.log.Level.debug,
    comptime scope: @Type(.enum_literal) = std.log.default_log_scope,
    comptime logFn: @TypeOf(log) = log,

    const Self = @This();
    pub fn init(comptime scope: @Type(.enum_literal), logFn: @TypeOf(log)) Self {
        return Self{
            .scope = scope,
            .logFn = logFn,
        };
    }

    pub fn setActiveLevel(self: *Self, newLevel: std.log.Level) void {
        self.activeLevel = newLevel;
    }

    pub fn err(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return self.logFn(self.scope, self.activeLevel, .err, fmt, args);
    }

    pub fn warn(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return self.logFn(self.scope, self.activeLevel, .warn, fmt, args);
    }
    pub fn info(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return self.logFn(self.scope, self.activeLevel, .info, fmt, args);
    }

    pub fn debug(
        self: *Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return self.logFn(self.scope, self.activeLevel, .debug, fmt, args);
    }
};

pub fn getScopedLogger(comptime scope: @Type(.enum_literal)) ZeamLogger {
    return ZeamLogger.init(scope, log);
}

pub fn getLogger() ZeamLogger {
    return ZeamLogger.init(std.log.default_log_scope, log);
}

fn noopLog(comptime scope: @Type(.enum_literal), activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
    _ = scope;
    _ = activeLevel;
    _ = level;
    _ = fmt;
    _ = args;
}

pub const noopLogger = ZeamLogger.init(std.log.default_log_scope, noopLog);
