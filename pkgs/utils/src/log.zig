const std = @import("std");
const builtin = @import("builtin");
const datetime = @import("datetime");

const Colors = struct {
    const reset = "\x1b[0m";

    const err = "\x1b[31m"; // Red
    const warn = "\x1b[33m"; // Yellow
    const info = "\x1b[32m"; // Green
    const debug = "\x1b[36m"; // Cyan

    const timestamp = "\x1b[90m"; // Bright black
    const scope = "\x1b[35m"; // Magenta
};

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn compTimeLog(comptime scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, fileLogParams: ?FileLogParams) void {
    if ((@intFromEnum(level) > @intFromEnum(activeLevel)) and (fileLogParams == null or (@intFromEnum(level) > @intFromEnum(fileLogParams.?.fileActiveLevel)))) {
        return;
    }

    const system_prefix = if (builtin.target.os.tag == .freestanding) "zkvm" else "zeam";

    const scope_prefix = "(" ++ switch (scope) {
        .default => system_prefix,
        else => system_prefix ++ "-" ++ @tagName(scope),
    } ++ "): ";
    const prefix = "[" ++ comptime level.asText() ++ "] " ++ scope_prefix;

    if (builtin.target.os.tag == .freestanding) {
        const io = @import("zkvm").io;
        var buf: [4096]u8 = undefined;
        const print_str = std.fmt.bufPrint(buf[0..], prefix ++ fmt ++ "\n", args) catch @panic("error formatting log\n");
        io.print_str(print_str);
    } else {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        const stderr = std.io.getStdErr().writer();

        var ts_buf: [64]u8 = undefined;
        const timestamp_str = getFormattedTimestamp(&ts_buf);

        // Get colors
        const level_color = getLevelColor(level);
        const timestamp_color = Colors.timestamp;
        const scope_color = Colors.scope;
        const reset_color = Colors.reset;

        var buf: [4096]u8 = undefined;
        var print_str = std.fmt.bufPrint(
            buf[0..],
            "{s}{s}{s} {s}[{s}]{s} {s}{s}{s}" ++ fmt ++ "\n",
            .{ timestamp_color, timestamp_str, reset_color, level_color, comptime level.asText(), reset_color, scope_color, scope_prefix, reset_color } ++ args,
        ) catch return;

        // Print to stderr
        if (@intFromEnum(activeLevel) >= @intFromEnum(level)) {
            nosuspend stderr.writeAll(print_str) catch return;
        }

        //write to file
        if (fileLogParams != null and @intFromEnum(fileLogParams.?.fileActiveLevel) >= @intFromEnum(level)) {
            if (fileLogParams.?.monocolorFile) {
                print_str = std.fmt.bufPrint(
                    buf[0..],
                    "{s} {s}" ++ fmt ++ "\n",
                    .{ timestamp_str, prefix } ++ args,
                ) catch return;
            }

            nosuspend fileLogParams.?.file.writeAll(print_str) catch |err| {
                stderr.print("{s}{s}{s} {s}[ERROR]{s} {s}{s}{s}Failed to write to log file: {any}\n", .{ timestamp_color, timestamp_str, reset_color, Colors.err, reset_color, scope_color, scope_prefix, reset_color, err }) catch {};
            };
        }
    }
}

pub fn log(scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, fileParams: ?FileParams) void {
    // Convert FileParams to FileLogParams - only create if file exists
    const fileLogParams: ?FileLogParams = if ((fileParams != null) and (fileParams.?.file != null))
        FileLogParams{ .fileActiveLevel = fileParams.?.fileBehaviour.fileActiveLevel, .file = fileParams.?.file.?, .monocolorFile = fileParams.?.fileBehaviour.monocolorFile }
    else
        null;

    switch (scope) {
        .default => return compTimeLog(.default, activeLevel, level, fmt, args, fileLogParams),
        .n1 => return compTimeLog(.n1, activeLevel, level, fmt, args, fileLogParams),
        .n2 => return compTimeLog(.n2, activeLevel, level, fmt, args, fileLogParams),
        .n3 => return compTimeLog(.n3, activeLevel, level, fmt, args, fileLogParams),
    }
}

const LoggerScope = enum {
    default,
    n1,
    n2,
    n3,
};

pub const FileLogParams = struct {
    fileActiveLevel: std.log.Level,
    file: std.fs.File,
    monocolorFile: bool,
};

pub const FileBehaviourParams = struct {
    fileActiveLevel: std.log.Level = .debug,
    filePath: []const u8,
    fileName: []const u8,
    monocolorFile: bool = false,
};

pub const FileParams = struct {
    file: ?std.fs.File = null,
    fileBehaviour: FileBehaviourParams,
    mutex: std.Thread.Mutex,
    last_rotation_day: i64 = 0,
};

pub const ZeamLogger = struct {
    activeLevel: std.log.Level,
    scope: LoggerScope,
    fileParams: ?FileParams,

    const Self = @This();
    pub fn init(scope: LoggerScope, activeLevel: std.log.Level, fileBehaviourParams: ?FileBehaviourParams) Self {
        const fileParams: ?FileParams = if (fileBehaviourParams) |params| blk: {
            break :blk FileParams{
                .file = getFile(scope, params.filePath, params.fileName),
                .fileBehaviour = params,
                .mutex = std.Thread.Mutex{},
                .last_rotation_day = if (builtin.target.os.tag == .freestanding) 0 else @as(i64, @intCast(@divFloor(std.time.timestamp(), 24 * 60 * 60))), // Set in FileParams
            };
        } else null;

        return Self{
            .scope = scope,
            .activeLevel = activeLevel,
            .fileParams = fileParams,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.fileParams) |*params| {
            if (params.file) |f| {
                f.close();
                params.file = null;
            }
        }
    }

    pub fn maybeRotate(self: *Self) !void {
        if (self.fileParams == null) return;
        if (self.fileParams.?.file == null) return;

        if (self.fileParams.?.file) |file| {
            const now = std.time.timestamp();
            const sec_per_day = 24 * 60 * 60;
            const current_epoch_day = @as(i64, @intCast(@divFloor(now, sec_per_day)));

            if (current_epoch_day == self.fileParams.?.last_rotation_day) {
                return;
            }
            const date = datetime.datetime.Datetime.fromTimestamp(self.fileParams.?.last_rotation_day * sec_per_day * 1000);

            var ts_buf: [128]u8 = undefined;
            const date_ext = try std.fmt.bufPrint(
                &ts_buf,
                "{d:0>4}{d:0>2}{d:0>2}",
                .{
                    date.date.year,
                    date.date.month,
                    date.date.day,
                },
            );

            var name_buf: [64]u8 = undefined;
            const base_name = switch (self.scope) {
                .default => try std.fmt.bufPrint(&name_buf, "{s}.log", .{self.fileParams.?.fileBehaviour.fileName}),
                else => try std.fmt.bufPrint(&name_buf, "{s}-{s}.log", .{ self.fileParams.?.fileBehaviour.fileName, @tagName(self.scope) }),
            };

            var new_buf: [128]u8 = undefined;
            const rotated_name = switch (self.scope) {
                .default => try std.fmt.bufPrint(&new_buf, "{s}-{s}.log", .{ self.fileParams.?.fileBehaviour.fileName, date_ext }),
                else => try std.fmt.bufPrint(&new_buf, "{s}-{s}-{s}.log", .{ self.fileParams.?.fileBehaviour.fileName, @tagName(self.scope), date_ext }),
            };

            self.fileParams.?.mutex.lock();
            defer self.fileParams.?.mutex.unlock();

            file.close();
            var dir = std.fs.cwd().openDir(self.fileParams.?.fileBehaviour.filePath, .{}) catch return;
            defer dir.close();
            try dir.rename(base_name, rotated_name);

            self.fileParams.?.file = getFile(self.scope, self.fileParams.?.fileBehaviour.filePath, self.fileParams.?.fileBehaviour.fileName);
            self.fileParams.?.last_rotation_day = current_epoch_day;
        }
    }

    pub fn err(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(
            self.scope,
            self.activeLevel,
            .err,
            fmt,
            args,
            self.fileParams,
        );
    }

    pub fn warn(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(
            self.scope,
            self.activeLevel,
            .warn,
            fmt,
            args,
            self.fileParams,
        );
    }

    pub fn info(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(
            self.scope,
            self.activeLevel,
            .info,
            fmt,
            args,
            self.fileParams,
        );
    }

    pub fn debug(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        return log(
            self.scope,
            self.activeLevel,
            .debug,
            fmt,
            args,
            self.fileParams,
        );
    }
};

pub fn getScopedLogger(comptime scope: LoggerScope, activeLevel: ?std.log.Level, fileBehaviourParams: ?FileBehaviourParams) ZeamLogger {
    return ZeamLogger.init(scope, activeLevel orelse std.log.default_level, fileBehaviourParams);
}

pub fn getLogger(activeLevel: ?std.log.Level, fileBehaviourParams: ?FileBehaviourParams) ZeamLogger {
    return ZeamLogger.init(.default, activeLevel orelse std.log.default_level, fileBehaviourParams);
}

pub fn getTestLogger() ZeamLogger {
    return ZeamLogger.init(.default, std.log.default_level, null);
}

pub fn getFormattedTimestamp(buf: []u8) []const u8 {
    const ts = std.time.milliTimestamp();
    // converts millisecond to Datetime
    const dt = datetime.datetime.Datetime.fromTimestamp(ts);

    const months: [12][]const u8 = .{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const month_str = months[dt.date.month - 1];
    const ms: u16 = @intCast(dt.time.nanosecond / 1_000_000);

    return std.fmt.bufPrint(buf[0..], "{s}-{:0>2} {:0>2}:{:0>2}:{:0>2}.{:0>3}", .{
        month_str,
        dt.date.day,
        dt.time.hour,
        dt.time.minute,
        dt.time.second,
        ms,
    }) catch return buf[0..0];
}

pub fn getFile(scope: LoggerScope, filePath: []const u8, fileName: []const u8) ?std.fs.File {
    // try to create/open a file
    // do not close here .. will be closed when log file is rotated and new log file is created
    // directory must exist already - if dir does not exist we will not write - default ./log is created in main() not here

    var dir = std.fs.cwd().openDir(filePath, .{}) catch |err| {
        std.debug.print("ERROR: Failed to open directory '{s}': {any}\n", .{ filePath, err });
        return null;
    };
    defer dir.close();

    var buf: [64]u8 = undefined;
    const filename_withscope = switch (scope) {
        .default => blk: {
            break :blk std.fmt.bufPrint(&buf, "{s}.log", .{fileName}) catch |err| {
                std.debug.print("ERROR: Failed to format filename '{s}.log': {any}\n", .{ fileName, err });
                return null;
            };
        },
        else => blk: {
            break :blk std.fmt.bufPrint(&buf, "{s}-{s}.log", .{ fileName, @tagName(scope) }) catch |err| {
                std.debug.print("ERROR: Failed to format filename '{s}-{s}.log': {any}\n", .{ fileName, @tagName(scope), err });
                return null;
            };
        },
    };

    const file = dir.createFile(
        filename_withscope,
        .{
            .read = true,
            .truncate = false,
        },
    ) catch |err| {
        std.debug.print("ERROR: Failed to create/open file '{s}' in directory '{s}': {any}\n", .{ filename_withscope, filePath, err });
        return null;
    };

    file.seekFromEnd(0) catch |err| {
        std.debug.print("WARNING: Failed to seek to end of file '{s}': {any}\n", .{ filename_withscope, err });
        // Don't return null here - seekFromEnd failure is not fatal
    };

    return file;
}

fn getLevelColor(comptime level: std.log.Level) []const u8 {
    return switch (level) {
        .err => Colors.err,
        .warn => Colors.warn,
        .info => Colors.info,
        .debug => Colors.debug,
    };
}
