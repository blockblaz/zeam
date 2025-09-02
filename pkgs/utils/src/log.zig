const std = @import("std");
const builtin = @import("builtin");
const datetime = @import("datetime");

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn compTimeLog(comptime scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, file: ?std.fs.File) void {
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
        // skip adding timestamp inside zkvm to keep the execution trace static between prover and verifier
        const print_str = std.fmt.bufPrint(buf[0..], prefix ++ fmt ++ "\n", args) catch @panic("error formatting log\n");
        io.print_str(print_str);
    } else {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        const stderr = std.io.getStdErr().writer();

        var ts_buf: [64]u8 = undefined;
        const timestamp_str = getFormattedTimestamp(&ts_buf);

        nosuspend stderr.print(
            "{s} {s}" ++ fmt ++ "\n",
            .{ timestamp_str, prefix } ++ args,
        ) catch return;
        // Also write to file if provided
        if (file) |f| {
            var buf: [4096]u8 = undefined;
            const print_str = std.fmt.bufPrint(
                buf[0..],
                "{s} {s}" ++ fmt ++ "\n",
                .{ timestamp_str, prefix } ++ args,
            ) catch return;
            nosuspend f.writeAll(print_str) catch return;
        }
    }
}

pub fn log(scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, file: ?std.fs.File) void {
    switch (scope) {
        .default => return compTimeLog(.default, activeLevel, level, fmt, args, file),
        .n1 => return compTimeLog(.n1, activeLevel, level, fmt, args, file),
        .n2 => return compTimeLog(.n2, activeLevel, level, fmt, args, file),
        .n3 => return compTimeLog(.n3, activeLevel, level, fmt, args, file),
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
    file: ?std.fs.File, // optional log file
    filePath: ?[]const u8, // path to log file directory
    // fileDate: datetime.datetime.Date,

    const Self = @This();
    pub fn init(scope: LoggerScope, activeLevel: std.log.Level, filePath: ?[]const u8) Self {
        const file = getFile(filePath);
        return Self{
            .scope = scope,
            .activeLevel = activeLevel,
            .file = file,
            .filePath = filePath,
            // .fileDate = date,
        };
    }

    fn maybeRotate(self: *const Self) !void {
        if (builtin.target.os.tag == .freestanding) {
            return;
        }

        if (self.file == null) {
            return; // no rotation if no file path is provided
        } else {
            const stat = self.file.?.stat() catch return;
            const size = stat.size;
            if (size < 10 * 1024 * 1024) { // 10 MB
                return;
            }

            self.file.?.close();

            try std.fs.cwd().rename("node.log", "node-0.log");

            self.file = getFile(self.filePath);
        }
    }

    pub fn err(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        maybeRotate(self) catch {};
        return log(self.scope, self.activeLevel, .err, fmt, args, self.file);
    }

    pub fn warn(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        maybeRotate(self) catch {};
        return log(self.scope, self.activeLevel, .warn, fmt, args, self.file);
    }
    pub fn info(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        maybeRotate(self) catch {};
        return log(self.scope, self.activeLevel, .info, fmt, args, self.file);
    }

    pub fn debug(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        maybeRotate(self) catch {};
        return log(self.scope, self.activeLevel, .debug, fmt, args, self.file);
    }
};

pub fn getScopedLogger(comptime scope: LoggerScope, activeLevel: ?std.log.Level, filePath: ?[]const u8) ZeamLogger {
    return ZeamLogger.init(scope, activeLevel orelse std.log.default_level, filePath);
}

pub fn getLogger(activeLevel: ?std.log.Level, filePath: ?[]const u8) ZeamLogger {
    return ZeamLogger.init(std.log.default_log_scope, activeLevel orelse std.log.default_level, filePath);
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

pub fn getFile(filePath: ?[]const u8) ?std.fs.File {
    if (filePath == null) {
        return null; // do not write to file if path is not provided
    }

    // try to create/open a file
    // do not close here .. will be closed when the last log gets written and new log file is created
    // directory must exist already
    var file: ?std.fs.File = null;
    if (filePath) |path| {
        var dir = std.fs.cwd().openDir(path, .{}) catch return null;

        // converts millisecond to Datetime
        // const dt = datetime.datetime.Datetime.fromTimestamp(std.time.milliTimestamp());
        // const name_buf: [32]u8 = undefined;
        // const file_name = std.fmt.bufPrint(&name_buf, "node-{:0>2}{:0>2}.log", .{
        //     dt.date.month,
        //     dt.date.day,
        // });

        file = dir.createFile(
            "node.log",
            .{
                .read = true,
                .truncate = false, // append mode
            },
        ) catch return null;
        // file.?.seekFromEnd(0);
    }
    return file;
}
