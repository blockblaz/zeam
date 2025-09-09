const std = @import("std");
const builtin = @import("builtin");
const datetime = @import("datetime");

// having activeLevel non comptime and dynamic allows us env based logging and even a keystroke activated one
// on a running client, may be can be revised later
pub fn compTimeLog(comptime scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, fileParams: ?FileParams) void {
    if ((@intFromEnum(level) > @intFromEnum(activeLevel)) and (fileParams == null or (@intFromEnum(level) > @intFromEnum(fileParams.?.fileActiveLevel)))) {
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

        var buf: [4096]u8 = undefined;
        const print_str = std.fmt.bufPrint(
            buf[0..],
            "{s} {s}" ++ fmt ++ "\n",
            .{ timestamp_str, prefix } ++ args,
        ) catch return;

        // Print to stderr
        if (@intFromEnum(activeLevel) >= @intFromEnum(level)) {
            nosuspend stderr.writeAll(print_str) catch return;
        }

        // Also write to file if provided and file exists
        if (fileParams != null and @intFromEnum(fileParams.?.fileActiveLevel) >= @intFromEnum(level) and fileParams.?.file != null) {
            nosuspend fileParams.?.file.?.writeAll(print_str) catch return;
        }
    }
}

pub fn log(scope: LoggerScope, activeLevel: std.log.Level, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype, fileParams: ?FileParams) void {
    switch (scope) {
        .default => return compTimeLog(.default, activeLevel, level, fmt, args, fileParams),
        .n1 => return compTimeLog(.n1, activeLevel, level, fmt, args, fileParams),
        .n2 => return compTimeLog(.n2, activeLevel, level, fmt, args, fileParams),
        .n3 => return compTimeLog(.n3, activeLevel, level, fmt, args, fileParams),
    }
}

const LoggerScope = enum {
    default,
    n1,
    n2,
    n3,
};

pub const FileParams = struct {
    fileActiveLevel: std.log.Level = .debug,
    filePath: []const u8,
    fileName: []const u8,
    file: ?std.fs.File = null, // optional log file
    last_rotation_day: i64 = 0,
    mutex: if (builtin.target.os.tag == .freestanding) void else std.Thread.Mutex = if (builtin.target.os.tag == .freestanding) {} else std.Thread.Mutex{},
};

pub const ZeamLogger = struct {
    activeLevel: std.log.Level,
    scope: LoggerScope,
    fileParams: ?FileParams,

    const Self = @This();
    pub fn init(scope: LoggerScope, activeLevel: std.log.Level, fileParams: ?FileParams) Self {
        var updated_params = fileParams;
        if (updated_params) |*params| {
            params.file = getFile(scope, params.filePath, params.fileName);
            params.last_rotation_day = if (builtin.target.os.tag == .freestanding) 0 else @as(i64, @intCast(@divFloor(std.time.timestamp(), 24 * 60 * 60)));
        }

        return Self{
            .scope = scope,
            .activeLevel = activeLevel,
            .fileParams = updated_params,
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
        // mayBeRotate will not and shouldn't be called from zkvm
        //         if (builtin.target.os.tag == .freestanding) return;
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
                .default => try std.fmt.bufPrint(&name_buf, "{s}.log", .{self.fileParams.?.fileName}),
                else => try std.fmt.bufPrint(&name_buf, "{s}-{s}.log", .{ self.fileParams.?.fileName, @tagName(self.scope) }),
            };

            var new_buf: [128]u8 = undefined;
            const rotated_name = switch (self.scope) {
                .default => try std.fmt.bufPrint(&new_buf, "{s}-{s}.log", .{ self.fileParams.?.fileName, date_ext }),
                else => try std.fmt.bufPrint(&new_buf, "{s}-{s}-{s}.log", .{ self.fileParams.?.fileName, @tagName(self.scope), date_ext }),
            };

            // Lock the mutex from fileParams
            self.fileParams.?.mutex.lock();
            defer self.fileParams.?.mutex.unlock();

            file.close();
            var dir = std.fs.cwd().openDir(self.fileParams.?.filePath, .{}) catch return;
            defer dir.close();
            try dir.rename(base_name, rotated_name);

            // Update the file and rotation day in fileParams
            self.fileParams.?.file = getFile(self.scope, self.fileParams.?.filePath, self.fileParams.?.fileName);
            self.fileParams.?.last_rotation_day = current_epoch_day;
        }
    }

    pub fn err(
        self: *const Self,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        // const file_level = if (self.fileParams) |params| params.fileActiveLevel else .debug;
        // const file = if (self.fileParams) |params| params.file else null;
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
        // const file_level = if (self.fileParams) |params| params.fileActiveLevel else .debug;
        // const file = if (self.fileParams) |params| params.file else null;
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
        // const file_level = if (self.fileParams) |params| params.fileActiveLevel else .debug;
        // const file = if (self.fileParams) |params| params.file else null;
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
        // const file_level = if (self.fileParams) |params| params.fileActiveLevel else .debug;
        // const file = if (self.fileParams) |params| params.file else null;
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

pub fn getScopedLogger(comptime scope: LoggerScope, activeLevel: ?std.log.Level, fileParams: ?FileParams) ZeamLogger {
    return ZeamLogger.init(scope, activeLevel orelse std.log.default_level, fileParams);
}

pub fn getLogger(activeLevel: ?std.log.Level, fileParams: ?FileParams) ZeamLogger {
    return ZeamLogger.init(.default, activeLevel orelse std.log.default_level, fileParams);
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
    if (builtin.target.os.tag == .freestanding) {
        return null; // no file logging inside zkvm for now
    }

    // try to create/open a file
    // do not close here .. will be closed when log file is rotated and new log file is created
    // directory must exist already

    var dir = std.fs.cwd().openDir(filePath, .{}) catch return null;
    defer dir.close();

    var buf: [64]u8 = undefined;
    const filename_withscope = switch (scope) {
        .default => blk: {
            break :blk std.fmt.bufPrint(&buf, "{s}.log", .{fileName}) catch return null;
        },
        else => blk: {
            break :blk std.fmt.bufPrint(&buf, "{s}-{s}.log", .{ fileName, @tagName(scope) }) catch return null;
        },
    };

    const file = dir.createFile(
        filename_withscope,
        .{
            .read = true,
            .truncate = false,
        },
    ) catch return null;

    file.seekFromEnd(0) catch {};
    return file;
}
