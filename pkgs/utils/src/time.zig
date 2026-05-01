const std = @import("std");
const builtin = @import("builtin");

pub fn unixTimestampSeconds() i64 {
    if (builtin.target.os.tag == .freestanding) return 0;

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

pub fn unixTimestampMillis() i64 {
    if (builtin.target.os.tag == .freestanding) return 0;

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @as(i64, @intCast(ts.sec)) * std.time.ms_per_s +
        @divFloor(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

pub fn sleepNs(ns: u64) void {
    if (builtin.target.os.tag == .freestanding) return;

    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.sleep(io, .{ .nanoseconds = ns }, .awake) catch {};
}

pub fn monotonicTimestampNs() i128 {
    if (builtin.target.os.tag == .freestanding) return 0;

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}
