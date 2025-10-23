const std = @import("std");
const xev = @import("xev");

const OnIntervalCbType = *const fn (ud: *anyopaque, slot: isize) anyerror!void;
pub const OnIntervalCbWrapper = struct {
    ptr: *anyopaque,
    onIntervalCb: OnIntervalCbType,
    interval: isize = 0,
    c: xev.Completion = undefined,

    pub fn onInterval(self: OnIntervalCbWrapper) !void {
        return self.onIntervalCb(self.ptr, self.interval);
    }
};
