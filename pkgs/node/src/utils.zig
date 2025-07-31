const std = @import("std");
const Thread = std.Thread;
const Mutex = Thread.Mutex;

const xev = @import("xev");

pub const EventLoop = struct {
    loop: *xev.Loop,
    // events from libp2p or other threads will also be pushed on it
    mutex: Mutex,

    const Self = @This();
    pub fn init(loop: *xev.Loop) !Self {
        const mutex = Mutex{};

        return Self{
            .loop = loop,
            .mutex = mutex,
        };
    }

    pub fn denit(self: *Self) !void {
        self.loop.deinit();
    }

    pub fn run(self: *Self, optMode: ?xev.RunMode) !void {
        const mode = optMode orelse xev.RunMode.until_done;
        // clock event should keep rearming itself and never run out
        try self.loop.run(mode);
    }
};

const OnSlotCbType = *const fn (ud: *anyopaque, slot: isize) anyerror!void;
pub const OnSlotCbWrapper = struct {
    ptr: *anyopaque,
    onSlotCb: OnSlotCbType,
    slot: isize = 0,
    c: xev.Completion = undefined,

    pub fn onSlot(self: OnSlotCbWrapper) !void {
        return self.onSlotCb(self.ptr, self.slot);
    }
};
