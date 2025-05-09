const std = @import("std");
const Allocator = std.mem.Allocator;

const xev = @import("xev");

const params = @import("@zeam/params");
const SECONDS_PER_SLOT_MS: isize = params.SECONDS_PER_SLOT * std.time.ms_per_s;

const utils = @import("./utils.zig");
const OnSlotCbWrapper = utils.OnSlotCbWrapper;

const CLOCK_DISPARITY_MS: isize = 100;

pub const Clock = struct {
    genesis_time_ms: isize,
    current_slot_time_ms: isize,
    current_slot: isize,
    events: utils.EventLoop,
    // track those who subscribed for on slot callbacks
    on_slot_cbs: std.ArrayList(*OnSlotCbWrapper),

    timer: xev.Timer,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        genesis_time: usize,
    ) !Self {
        const events = try utils.EventLoop.init();
        const timer = try xev.Timer.init();

        const genesis_time_ms: isize = @intCast(genesis_time * std.time.ms_per_s);
        const current_slot = @divFloor(@as(isize, @intCast(std.time.milliTimestamp())) + CLOCK_DISPARITY_MS - genesis_time_ms, SECONDS_PER_SLOT_MS);
        const current_slot_time_ms = genesis_time_ms + current_slot * SECONDS_PER_SLOT_MS;

        return Self{
            .genesis_time_ms = genesis_time_ms,
            .current_slot_time_ms = current_slot_time_ms,
            .current_slot = current_slot,
            .events = events,
            .timer = timer,
            .on_slot_cbs = std.ArrayList(*OnSlotCbWrapper).init(allocator),
        };
    }

    pub fn tickSlot(self: *Self) void {
        const time_now_ms: isize = @intCast(std.time.milliTimestamp());
        while (self.current_slot_time_ms + SECONDS_PER_SLOT_MS < time_now_ms + CLOCK_DISPARITY_MS) {
            self.current_slot_time_ms += SECONDS_PER_SLOT_MS;
            self.current_slot += 1;
        }

        const next_slot_time_ms: isize = self.current_slot_time_ms + SECONDS_PER_SLOT_MS;
        const time_to_next_slot_ms: usize = @intCast(next_slot_time_ms - time_now_ms);

        for (0..self.on_slot_cbs.items.len) |i| {
            const cbWrapper = self.on_slot_cbs.items[i];
            // const c = self.on_slot_cs.items[i];

            cbWrapper.slot = self.current_slot + 1;

            self.timer.run(
                &self.events.loop,
                &cbWrapper.c,
                time_to_next_slot_ms,
                OnSlotCbWrapper,
                cbWrapper,
                (struct {
                    fn callback(
                        ud: ?*OnSlotCbWrapper,
                        _: *xev.Loop,
                        _: *xev.Completion,
                        r: xev.Timer.RunError!void,
                    ) xev.CallbackAction {
                        _ = r catch unreachable;
                        if (ud) |cb_wrapper| {
                            _ = cb_wrapper.onSlot() catch void;
                        }
                        return .disarm;
                    }
                }).callback,
            );
        }
    }

    pub fn run(self: *Self) !void {
        while (true) {
            self.tickSlot();
            try self.events.run(.until_done);
        }
    }

    pub fn subscribeOnSlot(self: *Self, cb: *OnSlotCbWrapper) !void {
        try self.on_slot_cbs.append(cb);
    }
};
