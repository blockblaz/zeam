const std = @import("std");

fn observeNoop(ctx: *anyopaque, value: f32) void {
    _ = ctx;
    _ = value;
}

pub const Timer = struct {
    start_time: i128 = 0,
    context: *anyopaque = undefined,
    observeFn: *const fn (*anyopaque, f32) void = &observeNoop,

    pub fn observe(self: Timer) f32 {
        _ = self;
        return 0;
    }
};

pub const Histogram = struct {
    context: *anyopaque = undefined,
    observeFn: *const fn (*anyopaque, f32) void = &observeNoop,

    pub fn start(self: *const Histogram) Timer {
        _ = self;
        return Timer{};
    }

    pub fn observe(self: *Histogram, value: f32) void {
        _ = self;
        _ = value;
    }
};

pub const Gauge = struct {
    pub fn set(self: *Gauge, value: u64) void {
        _ = self;
        _ = value;
    }
};

pub const Counter = struct {
    pub fn incrBy(self: *Counter, value: u64) void {
        _ = self;
        _ = value;
    }
};

const Metrics = struct {
    chain_onblock_duration_seconds: Histogram = .{},
    block_processing_duration_seconds: Histogram = .{},
    lean_head_slot: Gauge = .{},
    lean_latest_justified_slot: Gauge = .{},
    lean_latest_finalized_slot: Gauge = .{},
    lean_state_transition_time_seconds: Histogram = .{},
    lean_state_transition_slots_processed_total: Counter = .{},
    lean_state_transition_slots_processing_time_seconds: Histogram = .{},
    lean_state_transition_block_processing_time_seconds: Histogram = .{},
    lean_state_transition_attestations_processed_total: Counter = .{},
    lean_state_transition_attestations_processing_time_seconds: Histogram = .{},
};

pub var metrics: Metrics = .{};
pub var chain_onblock_duration_seconds: Histogram = .{};
pub var block_processing_duration_seconds: Histogram = .{};

pub fn init(allocator: std.mem.Allocator) !void {
    _ = allocator;
}

pub fn writeMetrics(writer: anytype) !void {
    _ = writer;
}

pub fn startListener(allocator: std.mem.Allocator, port: u16) !void {
    _ = allocator;
    _ = port;
}
