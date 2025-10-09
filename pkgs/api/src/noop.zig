const std = @import("std");

/// Reason for an attestation being invalid (no-op version)
pub const AttestationInvalidReason = enum {
    from_future_gossip,
    unknown_head_gossip,
    unknown_head_block,
};

pub const Timer = struct {
    pub fn observe(self: Timer) f32 {
        _ = self;
        return 0;
    }
};

pub const Histogram = struct {
    pub fn start(self: *const Histogram) Timer {
        _ = self;
        return Timer{};
    }
};

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

pub fn setLeanHeadSlot(slot: u64) void {
    _ = slot;
}

pub fn incrementLeanAttestationsInvalid(reason: AttestationInvalidReason) void {
    _ = reason;
}

pub fn chain_onblock_duration_seconds_start() Timer {
    return chain_onblock_duration_seconds.start();
}
