const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;
pub const io = @import("./io.zig");

fn native_hash(data: *[12]u64) [4]u64 {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.native_hash)),
          [subcommand] "{a0}" (data),
        : .{ .memory = true });
    var ret: [4]u64 = undefined;
    std.mem.copyForwards(u64, ret[0..], data.*[0..4]);
    return ret;
}

var publics: committed_publics = committed_publics.new();

const committed_publics = struct {
    state: [12]u64,
    buffer_size: u8,

    const Self = @This();

    pub fn new() Self {
        return .{
            .state = [_]u64{0} ** 12,
            .buffer_size = 0,
        };
    }

    pub fn commit(self: *Self, n: u32) void {
        self.state[self.buffer_size + 4] = @intCast(n);
        self.buffer_size += 1;
        if (self.buffer_size == 4) {
            self.buffer_size = 0;
            self.update_state();
        }
    }

    pub fn update_state(self: *Self) void {
        _ = native_hash(&self.state);
    }

    pub fn finalize(self: *Self) [4]u64 {
        // prevent hash of empty
        self.commit(1);

        if (self.buffer_size != 0) {
            for (self.state[self.buffer_size + 4 .. 8]) |*n| {
                n.* = 0;
            }
            self.update_state();
        }

        var h: [4]u64 = undefined;
        std.mem.copyForwards(u64, h[0..], self.state[0..4]);
        self.* = Self.new();

        return h;
    }
};

fn finalize() void {
    const commits = publics.finalize();
    for (commits, 0..) |limb, i| {
        const low: u32 = @truncate(limb);
        const high: u32 = @truncate(limb >> 32);

        asm volatile ("ecall"
            :
            : [scallnum] "{t0}" (@intFromEnum(syscalls.commit_public)),
              [fd] "{a0}" (i * 2),
              [idx] "{a1}" (low),
            : .{ .memory = true });
        asm volatile ("ecall"
            :
            : [scallnum] "{t0}" (@intFromEnum(syscalls.commit_public)),
              [fd] "{a0}" (i * 2 + 1),
              [idx] "{a1}" (high),
            : .{ .memory = true });
    }
}

pub fn halt(_: u32) noreturn {
    finalize();
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.halt)),
    );
    while (true) {}
}

const __powdr_prover_data_start: [*]const u8 = @ptrFromInt(0x10000000);
// this is hardcoded for now, because the compiler seems unable to see
// linker script symbols.
// extern const _powdr_prover_data_start: [*]const u8;
// extern const __powdr_prover_data_end: [*]const u8;

pub fn get_input(_: std.mem.Allocator) []const u8 {
    const total_input_len = std.mem.bytesToValue(u32, __powdr_prover_data_start[2048..2052]);
    const total_input: []const u8 = __powdr_prover_data_start[2052 .. 2052 + total_input_len];
    const input_len = std.mem.bytesAsValue(u32, total_input[0..4]);
    return total_input[4 .. 4 + input_len.*];
}

pub fn free_input(_: std.mem.Allocator, _: []const u8) void {}
