const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;
pub const io = @import("./io.zig");

fn native_hash(data: *[12]u64) [4]u64 {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.native_hash)),
          [subcommand] "{a0}" (data),
        : "memory"
    );
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
            : "memory"
        );
        asm volatile ("ecall"
            :
            : [scallnum] "{t0}" (@intFromEnum(syscalls.commit_public)),
              [fd] "{a0}" (i * 2 + 1),
              [idx] "{a1}" (high),
            : "memory"
        );
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
