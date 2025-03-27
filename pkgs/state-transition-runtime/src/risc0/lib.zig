const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;
pub const io = @import("./io.zig");

pub fn halt(status: u32) noreturn {
    sys_halt(null, status);
}

fn sys_halt(out_state: *[8]u32, status: u32) noreturn {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.halt)),
          [code] "{a0}" (status),
          [outstate] "{a1}" (out_state),
    );
    unreachable;
}
