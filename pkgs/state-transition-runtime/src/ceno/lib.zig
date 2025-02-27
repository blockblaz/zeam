const std = @import("std");
const syscalls = @import("./syscalls.zig");
pub const io = @import("./io.zig");

pub fn halt(exit_code: u32) noreturn {
    asm volatile ("ecall"
        :
        : [exit_code] "{a0}" (exit_code),
          [arg] "{t0}" (syscalls.halt_call),
    );
    unreachable;
}

pub fn keccack_permute(state: []u64) !void {
    if (state.length != 25) {
        return error.InvalidKeccakInputSize;
    }

    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (syscalls.keccack_permute),
          [buf] "{a0}" (&state),
          [arg1] "{a1}" (0),
    );
}
