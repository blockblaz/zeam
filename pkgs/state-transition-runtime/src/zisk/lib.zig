const std = @import("std");
pub const io = @import("./io.zig");
pub const get_input = io.get_input;
pub const MARCHID_ZISK = 0xFFFEEE;

pub fn halt(_: u32) noreturn {
    const arch_id_zisk = asm volatile ("csrr %[ret], marchid"
        : [ret] "=r" (-> usize),
    );
    if (arch_id_zisk == MARCHID_ZISK) {
        // Zisk exit
        asm volatile (
            \\ li a7, 93
            \\ ecall
        );
    } else {
        // QEMU exit
        //"li t0, {_QEMU_EXIT_ADDR}",
        //"li t1, {_QEMU_EXIT_CODE}",
        asm volatile (
            \\ li t0, 0x100000
            \\ li t1, 0x5555
            \\ sw t1, 0(t0)
        );
    }
    unreachable;
}

pub fn free_input(_: std.mem.Allocator) void {}
