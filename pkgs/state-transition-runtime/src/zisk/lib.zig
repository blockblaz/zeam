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

pub extern var _init_stack_top: usize;
pub extern var _kernel_heap_top: usize;

pub fn get_allocator() std.mem.Allocator {
    const mem_start: [*]u8 = @ptrCast(&_init_stack_top);
    const mem_end: [*]u8 = @ptrCast(&_kernel_heap_top);
    // recompute the size here, because in pie mode the _kernel_heap_size symbol
    // will need to be relocated and that means more work than just subtracting
    // two pointers.
    const mem_size: usize = @intFromPtr(mem_end) - @intFromPtr(mem_start);
    const mem_area: []u8 = mem_start[0..mem_size];
    asm volatile ("" ::: .{ .memory = true });
    var fixed_allocator = std.heap.FixedBufferAllocator.init(mem_area);
    return fixed_allocator.allocator();
}
