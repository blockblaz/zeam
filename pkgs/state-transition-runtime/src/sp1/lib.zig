const std = @import("std");
pub const io = @import("./io.zig");
pub const syscalls = @import("./syscalls.zig");

extern fn main() noreturn;

export fn __start() noreturn {
    main();
}

pub fn halt(exit_code: u32) noreturn {
    asm volatile ("ecall"
        :
        : [syscall_num] "{t0}" (syscalls.HALT),
          [exit_code] "{a0}" (exit_code),
    );
    unreachable;
}

pub fn get_input(allocator: std.mem.Allocator) []const u8 {
    // HINT_LEN syscall: returns the input length in t0
    const len: usize = asm volatile ("ecall"
        : [ret] "={t0}" (-> usize),
        : [syscall_num] "{t0}" (syscalls.HINT_LEN),
    );

    const input = allocator.alloc(u8, len) catch @panic("could not allocate space for input");

    // HINT_READ syscall: reads len bytes into buffer
    asm volatile ("ecall"
        :
        : [syscall_num] "{t0}" (syscalls.HINT_READ),
          [dest_ptr] "{a0}" (input.ptr),
          [nbytes] "{a1}" (len),
        : "memory"
    );

    return input;
}

pub fn free_input(_: std.mem.Allocator) void {}

pub extern var _end: usize;
var fixed_allocator: std.heap.FixedBufferAllocator = undefined;
var fixed_allocator_initialized = false;

pub fn get_allocator() std.mem.Allocator {
    if (!fixed_allocator_initialized) {
        const mem_start: [*]u8 = @ptrCast(&_end);
        const mem_end: [*]u8 = @ptrFromInt(0x78000000);
        const mem_size: usize = @intFromPtr(mem_end) - @intFromPtr(mem_start);
        const mem_area: []u8 = mem_start[0..mem_size];
        asm volatile ("" ::: "memory");

        fixed_allocator = std.heap.FixedBufferAllocator.init(mem_area);
        fixed_allocator_initialized = true;
    }
    return fixed_allocator.allocator();
}
