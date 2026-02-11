const std = @import("std");
const syscalls = @import("./syscalls.zig");
pub const io = @import("./io.zig");

pub fn halt(status: u32) noreturn {
    syscalls.syscall_noreturn(syscalls.HALT, status);
}

pub fn get_input(allocator: std.mem.Allocator) []const u8 {
    const input_len = io.hint_len();

    // Sanity check: limit to 10MB to prevent excessive allocation
    if (input_len > 10 * 1024 * 1024) {
        @panic("input size exceeds maximum allowed (10MB)");
    }

    var buffer: []u8 = allocator.alloc(u8, input_len) catch @panic("could not allocate space for the input slice");
    const bytes_read = io.hint_read(buffer);
    if (bytes_read != input_len) {
        @panic("input size mismatch");
    }

    return buffer[0..bytes_read];
}

pub fn free_input(_: std.mem.Allocator) void {}

pub extern var _end: usize;

var fixed_allocator: std.heap.FixedBufferAllocator = undefined;
var fixed_allocator_initialized = false;

pub fn get_allocator() std.mem.Allocator {
    if (!fixed_allocator_initialized) {
        const mem_start: [*]u8 = @ptrCast(&_end);
        const mem_end: [*]u8 = @ptrFromInt(0x7E000000); // _heap_end from linker script
        const mem_size: usize = @intFromPtr(mem_end) - @intFromPtr(mem_start);
        const mem_area: []u8 = mem_start[0..mem_size];
        asm volatile ("" ::: "memory");

        fixed_allocator = std.heap.FixedBufferAllocator.init(mem_area);
        fixed_allocator_initialized = true;
    }
    return fixed_allocator.allocator();
}
