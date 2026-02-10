pub const io = @import("./io.zig");
const std = @import("std");

pub extern var _heap_start: usize;
var fixed_allocator: std.heap.FixedBufferAllocator = undefined;
var fixed_allocator_initialized = false;

pub fn get_allocator() std.mem.Allocator {
    if (!fixed_allocator_initialized) {
        const heap_start: [*]u8 = @ptrCast(&_heap_start);
        const heap_end: [*]u8 = @ptrFromInt(0x20000000);
        const heap_size: usize = @intFromPtr(heap_end) - @intFromPtr(heap_start);
        const heap_area: []u8 = heap_start[0..heap_size];
        asm volatile ("" ::: "memory");

        fixed_allocator = std.heap.FixedBufferAllocator.init(heap_area);
        fixed_allocator_initialized = true;
    }
    return fixed_allocator.allocator();
}

pub fn get_input(allocator: std.mem.Allocator) []const u8 {
    io.hint_input();

    var len_buf: u32 = 0;
    io.hint_store_u32(&len_buf);
    const input_len: usize = @intCast(len_buf);

    const word_count: u32 = @intCast((input_len + 3) / 4);
    const buf = allocator.alignedAlloc(u8, 4, word_count * 4) catch @panic("could not allocate space for input");

    io.hint_buffer_u32(buf.ptr, word_count);

    return buf[0..input_len];
}

pub fn free_input(_: std.mem.Allocator) void {}

pub fn halt(exit_code: u32) noreturn {
    asm volatile (".insn i 0x0b, 0, x0, x0, %[exit_code]"
        :
        : [exit_code] "i" (@as(u8, @truncate(exit_code))),
    );
    unreachable;
}
