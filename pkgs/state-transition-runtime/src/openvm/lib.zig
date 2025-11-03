pub const io = @import("./io.zig");
const std = @import("std");

pub extern var _heap_start: usize;
var fixed_allocator: std.heap.FixedBufferAllocator = undefined;
var fixed_allocator_initialized = false;

pub fn get_allocator() std.mem.Allocator {
    if (!fixed_allocator_initialized) {
        const heap_start: [*]u8 = @ptrCast(&_heap_start);
        const heap_end: [*]u8 = @ptrFromInt(0x10000000);
        const heap_size: usize = @intFromPtr(heap_end) - @intFromPtr(heap_start);
        const heap_area: []u8 = heap_start[0..heap_size];
        asm volatile ("" ::: "memory");

        fixed_allocator = std.heap.FixedBufferAllocator.init(heap_area);
        fixed_allocator_initialized = true;
    }
    return fixed_allocator.allocator();
}

pub fn get_input(allocator: std.mem.Allocator) []const u8 {
    // First read the 4-byte length prefix
    var len_bytes: [4]u8 = undefined;
    const len_bytes_read = io.read_input(&len_bytes);
    if (len_bytes_read != 4) {
        @panic("failed to read length prefix");
    }

    // Parse the length as little-endian u32
    const input_len = std.mem.readInt(u32, &len_bytes, .little);

    // Sanity check: limit to 1MB to prevent excessive allocation
    if (input_len > 1024 * 1024) {
        @panic("input size exceeds maximum allowed (1MB)");
    }

    // Allocate exact size needed
    var input: []u8 = allocator.alloc(u8, input_len) catch @panic("could not allocate space for the input slice");

    // Read the actual data
    const bytes_read = io.read_input(input[0..]);
    if (bytes_read != input_len) {
        @panic("input size mismatch");
    }

    return input[0..bytes_read];
}

pub fn free_input(allocator: std.mem.Allocator, input: []const u8) void {
    allocator.free(input);
}

pub fn halt(exit_code: u32) noreturn {
    asm volatile (".insn i 0x0b, 0, x0, x0, %[exit_code]"
        :
        : [exit_code] "i" (@as(u8, @truncate(exit_code))),
    );
    unreachable;
}

pub fn keccak(data: []const u8) []const u8 {
    var ret: usize = undefined;
    asm volatile (".insn r 0x0b, 100, 0, %[rd], %[rs1], %[rs2]"
        : [rd] "=r" (ret),
        : [rs1] "r" (data.ptr),
          [rs2] "r" (data.ptr + data.len),
    );
    const sliceptr: [*]const u8 = @ptrFromInt(ret);
    return sliceptr[0..32];
}

pub fn sha256(data: []const u8) []const u8 {
    var ret: usize = undefined;
    asm volatile (".insn r 0x0b, 100, 1, %[rd], %[rs1], %[rs2]"
        : [rd] "=r" (ret),
        : [rs1] "r" (data.ptr),
          [rs2] "r" (data.ptr + data.len),
    );
    const sliceptr: [*]const u8 = @ptrFromInt(ret);
    return sliceptr[0..32];
}
