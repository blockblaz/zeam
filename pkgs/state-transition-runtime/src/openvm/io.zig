const std = @import("std");

pub fn print_str(str: []const u8) void {
    // OpenVM debug print instruction
    // Uses custom RISC-V instruction encoding for debug output
    for (str) |byte| {
        print_char(byte);
    }
}

pub fn print_char(c: u8) void {
    asm volatile (".insn r 0x0b, 1, 0, x0, %[char], x0"
        :
        : [char] "r" (@as(usize, c)),
    );
}

pub fn read_input(buffer: []u8) usize {
    var bytes_read: usize = 0;
    const buffer_ptr = @intFromPtr(buffer.ptr);
    const buffer_end = buffer_ptr + buffer.len;

    asm volatile (".insn r 0x0b, 2, 0, %[bytes_read], %[buffer_start], %[buffer_end]"
        : [bytes_read] "=r" (bytes_read),
        : [buffer_start] "r" (buffer_ptr),
          [buffer_end] "r" (buffer_end),
    );

    return bytes_read;
}
