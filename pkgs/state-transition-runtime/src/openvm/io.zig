const std = @import("std");

pub fn print_str(str: []const u8) void {
    asm volatile (".insn i 0x0b, 3, x0, %[ptr], 1"
        :
        : [ptr] "r" (str.ptr),
          [len] "{x11}" (str.len),
    );
}

pub fn hint_input() void {
    asm volatile (".insn i 0x0b, 3, x0, x0, 0");
}

pub fn hint_store_u32(ptr: *u32) void {
    asm volatile (".insn i 0x0b, 1, %[ptr], x0, 0"
        :
        : [ptr] "r" (ptr),
        : "memory"
    );
}

pub fn hint_buffer_u32(ptr: [*]u8, word_count: u32) void {
    asm volatile (".insn i 0x0b, 1, %[ptr], %[wc], 1"
        :
        : [ptr] "r" (ptr),
          [wc] "r" (word_count),
        : "memory"
    );
}
