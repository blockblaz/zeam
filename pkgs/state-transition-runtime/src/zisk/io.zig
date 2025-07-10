const std = @import("std");
const mem_layout = @import("./layout.zig");

var input_ptr: [*]const u8 = @ptrFromInt(mem_layout.INPUT_ADDR);

pub fn get_input(_: std.mem.Allocator) []const u8 {
    const input_size = std.mem.readInt(u64, input_ptr[8..16], .little);
    if (input_size > mem_layout.INPUT_SIZE) @panic("invalid input size");
    return input_ptr[8 .. 8 + input_size];
}

pub fn print_str(str: []const u8) void {
    const arch_id_zisk = asm volatile ("csrr %[ret], marchid"
        : [ret] "=r" (-> usize),
    );
    var addr: [*]volatile u8 = if (arch_id_zisk == 0xFFFEEE) @ptrFromInt(0x1000_0000) else @ptrFromInt(mem_layout.UART_ADDR);
    for (str) |c| {
        addr[0] = c;
    }
}
