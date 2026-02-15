const syscalls = @import("./syscalls.zig");

pub fn print_str(str: []const u8) void {
    asm volatile ("ecall"
        :
        : [syscall_num] "{t0}" (syscalls.WRITE),
          [fd] "{a0}" (@as(u32, 1)), // stdout
          [buf_ptr] "{a1}" (str.ptr),
          [nbytes] "{a2}" (str.len),
        : "memory"
    );
}
