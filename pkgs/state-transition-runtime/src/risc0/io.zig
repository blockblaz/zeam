const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;

const fileno = enum {
    stdin,
    stdout,
    stderr,
    journal,
};

fn sys_write(fd: u32, data: []const u8) void {
    const syscall_name: [:0]const u8 = "risc0_zkvm_platform::syscall::nr::SYS_WRITE";
    asm volatile (
        \\ ecall
        :
        : [syscallNumber] "{t0}" (syscalls.software),
          [from_host] "{a0}" (data.ptr),
          [from_host_words] "{a1}" (0),
          [syscall_name] "{a2}" (syscall_name.ptr),
          [file_descriptor] "{a3}" (fd),
          [write_buf] "{a4}" (data.ptr),
          [write_buf_len] "{a5}" (data.len),
        : .{ .memory = true });
}

fn sys_read(fd: u32, nrequested: usize, buffer: []u8, nread: *u32, last: *u32) void {
    const main_words = nrequested / 4;

    const syscall_name: [:0]const u8 = "risc0_zkvm_platform::syscall::nr::SYS_READ";
    var a0: u32 = undefined;
    var a1: u32 = undefined;
    asm volatile (
        \\ ecall
        : [a0] "={a0}" (a0),
          [a1] "={a1}" (a1),
        : [syscallNumber] "{t0}" (syscalls.software),
          [from_host] "{a0}" (buffer.ptr),
          [from_host_words] "{a1}" (main_words),
          [syscall_name] "{a2}" (syscall_name.ptr),
          [file_descriptor] "{a3}" (fd),
          [main_requested] "{a4}" (nrequested),
        : .{ .memory = true });

    nread.* = a0;
    last.* = a1;
}

pub fn read_slice(fd: u32, data: []u8) usize {
    var count: u32 = 0;
    // TODO unaligned read if needed for starting point
    while (count < data.len) {
        const chunk_len = @min(data.len, 1024 * 4);
        var nread: u32 = undefined;
        var last: u32 = 0;
        sys_read(fd, chunk_len, data[count..], &nread, &last);
        count += nread;
        if (nread == 0) print_str("read 0\n");
        if (last == 0) print_str("last 0\n");
        if (nread < chunk_len) break;
    }
    // TODO unaligned read at the end if need be
    return @as(usize, count);
}

pub fn write_slice(fd: u32, data: []const u8) void {
    sys_write(fd, data);
}

pub fn print_str(str: []const u8) void {
    write_slice(@intFromEnum(fileno.stdout), str);
}
