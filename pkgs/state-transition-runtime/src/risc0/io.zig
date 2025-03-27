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
        : "memory"
    );
}

fn sys_read(fd: u32, comptime nrequested: usize, buffer: []u8) void {
    const main_words = nrequested / 4;

    const syscall_name: [:0]const u8 = "risc0_zkvm_platform::syscall::nr::SYS_READ";
    asm volatile (
        \\ ecall
        :
        : [syscallNumber] "{t0}" (syscalls.software),
          [from_host] "{a0}" (buffer),
          [from_host_words] "{a1}" (main_words),
          [syscall_name] "{a2}" (syscall_name.ptr),
          [file_descriptor] "{a3}" (fd),
          [main_requested] "{a4}" (nrequested),
        : "memory"
    );
}

pub fn read_slice(_: u32, data: []u32) void {
    var as_u8: []u8 = @ptrCast(data);
    read_slice(.stdin, as_u8[0..]);
}

pub fn write_slice(fd: u32, data: []const u8) void {
    sys_write(fd, data);
}

pub fn print_str(str: []const u8) void {
    write_slice(@intFromEnum(fileno.stdout), str);
}
