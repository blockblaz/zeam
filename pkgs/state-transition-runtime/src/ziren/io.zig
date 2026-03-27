const syscalls = @import("./syscalls.zig");

pub fn print_str(str: []const u8) void {
    write_slice(syscalls.FD_STDOUT, str);
}

pub fn write_slice(fd: u32, data: []const u8) void {
    _ = syscalls.syscall_3(
        syscalls.WRITE,
        fd,
        @intFromPtr(data.ptr),
        @intCast(data.len),
    );
}

pub fn hint_len() u32 {
    return syscalls.syscall_0(syscalls.SYSHINTLEN);
}

pub fn hint_read(buf: []u8) u32 {
    return syscalls.syscall_2(
        syscalls.SYSHINTREAD,
        @intFromPtr(buf.ptr),
        @intCast(buf.len),
    );
}
