const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;
const halt_reason = @import("./syscalls.zig").halt_reason;
pub const io = @import("./io.zig");

pub fn halt(status: u32) noreturn {
    sys_halt(&empty_digest, status);
}

const empty_digest = [_]u32{ 0x5c176f83, 0x53f3c062, 0x42651683, 0x340b8b7e, 0x19d2d1f6, 0xae4d7602, 0xb8c606b4, 0xb075b53d };

fn sys_halt(out_state: *const [8]u32, status: u32) noreturn {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.halt)),
          [code] "{a0}" (@intFromEnum(halt_reason.terminate) | (status << 8)),
          [digest] "{a1}" (out_state),
    );
    unreachable;
}

pub fn get_input(allocator: std.mem.Allocator) []const u8 {
    var input: []u8 = allocator.alloc(u8, 1024) catch @panic("could not allocate space for the input slice");
    const input_size = io.read_slice(0, input[0..]);
    return input[0..input_size];
}

pub fn free_input(allocator: std.mem.Allocator, input: []const u8) void {
    allocator.free(input);
}

var fixed_mem = [_]u8{0} ** (128 * 1024 * 1024);
var fixed_allocator = undefined;
var fixed_allocator_initialized = false;

pub fn get_allocator() std.mem.Allocator {
    fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_mem[0..]);
    return fixed_allocator.allocator();
}
