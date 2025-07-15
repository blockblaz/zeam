const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;
const halt_reason = @import("./syscalls.zig").halt_reason;
pub const io = @import("./io.zig");

pub fn halt(status: u32) noreturn {
    const journal_digest = global_hasher.finalize();
    sys_halt(&journal_digest, status);
}

// TODO save this as a context instead of a global variable
var global_hasher = sha256_state{ .state = [_]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 } };

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

pub const sha256_state = struct {
    const Self = @This();

    state: [8]u32,

    pub fn init() Self {}

    pub fn update(self: *Self, data: []const u8) void {
        sys_sha_buffer(&self.state, &self.state, data);
    }

    pub fn finalize(self: *Self) [8]u32 {
        return self.state;
    }
};

const MAX_SHA_COMPRESS_BLOCKS: usize = 1000;
pub const DIGEST_WORDS: usize = 8;
pub const DIGEST_BYTES: usize = @sizeOf(u32) * DIGEST_WORDS;

pub fn commit(bytes: []const u8) void {
    global_hasher.update(bytes);
    io.sys_write(3, bytes.ptr, bytes.len);
}

fn sys_sha_buffer(out_state: *[8]u32, in_state: *[8]u32, buf: []const u8) void {
    std.debug.assert(@intFromPtr(out_state) % @sizeOf(usize) == 0);
    std.debug.assert(@intFromPtr(in_state) % @sizeOf(usize) == 0);
    std.debug.assert(@intFromPtr(buf.ptr) % @sizeOf(usize) == 0);

    var ptr = buf.ptr;
    var in = in_state;
    var count = buf.len;
    while (count > 0) {
        const n = @min(count, MAX_SHA_COMPRESS_BLOCKS);
        asm volatile ("ecall"
            :
            : [scallnum] "{t0}" (@intFromEnum(syscalls.sha)),
              [outstate] "{a0}" (out_state),
              [instate] "{a1}" (in),
              [buf] "{a2}" (buf),
              [bufend] "{a3}" (ptr + DIGEST_BYTES),
              [n] "{a4}" (n),
        );
        count -= n;
        ptr += (2 * DIGEST_BYTES * count);
        in = out_state;
    }
}

fn sys_bigint(result: *[8]u32, op: u32, x: *[8]u32, y: *[8]u32, modulus: *[8]u32) void {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.bigint)),
          [result] "{a0}" (result),
          [op] "{a1}" (op),
          [x] "{a2}" (x),
          [y] "{a3}" (y),
          [modulus] "{a4}" (modulus),
    );
}

fn sys_rand(buf: []u8) void {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.random)),
          [result] "{a0}" (buf.ptr),
          [op] "{a1}" (buf.len),
    );
}

// TODO connect this to the panic handler, this is not used at the moment.
fn sys_panic(msg: []const u8) void {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.panic)),
          [result] "{a0}" (msg.ptr),
          [op] "{a1}" (msg.len),
    );
}

fn sys_poseidon2(state_addr: *[8]u32, in_buf_addr: *const u8, out_buf_addr: *[8]u32, bits_count: u32) void {
    _ = state_addr;
    _ = in_buf_addr;
    _ = out_buf_addr;
    _ = bits_count;
    // std.debug.assert(@intFromPtr(state_addr) % WORD_SIZE == 0);
    // std.debug.assert!(@intFromPtr(in_buf_addr) % WORD_SIZE == 0);
    // std.debug.assert!(@intFromPtr(out_buf_addr) % WORD_SIZE == 0);

    // asm volatile ("ecall"
    //     :
    //     : [scallnum] "{t0}" (@intFromEnum(syscalls.poseidon2)),
    //       [outstate] "{a0}" (out_state),
    //       [instate] "{a1}" (in),
    //       [buf] "{a2}" (buf),
    //       [bufend] "{a3}" (ptr + DIGEST_BYTES),
    //       [n] "{a4}" (n),
    // );
    // ecall_3(
    //     ecall::POSEIDON2,
    //     state_addr as u32 / WORD_SIZE as u32,
    //     in_buf_addr as u32 / WORD_SIZE as u32,
    //     out_buf_addr as u32 / WORD_SIZE as u32,
    //     bits_count,
    // );
}
