const std = @import("std");
const syscalls = @import("./syscalls.zig").syscalls;
const halt_reason = @import("./syscalls.zig").halt_reason;
pub const io = @import("./io.zig");

pub fn halt(status: u32) noreturn {
    sys_halt(&empty_digest, status);
}

const empty_digest_bytes = blk: {
    @setEvalBranchQuota(100000000);
    break :blk tagged_struct(
        "risc0.Output",
        &[2][32]u8{
            hash_bytes(&[0]u8{}), // sha256([])
            [_]u8{0} ** 32, // emtpy assumption
        },
        &[0]u32{}, // no extra data
    );
};

const empty_digest: [8]u32 = blk: {
    @setEvalBranchQuota(100000000);
    var result: [8]u32 = undefined;
    const bytes = std.mem.asBytes(&result);
    // @compileLog("Empty digest:", empty_digest_bytes);
    @memcpy(bytes, &empty_digest_bytes);
    break :blk result;
};

// SHA256 state structure - matches the internal state of SHA256
const Sha256State = struct {
    h: [8]u32,
    length: u64,
    buffer: [64]u8,
    buffer_len: u8,

    const initial_h = [8]u32{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    fn init() Sha256State {
        return Sha256State{
            .h = initial_h,
            .length = 0,
            .buffer = std.mem.zeroes([64]u8),
            .buffer_len = 0,
        };
    }
};

fn sys_sha_buf(state: *Sha256State, buffer: []const u8) void {
    asm volatile ("ecall"
        :
        : [scallnum] "{t0}" (@intFromEnum(syscalls.sha)),
    );
}

// SHA256 implementation using sys_sha_buf
const Sha256Syscall = struct {
    state: Sha256State,

    fn init() Sha256Syscall {
        return Sha256Syscall{
            .state = Sha256State.init(),
        };
    }

    fn update(self: *Sha256Syscall, input: []const u8) void {
        var remaining = input;

        while (remaining.len > 0) {
            // Calculate how much we can buffer
            const space_in_buffer = 64 - self.state.buffer_len;
            const to_buffer = @min(remaining.len, space_in_buffer);

            // Copy to internal buffer
            @memcpy(self.state.buffer[self.state.buffer_len .. self.state.buffer_len + to_buffer], remaining[0..to_buffer]);
            self.state.buffer_len += @intCast(to_buffer);
            self.state.length += to_buffer;
            remaining = remaining[to_buffer..];

            // If buffer is full, process it
            if (self.state.buffer_len == 64) {
                sys_sha_buf(&self.state, self.state.buffer[0..64]);
                self.state.buffer_len = 0;
            }
        }
    }

    fn final(self: *Sha256Syscall, out: []u8) void {
        // Pad the final block
        const bit_length = self.state.length * 8;

        // Add the '1' bit (0x80)
        self.state.buffer[self.state.buffer_len] = 0x80;
        self.state.buffer_len += 1;

        // If we don't have enough space for the length (8 bytes), process current block
        if (self.state.buffer_len > 56) {
            // Fill rest with zeros and process
            std.mem.set(u8, self.state.buffer[self.state.buffer_len..64], 0);
            sys_sha_buf(&self.state, self.state.buffer[0..64]);

            // Start new block
            std.mem.set(u8, self.state.buffer[0..56], 0);
        } else {
            // Fill with zeros up to position 56
            std.mem.set(u8, self.state.buffer[self.state.buffer_len..56], 0);
        }

        // Write length as big-endian u64 at the end
        std.mem.writeInt(u64, self.state.buffer[56..64], bit_length, .big);

        // Process final block
        sys_sha_buf(&self.state, self.state.buffer[0..64]);

        // Convert state to output (big-endian)
        for (self.state.h, 0..) |word, i| {
            std.mem.writeInt(u32, out[i * 4 .. (i + 1) * 4], word, .big);
        }
    }
};

fn hash_bytes_syscall(input: []const u8) [32]u8 {
    var hasher = Sha256Syscall.init();
    hasher.update(input);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}
fn hash_bytes(input: []const u8) [32]u8 {
    // Detect if we're in the zkvm context vs compile-time/client context
    // For compile-time (when computing constants), use std implementation
    // For runtime in zkvm, use custom implementation with sys_sha_buf

    // This is a simple heuristic - you might want a more sophisticated check
    if (@inComptime()) {
        // Compile-time: use standard library
        var result: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(input, &result, .{});
        return result;
    } else {
        // Runtime in zkvm: use custom implementation
        return hash_bytes_syscall(input);
    }
}

fn tagged_struct(tag: []const u8, down: []const [32]u8, data: []const u32) [32]u8 {
    // Calculate the total size needed
    const tag_digest = hash_bytes(tag);
    const total_size = 32 + (down.len * 32) + (data.len * 4) + 2;

    var buffer: [4096]u8 = undefined;
    if (total_size > buffer.len) {
        @panic("tagged_struct: input too large");
    }

    var offset: usize = 0;

    // Copy tag digest
    @memcpy(buffer[offset .. offset + 32], &tag_digest);
    offset += 32;

    // Copy down hashes
    for (down) |d| {
        @memcpy(buffer[offset .. offset + 32], &d);
        offset += 32;
    }

    // Copy data as little-endian u32s
    for (data) |d| {
        const bytes = std.mem.asBytes(&d);
        @memcpy(buffer[offset .. offset + 4], bytes);
        offset += 4;
    }

    // Add length field
    std.mem.writeInt(u16, buffer[offset .. offset + 2], @as(u16, @intCast(down.len)), .little);
    // @compileLog("hashed payload", buffer[0..total_size]);

    return hash_bytes(buffer[0..total_size]);
}


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

pub extern var _end: usize;
var fixed_allocator: std.heap.FixedBufferAllocator = undefined;
var fixed_allocator_initialized = false;

pub fn get_allocator() std.mem.Allocator {
    if (!fixed_allocator_initialized) {
        const mem_start: [*]u8 = @ptrCast(&_end);
        const mem_end: [*]u8 = @ptrFromInt(0xC000000);
        const mem_size: usize = @intFromPtr(mem_end) - @intFromPtr(mem_start);
        const mem_area: []u8 = mem_start[0..mem_size];
        asm volatile ("" ::: "memory");

        fixed_allocator = std.heap.FixedBufferAllocator.init(mem_area);
        fixed_allocator_initialized = true;
    }
    return fixed_allocator.allocator();
}
