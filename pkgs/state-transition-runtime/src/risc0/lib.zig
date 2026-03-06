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

fn hash_bytes(input: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    // Note that this is not using sys_hash, but it's fine for now.
    // TODO: differentiate between the zkvm and compile-time/client
    // runtime contexts and use sys_sha_buf in the zkvm context.
    std.crypto.hash.sha2.Sha256.hash(input, &result, .{});
    return result;
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
    var len_bytes: [4]u8 = undefined;
    const len_bytes_read = io.read_slice(0, &len_bytes);
    if (len_bytes_read != 4) {
        @panic("failed to read length prefix");
    }
    const input_len = std.mem.readInt(u32, &len_bytes, .little);

    // Sanity check: limit to 10MB to prevent excessive allocation
    if (input_len > 10 * 1024 * 1024) {
        @panic("input size exceeds maximum allowed (10MB)");
    }

    // The +4 here is because of a putative bug in risc0, which will return the total
    // amount of bytes read, and not just the bytes read in one instance.
    var input: []u8 = allocator.alloc(u8, input_len + 4) catch @panic("could not allocate space for the input slice");

    const bytes_read = io.read_slice(0, input[0..]);
    if (bytes_read != input_len) {
        @panic("input size mismatch");
    }

    // last 4 bytes, which are over-allocated as a workaround,
    // will be trailing the input slice but are still allocated.
    return input[0..bytes_read];
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
        asm volatile ("" ::: .{ .memory = true });

        fixed_allocator = std.heap.FixedBufferAllocator.init(mem_area);
        fixed_allocator_initialized = true;
    }
    return fixed_allocator.allocator();
}
