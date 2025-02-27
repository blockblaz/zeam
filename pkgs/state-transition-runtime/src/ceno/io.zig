const std = @import("std");

var info_out: [*]volatile u32 = @ptrFromInt(0x8010_0000);

var cursor: usize = 0;

fn alloc(msg_len: usize) []volatile u32 {
    // This isn't thread-safe, but it doesn't matter right now
    // as there are no threads in this environment.
    const old_cursor = cursor;
    cursor += (msg_len + 3) & 0xFFFFFFFC; // word-align
    return info_out[old_cursor..cursor];
}

pub fn print_str(str: []const u8) void {
    var buf = alloc(str.len);
    // @memcpy seems to greatly increase the heap size, which takes
    // the prover down. Do it manyally for now.
    // @memcpy(buf[0..], std.mem.bytesAsSlice(u32, buf));
    const as_u32 = std.mem.bytesAsSlice(u32, buf);
    for (as_u32, 0..) |word, i| {
        if (i < str.len / 4) {
            buf[i] = word;
        } else {
            const mask: u32 = @as(u32, 0xFFFFFFFF) >> @truncate(8 * (4 * i - str.len));
            buf[i] = word & mask;
        }
    }
}
