const std = @import("std");
const ssz = @import("ssz");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn hashTreeRoot(
    comptime T: type,
    value: T,
    out: *[Sha256.digest_length]u8,
    allocator: Allocator,
) !void {
    try ssz.hashTreeRoot(Sha256, T, value, out, allocator);
}
