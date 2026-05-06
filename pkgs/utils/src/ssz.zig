const std = @import("std");
const ssz = @import("ssz");

const Allocator = std.mem.Allocator;
const Hasher = std.crypto.hash.sha2.Sha256;

comptime {
    if (Hasher.digest_length != 32) {
        @compileError("SSZ hasher must have 32-byte digest length");
    }
}

pub fn hashTreeRoot(
    comptime T: type,
    value: T,
    out: *[Hasher.digest_length]u8,
    allocator: Allocator,
) !void {
    try ssz.hashTreeRoot(Hasher, T, value, out, allocator);
}
