const std = @import("std");

pub const Fork = struct {
    /// Human readable fork name used by Lean fixtures.
    name: []const u8,
    /// Directory segment under leanSpec fixtures.
    path: []const u8,
    /// Qualified symbol exposed by this module.
    symbol: []const u8,
};

pub const devnet = Fork{
    .name = "Devnet",
    .path = "devnet",
    .symbol = "forks.devnet",
};

pub const all = [_]Fork{devnet};

pub fn findByPath(path: []const u8) ?Fork {
    inline for (all) |fork| {
        if (std.mem.eql(u8, fork.path, path)) return fork;
    }
    return null;
}
