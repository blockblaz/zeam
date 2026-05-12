const std = @import("std");

pub const Fork = struct {
    /// Human readable fork name used by Lean fixtures.
    name: []const u8,
    /// Directory segment under leanSpec fixtures.
    path: []const u8,
    /// Qualified symbol exposed by this module.
    symbol: []const u8,
};

pub const lstar = Fork{
    .name = "Lstar",
    .path = "lstar",
    .symbol = "forks.lstar",
};

pub const all = [_]Fork{lstar};

pub fn findByPath(path: []const u8) ?Fork {
    inline for (all) |fork| {
        if (std.mem.eql(u8, fork.path, path)) return fork;
    }
    return null;
}
