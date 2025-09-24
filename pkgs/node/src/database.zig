const database = @import("@zeam/database");

pub const ColumnNamespace = database.ColumnNamespace;

pub const DbColumnNamespaces = [_]database.ColumnNamespace{
    .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "blocks", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "states", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "votes", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "checkpoints", .Key = []const u8, .Value = []const u8 },
};

pub const RocksDB = database.RocksDB(&DbColumnNamespaces);
