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

pub const DbDefaultNamespace = DbColumnNamespaces[0];
pub const DbBlocksNamespace = DbColumnNamespaces[1];
pub const DbStatesNamespace = DbColumnNamespaces[2];
pub const DbVotesNamespace = DbColumnNamespaces[3];
pub const DbCheckpointsNamespace = DbColumnNamespaces[4];
