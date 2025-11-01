const interface = @import("./interface.zig");
const rocksdb = @import("./rocksdb.zig");

pub const ColumnNamespace = interface.ColumnNamespace;

pub const DbColumnNamespaces = [_]interface.ColumnNamespace{
    .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "blocks", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "states", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "attestations", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "checkpoints", .Key = []const u8, .Value = []const u8 },
};

pub const DbDefaultNamespace = DbColumnNamespaces[0];
pub const DbBlocksNamespace = DbColumnNamespaces[1];
pub const DbStatesNamespace = DbColumnNamespaces[2];
pub const DbAttestationsNamespace = DbColumnNamespaces[3];
pub const DbCheckpointsNamespace = DbColumnNamespaces[4];

pub const Db = rocksdb.RocksDB(&DbColumnNamespaces);
