const rocksDB = @import("./rocksdb.zig");
const interface = @import("./interface.zig");

// Export the main types that are used by consumers
pub const ColumnNamespace = interface.ColumnNamespace;
pub const RocksDB = rocksDB.RocksDB;
