const rocksDB = @import("./rocksdb.zig");
pub const RocksDB = rocksDB.RocksDB;

const lmdbBackend = @import("./lmdb.zig");
pub const Lmdb = lmdbBackend.Lmdb;

const interface = @import("./interface.zig");
pub const formatBlockKey = interface.formatBlockKey;
pub const formatStateKey = interface.formatStateKey;
pub const formatFinalizedSlotKey = interface.formatFinalizedSlotKey;
pub const formatUnfinalizedSlotKey = interface.formatUnfinalizedSlotKey;
pub const ReturnType = interface.ReturnType;
pub const ColumnNamespace = interface.ColumnNamespace;
pub const IteratorDirection = interface.IteratorDirection;

const database = @import("./database.zig");
pub const DbColumnNamespaces = database.DbColumnNamespaces;
pub const DbDefaultNamespace = database.DbDefaultNamespace;
pub const DbBlocksNamespace = database.DbBlocksNamespace;
pub const DbStatesNamespace = database.DbStatesNamespace;
pub const DbAttestationsNamespace = database.DbAttestationsNamespace;
pub const DbCheckpointsNamespace = database.DbCheckpointsNamespace;
pub const DbFinalizedSlotsNamespace = database.DbFinalizedSlotsNamespace;
// TODO: uncomment this code if there is a need of slot to unfinalized index
// pub const DbUnfinalizedSlotsNamespace = database.DbUnfinalizedSlotsNamespace;
pub const Db = database.Db;
pub const Backend = database.Backend;
pub const RocksDbBackend = database.RocksDbBackend;
pub const LmdbBackend = database.LmdbBackend;
pub const WriteBatch = database.WriteBatch;
pub const Iterator = database.Iterator;

test "get tests" {
    @import("std").testing.refAllDecls(@This());
}
