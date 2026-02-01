const std = @import("std");
const interface = @import("./interface.zig");
const rocksdb = @import("rocksdb");
const ColumnNamespace = interface.ColumnNamespace;
const Allocator = std.mem.Allocator;
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const database = @import("./database.zig");
const test_helpers = @import("./test_helpers.zig");

pub fn RocksDB(comptime column_namespaces: []const ColumnNamespace) type {
    return struct {
        db: rocksdb.DB,
        allocator: Allocator,
        cf_handles: []const rocksdb.ColumnFamilyHandle,
        cfs: []const rocksdb.ColumnFamily,
        // Keep this as a null terminated string to avoid issues with the RocksDB API
        // As the path gets converted to ptr before being passed to the C API binding
        path: [:0]const u8,
        logger: zeam_utils.ModuleLogger,

        const Self = @This();

        const OpenError = Error || std.posix.MakeDirError || std.fs.Dir.StatFileError;

        pub fn open(allocator: Allocator, logger: zeam_utils.ModuleLogger, path: []const u8) OpenError!Self {
            logger.info("initializing RocksDB", .{});

            const owned_path = try std.fmt.allocPrintZ(allocator, "{s}/rocksdb", .{path});
            errdefer allocator.free(owned_path);

            try std.fs.cwd().makePath(owned_path);

            // Ideally this should be configurable via cli args
            const options = rocksdb.DBOptions{
                .create_if_missing = true,
                .create_missing_column_families = true,
            };

            comptime {
                // assert that the first cn is the default column family
                if (column_namespaces.len == 0 or !std.mem.eql(u8, column_namespaces[0].namespace, "default")) {
                    @compileError("default column namespace not found: first column namespace must be 'default'");
                }
            }

            // allocate cf descriptions
            const column_family_descriptions = try allocator
                .alloc(rocksdb.ColumnFamilyDescription, column_namespaces.len);
            defer allocator.free(column_family_descriptions);

            // initialize cf descriptions
            inline for (column_namespaces, 0..) |cn, i| {
                column_family_descriptions[i] = .{ .name = cn.namespace, .options = .{} };
            }

            const db: rocksdb.DB, //
            const cfs: []const rocksdb.ColumnFamily //
            = try callRocksDB(logger, rocksdb.DB.open, .{
                allocator,
                owned_path,
                options,
                column_family_descriptions,
            });

            // allocate handle slice
            var cf_handles = try allocator.alloc(rocksdb.ColumnFamilyHandle, column_namespaces.len);
            errdefer allocator.free(cf_handles); // kept alive as a field

            // initialize handle slice
            for (0..cfs.len) |i| {
                cf_handles[i] = cfs[i].handle;
            }

            return Self{
                .db = db,
                .allocator = allocator,
                .logger = logger,
                .cf_handles = cf_handles,
                .cfs = cfs,
                .path = owned_path,
            };
        }

        pub fn count(self: *Self, comptime cn: ColumnNamespace) Allocator.Error!u64 {
            const live_files = try self.db.liveFiles(self.allocator);
            defer live_files.deinit();
            defer for (live_files.items) |file| file.deinit();

            var sum: u64 = 0;
            for (live_files.items) |live_file| {
                if (std.mem.eql(u8, live_file.column_family_name, cn.namespace)) {
                    sum += live_file.num_entries;
                }
            }

            return sum;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.cf_handles);
            self.allocator.free(self.cfs);
            self.db.deinit();
            self.allocator.free(self.path);
        }

        pub fn put(self: Self, comptime cn: ColumnNamespace, key: cn.Key, value: cn.Value) !void {
            try callRocksDB(self.logger, rocksdb.DB.put, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], key, value });
        }

        pub fn get(self: *Self, comptime cn: ColumnNamespace, key: cn.Key) !?rocksdb.Data {
            const result: ?rocksdb.Data = try callRocksDB(self.logger, rocksdb.DB.get, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], key });
            return result;
        }

        pub fn delete(self: *Self, comptime cn: ColumnNamespace, key: cn.Key) !void {
            try callRocksDB(self.logger, rocksdb.DB.delete, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], key });
        }

        pub fn deleteFilesInRange(self: *Self, comptime cn: ColumnNamespace, start_key: cn.Key, end_key: cn.Key) !void {
            try callRocksDB(self.logger, rocksdb.DB.deleteFilesInRange, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], start_key, end_key });
        }

        pub fn initWriteBatch(self: *Self) WriteBatch {
            return .{
                .allocator = self.allocator,
                .inner = rocksdb.WriteBatch.init(),
                .cf_handles = self.cf_handles,
                .logger = self.logger,
            };
        }

        pub fn commit(self: *Self, batch: *WriteBatch) void {
            callRocksDB(self.logger, rocksdb.DB.write, .{ &self.db, batch.inner }) catch |err| {
                self.logger.err("failed to commit write batch: {any}", .{err});
                return;
            };
        }

        /// A write batch is a sequence of operations that execute atomically.
        /// This is typically called a "transaction" in most databases.
        ///
        /// Use this instead of Database.put or Database.delete when you need
        /// to ensure that a group of operations are either all executed
        /// successfully, or none of them are executed.
        ///
        /// It is called a write batch instead of a transaction because:
        /// - rocksdb uses the name "write batch" for this concept
        /// - this name avoids confusion with blockchain transactions
        pub const WriteBatch = struct {
            allocator: Allocator,
            inner: rocksdb.WriteBatch,
            cf_handles: []const rocksdb.ColumnFamilyHandle,
            logger: zeam_utils.ModuleLogger,

            pub fn deinit(self: *WriteBatch) void {
                self.inner.deinit();
            }

            pub fn put(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                key: cn.Key,
                value: cn.Value,
            ) void {
                self.inner.put(
                    self.cf_handles[cn.find(column_namespaces)],
                    key,
                    value,
                );
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                key: cn.Key,
            ) void {
                self.inner.delete(self.cf_handles[cn.find(column_namespaces)], key);
            }

            pub fn deleteRange(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                start: cn.Key,
                end: cn.Key,
            ) void {
                self.inner.deleteRange(
                    self.cf_handles[cn.find(column_namespaces)],
                    start,
                    end,
                );
            }

            /// Generic put function for batch operations
            fn putToBatch(
                self: *WriteBatch,
                comptime T: type,
                key: []const u8,
                value: T,
                comptime cn: ColumnNamespace,
                comptime log_message: []const u8,
                log_args: anytype,
            ) void {
                var serialized_value = std.ArrayList(u8).init(self.allocator);
                defer serialized_value.deinit();

                ssz.serialize(T, value, &serialized_value) catch |err| {
                    self.logger.err("failed to serialize value for putToBatch: {any}", .{err});
                    return;
                };

                self.put(cn, key, serialized_value.items);
                self.logger.debug(log_message, log_args);
            }

            /// Put a block to this write batch
            pub fn putBlock(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                block_root: types.Root,
                block: types.SignedBlockWithAttestation,
            ) void {
                const key = interface.formatBlockKey(self.allocator, block_root) catch |err| {
                    self.logger.err("failed to format block key for putBlock: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.putToBatch(
                    types.SignedBlockWithAttestation,
                    key,
                    block,
                    cn,
                    "added block to batch: root=0x{s}",
                    .{std.fmt.fmtSliceHexLower(&block_root)},
                );
            }

            /// Put a state to this write batch
            pub fn putState(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                state_root: types.Root,
                state: types.BeamState,
            ) void {
                const key = interface.formatStateKey(self.allocator, state_root) catch |err| {
                    self.logger.err("failed to format state key for putState: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.putToBatch(
                    types.BeamState,
                    key,
                    state,
                    cn,
                    "added state to batch: root=0x{s}",
                    .{std.fmt.fmtSliceHexLower(&state_root)},
                );
            }

            /// Put a attestation to this write batch
            pub fn putAttestation(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                attestation_key: []const u8,
                attestation: types.SignedAttestation,
            ) void {
                self.putToBatch(
                    types.SignedAttestation,
                    attestation_key,
                    attestation,
                    cn,
                    "added attestation to batch: key={s}",
                    .{attestation_key},
                );
            }

            /// Put a finalized slot index entry to this write batch
            pub fn putFinalizedSlotIndex(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                slot: types.Slot,
                blockroot: types.Root,
            ) void {
                const key = interface.formatFinalizedSlotKey(self.allocator, slot) catch |err| {
                    self.logger.err("failed to format finalized slot key: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.putToBatch(
                    types.Root,
                    key,
                    blockroot,
                    cn,
                    "added finalized slot index to batch: slot={d} root=0x{s}",
                    .{ slot, std.fmt.fmtSliceHexLower(&blockroot) },
                );
            }

            /// Put the latest finalized slot metadata to this write batch
            pub fn putLatestFinalizedSlot(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                slot: types.Slot,
            ) void {
                const key = "latest_finalized_slot";
                self.putToBatch(
                    types.Slot,
                    key,
                    slot,
                    cn,
                    "updated latest finalized slot metadata: slot={d}",
                    .{slot},
                );
            }

            /// Put an unfinalized slot index entry to this write batch
            pub fn putUnfinalizedSlotIndex(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                slot: types.Slot,
                blockroots: []const types.Root,
            ) void {
                const key = interface.formatUnfinalizedSlotKey(self.allocator, slot) catch |err| {
                    self.logger.err("failed to format unfinalized slot key: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.putToBatch(
                    []const types.Root,
                    key,
                    blockroots,
                    cn,
                    "added unfinalized slot index to batch: slot={d} count={d}",
                    .{ slot, blockroots.len },
                );
            }

            /// Delete an unfinalized slot index entry from this write batch
            pub fn deleteUnfinalizedSlotIndexFromBatch(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                slot: types.Slot,
            ) void {
                const key = interface.formatUnfinalizedSlotKey(self.allocator, slot) catch |err| {
                    self.logger.err("failed to format unfinalized slot key for deletion: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.delete(cn, key);
                self.logger.debug("deleted unfinalized slot index from batch: slot={d}", .{slot});
            }
        };

        pub fn iterator(
            self: Self,
            comptime cn: ColumnNamespace,
            comptime direction: interface.IteratorDirection,
            start: ?cn.Key,
        ) !Iterator(cn, direction) {
            return .{
                .allocator = self.allocator,
                .inner = self.db.iterator(
                    self.cf_handles[cn.find(column_namespaces)],
                    switch (direction) {
                        .forward => .forward,
                        .reverse => .reverse,
                    },
                    start,
                ),
                .logger = self.logger,
            };
        }

        pub fn Iterator(cf: ColumnNamespace, _: interface.IteratorDirection) type {
            return struct {
                allocator: Allocator,
                inner: rocksdb.Iterator,
                logger: zeam_utils.ModuleLogger,

                /// Calling this will free all slices returned by the iterator
                pub fn deinit(self: *@This()) void {
                    self.inner.deinit();
                }

                pub fn next(self: *@This()) !?cf.Entry() {
                    const entry = try callRocksDB(self.logger, rocksdb.Iterator.next, .{&self.inner});
                    return if (entry) |kv|
                        .{ kv[0].data, kv[1].data }
                    else
                        null;
                }

                pub fn nextKey(self: *@This()) !?cf.Key {
                    const entry = try callRocksDB(self.logger, rocksdb.Iterator.next, .{&self.inner});
                    return if (entry) |kv|
                        kv[0].data
                    else
                        null;
                }

                pub fn nextValue(self: *@This()) !?cf.Value {
                    const entry = try callRocksDB(self.logger, rocksdb.Iterator.next, .{&self.inner});
                    return if (entry) |kv|
                        kv[1].data
                    else
                        null;
                }
            };
        }

        pub fn flush(self: *Self, comptime cn: ColumnNamespace) error{RocksDBFlush}!void {
            try callRocksDB(
                self.logger,
                rocksdb.DB.flush,
                .{ &self.db, self.cf_handles[cn.find(column_namespaces)] },
            );
        }

        /// Generic save function for database operations
        fn saveToDatabase(
            self: *Self,
            comptime T: type,
            key: []const u8,
            value: T,
            comptime cn: ColumnNamespace,
            comptime log_message: []const u8,
            log_args: anytype,
        ) void {
            var serialized_value = std.ArrayList(u8).init(self.allocator);
            defer serialized_value.deinit();

            ssz.serialize(T, value, &serialized_value) catch |err| {
                self.logger.err("failed to serialize value for saveToDatabase: {any}", .{err});
                return;
            };

            self.put(cn, key, serialized_value.items) catch |err| {
                self.logger.err("failed to put value to database in saveToDatabase: {any}", .{err});
                return;
            };
            self.logger.debug(log_message, log_args);
        }

        /// Generic load function for database operations
        fn loadFromDatabase(
            self: *Self,
            comptime T: type,
            key: []const u8,
            comptime cn: ColumnNamespace,
            comptime log_message: []const u8,
            log_args: anytype,
        ) ?T {
            const value = self.get(cn, key) catch |err| {
                self.logger.err("failed to get value from database in loadFromDatabase: {any}", .{err});
                return null;
            };
            if (value) |encoded_value| {
                defer encoded_value.deinit();

                var decoded_value: T = undefined;
                ssz.deserialize(T, encoded_value.data, &decoded_value, self.allocator) catch |err| {
                    self.logger.err("failed to deserialize value in loadFromDatabase: {any}", .{err});
                    return null;
                };

                self.logger.debug(log_message, log_args);
                return decoded_value;
            }
            return null;
        }

        /// Save a block to the database
        pub fn saveBlock(self: *Self, comptime cn: ColumnNamespace, block_root: types.Root, block: types.SignedBlockWithAttestation) void {
            const key = interface.formatBlockKey(self.allocator, block_root) catch |err| {
                self.logger.err("failed to format block key for saveBlock: {any}", .{err});
                return;
            };
            defer self.allocator.free(key);

            self.saveToDatabase(
                types.SignedBlockWithAttestation,
                key,
                block,
                cn,
                "saved block to database: root=0x{s}",
                .{std.fmt.fmtSliceHexLower(&block_root)},
            );
        }

        /// Load a block from the database
        pub fn loadBlock(self: *Self, comptime cn: ColumnNamespace, block_root: types.Root) ?types.SignedBlockWithAttestation {
            const key = interface.formatBlockKey(self.allocator, block_root) catch |err| {
                self.logger.err("failed to format block key for loadBlock: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            return self.loadFromDatabase(
                types.SignedBlockWithAttestation,
                key,
                cn,
                "loaded block from database: root=0x{s}",
                .{std.fmt.fmtSliceHexLower(&block_root)},
            );
        }

        /// Save a state to the database
        pub fn saveState(self: *Self, comptime cn: ColumnNamespace, state_root: types.Root, state: types.BeamState) void {
            const key = interface.formatStateKey(self.allocator, state_root) catch |err| {
                self.logger.err("failed to format state key for saveState: {any}", .{err});
                return;
            };
            defer self.allocator.free(key);

            self.saveToDatabase(
                types.BeamState,
                key,
                state,
                cn,
                "saved state to database: root=0x{s}",
                .{std.fmt.fmtSliceHexLower(&state_root)},
            );
        }

        /// Load a state from the database
        pub fn loadState(self: *Self, comptime cn: ColumnNamespace, state_root: types.Root) ?types.BeamState {
            const key = interface.formatStateKey(self.allocator, state_root) catch |err| {
                self.logger.err("failed to format state key for loadState: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            return self.loadFromDatabase(
                types.BeamState,
                key,
                cn,
                "loaded state from database: root=0x{s}",
                .{std.fmt.fmtSliceHexLower(&state_root)},
            );
        }

        /// Save a attestation to the database
        pub fn saveAttestation(self: *Self, comptime cn: ColumnNamespace, attestation_key: []const u8, attestation: types.SignedAttestation) void {
            self.saveToDatabase(
                types.SignedAttestation,
                attestation_key,
                attestation,
                cn,
                "saved attestation to database: key={s}",
                .{attestation_key},
            );
        }

        /// Load a attestation from the database
        pub fn loadAttestation(self: *Self, comptime cn: ColumnNamespace, attestation_key: []const u8) ?types.SignedAttestation {
            return self.loadFromDatabase(
                types.SignedAttestation,
                attestation_key,
                cn,
                "loaded attestation from database: key={s}",
                .{attestation_key},
            );
        }

        /// Load a finalized slot index from the database
        pub fn loadFinalizedSlotIndex(self: *Self, comptime cn: ColumnNamespace, slot: types.Slot) ?types.Root {
            const key = interface.formatFinalizedSlotKey(self.allocator, slot) catch |err| {
                self.logger.err("failed to format finalized slot key: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            return self.loadFromDatabase(
                types.Root,
                key,
                cn,
                "loaded finalized slot index from database: slot={d}",
                .{slot},
            );
        }

        /// Load the latest finalized slot metadata from the database
        pub fn loadLatestFinalizedSlot(self: *Self, comptime cn: ColumnNamespace) ?types.Slot {
            const key = "latest_finalized_slot";
            return self.loadFromDatabase(
                types.Slot,
                key,
                cn,
                "loaded latest finalized slot metadata",
                .{},
            );
        }

        /// Attempts to load the latest finalized state from the database
        /// Returns null if no finalized state is found (e.g., first run)
        pub fn loadLatestFinalizedState(
            self: *Self,
            state_ptr: *types.BeamState,
        ) !void {
            // Load the latest finalized slot from metadata
            const finalized_slot = self.loadLatestFinalizedSlot(database.DbDefaultNamespace) orelse {
                self.logger.info("no finalized state found in database, will use genesis", .{});
                return error.NoFinalizedStateFound;
            };

            self.logger.info("found latest finalized slot {d}, loading block root...", .{finalized_slot});

            // Load the block root for this finalized slot
            const block_root = self.loadFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, finalized_slot) orelse {
                self.logger.warn("finalized slot {d} found in metadata but not in finalized index", .{finalized_slot});
                return error.FinalizedSlotNotFoundInIndex;
            };

            // Load the state from the database
            if (self.loadState(database.DbStatesNamespace, block_root)) |state| {
                state_ptr.* = state;
                self.logger.info("successfully loaded finalized state at slot {d}", .{finalized_slot});
                return;
            } else {
                self.logger.warn("finalized slot {d} found in index but state not in database", .{finalized_slot});
                return error.FinalizedStateNotFoundInDatabase;
            }
        }

        /// Load an unfinalized slot index from the database
        pub fn loadUnfinalizedSlotIndex(self: *Self, comptime cn: ColumnNamespace, slot: types.Slot) ?[]types.Root {
            const key = interface.formatUnfinalizedSlotKey(self.allocator, slot) catch |err| {
                self.logger.err("failed to format unfinalized slot key: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            return self.loadFromDatabase(
                []types.Root,
                key,
                cn,
                "loaded unfinalized slot index from database: slot={d}",
                .{slot},
            );
        }

        const Error = error{
            DefaultColumnNamespaceNotFound,
            RocksDBOpen,
            RocksDBPut,
            RocksDBGet,
            RocksDBDelete,
            RocksDBDeleteFilesInRange,
            RocksDBIterator,
            RocksDBWrite,
            RocksDBFlush,
        } || Allocator.Error;
    };
}

fn callRocksDB(logger: zeam_utils.ModuleLogger, func: anytype, args: anytype) interface.ReturnType(@TypeOf(func)) {
    var err_str: ?rocksdb.Data = null;
    return @call(.auto, func, args ++ .{&err_str}) catch |e| {
        const func_name = @typeName(@TypeOf(func));
        logger.err("failed to call RocksDB function: '{s}', error: {} - {s}", .{ func_name, e, err_str.? });
        return e;
    };
}

test "test_column_namespaces" {
    const cn = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = u8, .Value = u8 },
        .{ .namespace = "cn1", .Key = u8, .Value = u8 },
        .{ .namespace = "cn2", .Key = u8, .Value = u8 },
    };

    try std.testing.expectEqual(@as(comptime_int, 0), cn[0].find(&cn));
    try std.testing.expectEqual(@as(comptime_int, 1), cn[1].find(&cn));
    try std.testing.expectEqual(@as(comptime_int, 2), cn[2].find(&cn));
}

test "test_rocksdb_with_default_cn" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    const column_namespaces = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.database_test);

    const rdb = RocksDB(&column_namespaces);
    var db = try rdb.open(allocator, module_logger, data_dir);
    defer db.deinit();

    // Put values into the default column family
    try db.put(column_namespaces[0], "default_key", "default_value");

    // Get values from the default column family
    const value = try db.get(column_namespaces[0], "default_key");
    if (value) |v| {
        defer v.deinit();
        try std.testing.expectEqualStrings("default_value", v.data);
    }

    // Delete values from the default column family
    try db.delete(column_namespaces[0], "default_key");

    // Verify deletion
    const value2 = try db.get(column_namespaces[0], "default_key");
    try std.testing.expect(value2 == null);
}

test "test_column_families_with_multiple_cns" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    // Default column family is necessary for the RocksDB API to work
    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
        .{ .namespace = "cn1", .Key = []const u8, .Value = []const u8 },
        .{ .namespace = "cn2", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.database_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, data_dir);
    defer db.deinit();

    // Put values into the column families
    try db.put(column_namespace[1], "cn1_key", "cn1_value");
    try db.put(column_namespace[2], "cn2_key", "cn2_value");

    // Get values from the column families
    const value = try db.get(column_namespace[1], "cn1_key");
    if (value) |v| {
        defer v.deinit();
        try std.testing.expectEqualStrings("cn1_value", v.data);
    }

    const value2 = try db.get(column_namespace[2], "cn2_key");
    if (value2) |v2| {
        defer v2.deinit();
        try std.testing.expectEqualStrings("cn2_value", v2.data);
    }

    // Delete values from the column families
    try db.delete(column_namespace[1], "cn1_key");
    try db.delete(column_namespace[2], "cn2_key");

    // Verify deletion
    const value3 = try db.get(column_namespace[1], "cn1_key");
    try std.testing.expect(value3 == null);

    const value4 = try db.get(column_namespace[2], "cn2_key");
    try std.testing.expect(value4 == null);
}

test "test_count_function" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.database_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, data_dir);
    defer db.deinit();

    // Initially, the column family should have 0 entries
    try std.testing.expectEqual(@as(u64, 0), try db.count(column_namespace[0]));

    // Add some entries to the default column family
    try db.put(column_namespace[0], "default_key1", "default_value1");
    try db.put(column_namespace[0], "default_key2", "default_value2");

    // Force a flush to ensure data is written to disk and counted properly
    try db.flush(column_namespace[0]);

    // Check count after adding entries
    try std.testing.expectEqual(@as(u64, 2), try db.count(column_namespace[0]));
}

test "test_batch_write_function" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.database_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, data_dir);
    defer db.deinit();

    var batch = db.initWriteBatch();
    defer batch.deinit();

    // Add entry to batch but don't commit yet
    batch.put(column_namespace[0], "default_key1", "default_value1");

    // Verify entry is not yet visible in database
    try std.testing.expect((try db.get(column_namespace[0], "default_key1")) == null);

    // Commit the batch to make changes visible
    db.commit(&batch);

    // Verify entry is now visible in database
    const value1 = try db.get(column_namespace[0], "default_key1");
    if (value1) |v1| {
        defer v1.deinit();
        try std.testing.expectEqualStrings("default_value1", v1.data);
    }

    // Add delete operation to batch but don't commit yet
    batch.delete(column_namespace[0], "default_key1");

    // Verify entry is still visible before commit
    const value2 = try db.get(column_namespace[0], "default_key1");
    if (value2) |v2| {
        defer v2.deinit();
        try std.testing.expectEqualStrings("default_value1", v2.data);
    }

    // Commit the delete operation
    db.commit(&batch);

    // Verify entry is now deleted from database
    try std.testing.expect((try db.get(column_namespace[0], "default_key1")) == null);
}

test "test_iterator_functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.database_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, data_dir);
    defer db.deinit();

    // Add multiple entries to test iteration
    try db.put(column_namespace[0], "key1", "value1");
    try db.put(column_namespace[0], "key2", "value2");
    try db.put(column_namespace[0], "key3", "value3");
    try db.put(column_namespace[0], "key4", "value4");
    try db.put(column_namespace[0], "key5", "value5");

    // Test forward iterator
    var forward_iter = try db.iterator(column_namespace[0], .forward, null);
    defer forward_iter.deinit();

    // Test next() method - should return key-value pairs in order
    const entry1 = try forward_iter.next();
    try std.testing.expect(entry1 != null);
    try std.testing.expectEqualStrings("key1", entry1.?.@"0");
    try std.testing.expectEqualStrings("value1", entry1.?.@"1");

    const entry2 = try forward_iter.next();
    try std.testing.expect(entry2 != null);
    try std.testing.expectEqualStrings("key2", entry2.?.@"0");
    try std.testing.expectEqualStrings("value2", entry2.?.@"1");

    // Test nextKey() method
    const key3 = try forward_iter.nextKey();
    try std.testing.expect(key3 != null);
    try std.testing.expectEqualStrings("key3", key3.?);

    // Test nextValue() method
    const value4 = try forward_iter.nextValue();
    try std.testing.expect(value4 != null);
    try std.testing.expectEqualStrings("value4", value4.?);

    // Get the last entry
    const entry5 = try forward_iter.next();
    try std.testing.expect(entry5 != null);
    try std.testing.expectEqualStrings("key5", entry5.?.@"0");
    try std.testing.expectEqualStrings("value5", entry5.?.@"1");

    // Should return null when no more entries
    const end_entry = try forward_iter.next();
    try std.testing.expect(end_entry == null);

    // Test reverse iterator
    var reverse_iter = try db.iterator(column_namespace[0], .reverse, null);
    defer reverse_iter.deinit();

    // Test reverse iteration - should return entries in reverse order
    const rev_entry1 = try reverse_iter.next();
    try std.testing.expect(rev_entry1 != null);
    try std.testing.expectEqualStrings("key5", rev_entry1.?.@"0");
    try std.testing.expectEqualStrings("value5", rev_entry1.?.@"1");

    const rev_entry2 = try reverse_iter.next();
    try std.testing.expect(rev_entry2 != null);
    try std.testing.expectEqualStrings("key4", rev_entry2.?.@"0");
    try std.testing.expectEqualStrings("value4", rev_entry2.?.@"1");

    // Test iterator with start key
    var start_iter = try db.iterator(column_namespace[0], .forward, "key3");
    defer start_iter.deinit();

    // Should start from key3
    const start_entry = try start_iter.next();
    try std.testing.expect(start_entry != null);
    try std.testing.expectEqualStrings("key3", start_entry.?.@"0");
    try std.testing.expectEqualStrings("value3", start_entry.?.@"1");

    // Next should be key4
    const start_entry2 = try start_iter.next();
    try std.testing.expect(start_entry2 != null);
    try std.testing.expectEqualStrings("key4", start_entry2.?.@"0");
    try std.testing.expectEqualStrings("value4", start_entry2.?.@"1");
}

test "save and load block" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Create test data using helper functions
    const test_block_root = test_helpers.createDummyRoot(0xAB);

    // Create dummy attestation signatures using helper
    var attestation_signatures = try test_helpers.createDummyAttestationSignatures(allocator, 3);
    var attestation_signatures_cleanup = true;
    errdefer if (attestation_signatures_cleanup) {
        for (attestation_signatures.slice()) |*sig| {
            sig.deinit();
        }
        attestation_signatures.deinit();
    };

    var signed_block = try test_helpers.createDummyBlock(allocator, 1, 0, 0xCD, 0xEF, attestation_signatures);
    attestation_signatures_cleanup = false; // ownership moved into signed_block
    defer signed_block.deinit();

    // Save the block
    db.saveBlock(database.DbBlocksNamespace, test_block_root, signed_block);

    // Load the block back
    const loaded_block = db.loadBlock(database.DbBlocksNamespace, test_block_root);
    try std.testing.expect(loaded_block != null);

    const loaded = loaded_block.?.message;

    // Verify all block fields match
    try std.testing.expect(loaded.block.slot == signed_block.message.block.slot);
    try std.testing.expect(loaded.block.proposer_index == signed_block.message.block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &loaded.block.parent_root, &signed_block.message.block.parent_root));
    try std.testing.expect(std.mem.eql(u8, &loaded.block.state_root, &signed_block.message.block.state_root));

    // Verify attestations list is empty as expected
    try std.testing.expect(loaded.block.body.attestations.len() == 0);

    // Verify attestation signatures count matches
    const signature_proofs = loaded_block.?.signature.attestation_signatures;
    try std.testing.expect(signature_proofs.len() == signed_block.signature.attestation_signatures.len());

    // Test loading a non-existent block
    const non_existent_root = test_helpers.createDummyRoot(0xFF);
    const loaded_non_existent_block = db.loadBlock(database.DbBlocksNamespace, non_existent_root);
    try std.testing.expect(loaded_non_existent_block == null);
}

test "save and load state" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Create test data using helper functions
    const test_state_root = test_helpers.createDummyRoot(0x11);
    var test_state = try test_helpers.createDummyState(allocator, 1, 4, 93, 0, 0, 0x22, 0x33);
    defer test_state.deinit();

    // Save the state
    db.saveState(database.DbStatesNamespace, test_state_root, test_state);

    // Load the state back
    const loaded_state = db.loadState(database.DbStatesNamespace, test_state_root);
    try std.testing.expect(loaded_state != null);

    const loaded = loaded_state.?;

    // Verify state fields match
    try std.testing.expect(loaded.slot == test_state.slot);
    try std.testing.expect(loaded.latest_justified.slot == test_state.latest_justified.slot);
    try std.testing.expect(std.mem.eql(u8, &loaded.latest_justified.root, &test_state.latest_justified.root));
    try std.testing.expect(loaded.latest_finalized.slot == test_state.latest_finalized.slot);
    try std.testing.expect(std.mem.eql(u8, &loaded.latest_finalized.root, &test_state.latest_finalized.root));
    try std.testing.expect(loaded.historical_block_hashes.len() == test_state.historical_block_hashes.len());
    try std.testing.expect(loaded.justified_slots.len() == test_state.justified_slots.len());

    // Test loading a non-existent state root
    const non_existent_root = test_helpers.createDummyRoot(0xFF);
    const loaded_non_existent_state = db.loadState(database.DbStatesNamespace, non_existent_root);
    try std.testing.expect(loaded_non_existent_state == null);
}

test "batch write and commit" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Create test data using helper functions
    const test_block_root = test_helpers.createDummyRoot(0xAA);

    // Create dummy attestation signatures using helper
    var attestation_signatures = try test_helpers.createDummyAttestationSignatures(allocator, 3);
    var attestation_signatures_cleanup = true;
    errdefer if (attestation_signatures_cleanup) {
        for (attestation_signatures.slice()) |*sig| {
            sig.deinit();
        }
        attestation_signatures.deinit();
    };

    var signed_block = try test_helpers.createDummyBlock(allocator, 2, 1, 0xBB, 0xCC, attestation_signatures);
    attestation_signatures_cleanup = false; // ownership moved into signed_block
    defer signed_block.deinit();

    const test_state_root = test_helpers.createDummyRoot(0xEE);
    var test_state = try test_helpers.createDummyState(allocator, 2, 4, 93, 1, 0, 0xFF, 0x00);
    defer test_state.deinit();

    // Test batch write and commit
    var batch = db.initWriteBatch();
    defer batch.deinit();

    // Verify block doesn't exist before batch commit
    const loaded_null_block = db.loadBlock(database.DbBlocksNamespace, test_block_root);
    try std.testing.expect(loaded_null_block == null);

    // Verify state doesn't exist before batch commit
    const loaded_null_state = db.loadState(database.DbStatesNamespace, test_state_root);
    try std.testing.expect(loaded_null_state == null);

    // Add block and state to batch
    batch.putBlock(database.DbBlocksNamespace, test_block_root, signed_block);
    batch.putState(database.DbStatesNamespace, test_state_root, test_state);

    // Commit the batch
    db.commit(&batch);

    // Verify block was saved and can be loaded
    const loaded_block = db.loadBlock(database.DbBlocksNamespace, test_block_root);
    try std.testing.expect(loaded_block != null);

    const loaded_block_data = loaded_block.?.message;
    try std.testing.expect(loaded_block_data.block.slot == signed_block.message.block.slot);
    try std.testing.expect(loaded_block_data.block.proposer_index == signed_block.message.block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &loaded_block_data.block.parent_root, &signed_block.message.block.parent_root));
    try std.testing.expect(std.mem.eql(u8, &loaded_block_data.block.state_root, &signed_block.message.block.state_root));

    // Verify attestation signatures count matches
    const batch_signature_proofs = loaded_block.?.signature.attestation_signatures;
    try std.testing.expect(batch_signature_proofs.len() == attestation_signatures.len());

    // Verify state was saved and can be loaded
    const loaded_state = db.loadState(database.DbStatesNamespace, test_state_root);
    try std.testing.expect(loaded_state != null);

    const loaded_state_data = loaded_state.?;
    try std.testing.expect(loaded_state_data.slot == test_state.slot);
    try std.testing.expect(loaded_state_data.latest_justified.slot == test_state.latest_justified.slot);
    try std.testing.expect(std.mem.eql(u8, &loaded_state_data.latest_justified.root, &test_state.latest_justified.root));
    try std.testing.expect(loaded_state_data.latest_finalized.slot == test_state.latest_finalized.slot);
    try std.testing.expect(std.mem.eql(u8, &loaded_state_data.latest_finalized.root, &test_state.latest_finalized.root));
}

test "loadLatestFinalizedState" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Empty DB -> no finalized slot metadata
    {
        var out_state: types.BeamState = undefined;
        try std.testing.expectError(error.NoFinalizedStateFound, db.loadLatestFinalizedState(&out_state));
    }

    // Metadata present but slot index missing -> error
    {
        var batch = db.initWriteBatch();
        defer batch.deinit();

        const finalized_slot: types.Slot = 7;
        batch.putLatestFinalizedSlot(database.DbDefaultNamespace, finalized_slot);
        db.commit(&batch);

        var out_state: types.BeamState = undefined;
        try std.testing.expectError(error.FinalizedSlotNotFoundInIndex, db.loadLatestFinalizedState(&out_state));
    }

    // Slot index present but state missing -> error
    {
        var batch = db.initWriteBatch();
        defer batch.deinit();

        const finalized_slot: types.Slot = 9;
        const block_root = test_helpers.createDummyRoot(0xAA);
        batch.putLatestFinalizedSlot(database.DbDefaultNamespace, finalized_slot);
        batch.putFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, finalized_slot, block_root);
        db.commit(&batch);

        var out_state: types.BeamState = undefined;
        try std.testing.expectError(error.FinalizedStateNotFoundInDatabase, db.loadLatestFinalizedState(&out_state));
    }

    // Happy path: metadata + slot index + state all present
    {
        var batch = db.initWriteBatch();
        defer batch.deinit();

        const finalized_slot: types.Slot = 11;
        const block_root = test_helpers.createDummyRoot(0x42);

        var expected_state = try test_helpers.createDummyState(allocator, 123, 4, 93, 1, 0, 0x10, 0x20);
        defer expected_state.deinit();

        batch.putLatestFinalizedSlot(database.DbDefaultNamespace, finalized_slot);
        batch.putFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, finalized_slot, block_root);
        batch.putState(database.DbStatesNamespace, block_root, expected_state);
        db.commit(&batch);

        var loaded_state: types.BeamState = undefined;
        try db.loadLatestFinalizedState(&loaded_state);

        // Spot-check a few fields to ensure the loaded state matches what we stored.
        try std.testing.expectEqual(expected_state.slot, loaded_state.slot);
        try std.testing.expectEqual(expected_state.latest_justified.slot, loaded_state.latest_justified.slot);
        try std.testing.expect(std.mem.eql(u8, &expected_state.latest_justified.root, &loaded_state.latest_justified.root));
        try std.testing.expectEqual(expected_state.latest_finalized.slot, loaded_state.latest_finalized.slot);
        try std.testing.expect(std.mem.eql(u8, &expected_state.latest_finalized.root, &loaded_state.latest_finalized.root));
    }
}
