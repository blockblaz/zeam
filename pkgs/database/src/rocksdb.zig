const std = @import("std");
const interface = @import("./interface.zig");
const rocksdb = @import("rocksdb");
const ColumnNamespace = interface.ColumnNamespace;
const Allocator = std.mem.Allocator;
const zeam_utils = @import("@zeam/utils");

pub fn RocksDB(comptime column_namespaces: []const ColumnNamespace) type {
    return struct {
        db: rocksdb.DB,
        allocator: Allocator,
        cf_handles: []const rocksdb.ColumnFamilyHandle,
        path: []const u8,
        logger: zeam_utils.ModuleLogger,

        const Self = @This();

        const OpenError = Error || std.posix.MakeDirError || std.fs.Dir.StatFileError;

        pub fn open(allocator: Allocator, logger: zeam_utils.ModuleLogger, path: []const u8) OpenError!Self {
            logger.info("Initializing RocksDB", .{});

            const owned_path = try std.fmt.allocPrint(allocator, "{s}/rocksdb", .{path});
            errdefer allocator.free(owned_path);

            try std.fs.cwd().makePath(owned_path);

            // Ideally this should be configurable via cli args
            const options = rocksdb.DBOptions{
                .create_if_missing = true,
                .create_missing_column_families = true,
            };

            // assert that the first cn is the default column family
            if (column_namespaces.len == 0 or !std.mem.eql(u8, column_namespaces[0].namespace, "default")) {
                return error.DefaultColumnNamespaceNotFound;
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
            defer allocator.free(cfs);

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
            self.db.deinit();
            self.allocator.free(self.path);
        }

        pub fn put(self: Self, comptime cn: ColumnNamespace, key: cn.Key, value: cn.Value) anyerror!void {
            try callRocksDB(self.logger, rocksdb.DB.put, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], key, value });
        }

        pub fn get(self: *Self, comptime cn: ColumnNamespace, key: cn.Key) anyerror!?rocksdb.Data {
            const result: ?rocksdb.Data = try callRocksDB(self.logger, rocksdb.DB.get, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], key });
            return result;
        }

        pub fn delete(self: *Self, comptime cn: ColumnNamespace, key: cn.Key) anyerror!void {
            try callRocksDB(self.logger, rocksdb.DB.delete, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], key });
        }

        pub fn deleteFilesInRange(self: *Self, comptime cn: ColumnNamespace, start_key: cn.Key, end_key: cn.Key) anyerror!void {
            try callRocksDB(self.logger, rocksdb.DB.deleteFilesInRange, .{ &self.db, self.cf_handles[cn.find(column_namespaces)], start_key, end_key });
        }

        pub fn initWriteBatch(self: *Self) Error!WriteBatch {
            return .{
                .allocator = self.allocator,
                .inner = rocksdb.WriteBatch.init(),
                .cf_handles = self.cf_handles,
            };
        }

        pub fn commit(self: *Self, batch: *WriteBatch) Error!void {
            return callRocksDB(self.logger, rocksdb.DB.write, .{ &self.db, batch.inner });
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

            pub fn deinit(self: *WriteBatch) void {
                self.inner.deinit();
            }

            pub fn put(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                key: cn.Key,
                value: cn.Value,
            ) anyerror!void {
                try self.inner.put(
                    self.cf_handles[cn.find(column_namespaces)],
                    key,
                    value,
                );
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                key: cn.Key,
            ) anyerror!void {
                try self.inner.delete(self.cf_handles[cn.find(column_namespaces)], key);
            }

            pub fn deleteRange(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                start: cn.Key,
                end: cn.Key,
            ) anyerror!void {
                self.inner.deleteRange(
                    self.cf_handles[cn.find(column_namespaces)],
                    start,
                    end,
                );
            }
        };

        pub fn iterator(
            self: Self,
            comptime cn: ColumnNamespace,
            comptime direction: interface.IteratorDirection,
            start: ?cn.Key,
        ) anyerror!Iterator(cn, direction) {
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

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    const entry = try callRocksDB(self.logger, rocksdb.Iterator.next, .{&self.inner});
                    return if (entry) |kv| .{ kv[0].data, kv[1].data } orelse null;
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    const entry = try callRocksDB(self.logger, rocksdb.Iterator.next, .{&self.inner});
                    return if (entry) |kv|
                        kv[0].data
                    else
                        null;
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
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
        logger.err("Failed to call RocksDB function: '{s}', error: {} - {s}", .{ func_name, e, err_str.? });
        return e;
    };
}

test "column_namespaces" {
    const cn = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = u8, .Value = u8 },
        .{ .namespace = "cn1", .Key = u8, .Value = u8 },
        .{ .namespace = "cn2", .Key = u8, .Value = u8 },
    };

    try std.testing.expectEqual(@as(comptime_int, 0), cn[0].find(&cn));
    try std.testing.expectEqual(@as(comptime_int, 1), cn[1].find(&cn));
    try std.testing.expectEqual(@as(comptime_int, 2), cn[2].find(&cn));
}

test "test_rocksdb_with_empty_cn" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);

    const column_namespaces = [_]ColumnNamespace{};

    // Create a test logger
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.network_test);

    // Should fail to initialize RocksDB with empty column namespaces
    const db = RocksDB(&column_namespaces);
    const result = db.open(allocator, module_logger, db_path);
    try std.testing.expectError(error.DefaultColumnNamespaceNotFound, result);
}

test "test_rocksdb_with_default_cn" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);

    const column_namespaces = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.network_test);

    const rdb = RocksDB(&column_namespaces);
    var db = try rdb.open(allocator, module_logger, db_path);
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

    const db_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);

    // Default column family is necessary for the RocksDB API to work
    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
        .{ .namespace = "cn1", .Key = []const u8, .Value = []const u8 },
        .{ .namespace = "cn2", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.network_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, db_path);
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

    const db_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);

    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.network_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, db_path);
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

    const db_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);

    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.network_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, db_path);
    defer db.deinit();

    var batch = try db.initWriteBatch();
    defer batch.deinit();

    // Add entry to batch but don't commit yet
    try batch.put(column_namespace[0], "default_key1", "default_value1");

    // Verify entry is not yet visible in database
    try std.testing.expect((try db.get(column_namespace[0], "default_key1")) == null);

    // Commit the batch to make changes visible
    try db.commit(&batch);

    // Verify entry is now visible in database
    const value1 = try db.get(column_namespace[0], "default_key1");
    if (value1) |v1| {
        defer v1.deinit();
        try std.testing.expectEqualStrings("default_value1", v1.data);
    }

    // Add delete operation to batch but don't commit yet
    try batch.delete(column_namespace[0], "default_key1");

    // Verify entry is still visible before commit
    const value2 = try db.get(column_namespace[0], "default_key1");
    if (value2) |v2| {
        defer v2.deinit();
        try std.testing.expectEqualStrings("default_value1", v2.data);
    }

    // Commit the delete operation
    try db.commit(&batch);

    // Verify entry is now deleted from database
    try std.testing.expect((try db.get(column_namespace[0], "default_key1")) == null);
}

test "test_iterator_functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const db_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);

    const column_namespace = [_]ColumnNamespace{
        .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    };

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();
    const module_logger = zeam_logger_config.logger(.network_test);

    const rdb = RocksDB(&column_namespace);
    var db = try rdb.open(allocator, module_logger, db_path);
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
