const std = @import("std");
const interface = @import("./interface.zig");
const lmdb = @import("lmdb");
const ColumnNamespace = interface.ColumnNamespace;
const Allocator = std.mem.Allocator;
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");
const types = @import("@zeam/types");
const database = @import("./database.zig");

/// Generic LMDB-backed `Db` that mirrors the shape of `RocksDB(...)` in
/// `pkgs/database/src/rocksdb.zig`. Callers use exactly the same method
/// surface (`put` / `get` / `delete` / `initWriteBatch` / `commit` /
/// `iterator` plus the SSZ convenience helpers) so the two backends can
/// sit behind a single tagged union.
///
/// LMDB's concurrency model (SWMR) maps cleanly to zeam's current
/// threading — one writer serialised by `BeamNode.mutex`, potentially
/// many readers once DB reads are lifted out of that mutex. DBI
/// handles are opened once at `open` time in a write transaction; each
/// subsequent direct read/write spins up a short-lived txn, while
/// `WriteBatch` and `Iterator` hold the txn for their full lifetime.
pub fn Lmdb(comptime column_namespaces: []const ColumnNamespace) type {
    return struct {
        env: lmdb.Env,
        dbi_handles: [column_namespaces.len]lmdb.Dbi,
        allocator: Allocator,
        path: [:0]const u8,
        logger: zeam_utils.ModuleLogger,

        const Self = @This();

        const OpenError = anyerror;

        /// Default map size for newly-created environments. LMDB
        /// reserves the corresponding amount of virtual address space
        /// up front; physical disk usage grows on demand.
        ///
        /// 256 GiB is comfortably beyond the expected working-set size
        /// for a lean-consensus node while still leaving room for
        /// several parallel env opens (mock networks, in-process
        /// multi-node tests). Bumping higher exhausts user-space VA on
        /// crowded machines and trips `vm.overcommit_memory = 2`.
        const DEFAULT_MAP_SIZE: usize = 256 * (1 << 30);

        pub fn open(allocator: Allocator, logger: zeam_utils.ModuleLogger, path: []const u8) OpenError!Self {
            logger.info("initializing LMDB", .{});
            const io = std.Io.Threaded.global_single_threaded.io();

            comptime {
                if (column_namespaces.len == 0 or !std.mem.eql(u8, column_namespaces[0].namespace, "default")) {
                    @compileError("default column namespace not found: first column namespace must be 'default'");
                }
            }

            const owned_path = try std.fmt.allocPrintSentinel(allocator, "{s}/lmdb", .{path}, 0);
            errdefer allocator.free(owned_path);
            try std.Io.Dir.cwd().createDirPath(io, owned_path);

            var env = lmdb.Env.open(owned_path, .{
                .map_size = DEFAULT_MAP_SIZE,
                // Reserve headroom in the named-DB array so LMDB's
                // internal metadata has room to grow.
                .max_dbs = @intCast(column_namespaces.len + 4),
            }) catch |err| {
                logger.err("failed to open LMDB environment at {s}: {any}", .{ owned_path, err });
                return error.LmdbOpen;
            };
            errdefer env.close();

            // DBI handles are durable once opened inside a committed
            // write transaction; subsequent transactions reuse them.
            var dbi_handles: [column_namespaces.len]lmdb.Dbi = undefined;
            var txn = env.beginTxn(false) catch |err| {
                logger.err("failed to begin LMDB bootstrap txn: {any}", .{err});
                return error.LmdbOpen;
            };
            errdefer txn.abort();

            inline for (column_namespaces, 0..) |cn, i| {
                // `null` as the sub-DB name would select LMDB's unnamed
                // main DB, which is unique per env; every column
                // namespace needs its own named sub-DB.
                const name_z = try std.fmt.allocPrintSentinel(allocator, "{s}", .{cn.namespace}, 0);
                defer allocator.free(name_z);
                dbi_handles[i] = txn.openDbi(name_z, true) catch |err| {
                    logger.err("failed to open LMDB sub-db '{s}': {any}", .{ cn.namespace, err });
                    return error.LmdbOpen;
                };
            }

            txn.commit() catch |err| {
                logger.err("failed to commit LMDB bootstrap txn: {any}", .{err});
                return error.LmdbOpen;
            };

            return Self{
                .env = env,
                .dbi_handles = dbi_handles,
                .allocator = allocator,
                .path = owned_path,
                .logger = logger,
            };
        }

        pub fn deinit(self: *Self) void {
            self.env.close();
            self.allocator.free(self.path);
        }

        pub fn count(self: *Self, comptime cn: ColumnNamespace) Allocator.Error!u64 {
            var txn = self.env.beginTxn(true) catch |err| {
                self.logger.err("count: failed to open read txn: {any}", .{err});
                return 0;
            };
            defer txn.abort();

            var cur = txn.openCursor(self.dbi_handles[cn.find(column_namespaces)]) catch |err| {
                self.logger.err("count: failed to open cursor: {any}", .{err});
                return 0;
            };
            defer cur.close();

            var n: u64 = 0;
            var entry = cur.first() catch |err| {
                self.logger.err("count: cursor.first failed: {any}", .{err});
                return 0;
            };
            while (entry) |_| : (entry = cur.next() catch |err| {
                self.logger.err("count: cursor.next failed: {any}", .{err});
                return n;
            }) {
                n += 1;
            }
            return n;
        }

        pub fn put(self: *Self, comptime cn: ColumnNamespace, key: cn.Key, value: cn.Value) !void {
            var txn = self.env.beginTxn(false) catch |err| {
                self.logger.err("put: failed to open write txn: {any}", .{err});
                return error.LmdbPut;
            };
            errdefer txn.abort();

            txn.put(self.dbi_handles[cn.find(column_namespaces)], key, value) catch |err| {
                self.logger.err("put: txn.put failed: {any}", .{err});
                return error.LmdbPut;
            };
            txn.commit() catch |err| {
                self.logger.err("put: txn.commit failed: {any}", .{err});
                return error.LmdbPut;
            };
        }

        /// Returns a heap-allocated copy of the value (caller must
        /// `Data.deinit`). LMDB's native `get` returns a slice into the
        /// memory map whose lifetime ends with the transaction, so we
        /// copy eagerly to match the `RocksDB.get` contract.
        pub fn get(self: *Self, comptime cn: ColumnNamespace, key: cn.Key) !?Data {
            var txn = self.env.beginTxn(true) catch |err| {
                self.logger.err("get: failed to open read txn: {any}", .{err});
                return error.LmdbGet;
            };
            defer txn.abort();

            const maybe = txn.get(self.dbi_handles[cn.find(column_namespaces)], key) catch |err| {
                self.logger.err("get: txn.get failed: {any}", .{err});
                return error.LmdbGet;
            };
            const raw = maybe orelse return null;

            const copy = try self.allocator.dupe(u8, raw);
            return Data{ .allocator = self.allocator, .data = copy };
        }

        pub fn delete(self: *Self, comptime cn: ColumnNamespace, key: cn.Key) !void {
            var txn = self.env.beginTxn(false) catch |err| {
                self.logger.err("delete: failed to open write txn: {any}", .{err});
                return error.LmdbDelete;
            };
            errdefer txn.abort();

            txn.delete(self.dbi_handles[cn.find(column_namespaces)], key) catch |err| {
                self.logger.err("delete: txn.delete failed: {any}", .{err});
                return error.LmdbDelete;
            };
            txn.commit() catch |err| {
                self.logger.err("delete: txn.commit failed: {any}", .{err});
                return error.LmdbDelete;
            };
        }

        /// LMDB has no direct analogue to RocksDB's
        /// `delete_files_in_range`. Implement by scanning with a cursor
        /// and deleting every key in [start_key, end_key). The range is
        /// half-open, matching the RocksDB contract.
        pub fn deleteFilesInRange(self: *Self, comptime cn: ColumnNamespace, start_key: cn.Key, end_key: cn.Key) !void {
            var txn = self.env.beginTxn(false) catch |err| {
                self.logger.err("deleteFilesInRange: failed to open write txn: {any}", .{err});
                return error.LmdbDeleteRange;
            };
            errdefer txn.abort();

            const dbi = self.dbi_handles[cn.find(column_namespaces)];

            // Collect keys first, then delete; mutating during cursor
            // iteration is safe in LMDB but less obviously correct.
            var keys: std.ArrayListUnmanaged([]u8) = .empty;
            defer {
                for (keys.items) |k| self.allocator.free(k);
                keys.deinit(self.allocator);
            }

            var cur = txn.openCursor(dbi) catch |err| {
                self.logger.err("deleteFilesInRange: openCursor failed: {any}", .{err});
                return error.LmdbDeleteRange;
            };
            var entry = cur.seekRange(start_key) catch |err| {
                cur.close();
                self.logger.err("deleteFilesInRange: seekRange failed: {any}", .{err});
                return error.LmdbDeleteRange;
            };
            while (entry) |e| : (entry = cur.next() catch |err| {
                cur.close();
                self.logger.err("deleteFilesInRange: cursor.next failed: {any}", .{err});
                return error.LmdbDeleteRange;
            }) {
                if (std.mem.order(u8, e.key, end_key) != .lt) break;
                const owned = try self.allocator.dupe(u8, e.key);
                try keys.append(self.allocator, owned);
            }
            cur.close();

            for (keys.items) |k| {
                txn.delete(dbi, k) catch |err| {
                    self.logger.err("deleteFilesInRange: txn.delete failed: {any}", .{err});
                    return error.LmdbDeleteRange;
                };
            }
            txn.commit() catch |err| {
                self.logger.err("deleteFilesInRange: txn.commit failed: {any}", .{err});
                return error.LmdbDeleteRange;
            };
        }

        pub fn initWriteBatch(self: *Self) Error!WriteBatch {
            const txn = self.env.beginTxn(false) catch |err| {
                self.logger.err("initWriteBatch: failed to open write txn: {any}", .{err});
                return error.LmdbBatch;
            };
            return .{
                .allocator = self.allocator,
                .dbi_handles = &self.dbi_handles,
                .logger = self.logger,
                .txn = txn,
                .failed = false,
            };
        }

        /// Commit a write batch.
        ///
        /// Two ways this can fail:
        ///   1. One of the queued `put`/`delete` calls already failed
        ///      (tracked in `batch.failed`). The txn is poisoned, so
        ///      abort it and surface `error.LmdbBatch` rather than
        ///      committing a partial batch.
        ///   2. `txn.commit()` itself fails (disk full, MDB_MAP_FULL,
        ///      EIO, ...). Surface `error.LmdbCommit`.
        ///
        /// Either way the txn handle is consumed — the batch is left in
        /// the "already committed / aborted" state so `deinit` is a
        /// no-op.
        pub fn commit(self: *Self, batch: *WriteBatch) Error!void {
            _ = self;
            const txn_ptr = if (batch.txn) |*t| t else return;

            if (batch.failed) {
                txn_ptr.abort();
                batch.txn = null;
                batch.logger.err("commit: refusing to commit batch with failed ops", .{});
                return error.LmdbBatch;
            }

            txn_ptr.commit() catch |err| {
                batch.logger.err("commit: txn.commit failed: {any}", .{err});
                batch.txn = null;
                return error.LmdbCommit;
            };
            batch.txn = null;
        }

        /// LMDB is sync-on-commit by default; this is a no-op but kept
        /// to satisfy the RocksDB-shaped API.
        pub fn flush(self: *Self, comptime cn: ColumnNamespace) error{LmdbFlush}!void {
            _ = cn;
            self.env.sync(true) catch |err| {
                self.logger.err("flush: env.sync failed: {any}", .{err});
                return error.LmdbFlush;
            };
        }

        pub const WriteBatch = struct {
            allocator: Allocator,
            dbi_handles: *const [column_namespaces.len]lmdb.Dbi,
            logger: zeam_utils.ModuleLogger,
            /// Present while the batch is still pending. Cleared to
            /// `null` once the batch is committed or aborted so
            /// `deinit` knows not to abort a spent txn.
            txn: ?lmdb.Txn,
            /// Sticky flag set by any queued `put`/`delete`/`deleteRange`
            /// that failed mid-batch. `commit` refuses to commit a
            /// poisoned batch and surfaces `error.LmdbBatch` so the
            /// caller can react. Without this, a single silent
            /// `MDB_MAP_FULL` on `put` would leave the chain believing a
            /// partial batch was durably persisted.
            failed: bool,

            pub fn deinit(self: *WriteBatch) void {
                if (self.txn) |*txn| {
                    txn.abort();
                    self.txn = null;
                }
            }

            pub fn put(self: *WriteBatch, comptime cn: ColumnNamespace, key: cn.Key, value: cn.Value) void {
                var txn = &(self.txn orelse return);
                txn.put(self.dbi_handles[cn.find(column_namespaces)], key, value) catch |err| {
                    self.logger.err("batch put: txn.put failed: {any}", .{err});
                    self.failed = true;
                };
            }

            pub fn delete(self: *WriteBatch, comptime cn: ColumnNamespace, key: cn.Key) void {
                var txn = &(self.txn orelse return);
                txn.delete(self.dbi_handles[cn.find(column_namespaces)], key) catch |err| {
                    self.logger.err("batch delete: txn.delete failed: {any}", .{err});
                    self.failed = true;
                };
            }

            pub fn deleteRange(self: *WriteBatch, comptime cn: ColumnNamespace, start: cn.Key, end: cn.Key) void {
                var txn = &(self.txn orelse return);
                const dbi = self.dbi_handles[cn.find(column_namespaces)];
                var cur = txn.openCursor(dbi) catch |err| {
                    self.logger.err("batch deleteRange: openCursor failed: {any}", .{err});
                    self.failed = true;
                    return;
                };
                defer cur.close();

                var keys: std.ArrayListUnmanaged([]u8) = .empty;
                defer {
                    for (keys.items) |k| self.allocator.free(k);
                    keys.deinit(self.allocator);
                }

                var entry = cur.seekRange(start) catch |err| {
                    self.logger.err("batch deleteRange: seekRange failed: {any}", .{err});
                    self.failed = true;
                    return;
                };
                while (entry) |e| : (entry = cur.next() catch |err| {
                    self.logger.err("batch deleteRange: cursor.next failed: {any}", .{err});
                    self.failed = true;
                    return;
                }) {
                    if (std.mem.order(u8, e.key, end) != .lt) break;
                    const owned = self.allocator.dupe(u8, e.key) catch |err| {
                        self.logger.err("batch deleteRange: dupe failed: {any}", .{err});
                        self.failed = true;
                        return;
                    };
                    keys.append(self.allocator, owned) catch |err| {
                        self.allocator.free(owned);
                        self.logger.err("batch deleteRange: append failed: {any}", .{err});
                        self.failed = true;
                        return;
                    };
                }

                for (keys.items) |k| {
                    txn.delete(dbi, k) catch |err| {
                        self.logger.err("batch deleteRange: txn.delete failed: {any}", .{err});
                        self.failed = true;
                    };
                }
            }

            fn putToBatch(
                self: *WriteBatch,
                comptime T: type,
                key: []const u8,
                value: T,
                comptime cn: ColumnNamespace,
                comptime log_message: []const u8,
                log_args: anytype,
            ) void {
                var serialized_value: std.ArrayList(u8) = .empty;
                defer serialized_value.deinit(self.allocator);

                ssz.serialize(T, value, &serialized_value, self.allocator) catch |err| {
                    self.logger.err("failed to serialize value for putToBatch: {any}", .{err});
                    return;
                };

                self.put(cn, key, serialized_value.items);
                self.logger.debug(log_message, log_args);
            }

            pub fn putBlock(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                block_root: types.Root,
                block: types.SignedBlock,
            ) void {
                const key = interface.formatBlockKey(self.allocator, &block_root) catch |err| {
                    self.logger.err("failed to format block key for putBlock: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.putToBatch(
                    types.SignedBlock,
                    key,
                    block,
                    cn,
                    "added block to batch: root=0x{x}",
                    .{&block_root},
                );
            }

            pub fn putBlockSerialized(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                block_root: types.Root,
                serialized_block: []const u8,
            ) void {
                const key = interface.formatBlockKey(self.allocator, &block_root) catch |err| {
                    self.logger.err("failed to format block key for putBlockSerialized: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.put(cn, key, serialized_block);
                self.logger.debug("added pre-serialized block to batch: root=0x{x} len={d}", .{ &block_root, serialized_block.len });
            }

            pub fn putState(
                self: *WriteBatch,
                comptime cn: ColumnNamespace,
                state_root: types.Root,
                state: types.BeamState,
            ) void {
                const key = interface.formatStateKey(self.allocator, &state_root) catch |err| {
                    self.logger.err("failed to format state key for putState: {any}", .{err});
                    return;
                };
                defer self.allocator.free(key);

                self.putToBatch(
                    types.BeamState,
                    key,
                    state,
                    cn,
                    "added state to batch: root=0x{x}",
                    .{&state_root},
                );
            }

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
                    "added finalized slot index to batch: slot={d} root=0x{x}",
                    .{ slot, &blockroot },
                );
            }

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
            var txn = self.env.beginTxn(true) catch |err| {
                self.logger.err("iterator: failed to open read txn: {any}", .{err});
                return error.LmdbIterator;
            };
            errdefer txn.abort();

            var cur = txn.openCursor(self.dbi_handles[cn.find(column_namespaces)]) catch |err| {
                self.logger.err("iterator: openCursor failed: {any}", .{err});
                return error.LmdbIterator;
            };
            errdefer cur.close();

            return .{
                .allocator = self.allocator,
                .logger = self.logger,
                .txn = txn,
                .cursor = cur,
                .started = false,
                .start = start,
            };
        }

        pub fn Iterator(cf: ColumnNamespace, dir: interface.IteratorDirection) type {
            return struct {
                allocator: Allocator,
                logger: zeam_utils.ModuleLogger,
                txn: lmdb.Txn,
                cursor: lmdb.Cursor,
                /// First `next` call seeds the cursor; later calls step.
                started: bool,
                /// Optional seek target. `null` means start at the
                /// first/last key depending on direction.
                start: ?cf.Key,
                /// Backing storage for the current entry. `next`
                /// returns slices pointing into this buffer; the
                /// previous entry is invalidated on the next call.
                cur_key: std.ArrayListUnmanaged(u8) = .empty,
                cur_value: std.ArrayListUnmanaged(u8) = .empty,

                const Iter = @This();

                pub fn deinit(self: *Iter) void {
                    self.cur_key.deinit(self.allocator);
                    self.cur_value.deinit(self.allocator);
                    self.cursor.close();
                    self.txn.abort();
                }

                pub fn next(self: *Iter) !?cf.Entry() {
                    const entry = (try self.advance()) orelse return null;
                    return .{ entry.key, entry.value };
                }

                pub fn nextKey(self: *Iter) !?cf.Key {
                    const entry = (try self.advance()) orelse return null;
                    return entry.key;
                }

                pub fn nextValue(self: *Iter) !?cf.Value {
                    const entry = (try self.advance()) orelse return null;
                    return entry.value;
                }

                fn advance(self: *Iter) !?lmdb.Entry {
                    const raw: ?lmdb.Entry = if (!self.started) blk: {
                        self.started = true;
                        break :blk try self.seedCursor();
                    } else blk: {
                        break :blk switch (dir) {
                            .forward => self.cursor.next() catch |err| {
                                self.logger.err("iterator: next failed: {any}", .{err});
                                return error.LmdbIterator;
                            },
                            .reverse => self.cursor.prev() catch |err| {
                                self.logger.err("iterator: prev failed: {any}", .{err});
                                return error.LmdbIterator;
                            },
                        };
                    };

                    const entry = raw orelse return null;
                    self.cur_key.clearRetainingCapacity();
                    self.cur_value.clearRetainingCapacity();
                    try self.cur_key.appendSlice(self.allocator, entry.key);
                    try self.cur_value.appendSlice(self.allocator, entry.value);
                    return lmdb.Entry{ .key = self.cur_key.items, .value = self.cur_value.items };
                }

                fn seedCursor(self: *Iter) !?lmdb.Entry {
                    return switch (dir) {
                        .forward => if (self.start) |needle|
                            self.cursor.seekRange(needle) catch |err| {
                                self.logger.err("iterator: seekRange failed: {any}", .{err});
                                return error.LmdbIterator;
                            }
                        else
                            self.cursor.first() catch |err| {
                                self.logger.err("iterator: first failed: {any}", .{err});
                                return error.LmdbIterator;
                            },
                        .reverse => if (self.start) |needle| rev: {
                            // Reverse iteration from a seek target:
                            // position at the smallest key >= needle,
                            // then step back. If no such key exists,
                            // LMDB leaves the cursor unpositioned, so
                            // jump to `last` as the tail of the range.
                            const maybe = self.cursor.seekRange(needle) catch |err| {
                                self.logger.err("iterator: seekRange failed: {any}", .{err});
                                return error.LmdbIterator;
                            };
                            if (maybe == null) break :rev self.cursor.last() catch |err| {
                                self.logger.err("iterator: last failed: {any}", .{err});
                                return error.LmdbIterator;
                            };
                            break :rev self.cursor.prev() catch |err| {
                                self.logger.err("iterator: prev failed: {any}", .{err});
                                return error.LmdbIterator;
                            };
                        } else self.cursor.last() catch |err| {
                            self.logger.err("iterator: last failed: {any}", .{err});
                            return error.LmdbIterator;
                        },
                    };
                }
            };
        }

        fn saveToDatabase(
            self: *Self,
            comptime T: type,
            key: []const u8,
            value: T,
            comptime cn: ColumnNamespace,
            comptime log_message: []const u8,
            log_args: anytype,
        ) void {
            var serialized_value: std.ArrayList(u8) = .empty;
            defer serialized_value.deinit(self.allocator);

            ssz.serialize(T, value, &serialized_value, self.allocator) catch |err| {
                self.logger.err("failed to serialize value for saveToDatabase: {any}", .{err});
                return;
            };

            self.put(cn, key, serialized_value.items) catch |err| {
                self.logger.err("failed to put value to database in saveToDatabase: {any}", .{err});
                return;
            };
            self.logger.debug(log_message, log_args);
        }

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

        pub fn saveBlock(self: *Self, comptime cn: ColumnNamespace, block_root: types.Root, block: types.SignedBlock) void {
            const key = interface.formatBlockKey(self.allocator, &block_root) catch |err| {
                self.logger.err("failed to format block key for saveBlock: {any}", .{err});
                return;
            };
            defer self.allocator.free(key);

            self.saveToDatabase(
                types.SignedBlock,
                key,
                block,
                cn,
                "saved block to database: root=0x{x}",
                .{&block_root},
            );
        }

        pub fn loadBlock(self: *Self, comptime cn: ColumnNamespace, block_root: types.Root) ?types.SignedBlock {
            const key = interface.formatBlockKey(self.allocator, &block_root) catch |err| {
                self.logger.err("failed to format block key for loadBlock: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            return self.loadFromDatabase(
                types.SignedBlock,
                key,
                cn,
                "loaded block from database: root=0x{x}",
                .{&block_root},
            );
        }

        /// Returns raw SSZ bytes for a block without deserialising.
        /// Caller must free the returned slice with `allocator.free`.
        pub fn loadBlockBytes(
            self: *Self,
            comptime cn: ColumnNamespace,
            block_root: types.Root,
            allocator: std.mem.Allocator,
        ) ?[]u8 {
            const key = interface.formatBlockKey(self.allocator, &block_root) catch |err| {
                self.logger.err("failed to format block key for loadBlockBytes: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            const maybe_data = self.get(cn, key) catch return null;
            const data = maybe_data orelse return null;
            defer data.deinit();
            return allocator.dupe(u8, data.data) catch null;
        }

        pub fn saveState(self: *Self, comptime cn: ColumnNamespace, state_root: types.Root, state: types.BeamState) void {
            const key = interface.formatStateKey(self.allocator, &state_root) catch |err| {
                self.logger.err("failed to format state key for saveState: {any}", .{err});
                return;
            };
            defer self.allocator.free(key);

            self.saveToDatabase(
                types.BeamState,
                key,
                state,
                cn,
                "saved state to database: root=0x{x}",
                .{&state_root},
            );
        }

        pub fn loadState(self: *Self, comptime cn: ColumnNamespace, state_root: types.Root) ?types.BeamState {
            const key = interface.formatStateKey(self.allocator, &state_root) catch |err| {
                self.logger.err("failed to format state key for loadState: {any}", .{err});
                return null;
            };
            defer self.allocator.free(key);

            return self.loadFromDatabase(
                types.BeamState,
                key,
                cn,
                "loaded state from database: root=0x{x}",
                .{&state_root},
            );
        }

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

        pub fn loadAttestation(self: *Self, comptime cn: ColumnNamespace, attestation_key: []const u8) ?types.SignedAttestation {
            return self.loadFromDatabase(
                types.SignedAttestation,
                attestation_key,
                cn,
                "loaded attestation from database: key={s}",
                .{attestation_key},
            );
        }

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

        pub fn loadLatestFinalizedState(self: *Self, state_ptr: *types.BeamState) !void {
            const finalized_slot = self.loadLatestFinalizedSlot(database.DbDefaultNamespace) orelse {
                self.logger.info("no finalized slot metadata found in database, will use genesis", .{});
                return error.NoFinalizedStateFound;
            };

            self.logger.info("found latest finalized slot {d} in database, loading block root...", .{finalized_slot});

            const block_root = self.loadFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, finalized_slot) orelse {
                self.logger.warn("finalized slot {d} found in metadata but block root not in finalized index — database may be corrupt", .{finalized_slot});
                return error.FinalizedSlotNotFoundInIndex;
            };

            self.logger.info("found block root 0x{x} for finalized slot {d}, loading state...", .{ &block_root, finalized_slot });

            if (self.loadState(database.DbStatesNamespace, block_root)) |state| {
                state_ptr.* = state;
                self.logger.info("successfully recovered finalized state from database: slot={d}, block_root=0x{x}", .{ finalized_slot, &block_root });
                return;
            } else {
                self.logger.warn("finalized slot {d} block_root=0x{x} found in index but state not in database — state may have been pruned or database is corrupt", .{ finalized_slot, &block_root });
                return error.FinalizedStateNotFoundInDatabase;
            }
        }

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
            LmdbOpen,
            LmdbPut,
            LmdbGet,
            LmdbDelete,
            LmdbDeleteRange,
            LmdbIterator,
            LmdbFlush,
            LmdbBatch,
            LmdbCommit,
        } || Allocator.Error;
    };
}

/// Heap-owned copy of a value returned by `Lmdb.get`. The raw slice
/// returned by LMDB lives only for the transaction's lifetime, so `get`
/// copies into `data`; callers must call `deinit` to release it.
pub const Data = struct {
    allocator: Allocator,
    data: []const u8,

    pub fn deinit(self: Data) void {
        self.allocator.free(self.data);
    }
};
