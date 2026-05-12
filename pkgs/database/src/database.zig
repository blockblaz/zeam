const std = @import("std");
const Allocator = std.mem.Allocator;

const interface = @import("./interface.zig");
const rocksdb_impl = @import("./rocksdb.zig");
const lmdb_impl = @import("./lmdb.zig");
const test_helpers = @import("./test_helpers.zig");

const zeam_utils = @import("@zeam/utils");
const types = @import("@zeam/types");

pub const ColumnNamespace = interface.ColumnNamespace;

pub const DbColumnNamespaces = [_]interface.ColumnNamespace{
    .{ .namespace = "default", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "blocks", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "states", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "attestations", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "checkpoints", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "finalized_slots", .Key = []const u8, .Value = []const u8 },
    .{ .namespace = "unfinalized_slots", .Key = []const u8, .Value = []const u8 },
};

pub const DbDefaultNamespace = DbColumnNamespaces[0];
pub const DbBlocksNamespace = DbColumnNamespaces[1];
pub const DbStatesNamespace = DbColumnNamespaces[2];
pub const DbAttestationsNamespace = DbColumnNamespaces[3];
pub const DbCheckpointsNamespace = DbColumnNamespaces[4];
pub const DbFinalizedSlotsNamespace = DbColumnNamespaces[5];
// TODO: uncomment this code if there is a need of slot to unfinalized index
// pub const DbUnfinalizedSlotsNamespace = DbColumnNamespaces[6];

/// Concrete backend types specialised to zeam's column namespaces.
/// Exposed so tests and tooling can construct a specific backend
/// directly without going through the `Db` tagged union.
pub const RocksDbBackend = rocksdb_impl.RocksDB(&DbColumnNamespaces);
pub const LmdbBackend = lmdb_impl.Lmdb(&DbColumnNamespaces);

/// Which storage engine to use at runtime. Exposed through
/// `--db-backend <rocksdb|lmdb>`.
pub const Backend = enum {
    rocksdb,
    lmdb,

    pub fn fromString(s: []const u8) ?Backend {
        if (std.ascii.eqlIgnoreCase(s, "rocksdb")) return .rocksdb;
        if (std.ascii.eqlIgnoreCase(s, "lmdb")) return .lmdb;
        return null;
    }
};

/// If the operator previously ran with the *other* backend, that
/// backend's on-disk directory (`{path}/rocksdb` or `{path}/lmdb`)
/// will still contain chain data. Silently starting from genesis on
/// the newly selected engine is almost always a surprise, so log a
/// loud warning. Best-effort: any filesystem error here is suppressed
/// — it is a diagnostic, not a correctness barrier.
fn warnIfOtherBackendPopulated(
    logger: zeam_utils.ModuleLogger,
    path: []const u8,
    selected: Backend,
) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const other: Backend = switch (selected) {
        .rocksdb => .lmdb,
        .lmdb => .rocksdb,
    };
    const other_name = switch (other) {
        .rocksdb => "rocksdb",
        .lmdb => "lmdb",
    };

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const other_path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ path, other_name }) catch return;

    var dir = std.Io.Dir.cwd().openDir(io, other_path, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    const has_entries = while (it.next(io) catch return) |_| break true else false;
    if (!has_entries) return;

    const selected_name = switch (selected) {
        .rocksdb => "rocksdb",
        .lmdb => "lmdb",
    };
    logger.warn(
        "detected existing {s} data at {s} while starting with --db-backend {s}; " ++
            "the previous engine's data is NOT migrated. Delete {s} or switch back to " ++
            "--db-backend {s} to re-use it.",
        .{ other_name, other_path, selected_name, other_path, other_name },
    );
}

/// Runtime-selectable database handle. Both variants implement the
/// same method surface (matching the RocksDB-shaped API used by
/// `pkgs/node`); the `switch` arms below forward every call to the
/// active backend.
///
/// The tagged-union shape (rather than a vtable) is deliberate: every
/// method takes `comptime cn: ColumnNamespace`, and comptime arguments
/// survive `switch` dispatch but not pointer indirection.
pub const Db = union(Backend) {
    rocksdb: RocksDbBackend,
    lmdb: LmdbBackend,

    /// Open with the default backend (rocksdb). Kept for call sites
    /// that don't care which engine is used (tests, legacy paths).
    pub fn open(
        allocator: Allocator,
        logger: zeam_utils.ModuleLogger,
        path: []const u8,
    ) !Db {
        return openBackend(allocator, logger, path, .rocksdb);
    }

    /// Open with an explicitly chosen backend. Used by the CLI so
    /// operators can select the engine via `--db-backend`.
    pub fn openBackend(
        allocator: Allocator,
        logger: zeam_utils.ModuleLogger,
        path: []const u8,
        backend: Backend,
    ) !Db {
        warnIfOtherBackendPopulated(logger, path, backend);
        return switch (backend) {
            .rocksdb => Db{ .rocksdb = try RocksDbBackend.open(allocator, logger, path) },
            .lmdb => Db{ .lmdb = try LmdbBackend.open(allocator, logger, path) },
        };
    }

    pub fn deinit(self: *Db) void {
        switch (self.*) {
            inline else => |*impl| impl.deinit(),
        }
    }

    pub fn count(self: *Db, comptime cn: ColumnNamespace) Allocator.Error!u64 {
        switch (self.*) {
            inline else => |*impl| return impl.count(cn),
        }
    }

    pub fn put(self: *Db, comptime cn: ColumnNamespace, key: cn.Key, value: cn.Value) !void {
        switch (self.*) {
            inline else => |*impl| try impl.put(cn, key, value),
        }
    }

    pub fn delete(self: *Db, comptime cn: ColumnNamespace, key: cn.Key) !void {
        switch (self.*) {
            inline else => |*impl| try impl.delete(cn, key),
        }
    }

    pub fn deleteFilesInRange(
        self: *Db,
        comptime cn: ColumnNamespace,
        start_key: cn.Key,
        end_key: cn.Key,
    ) !void {
        switch (self.*) {
            inline else => |*impl| try impl.deleteFilesInRange(cn, start_key, end_key),
        }
    }

    pub fn flush(self: *Db, comptime cn: ColumnNamespace) !void {
        switch (self.*) {
            inline else => |*impl| try impl.flush(cn),
        }
    }

    pub fn initWriteBatch(self: *Db) !WriteBatch {
        return switch (self.*) {
            .rocksdb => |*r| WriteBatch{ .rocksdb = r.initWriteBatch() },
            .lmdb => |*l| WriteBatch{ .lmdb = try l.initWriteBatch() },
        };
    }

    /// Commit a write batch. Propagates the underlying backend's
    /// error so consensus-critical writes (finalization advancement,
    /// state persistence) can detect a failed commit instead of
    /// silently continuing as if the write succeeded.
    pub fn commit(self: *Db, batch: *WriteBatch) !void {
        switch (self.*) {
            .rocksdb => |*r| {
                std.debug.assert(batch.* == .rocksdb);
                try r.commit(&batch.rocksdb);
            },
            .lmdb => |*l| {
                std.debug.assert(batch.* == .lmdb);
                try l.commit(&batch.lmdb);
            },
        }
    }

    pub fn iterator(
        self: *Db,
        comptime cn: ColumnNamespace,
        comptime direction: interface.IteratorDirection,
        start: ?cn.Key,
    ) !Iterator(cn, direction) {
        return switch (self.*) {
            .rocksdb => |*r| Iterator(cn, direction){ .rocksdb = try r.iterator(cn, direction, start) },
            .lmdb => |*l| Iterator(cn, direction){ .lmdb = try l.iterator(cn, direction, start) },
        };
    }

    // SSZ convenience helpers. Each backend implements the full suite
    // independently, so the dispatch is uniform.

    pub fn saveBlock(self: *Db, comptime cn: ColumnNamespace, block_root: types.Root, block: types.SignedBlock) void {
        switch (self.*) {
            inline else => |*impl| impl.saveBlock(cn, block_root, block),
        }
    }

    pub fn loadBlock(self: *Db, comptime cn: ColumnNamespace, block_root: types.Root) ?types.SignedBlock {
        return switch (self.*) {
            inline else => |*impl| impl.loadBlock(cn, block_root),
        };
    }

    /// Returns the raw SSZ bytes for a block without deserialising, or null if
    /// not found.  Caller must free the returned slice with `allocator.free`.
    /// Prefer this over `loadBlock` when only the serialised bytes are needed
    /// (e.g. serving blocks_by_root) to avoid an unnecessary SSZ round-trip.
    pub fn loadBlockBytes(
        self: *Db,
        comptime cn: ColumnNamespace,
        block_root: types.Root,
        allocator: std.mem.Allocator,
    ) ?[]u8 {
        return switch (self.*) {
            inline else => |*impl| impl.loadBlockBytes(cn, block_root, allocator),
        };
    }

    pub fn saveState(self: *Db, comptime cn: ColumnNamespace, state_root: types.Root, state: types.BeamState) void {
        switch (self.*) {
            inline else => |*impl| impl.saveState(cn, state_root, state),
        }
    }

    pub fn loadState(self: *Db, comptime cn: ColumnNamespace, state_root: types.Root) ?types.BeamState {
        return switch (self.*) {
            inline else => |*impl| impl.loadState(cn, state_root),
        };
    }

    pub fn saveAttestation(
        self: *Db,
        comptime cn: ColumnNamespace,
        attestation_key: []const u8,
        attestation: types.SignedAttestation,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.saveAttestation(cn, attestation_key, attestation),
        }
    }

    pub fn loadAttestation(
        self: *Db,
        comptime cn: ColumnNamespace,
        attestation_key: []const u8,
    ) ?types.SignedAttestation {
        return switch (self.*) {
            inline else => |*impl| impl.loadAttestation(cn, attestation_key),
        };
    }

    pub fn loadFinalizedSlotIndex(
        self: *Db,
        comptime cn: ColumnNamespace,
        slot: types.Slot,
    ) ?types.Root {
        return switch (self.*) {
            inline else => |*impl| impl.loadFinalizedSlotIndex(cn, slot),
        };
    }

    pub fn loadLatestFinalizedSlot(self: *Db, comptime cn: ColumnNamespace) ?types.Slot {
        return switch (self.*) {
            inline else => |*impl| impl.loadLatestFinalizedSlot(cn),
        };
    }

    pub fn loadLatestFinalizedState(self: *Db, state_ptr: *types.BeamState) !void {
        switch (self.*) {
            inline else => |*impl| try impl.loadLatestFinalizedState(state_ptr),
        }
    }

    pub fn loadUnfinalizedSlotIndex(
        self: *Db,
        comptime cn: ColumnNamespace,
        slot: types.Slot,
    ) ?[]types.Root {
        return switch (self.*) {
            inline else => |*impl| impl.loadUnfinalizedSlotIndex(cn, slot),
        };
    }
};

/// Cross-backend write batch. Every method forwards to the active
/// backend's own batch implementation, which preserves transactional
/// semantics (all-or-nothing on commit, caller frees uncommitted work
/// via `deinit`).
pub const WriteBatch = union(Backend) {
    rocksdb: RocksDbBackend.WriteBatch,
    lmdb: LmdbBackend.WriteBatch,

    pub fn deinit(self: *WriteBatch) void {
        switch (self.*) {
            inline else => |*impl| impl.deinit(),
        }
    }

    pub fn put(self: *WriteBatch, comptime cn: ColumnNamespace, key: cn.Key, value: cn.Value) void {
        switch (self.*) {
            inline else => |*impl| impl.put(cn, key, value),
        }
    }

    pub fn delete(self: *WriteBatch, comptime cn: ColumnNamespace, key: cn.Key) void {
        switch (self.*) {
            inline else => |*impl| impl.delete(cn, key),
        }
    }

    pub fn deleteRange(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        start: cn.Key,
        end: cn.Key,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.deleteRange(cn, start, end),
        }
    }

    pub fn putBlock(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        block_root: types.Root,
        block: types.SignedBlock,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putBlock(cn, block_root, block),
        }
    }

    pub fn putBlockSerialized(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        block_root: types.Root,
        serialized_block: []const u8,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putBlockSerialized(cn, block_root, serialized_block),
        }
    }

    pub fn putState(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        state_root: types.Root,
        state: types.BeamState,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putState(cn, state_root, state),
        }
    }

    pub fn putAttestation(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        attestation_key: []const u8,
        attestation: types.SignedAttestation,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putAttestation(cn, attestation_key, attestation),
        }
    }

    pub fn putFinalizedSlotIndex(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        slot: types.Slot,
        blockroot: types.Root,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putFinalizedSlotIndex(cn, slot, blockroot),
        }
    }

    pub fn putLatestFinalizedSlot(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        slot: types.Slot,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putLatestFinalizedSlot(cn, slot),
        }
    }

    pub fn putUnfinalizedSlotIndex(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        slot: types.Slot,
        blockroots: []const types.Root,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.putUnfinalizedSlotIndex(cn, slot, blockroots),
        }
    }

    pub fn deleteUnfinalizedSlotIndexFromBatch(
        self: *WriteBatch,
        comptime cn: ColumnNamespace,
        slot: types.Slot,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.deleteUnfinalizedSlotIndexFromBatch(cn, slot),
        }
    }
};

/// Cross-backend iterator. Parametric on column namespace + direction so
/// the comptime types flow through identically to the per-backend
/// iterator types.
pub fn Iterator(cf: ColumnNamespace, dir: interface.IteratorDirection) type {
    return union(Backend) {
        rocksdb: RocksDbBackend.Iterator(cf, dir),
        lmdb: LmdbBackend.Iterator(cf, dir),

        const Iter = @This();

        pub fn deinit(self: *Iter) void {
            switch (self.*) {
                inline else => |*impl| impl.deinit(),
            }
        }

        pub fn next(self: *Iter) !?cf.Entry() {
            return switch (self.*) {
                inline else => |*impl| try impl.next(),
            };
        }

        pub fn nextKey(self: *Iter) !?cf.Key {
            return switch (self.*) {
                inline else => |*impl| try impl.nextKey(),
            };
        }

        pub fn nextValue(self: *Iter) !?cf.Value {
            return switch (self.*) {
                inline else => |*impl| try impl.nextValue(),
            };
        }
    };
}

// The tests below exercise the tagged-union `Db` dispatch through both
// backends, guaranteeing behavioural parity at the public API surface.
// Each test opens a fresh temp directory with the requested backend and
// runs the same store/load/batch workflow.

test "Db tagged-union: save and load block (lmdb)" {
    try testSaveAndLoadBlock(.lmdb);
}

test "Db tagged-union: save and load block (rocksdb)" {
    try testSaveAndLoadBlock(.rocksdb);
}

test "Db tagged-union: batch write and commit (lmdb)" {
    try testBatchWriteAndCommit(.lmdb);
}

test "Db tagged-union: batch write and commit (rocksdb)" {
    try testBatchWriteAndCommit(.rocksdb);
}

test "Db tagged-union: loadLatestFinalizedState happy path (lmdb)" {
    try testLoadLatestFinalizedStateHappyPath(.lmdb);
}

test "Db tagged-union: loadLatestFinalizedState happy path (rocksdb)" {
    try testLoadLatestFinalizedStateHappyPath(.rocksdb);
}

fn testSaveAndLoadBlock(backend: Backend) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try Db.openBackend(allocator, zeam_logger_config.logger(.database_test), data_dir, backend);
    defer db.deinit();

    const block_root = test_helpers.createDummyRoot(0xAB);

    var attestation_signatures = try test_helpers.createDummyAttestationSignatures(allocator, 3);
    var attestation_signatures_cleanup = true;
    errdefer if (attestation_signatures_cleanup) {
        for (attestation_signatures.slice()) |*sig| {
            sig.deinit();
        }
        attestation_signatures.deinit();
    };

    var signed_block = try test_helpers.createDummyBlock(allocator, 1, 0, 0xCD, 0xEF, attestation_signatures);
    attestation_signatures_cleanup = false;
    defer signed_block.deinit();

    db.saveBlock(DbBlocksNamespace, block_root, signed_block);

    const loaded = db.loadBlock(DbBlocksNamespace, block_root);
    try std.testing.expect(loaded != null);
    try std.testing.expectEqual(signed_block.block.slot, loaded.?.block.slot);
    try std.testing.expectEqual(signed_block.block.proposer_index, loaded.?.block.proposer_index);
    try std.testing.expect(std.mem.eql(u8, &signed_block.block.parent_root, &loaded.?.block.parent_root));

    try std.testing.expect(db.loadBlock(DbBlocksNamespace, test_helpers.createDummyRoot(0xFF)) == null);
}

fn testBatchWriteAndCommit(backend: Backend) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try Db.openBackend(allocator, zeam_logger_config.logger(.database_test), data_dir, backend);
    defer db.deinit();

    const block_root = test_helpers.createDummyRoot(0xAA);
    var attestation_signatures = try test_helpers.createDummyAttestationSignatures(allocator, 3);
    var attestation_signatures_cleanup = true;
    errdefer if (attestation_signatures_cleanup) {
        for (attestation_signatures.slice()) |*sig| {
            sig.deinit();
        }
        attestation_signatures.deinit();
    };

    var signed_block = try test_helpers.createDummyBlock(allocator, 2, 1, 0xBB, 0xCC, attestation_signatures);
    attestation_signatures_cleanup = false;
    defer signed_block.deinit();

    const state_root = test_helpers.createDummyRoot(0xEE);
    var state = try test_helpers.createDummyState(allocator, 2, 4, 93, 1, 0, 0xFF, 0x00);
    defer state.deinit();

    var batch = try db.initWriteBatch();
    defer batch.deinit();

    try std.testing.expect(db.loadBlock(DbBlocksNamespace, block_root) == null);
    try std.testing.expect(db.loadState(DbStatesNamespace, state_root) == null);

    batch.putBlock(DbBlocksNamespace, block_root, signed_block);
    batch.putState(DbStatesNamespace, state_root, state);
    try db.commit(&batch);

    const loaded_block = db.loadBlock(DbBlocksNamespace, block_root);
    try std.testing.expect(loaded_block != null);
    try std.testing.expectEqual(signed_block.block.slot, loaded_block.?.block.slot);

    const loaded_state = db.loadState(DbStatesNamespace, state_root);
    try std.testing.expect(loaded_state != null);
    try std.testing.expectEqual(state.slot, loaded_state.?.slot);
}

fn testLoadLatestFinalizedStateHappyPath(backend: Backend) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try Db.openBackend(allocator, zeam_logger_config.logger(.database_test), data_dir, backend);
    defer db.deinit();

    // Empty db -> no finalized slot metadata
    var out_state: types.BeamState = undefined;
    try std.testing.expectError(error.NoFinalizedStateFound, db.loadLatestFinalizedState(&out_state));

    // Wire up metadata + slot index + state.
    const finalized_slot: types.Slot = 11;
    const block_root = test_helpers.createDummyRoot(0x42);
    var expected_state = try test_helpers.createDummyState(allocator, 123, 4, 93, 1, 0, 0x10, 0x20);
    defer expected_state.deinit();

    var batch = try db.initWriteBatch();
    defer batch.deinit();
    batch.putLatestFinalizedSlot(DbDefaultNamespace, finalized_slot);
    batch.putFinalizedSlotIndex(DbFinalizedSlotsNamespace, finalized_slot, block_root);
    batch.putState(DbStatesNamespace, block_root, expected_state);
    try db.commit(&batch);

    var loaded_state: types.BeamState = undefined;
    try db.loadLatestFinalizedState(&loaded_state);
    try std.testing.expectEqual(expected_state.slot, loaded_state.slot);
    try std.testing.expectEqual(expected_state.latest_justified.slot, loaded_state.latest_justified.slot);
    try std.testing.expect(std.mem.eql(u8, &expected_state.latest_justified.root, &loaded_state.latest_justified.root));
}
