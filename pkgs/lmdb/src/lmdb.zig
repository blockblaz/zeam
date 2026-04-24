//! Low-level Zig wrapper over the vendored `liblmdb` C library.
//!
//! This module exposes just enough of LMDB to back a RocksDB-shaped
//! key/value API in `pkgs/database`. Higher-level concerns (column
//! namespaces, SSZ serialisation, batched convenience methods) live
//! outside of this file; everything here is a thin, allocator-free-ish
//! wrapper that translates LMDB error codes into Zig errors and owns
//! nothing beyond what liblmdb itself owns.
//!
//! LMDB's object model, for context:
//!
//! - One `Env` per database directory. Holds the memory map.
//! - Up to `max_dbs` named sub-databases (`Dbi`) per env.
//! - Every operation runs inside a `Txn` (read-only or read-write).
//! - A writer excludes other writers; readers never block writers.
//!
//! See the upstream C API at `pkgs/lmdb/vendor/liblmdb/lmdb.h`.

const std = @import("std");
const c = @import("c.zig").c;

pub const Error = error{
    LmdbKeyExists,
    LmdbNotFound,
    LmdbPageNotFound,
    LmdbCorrupted,
    LmdbPanic,
    LmdbVersionMismatch,
    LmdbInvalid,
    LmdbMapFull,
    LmdbDbsFull,
    LmdbReadersFull,
    LmdbTxnFull,
    LmdbCursorFull,
    LmdbPageFull,
    LmdbMapResized,
    LmdbIncompatible,
    LmdbBadRslot,
    LmdbBadTxn,
    LmdbBadValSize,
    LmdbBadDbi,
    LmdbProblem,
    LmdbUnknown,

    OutOfMemory,
    AccessDenied,
    NoSpaceLeft,
    FileBusy,
    PermissionDenied,
};

fn check(rc: c_int) Error!void {
    if (rc == c.MDB_SUCCESS) return;
    return switch (rc) {
        c.MDB_KEYEXIST => error.LmdbKeyExists,
        c.MDB_NOTFOUND => error.LmdbNotFound,
        c.MDB_PAGE_NOTFOUND => error.LmdbPageNotFound,
        c.MDB_CORRUPTED => error.LmdbCorrupted,
        c.MDB_PANIC => error.LmdbPanic,
        c.MDB_VERSION_MISMATCH => error.LmdbVersionMismatch,
        c.MDB_INVALID => error.LmdbInvalid,
        c.MDB_MAP_FULL => error.LmdbMapFull,
        c.MDB_DBS_FULL => error.LmdbDbsFull,
        c.MDB_READERS_FULL => error.LmdbReadersFull,
        c.MDB_TXN_FULL => error.LmdbTxnFull,
        c.MDB_CURSOR_FULL => error.LmdbCursorFull,
        c.MDB_PAGE_FULL => error.LmdbPageFull,
        c.MDB_MAP_RESIZED => error.LmdbMapResized,
        c.MDB_INCOMPATIBLE => error.LmdbIncompatible,
        c.MDB_BAD_RSLOT => error.LmdbBadRslot,
        c.MDB_BAD_TXN => error.LmdbBadTxn,
        c.MDB_BAD_VALSIZE => error.LmdbBadValSize,
        c.MDB_BAD_DBI => error.LmdbBadDbi,
        c.MDB_PROBLEM => error.LmdbProblem,
        @as(c_int, @intFromEnum(std.posix.E.NOMEM)) => error.OutOfMemory,
        @as(c_int, @intFromEnum(std.posix.E.ACCES)) => error.AccessDenied,
        @as(c_int, @intFromEnum(std.posix.E.NOSPC)) => error.NoSpaceLeft,
        @as(c_int, @intFromEnum(std.posix.E.BUSY)) => error.FileBusy,
        @as(c_int, @intFromEnum(std.posix.E.PERM)) => error.PermissionDenied,
        else => error.LmdbUnknown,
    };
}

/// Options passed to `Env.open`. Keep them minimal; more switches can be
/// surfaced as needs arise.
pub const EnvOptions = struct {
    /// Upper bound on the mmap size for the DB. LMDB reserves virtual
    /// address space equal to this value (not physical disk); pick
    /// generously. Can be raised later only by reopening the env.
    map_size: usize = 1 << 40,
    /// Maximum number of named sub-databases ("DBIs") that may be opened
    /// within this env.
    max_dbs: c_uint = 32,
    /// Maximum number of concurrent reader slots. LMDB reserves a fixed
    /// array of this size in the lock file.
    max_readers: c_uint = 256,
    /// Flags forwarded to `mdb_env_open`. Caller may OR in constants
    /// from `lmdb.h` such as `MDB_NOSYNC`, `MDB_WRITEMAP`, etc.
    flags: c_uint = 0,
    /// POSIX file mode for newly-created files in the env directory.
    mode: c.mdb_mode_t = 0o664,
};

/// LMDB environment. One per on-disk database directory.
pub const Env = struct {
    env: *c.MDB_env,

    pub fn open(path: [:0]const u8, opts: EnvOptions) Error!Env {
        var raw: ?*c.MDB_env = null;
        try check(c.mdb_env_create(&raw));
        const env = raw orelse return error.LmdbUnknown;
        errdefer c.mdb_env_close(env);

        try check(c.mdb_env_set_mapsize(env, opts.map_size));
        try check(c.mdb_env_set_maxdbs(env, opts.max_dbs));
        try check(c.mdb_env_set_maxreaders(env, opts.max_readers));
        try check(c.mdb_env_open(env, path.ptr, opts.flags, opts.mode));
        return .{ .env = env };
    }

    pub fn close(self: *Env) void {
        c.mdb_env_close(self.env);
        self.* = undefined;
    }

    /// Force synchronous flush of pending writes to disk. `force`
    /// overrides the env's lazy-sync settings.
    pub fn sync(self: *Env, force: bool) Error!void {
        try check(c.mdb_env_sync(self.env, if (force) 1 else 0));
    }

    pub fn beginTxn(self: *Env, read_only: bool) Error!Txn {
        var raw: ?*c.MDB_txn = null;
        const flags: c_uint = if (read_only) c.MDB_RDONLY else 0;
        try check(c.mdb_txn_begin(self.env, null, flags, &raw));
        return .{ .txn = raw orelse return error.LmdbUnknown };
    }
};

/// LMDB transaction. Read-only txns may live across threads with
/// reset/renew; read-write txns must be committed or aborted on the
/// same thread that started them.
pub const Txn = struct {
    txn: *c.MDB_txn,

    /// Open (or create) a named sub-DB within this transaction. The
    /// returned `Dbi` handle may be reused across subsequent
    /// transactions on the same env.
    pub fn openDbi(self: *Txn, name: ?[:0]const u8, create: bool) Error!Dbi {
        var dbi: c.MDB_dbi = 0;
        const flags: c_uint = if (create) c.MDB_CREATE else 0;
        const name_ptr: ?[*:0]const u8 = if (name) |n| n.ptr else null;
        try check(c.mdb_dbi_open(self.txn, name_ptr, flags, &dbi));
        return .{ .dbi = dbi };
    }

    pub fn commit(self: *Txn) Error!void {
        try check(c.mdb_txn_commit(self.txn));
        self.* = undefined;
    }

    pub fn abort(self: *Txn) void {
        c.mdb_txn_abort(self.txn);
        self.* = undefined;
    }

    /// Fetch a value. The returned slice is valid only for the lifetime
    /// of this transaction; callers that need to keep the bytes around
    /// must copy them.
    pub fn get(self: *Txn, dbi: Dbi, key: []const u8) Error!?[]const u8 {
        var k = toVal(key);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(self.txn, dbi.dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try check(rc);
        return fromVal(v);
    }

    pub fn put(self: *Txn, dbi: Dbi, key: []const u8, value: []const u8) Error!void {
        var k = toVal(key);
        var v = toVal(value);
        try check(c.mdb_put(self.txn, dbi.dbi, &k, &v, 0));
    }

    pub fn delete(self: *Txn, dbi: Dbi, key: []const u8) Error!void {
        var k = toVal(key);
        const rc = c.mdb_del(self.txn, dbi.dbi, &k, null);
        if (rc == c.MDB_NOTFOUND) return;
        try check(rc);
    }

    pub fn openCursor(self: *Txn, dbi: Dbi) Error!Cursor {
        var raw: ?*c.MDB_cursor = null;
        try check(c.mdb_cursor_open(self.txn, dbi.dbi, &raw));
        return .{ .cursor = raw orelse return error.LmdbUnknown };
    }
};

/// Handle to a named sub-database inside an env. Cheap to copy; the
/// underlying resource is owned by the env and lives until env close.
pub const Dbi = struct {
    dbi: c.MDB_dbi,
};

/// Positioned iterator over a sub-DB. Keys are returned in native
/// lexicographic order.
pub const Cursor = struct {
    cursor: *c.MDB_cursor,

    pub fn close(self: *Cursor) void {
        c.mdb_cursor_close(self.cursor);
        self.* = undefined;
    }

    /// Position to the first key. Returns null on empty DB.
    pub fn first(self: *Cursor) Error!?Entry {
        return self.getAt(c.MDB_FIRST, null);
    }

    /// Position to the last key. Returns null on empty DB.
    pub fn last(self: *Cursor) Error!?Entry {
        return self.getAt(c.MDB_LAST, null);
    }

    /// Advance to the next key. Returns null past the end.
    pub fn next(self: *Cursor) Error!?Entry {
        return self.getAt(c.MDB_NEXT, null);
    }

    /// Step back to the previous key. Returns null past the beginning.
    pub fn prev(self: *Cursor) Error!?Entry {
        return self.getAt(c.MDB_PREV, null);
    }

    /// Position to the smallest key `>= needle`. Returns null if no such
    /// key exists.
    pub fn seekRange(self: *Cursor, needle: []const u8) Error!?Entry {
        return self.getAt(c.MDB_SET_RANGE, needle);
    }

    fn getAt(self: *Cursor, op: c.MDB_cursor_op, needle: ?[]const u8) Error!?Entry {
        var k: c.MDB_val = if (needle) |n| toVal(n) else std.mem.zeroes(c.MDB_val);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_cursor_get(self.cursor, &k, &v, op);
        if (rc == c.MDB_NOTFOUND) return null;
        try check(rc);
        return Entry{ .key = fromVal(k), .value = fromVal(v) };
    }
};

pub const Entry = struct {
    key: []const u8,
    value: []const u8,
};

fn toVal(bytes: []const u8) c.MDB_val {
    return .{
        .mv_size = bytes.len,
        // LMDB's C API is non-const for the pointer; we never mutate
        // caller-provided input slices on the read path, and on the
        // write path we hand them to `mdb_put` which copies immediately.
        .mv_data = @ptrCast(@constCast(bytes.ptr)),
    };
}

fn fromVal(v: c.MDB_val) []const u8 {
    if (v.mv_size == 0) return &[_]u8{};
    const ptr: [*]const u8 = @ptrCast(v.mv_data);
    return ptr[0..v.mv_size];
}

test "env open / put / get / delete / reopen" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &path_buf);
    const path_z = try std.fmt.allocPrintSentinel(
        testing.allocator,
        "{s}",
        .{tmp_path},
        0,
    );
    defer testing.allocator.free(path_z);

    {
        var env = try Env.open(path_z, .{ .map_size = 16 * 1024 * 1024, .max_dbs = 4 });
        defer env.close();

        var txn = try env.beginTxn(false);
        const dbi = try txn.openDbi("blocks", true);
        try txn.put(dbi, "hello", "world");
        try txn.commit();

        var rtxn = try env.beginTxn(true);
        defer rtxn.abort();
        const dbi2 = try rtxn.openDbi("blocks", false);
        const value = try rtxn.get(dbi2, "hello");
        try testing.expect(value != null);
        try testing.expectEqualStrings("world", value.?);
    }

    {
        var env = try Env.open(path_z, .{ .map_size = 16 * 1024 * 1024, .max_dbs = 4 });
        defer env.close();

        var txn = try env.beginTxn(false);
        const dbi = try txn.openDbi("blocks", false);
        const value = try txn.get(dbi, "hello");
        try testing.expect(value != null);
        try testing.expectEqualStrings("world", value.?);

        try txn.delete(dbi, "hello");
        try txn.commit();

        var rtxn = try env.beginTxn(true);
        defer rtxn.abort();
        const dbi2 = try rtxn.openDbi("blocks", false);
        try testing.expect((try rtxn.get(dbi2, "hello")) == null);
    }
}

test "cursor ordered iteration" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &path_buf);
    const path_z = try std.fmt.allocPrintSentinel(testing.allocator, "{s}", .{tmp_path}, 0);
    defer testing.allocator.free(path_z);

    var env = try Env.open(path_z, .{ .map_size = 16 * 1024 * 1024, .max_dbs = 4 });
    defer env.close();

    var wtxn = try env.beginTxn(false);
    const dbi = try wtxn.openDbi("ns", true);
    try wtxn.put(dbi, "a", "1");
    try wtxn.put(dbi, "b", "2");
    try wtxn.put(dbi, "c", "3");
    try wtxn.commit();

    var rtxn = try env.beginTxn(true);
    defer rtxn.abort();
    const dbi2 = try rtxn.openDbi("ns", false);
    var cur = try rtxn.openCursor(dbi2);
    defer cur.close();

    var collected: [3][]const u8 = undefined;
    var i: usize = 0;
    var entry = try cur.first();
    while (entry) |e| : (entry = try cur.next()) {
        collected[i] = e.key;
        i += 1;
    }
    try testing.expectEqual(@as(usize, 3), i);
    try testing.expectEqualStrings("a", collected[0]);
    try testing.expectEqualStrings("b", collected[1]);
    try testing.expectEqualStrings("c", collected[2]);
}
