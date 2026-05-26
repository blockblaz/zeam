//! XMSS sign / verify / aggregation benchmark.
//!
//! Measures:
//!   * Single-signature sign + verify time (drives the per-validator
//!     cost model — see `--sign-bench-samples` / `--sign-bench-iters`).
//!   * Aggregation time, aggregate signature size, and verification
//!     time for two-level aggregation shapes (flat + tree).
//!
//! Aggregation workload table:
//!
//!   aggregate.flat_N        : N raw signatures aggregated as a single proof.
//!   aggregate.tree_NxK      : N child proofs each aggregating K raw
//!                              signatures, then a root proof combining the
//!                              N children with 0 raw signatures.
//!
//! Run via `zig build bench-aggregate -- <args>`. See `printHelp` below for
//! the supported flags.
//!
//! Memory model: distinct XMSS keypairs are slow to generate (seconds each)
//! and each serialized SK is ~8 MiB. To keep peak RSS bounded the
//! benchmark NEVER holds more than `--keygen-threads` KeyPairs in memory
//! simultaneously. Each worker loads (or generates) a keypair, signs the
//! benchmark message, persists the signature to disk, and drops the SK
//! immediately. Only the standalone public-key handle + signature handle
//! survive into the aggregation phase, both of which are small. Cached
//! signatures live under `--sigs-dir` keyed by (epoch, message-hash
//! prefix), so subsequent runs with the same parameters skip both keygen
//! and signing entirely.
//!
//! The aggregator does not dedupe inputs (see
//! rust/multisig-glue/src/lib.rs::xmss_aggregate), so per-signer prover
//! work — and therefore the timing/size measurements — match what a run
//! with fully unique keys would produce.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const xmss = @import("@zeam/xmss");
const KeyPair = xmss.KeyPair;
const Signature = xmss.Signature;
const PublicKey = xmss.PublicKey;
const HashSigPublicKey = xmss.HashSigPublicKey;
const HashSigSignature = xmss.HashSigSignature;
const ByteListMiB = xmss.ByteListMiB;

const ShapeKind = enum { flat, tree };

const Shape = struct {
    kind: ShapeKind,
    /// For `.tree`, the number of children. For `.flat`, always 1.
    children: u32,
    /// For `.tree`, signatures per child. For `.flat`, total signatures.
    per_child: u32,

    fn totalSigners(self: Shape) usize {
        return @as(usize, self.children) * @as(usize, self.per_child);
    }
};

const BaseWorkload = struct {
    base_name: []const u8,
    shape: Shape,
};

/// Workload set mirrors the table in the issue: flat {125, 250, 500, 1000}
/// and tree {2,4,8} × {125, 250, 500}. The `_r<rate>` suffix is appended
/// at print time from `--log-inv-rate`.
const default_workloads = [_]BaseWorkload{
    .{ .base_name = "aggregate.flat_125", .shape = .{ .kind = .flat, .children = 1, .per_child = 125 } },
    .{ .base_name = "aggregate.flat_250", .shape = .{ .kind = .flat, .children = 1, .per_child = 250 } },
    .{ .base_name = "aggregate.flat_500", .shape = .{ .kind = .flat, .children = 1, .per_child = 500 } },
    .{ .base_name = "aggregate.flat_1000", .shape = .{ .kind = .flat, .children = 1, .per_child = 1000 } },
    .{ .base_name = "aggregate.tree_2x125", .shape = .{ .kind = .tree, .children = 2, .per_child = 125 } },
    .{ .base_name = "aggregate.tree_2x250", .shape = .{ .kind = .tree, .children = 2, .per_child = 250 } },
    .{ .base_name = "aggregate.tree_2x500", .shape = .{ .kind = .tree, .children = 2, .per_child = 500 } },
    .{ .base_name = "aggregate.tree_4x125", .shape = .{ .kind = .tree, .children = 4, .per_child = 125 } },
    .{ .base_name = "aggregate.tree_4x250", .shape = .{ .kind = .tree, .children = 4, .per_child = 250 } },
    .{ .base_name = "aggregate.tree_4x500", .shape = .{ .kind = .tree, .children = 4, .per_child = 500 } },
    .{ .base_name = "aggregate.tree_8x125", .shape = .{ .kind = .tree, .children = 8, .per_child = 125 } },
    .{ .base_name = "aggregate.tree_8x250", .shape = .{ .kind = .tree, .children = 8, .per_child = 250 } },
    .{ .base_name = "aggregate.tree_8x500", .shape = .{ .kind = .tree, .children = 8, .per_child = 500 } },
};

const Args = struct {
    iters: usize = 1,
    log_inv_rate: usize = 2,
    keys_dir: []const u8 = ".bench-cache/xmss-keys/v1",
    sigs_dir: []const u8 = ".bench-cache/xmss-sigs/v1",
    num_distinct_keys: ?usize = null,
    keygen_threads: ?usize = null,
    filter: ?[]const u8 = null,
    json_path: ?[]const u8 = null,
    csv_path: ?[]const u8 = null,
    rayon_threads: ?usize = null,
    epoch: u32 = 0,
    sign_bench_samples: usize = 8,
    /// 0 means "mirror --iters" at runtime.
    sign_bench_iters: usize = 0,
    skip_single_bench: bool = false,
    skip_aggregate_bench: bool = false,
    print_help: bool = false,
};

fn printHelp() void {
    const help =
        \\zeam-bench-aggregate — XMSS sign / verify / aggregation benchmark
        \\
        \\Usage: zig build bench-aggregate -- [options]
        \\
        \\Single-sig sign + verify timing is reported first, followed by the
        \\aggregation workloads. Signatures are cached under --sigs-dir keyed
        \\by (epoch, message hash) so subsequent runs avoid both keygen and
        \\signing.
        \\
        \\Options:
        \\  --iters N                Iterations per aggregation workload; median
        \\                           timing reported (default: 1)
        \\  --log-inv-rate N         log_inv_rate passed to the prover (default: 2)
        \\  --num-distinct-keys N    Distinct XMSS keypairs in the signer pool.
        \\                           Defaults to the largest signer count across
        \\                           selected workloads (the prover/verifier
        \\                           require distinct pubkeys). Each cached SK is
        \\                           ~8 MiB on disk and keygen costs ~3s/key —
        \\                           first-run cost is high but the cache makes
        \\                           subsequent runs fast. The benchmark never
        \\                           keeps more than --keygen-threads SKs in RAM.
        \\  --keygen-threads N       Worker threads used to build the signer pool
        \\                           (default: min(8, num_cpus)). Use 1 to disable.
        \\  --keys-dir PATH          Cache directory for generated keypairs
        \\                           (default: .bench-cache/xmss-keys/v1)
        \\  --sigs-dir PATH          Cache directory for benchmark signatures
        \\                           (default: .bench-cache/xmss-sigs/v1). A
        \\                           per-(epoch, message-hash) subdirectory is
        \\                           used so the cache is safe across runs with
        \\                           different parameters.
        \\  --filter SUBSTR          Only run aggregation workloads whose
        \\                           emitted name (e.g.
        \\                           aggregate.tree_4x250_r2) contains SUBSTR
        \\  --json PATH              Also write machine-readable JSON report to PATH
        \\  --csv PATH               Also write CSV report (aggregation only) to PATH
        \\  --rayon-threads N        Configure the rayon pool used by the aggregate
        \\                           prover (default: rayon default, i.e. one thread
        \\                           per logical CPU)
        \\  --epoch N                Epoch used for signing and aggregation (default: 0)
        \\  --sign-bench-samples N   Distinct keys used for the single-sig sign/verify
        \\                           benchmark (default: 8). Each sample is loaded
        \\                           into memory only for the duration of the bench
        \\                           and dropped immediately after.
        \\  --sign-bench-iters N     Iterations per sample for the single-sig bench
        \\                           (default: --iters)
        \\  --skip-single-bench      Skip the single sign/verify benchmark pass
        \\  --skip-aggregate-bench   Skip the aggregation workloads (run only the
        \\                           single-sig bench)
        \\  -h, --help               Print this help and exit
        \\
        \\
    ;
    var stderr_buf: [help.len + 16]u8 = undefined;
    var w = std.Io.File.stderr().writer(threadedIo(), &stderr_buf);
    w.interface.writeAll(help) catch {};
    w.interface.flush() catch {};
}

/// Substring-match a workload filter against the workload's emitted name —
/// i.e. `{base_name}_r{log_inv_rate}`, which is what the report, CSV, and
/// JSON outputs print. Matching against the bare `base_name` (as the
/// previous implementation did) silently rejected any filter copied out of
/// the tool's own output, because the user-visible name always carries the
/// `_r<rate>` suffix.
fn workloadMatchesFilter(filter: ?[]const u8, base_name: []const u8, log_inv_rate: usize) bool {
    const needle = filter orelse return true;
    var buf: [128]u8 = undefined;
    const full = std.fmt.bufPrint(&buf, "{s}_r{d}", .{ base_name, log_inv_rate }) catch {
        // Workload names are all short and fit comfortably; if we somehow
        // overflow, degrade to base-name matching rather than failing the
        // whole run.
        return std.mem.indexOf(u8, base_name, needle) != null;
    };
    return std.mem.indexOf(u8, full, needle) != null;
}

/// Consume the next argv entry as the value for `flag`. Bounds-checks so
/// a trailing value-taking flag (e.g. `--iters` with nothing after it)
/// surfaces as InvalidArgs instead of an index-out-of-bounds panic.
fn nextValue(raw: []const []const u8, i: *usize, flag: []const u8) ![]const u8 {
    i.* += 1;
    if (i.* >= raw.len) {
        std.debug.print("error: {s} requires a value\n", .{flag});
        return error.InvalidArgs;
    }
    return raw[i.*];
}

/// Parse command-line arguments using the Zig 0.16 `std.process.Init` API.
/// String args (paths/filter) are sliced directly out of the args buffer
/// owned by `init.arena`, which lives for the duration of the process.
fn parseArgs(init: std.process.Init) !Args {
    const raw = try init.minimal.args.toSlice(init.arena.allocator());
    var args = Args{};
    var i: usize = 1; // raw[0] is argv[0]
    while (i < raw.len) : (i += 1) {
        const a: []const u8 = raw[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            args.print_help = true;
        } else if (std.mem.eql(u8, a, "--iters")) {
            args.iters = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
            if (args.iters == 0) return error.InvalidArgs;
        } else if (std.mem.eql(u8, a, "--log-inv-rate")) {
            args.log_inv_rate = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
        } else if (std.mem.eql(u8, a, "--num-distinct-keys")) {
            args.num_distinct_keys = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
        } else if (std.mem.eql(u8, a, "--keygen-threads")) {
            args.keygen_threads = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
            if (args.keygen_threads.? == 0) return error.InvalidArgs;
        } else if (std.mem.eql(u8, a, "--keys-dir")) {
            args.keys_dir = try nextValue(raw, &i, a);
        } else if (std.mem.eql(u8, a, "--sigs-dir")) {
            args.sigs_dir = try nextValue(raw, &i, a);
        } else if (std.mem.eql(u8, a, "--filter")) {
            args.filter = try nextValue(raw, &i, a);
        } else if (std.mem.eql(u8, a, "--json")) {
            args.json_path = try nextValue(raw, &i, a);
        } else if (std.mem.eql(u8, a, "--csv")) {
            args.csv_path = try nextValue(raw, &i, a);
        } else if (std.mem.eql(u8, a, "--rayon-threads")) {
            args.rayon_threads = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
        } else if (std.mem.eql(u8, a, "--epoch")) {
            args.epoch = try std.fmt.parseInt(u32, try nextValue(raw, &i, a), 10);
        } else if (std.mem.eql(u8, a, "--sign-bench-samples")) {
            args.sign_bench_samples = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
            if (args.sign_bench_samples == 0) return error.InvalidArgs;
        } else if (std.mem.eql(u8, a, "--sign-bench-iters")) {
            args.sign_bench_iters = try std.fmt.parseInt(usize, try nextValue(raw, &i, a), 10);
        } else if (std.mem.eql(u8, a, "--skip-single-bench")) {
            args.skip_single_bench = true;
        } else if (std.mem.eql(u8, a, "--skip-aggregate-bench")) {
            args.skip_aggregate_bench = true;
        } else {
            std.debug.print("unknown argument: {s}\n", .{a});
            return error.InvalidArgs;
        }
    }
    return args;
}

fn threadedIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Monotonic timestamp in nanoseconds. Mirrors
/// `@zeam/utils.monotonicTimestampNs`; we avoid the cross-package import
/// to keep the benchmark exe's module graph minimal.
fn nowNs() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

fn elapsedNs(start_ns: i128) u64 {
    const end_ns = nowNs();
    const delta: i128 = if (end_ns >= start_ns) end_ns - start_ns else 0;
    return @intCast(delta);
}

fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}

// ---------------------------------------------------------------------------
// Signer pool: streaming load + per-validator signature cache
// ---------------------------------------------------------------------------

/// Maximum SSZ-serialized XMSS secret key size. Mirrors
/// `key-manager.MAX_SK_SIZE` so we don't add a cross-package import.
const MAX_SK_SIZE: usize = 1024 * 1024 * 20;
const MAX_PK_SIZE: usize = 256;
/// Loose upper bound on the SSZ-serialised XMSS signature. The hashsig
/// roundtrip test in pkgs/xmss/src/hashsig.zig uses a 4000-byte scratch
/// buffer for the same shape; 8 KiB gives generous margin and is still
/// tiny compared to an SK.
const MAX_SIG_SIZE: usize = 8 * 1024;

/// SignerPool holds the per-signer state required by the aggregator
/// (public key + signature) WITHOUT keeping the secret key alive.
/// Workers stream the SK in, sign, persist the resulting signature to
/// disk, and drop the SK before the next slot starts. Peak RSS during
/// pool build is therefore O(keygen_threads × |SK|) ≈ a few dozen MiB
/// rather than O(num_keys × |SK|) ≈ many GiB.
const SignerPool = struct {
    allocator: Allocator,
    /// Standalone (heap-owned) pubkey handles. Required because the
    /// KeyPair-borrowed pubkey pointer dies with the KeyPair, and we
    /// drop the KeyPair immediately after signing.
    pub_key_owned: []PublicKey,
    signatures: []Signature,
    /// Flattened pointer tables for cheap FFI hand-off.
    pub_keys: []*const HashSigPublicKey,
    sigs: []*const HashSigSignature,

    fn deinit(self: *SignerPool) void {
        for (self.signatures) |*s| s.deinit();
        for (self.pub_key_owned) |*p| p.deinit();
        self.allocator.free(self.signatures);
        self.allocator.free(self.pub_key_owned);
        self.allocator.free(self.pub_keys);
        self.allocator.free(self.sigs);
    }
};

fn ensureDir(path: []const u8) !void {
    const io = threadedIo();
    try std.Io.Dir.cwd().createDirPath(io, path);
}

fn readFileAllocAtPath(allocator: Allocator, path: []const u8, max_size: usize) ![]u8 {
    const io = threadedIo();
    if (std.fs.path.isAbsolute(path)) {
        var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
        defer file.close(io);
        var read_buf: [4096]u8 = undefined;
        var reader = file.reader(io, &read_buf);
        return reader.interface.allocRemaining(allocator, .limited(max_size));
    }
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_size));
}

fn writeFileAtPath(path: []const u8, data: []const u8) !void {
    const io = threadedIo();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = data,
        .flags = .{ .truncate = true },
    });
}

fn formatHexLower16(buf: *[16]u8, bytes: []const u8) []const u8 {
    const hex_chars = "0123456789abcdef";
    std.debug.assert(bytes.len >= 8);
    for (0..8) |i| {
        buf[i * 2] = hex_chars[bytes[i] >> 4];
        buf[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    return buf[0..16];
}

/// Per-(epoch, message-hash-prefix) sub-directory for cached signatures.
/// We bake the parameters into the path so that re-running with a
/// different epoch or message can't accidentally consume a stale cache.
fn sigCacheSubdir(
    allocator: Allocator,
    sigs_dir: []const u8,
    message_hash: *const [32]u8,
    epoch: u32,
) ![]u8 {
    var hex_buf: [16]u8 = undefined;
    const hex = formatHexLower16(&hex_buf, message_hash);
    return std.fmt.allocPrint(allocator, "{s}/epoch_{d}_msg_{s}", .{ sigs_dir, epoch, hex });
}

/// Build the cache path for `validator_{index}` at `num_active_epochs`.
/// The XMSS public key depends on the activation lifetime, so we MUST
/// bake the lifetime into the filename — otherwise a run with `--epoch 0`
/// (lifetime 1) and a later run with `--epoch 5` (lifetime 6) would share
/// the same `validator_{i}_pk.ssz` path, and one of the two would consume
/// a key it cannot sign with, aborting in the Rust signer.
fn keyCachePaths(
    keys_dir: []const u8,
    index: usize,
    num_active_epochs: usize,
    sk_buf: *[512]u8,
    pk_buf: *[512]u8,
) !struct { sk: []const u8, pk: []const u8 } {
    const sk = try std.fmt.bufPrint(sk_buf, "{s}/validator_{d}_lt{d}_sk.ssz", .{ keys_dir, index, num_active_epochs });
    const pk = try std.fmt.bufPrint(pk_buf, "{s}/validator_{d}_lt{d}_pk.ssz", .{ keys_dir, index, num_active_epochs });
    return .{ .sk = sk, .pk = pk };
}

fn loadOrGenerateKey(
    allocator: Allocator,
    keys_dir: []const u8,
    index: usize,
    num_active_epochs: usize,
) !KeyPair {
    var sk_path_buf: [512]u8 = undefined;
    var pk_path_buf: [512]u8 = undefined;
    const paths = try keyCachePaths(keys_dir, index, num_active_epochs, &sk_path_buf, &pk_path_buf);

    // Try cache first.
    if (readFileAllocAtPath(allocator, paths.sk, MAX_SK_SIZE)) |sk_bytes| {
        defer allocator.free(sk_bytes);
        if (readFileAllocAtPath(allocator, paths.pk, MAX_PK_SIZE)) |pk_bytes| {
            defer allocator.free(pk_bytes);
            if (KeyPair.fromSsz(allocator, sk_bytes, pk_bytes)) |kp| {
                return kp;
            } else |_| {}
        } else |_| {}
    } else |_| {}

    // Cache miss — generate with a deterministic seed so cache builds are
    // reproducible across runs and machines.
    var seed_buf: [64]u8 = undefined;
    const seed = try std.fmt.bufPrint(&seed_buf, "zeam_bench_aggregate_validator_{d}", .{index});

    var kp = try KeyPair.generate(allocator, seed, 0, num_active_epochs);
    errdefer kp.deinit();

    // Serialize and persist for next time. SK can be large; allocate from
    // heap rather than stack.
    const sk_buf = try allocator.alloc(u8, MAX_SK_SIZE);
    defer allocator.free(sk_buf);
    const sk_len = try kp.privkeyToBytes(sk_buf);

    var pk_buf: [MAX_PK_SIZE]u8 = undefined;
    const pk_len = try kp.pubkeyToBytes(&pk_buf);

    writeFileAtPath(paths.sk, sk_buf[0..sk_len]) catch |err| {
        std.debug.print("warning: failed to write {s}: {s}\n", .{ paths.sk, @errorName(err) });
    };
    writeFileAtPath(paths.pk, pk_buf[0..pk_len]) catch |err| {
        std.debug.print("warning: failed to write {s}: {s}\n", .{ paths.pk, @errorName(err) });
    };
    return kp;
}

/// Per-signer artifacts retained in the SignerPool. Wrapped in a named
/// struct so callers and helpers agree on the type — anonymous struct
/// literals are distinct types in Zig and can't be cross-assigned.
const SignerArtifacts = struct {
    pk: PublicKey,
    sig: Signature,
};

/// Best-effort load of a previously-persisted pubkey + signature for the
/// given (index, epoch, message). Returns null when either cache entry
/// is missing or fails to deserialise — the caller then falls back to
/// the keygen + sign + persist path. Never loads the SK.
fn loadCachedSignerArtifacts(
    allocator: Allocator,
    keys_dir: []const u8,
    sigs_subdir: []const u8,
    index: usize,
    num_active_epochs: usize,
) ?SignerArtifacts {
    var pk_path_buf: [512]u8 = undefined;
    const pk_path = std.fmt.bufPrint(
        &pk_path_buf,
        "{s}/validator_{d}_lt{d}_pk.ssz",
        .{ keys_dir, index, num_active_epochs },
    ) catch return null;
    var sig_path_buf: [512]u8 = undefined;
    const sig_path = std.fmt.bufPrint(&sig_path_buf, "{s}/validator_{d}_sig.ssz", .{ sigs_subdir, index }) catch return null;

    const pk_bytes = readFileAllocAtPath(allocator, pk_path, MAX_PK_SIZE) catch return null;
    defer allocator.free(pk_bytes);
    const sig_bytes = readFileAllocAtPath(allocator, sig_path, MAX_SIG_SIZE) catch return null;
    defer allocator.free(sig_bytes);

    var pk = PublicKey.fromBytes(pk_bytes) catch return null;
    const sig = Signature.fromBytes(sig_bytes) catch {
        pk.deinit();
        return null;
    };
    return .{ .pk = pk, .sig = sig };
}

/// Load (or generate) one validator's signing artifacts. On return the
/// pubkey + signature are owned standalone handles; callers must free
/// both via deinit(). The KeyPair (and its multi-MiB SK) is dropped
/// before this function returns — SK memory is released immediately.
fn loadOrGenerateSignerArtifacts(
    allocator: Allocator,
    keys_dir: []const u8,
    sigs_subdir: []const u8,
    index: usize,
    message_hash: *const [32]u8,
    epoch: u32,
    num_active_epochs: usize,
) !SignerArtifacts {
    if (loadCachedSignerArtifacts(allocator, keys_dir, sigs_subdir, index, num_active_epochs)) |cached| {
        return cached;
    }

    var kp = try loadOrGenerateKey(allocator, keys_dir, index, num_active_epochs);
    defer kp.deinit();

    var sig = try kp.sign(message_hash, epoch);
    errdefer sig.deinit();

    // Persist the signature for future runs (best-effort).
    var sig_buf: [MAX_SIG_SIZE]u8 = undefined;
    const sig_len = try sig.toBytes(&sig_buf);
    var sig_path_buf: [512]u8 = undefined;
    const sig_path = try std.fmt.bufPrint(&sig_path_buf, "{s}/validator_{d}_sig.ssz", .{ sigs_subdir, index });
    writeFileAtPath(sig_path, sig_buf[0..sig_len]) catch |err| {
        std.debug.print("warning: failed to write {s}: {s}\n", .{ sig_path, @errorName(err) });
    };

    // Reconstruct a standalone PublicKey handle so the KeyPair can be
    // dropped safely. The KeyPair-borrowed pubkey pointer dies with
    // the KeyPair, so we can't reuse `kp.public_key` here.
    var pk_buf: [MAX_PK_SIZE]u8 = undefined;
    const pk_len = try kp.pubkeyToBytes(&pk_buf);
    var pk = try PublicKey.fromBytes(pk_buf[0..pk_len]);
    errdefer pk.deinit();

    return .{ .pk = pk, .sig = sig };
}

/// Shared state for the streaming signer-pool worker pool.
const PoolBuildShared = struct {
    allocator: Allocator,
    keys_dir: []const u8,
    sigs_subdir: []const u8,
    message_hash: *const [32]u8,
    epoch: u32,
    /// Lifetime to provision newly-generated keypairs with. Must be
    /// >= epoch + 1 — otherwise signing at `epoch` aborts inside the
    /// Rust signer. Also baked into the cache filename so different
    /// lifetimes get distinct cache entries.
    num_active_epochs: usize,
    pub_key_owned: []PublicKey,
    signatures: []Signature,
    /// Per-slot init flag. Workers claim indices via `next_index.fetchAdd`
    /// and may finish out-of-order, so cleanup-on-failure cannot iterate
    /// by `done_count` alone (it would deinit() uninitialised early slots
    /// and skip initialised later ones). Cleanup checks this bitmap and
    /// only deinits slots a worker actually populated.
    populated: []std.atomic.Value(u8),
    next_index: std.atomic.Value(usize),
    done_count: std.atomic.Value(usize),
    failed: std.atomic.Value(bool),
};

fn poolBuildWorker(shared: *PoolBuildShared) void {
    while (true) {
        const i = shared.next_index.fetchAdd(1, .acq_rel);
        if (i >= shared.pub_key_owned.len) return;
        if (shared.failed.load(.acquire)) return;

        const artifacts = loadOrGenerateSignerArtifacts(
            shared.allocator,
            shared.keys_dir,
            shared.sigs_subdir,
            i,
            shared.message_hash,
            shared.epoch,
            shared.num_active_epochs,
        ) catch {
            shared.failed.store(true, .release);
            return;
        };
        shared.pub_key_owned[i] = artifacts.pk;
        shared.signatures[i] = artifacts.sig;
        // Mark slot populated AFTER writing both fields; cleanup pairs
        // this with an .acquire load to ensure it sees the writes.
        shared.populated[i].store(1, .release);
        _ = shared.done_count.fetchAdd(1, .acq_rel);
    }
}

fn buildSignerPool(
    allocator: Allocator,
    keys_dir: []const u8,
    sigs_dir: []const u8,
    num_keys: usize,
    message_hash: *const [32]u8,
    epoch: u32,
    num_active_epochs: usize,
    keygen_threads: usize,
) !SignerPool {
    try ensureDir(keys_dir);

    const sigs_subdir = try sigCacheSubdir(allocator, sigs_dir, message_hash, epoch);
    defer allocator.free(sigs_subdir);
    try ensureDir(sigs_subdir);

    var pub_key_owned = try allocator.alloc(PublicKey, num_keys);
    errdefer allocator.free(pub_key_owned);
    var signatures = try allocator.alloc(Signature, num_keys);
    errdefer allocator.free(signatures);

    const populated = try allocator.alloc(std.atomic.Value(u8), num_keys);
    defer allocator.free(populated);
    for (populated) |*p| p.* = std.atomic.Value(u8).init(0);

    var shared = PoolBuildShared{
        .allocator = allocator,
        .keys_dir = keys_dir,
        .sigs_subdir = sigs_subdir,
        .message_hash = message_hash,
        .epoch = epoch,
        .num_active_epochs = num_active_epochs,
        .pub_key_owned = pub_key_owned,
        .signatures = signatures,
        .populated = populated,
        .next_index = std.atomic.Value(usize).init(0),
        .done_count = std.atomic.Value(usize).init(0),
        .failed = std.atomic.Value(bool).init(false),
    };

    const thread_count = @max(@as(usize, 1), keygen_threads);
    const threads = try allocator.alloc(std.Thread, thread_count - 1);
    defer allocator.free(threads);

    var spawned: usize = 0;
    var joined: bool = false;

    // Single errdefer for the worker phase. We must NOT also join inside
    // a separate errdefer the way the previous version did — Thread.join
    // is consuming, so re-joining a handle is undefined behaviour. The
    // success path joins explicitly (see below) and sets `joined = true`,
    // and this cleanup skips the join in that case.
    errdefer {
        if (!joined) {
            shared.failed.store(true, .release);
            for (threads[0..spawned]) |t| t.join();
            joined = true;
        }
        // Free only slots a worker actually populated. Worker indices are
        // claimed via fetchAdd and may complete out-of-order, so iterating
        // by done_count would mis-pair initialised and uninitialised slots.
        for (0..num_keys) |i| {
            if (shared.populated[i].load(.acquire) != 0) {
                signatures[i].deinit();
                pub_key_owned[i].deinit();
            }
        }
    }

    // Progress reporting on the main thread.
    const pool_start_ns = nowNs();
    var last_print_ns: u64 = 0;
    const print_every_ns: u64 = 5 * std.time.ns_per_s;

    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, poolBuildWorker, .{&shared});
        spawned += 1;
    }

    // Main thread also drives the pool build — gives us 1× extra worker
    // for free and avoids the "idle main while threads work" pattern.
    while (true) {
        const i = shared.next_index.fetchAdd(1, .acq_rel);
        if (i >= num_keys) break;
        if (shared.failed.load(.acquire)) break;

        const artifacts = loadOrGenerateSignerArtifacts(
            allocator,
            keys_dir,
            sigs_subdir,
            i,
            message_hash,
            epoch,
            num_active_epochs,
        ) catch {
            shared.failed.store(true, .release);
            break;
        };
        pub_key_owned[i] = artifacts.pk;
        signatures[i] = artifacts.sig;
        shared.populated[i].store(1, .release);
        _ = shared.done_count.fetchAdd(1, .acq_rel);

        const elapsed = elapsedNs(pool_start_ns);
        if (elapsed - last_print_ns >= print_every_ns) {
            const done_now = shared.done_count.load(.acquire);
            std.debug.print("  signer pool: {d}/{d} ready ({d:.1}s elapsed)\n", .{
                done_now,
                num_keys,
                @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s,
            });
            last_print_ns = elapsed;
        }
    }

    // Explicit join: also synchronises the per-slot writes performed by
    // worker threads into the main thread before we materialise the
    // flattened pointer tables below.
    for (threads[0..spawned]) |t| t.join();
    joined = true;

    if (shared.failed.load(.acquire)) return error.PoolBuildFailed;

    var pub_keys = try allocator.alloc(*const HashSigPublicKey, num_keys);
    errdefer allocator.free(pub_keys);
    var sigs = try allocator.alloc(*const HashSigSignature, num_keys);
    errdefer allocator.free(sigs);
    for (0..num_keys) |i| {
        pub_keys[i] = pub_key_owned[i].handle;
        sigs[i] = signatures[i].handle;
    }

    return .{
        .allocator = allocator,
        .pub_key_owned = pub_key_owned,
        .signatures = signatures,
        .pub_keys = pub_keys,
        .sigs = sigs,
    };
}

// ---------------------------------------------------------------------------
// Single-signature sign + verify benchmark
// ---------------------------------------------------------------------------

const SingleSigMetrics = struct {
    samples: usize,
    iters_per_sample: usize,
    sign_ms: f64,
    verify_ms: f64,
    sign_min_ms: f64,
    sign_max_ms: f64,
    verify_min_ms: f64,
    verify_max_ms: f64,
};

fn medianF64(values: []f64) f64 {
    std.mem.sort(f64, values, {}, std.sort.asc(f64));
    const n = values.len;
    if (n == 0) return 0;
    if (n % 2 == 1) return values[n / 2];
    return (values[n / 2 - 1] + values[n / 2]) / 2.0;
}

fn minF64(values: []const f64) f64 {
    if (values.len == 0) return 0;
    var m = values[0];
    for (values[1..]) |v| {
        if (v < m) m = v;
    }
    return m;
}

fn maxF64(values: []const f64) f64 {
    if (values.len == 0) return 0;
    var m = values[0];
    for (values[1..]) |v| {
        if (v > m) m = v;
    }
    return m;
}

/// Time `samples × iters_per_sample` individual sign + verify operations.
/// Each sample loads exactly one KeyPair (cache hit on subsequent runs),
/// runs `iters_per_sample` sign/verify pairs against it, and drops the
/// KeyPair before moving on — so at most one SK is resident at a time.
fn runSingleSigBench(
    allocator: Allocator,
    keys_dir: []const u8,
    samples: usize,
    iters_per_sample: usize,
    message_hash: *const [32]u8,
    epoch: u32,
    num_active_epochs: usize,
) !SingleSigMetrics {
    std.debug.assert(samples > 0 and iters_per_sample > 0);

    const total = samples * iters_per_sample;
    var sign_ms = try allocator.alloc(f64, total);
    defer allocator.free(sign_ms);
    var verify_ms = try allocator.alloc(f64, total);
    defer allocator.free(verify_ms);

    var slot: usize = 0;
    for (0..samples) |s| {
        var kp = try loadOrGenerateKey(allocator, keys_dir, s, num_active_epochs);
        defer kp.deinit();

        for (0..iters_per_sample) |_| {
            const sign_start = nowNs();
            var sig = try kp.sign(message_hash, epoch);
            const sign_ns = elapsedNs(sign_start);
            defer sig.deinit();

            const verify_start = nowNs();
            try kp.verify(message_hash, &sig, epoch);
            const verify_ns = elapsedNs(verify_start);

            sign_ms[slot] = nsToMs(sign_ns);
            verify_ms[slot] = nsToMs(verify_ns);
            slot += 1;
        }
    }

    return .{
        .samples = samples,
        .iters_per_sample = iters_per_sample,
        .sign_ms = medianF64(sign_ms),
        .verify_ms = medianF64(verify_ms),
        .sign_min_ms = minF64(sign_ms),
        .sign_max_ms = maxF64(sign_ms),
        .verify_min_ms = minF64(verify_ms),
        .verify_max_ms = maxF64(verify_ms),
    };
}

// ---------------------------------------------------------------------------
// Aggregation workload execution
// ---------------------------------------------------------------------------

const IterMetrics = struct {
    leaf_size_bytes: usize,
    root_size_bytes: usize,
    leaf_total_ns: u64,
    leaf_avg_ns: u64,
    root_ns: u64,
    verify_ns: u64,
};

const WorkloadResult = struct {
    name: []u8,
    shape: Shape,
    total_signers: usize,
    log_inv_rate: usize,
    leaf_size_bytes: usize,
    root_size_bytes: usize,
    leaf_total_ms: f64,
    leaf_avg_ms: f64,
    root_ms: ?f64,
    verify_ms: f64,
    iterations: usize,
};

fn pickPubKeys(allocator: Allocator, pool: *const SignerPool, count: usize, offset: usize) ![]*const HashSigPublicKey {
    const out = try allocator.alloc(*const HashSigPublicKey, count);
    for (0..count) |i| {
        out[i] = pool.pub_keys[(offset + i) % pool.pub_keys.len];
    }
    return out;
}

fn pickSigs(allocator: Allocator, pool: *const SignerPool, count: usize, offset: usize) ![]*const HashSigSignature {
    const out = try allocator.alloc(*const HashSigSignature, count);
    for (0..count) |i| {
        out[i] = pool.sigs[(offset + i) % pool.sigs.len];
    }
    return out;
}

fn runIteration(
    allocator: Allocator,
    pool: *const SignerPool,
    shape: Shape,
    message_hash: *const [32]u8,
    epoch: u32,
    log_inv_rate: usize,
) !IterMetrics {
    switch (shape.kind) {
        .flat => {
            const n = shape.per_child;
            const pub_keys = try pickPubKeys(allocator, pool, n, 0);
            defer allocator.free(pub_keys);
            const sigs = try pickSigs(allocator, pool, n, 0);
            defer allocator.free(sigs);

            var proof = try ByteListMiB.init(allocator);
            defer proof.deinit();

            const no_child_pks: []const []*const HashSigPublicKey = &.{};
            const no_child_proofs: []const ByteListMiB = &.{};

            const agg_start = nowNs();
            try xmss.aggregateSignatures(
                pub_keys,
                sigs,
                no_child_pks,
                no_child_proofs,
                message_hash,
                epoch,
                log_inv_rate,
                &proof,
            );
            const agg_ns = elapsedNs(agg_start);

            const size = proof.constSlice().len;

            // Verify against the same pubkey set.
            const verify_start = nowNs();
            try xmss.verifyAggregatedPayload(pub_keys, message_hash, epoch, &proof);
            const verify_ns = elapsedNs(verify_start);

            return .{
                .leaf_size_bytes = size,
                .root_size_bytes = size,
                .leaf_total_ns = agg_ns,
                .leaf_avg_ns = agg_ns,
                .root_ns = 0,
                .verify_ns = verify_ns,
            };
        },
        .tree => {
            const num_children = shape.children;
            const per_child = shape.per_child;

            // Build N child proofs. Each per-child allocation is tracked by
            // its own counter so a mid-loop failure (e.g. OOM in pickSigs
            // after pickPubKeys succeeded) frees only the slots we actually
            // populated. Freeing an uninitialised slice handle would be UB.
            const child_pub_keys = try allocator.alloc([]*const HashSigPublicKey, num_children);
            var num_pub_key_slices_built: usize = 0;
            defer {
                for (child_pub_keys[0..num_pub_key_slices_built]) |slice| allocator.free(slice);
                allocator.free(child_pub_keys);
            }
            const child_sigs = try allocator.alloc([]*const HashSigSignature, num_children);
            var num_sig_slices_built: usize = 0;
            defer {
                for (child_sigs[0..num_sig_slices_built]) |slice| allocator.free(slice);
                allocator.free(child_sigs);
            }
            const child_proofs = try allocator.alloc(ByteListMiB, num_children);
            var num_proofs_built: usize = 0;
            defer {
                for (child_proofs[0..num_proofs_built]) |*p| p.deinit();
                allocator.free(child_proofs);
            }

            const no_child_pks: []const []*const HashSigPublicKey = &.{};
            const no_child_proofs: []const ByteListMiB = &.{};

            var leaf_total_ns: u64 = 0;

            for (0..num_children) |c| {
                const offset = c * per_child;
                child_pub_keys[c] = try pickPubKeys(allocator, pool, per_child, offset);
                num_pub_key_slices_built = c + 1;
                child_sigs[c] = try pickSigs(allocator, pool, per_child, offset);
                num_sig_slices_built = c + 1;
                child_proofs[c] = try ByteListMiB.init(allocator);
                num_proofs_built = c + 1;

                const leaf_start = nowNs();
                try xmss.aggregateSignatures(
                    child_pub_keys[c],
                    child_sigs[c],
                    no_child_pks,
                    no_child_proofs,
                    message_hash,
                    epoch,
                    log_inv_rate,
                    &child_proofs[c],
                );
                leaf_total_ns += elapsedNs(leaf_start);
            }

            const leaf_size = child_proofs[0].constSlice().len;

            // Root aggregation: 0 raw signatures, N children.
            const parent_raw_pks: []*const HashSigPublicKey = &.{};
            const parent_raw_sigs: []*const HashSigSignature = &.{};

            var root_proof = try ByteListMiB.init(allocator);
            defer root_proof.deinit();

            const root_start = nowNs();
            try xmss.aggregateSignatures(
                parent_raw_pks,
                parent_raw_sigs,
                child_pub_keys,
                child_proofs,
                message_hash,
                epoch,
                log_inv_rate,
                &root_proof,
            );
            const root_ns = elapsedNs(root_start);

            const root_size = root_proof.constSlice().len;

            // Combined pubkey list for verification: flatten the children's
            // pubkeys in order. The aggregate proof is bound to the same
            // ordered set.
            const combined = try allocator.alloc(*const HashSigPublicKey, num_children * per_child);
            defer allocator.free(combined);
            var idx: usize = 0;
            for (child_pub_keys) |slice| {
                for (slice) |pk| {
                    combined[idx] = pk;
                    idx += 1;
                }
            }

            const verify_start = nowNs();
            try xmss.verifyAggregatedPayload(combined, message_hash, epoch, &root_proof);
            const verify_ns = elapsedNs(verify_start);

            return .{
                .leaf_size_bytes = leaf_size,
                .root_size_bytes = root_size,
                .leaf_total_ns = leaf_total_ns,
                .leaf_avg_ns = leaf_total_ns / num_children,
                .root_ns = root_ns,
                .verify_ns = verify_ns,
            };
        },
    }
}

fn runWorkload(
    allocator: Allocator,
    pool: *const SignerPool,
    base: BaseWorkload,
    message_hash: *const [32]u8,
    epoch: u32,
    log_inv_rate: usize,
    iters: usize,
) !WorkloadResult {
    const total_signers = base.shape.totalSigners();

    var leaf_total_ms = try allocator.alloc(f64, iters);
    defer allocator.free(leaf_total_ms);
    var leaf_avg_ms = try allocator.alloc(f64, iters);
    defer allocator.free(leaf_avg_ms);
    var root_ms = try allocator.alloc(f64, iters);
    defer allocator.free(root_ms);
    var verify_ms = try allocator.alloc(f64, iters);
    defer allocator.free(verify_ms);

    var leaf_size_bytes: usize = 0;
    var root_size_bytes: usize = 0;

    for (0..iters) |it| {
        const m = try runIteration(allocator, pool, base.shape, message_hash, epoch, log_inv_rate);
        leaf_total_ms[it] = nsToMs(m.leaf_total_ns);
        leaf_avg_ms[it] = nsToMs(m.leaf_avg_ns);
        root_ms[it] = nsToMs(m.root_ns);
        verify_ms[it] = nsToMs(m.verify_ns);
        // Sizes are deterministic for a given shape; keep the last
        // observation (any value would do).
        leaf_size_bytes = m.leaf_size_bytes;
        root_size_bytes = m.root_size_bytes;
    }

    const name = try std.fmt.allocPrint(allocator, "{s}_r{d}", .{ base.base_name, log_inv_rate });

    return .{
        .name = name,
        .shape = base.shape,
        .total_signers = total_signers,
        .log_inv_rate = log_inv_rate,
        .leaf_size_bytes = leaf_size_bytes,
        .root_size_bytes = root_size_bytes,
        .leaf_total_ms = medianF64(leaf_total_ms),
        .leaf_avg_ms = medianF64(leaf_avg_ms),
        .root_ms = if (base.shape.kind == .tree) medianF64(root_ms) else null,
        .verify_ms = medianF64(verify_ms),
        .iterations = iters,
    };
}

// ---------------------------------------------------------------------------
// Report emitters
// ---------------------------------------------------------------------------

fn bytesToKib(bytes: usize) f64 {
    return @as(f64, @floatFromInt(bytes)) / 1024.0;
}

fn writeMarkdownReport(
    writer: *std.Io.Writer,
    args: Args,
    num_keys: usize,
    single_sig: ?SingleSigMetrics,
    results: []const WorkloadResult,
) !void {
    try writer.print("# XMSS sign / verify / aggregation benchmark\n\n", .{});
    try writer.print("- log_inv_rate: {d}\n", .{args.log_inv_rate});
    try writer.print("- iters per aggregation workload: {d} (median reported)\n", .{args.iters});
    try writer.print("- distinct keypairs in signer pool: {d}\n", .{num_keys});
    try writer.print("- keys dir: {s}\n", .{args.keys_dir});
    try writer.print("- sigs dir: {s}\n", .{args.sigs_dir});
    if (args.rayon_threads) |t| {
        try writer.print("- rayon threads: {d}\n", .{t});
    }
    try writer.print("\n", .{});

    if (single_sig) |sb| {
        try writer.writeAll("## Single-signature sign / verify\n\n");
        try writer.print("- samples: {d} distinct keys × {d} iterations = {d} measurements\n\n", .{
            sb.samples, sb.iters_per_sample, sb.samples * sb.iters_per_sample,
        });
        try writer.writeAll("| operation | median ms | min ms | max ms |\n");
        try writer.writeAll("|---|---:|---:|---:|\n");
        try writer.print("| xmss.sign   | {d:.3} | {d:.3} | {d:.3} |\n", .{ sb.sign_ms, sb.sign_min_ms, sb.sign_max_ms });
        try writer.print("| xmss.verify | {d:.3} | {d:.3} | {d:.3} |\n\n", .{ sb.verify_ms, sb.verify_min_ms, sb.verify_max_ms });
    }

    if (results.len > 0) {
        try writer.writeAll("## Aggregation\n\n");
        try writer.writeAll("| workload | signers | leaf KiB | root KiB | leaf avg ms | leaf total ms | root ms | verify ms |\n");
        try writer.writeAll("|---|---:|---:|---:|---:|---:|---:|---:|\n");
        for (results) |r| {
            try writer.print("| {s} | {d} | {d:.2} | {d:.2} | {d:.1} | {d:.1} | ", .{
                r.name,
                r.total_signers,
                bytesToKib(r.leaf_size_bytes),
                bytesToKib(r.root_size_bytes),
                r.leaf_avg_ms,
                r.leaf_total_ms,
            });
            if (r.root_ms) |rm| {
                try writer.print("{d:.1}", .{rm});
            } else {
                try writer.writeAll("—");
            }
            try writer.print(" | {d:.1} |\n", .{r.verify_ms});
        }
        try writer.writeAll("\n");
    }
}

fn writeCsvReport(writer: *std.Io.Writer, results: []const WorkloadResult) !void {
    try writer.writeAll("workload,kind,children,per_child,signers,log_inv_rate,leaf_size_bytes,root_size_bytes,leaf_total_ms,leaf_avg_ms,root_ms,verify_ms,iterations\n");
    for (results) |r| {
        const kind: []const u8 = switch (r.shape.kind) {
            .flat => "flat",
            .tree => "tree",
        };
        try writer.print("{s},{s},{d},{d},{d},{d},{d},{d},{d:.3},{d:.3},", .{
            r.name,
            kind,
            r.shape.children,
            r.shape.per_child,
            r.total_signers,
            r.log_inv_rate,
            r.leaf_size_bytes,
            r.root_size_bytes,
            r.leaf_total_ms,
            r.leaf_avg_ms,
        });
        if (r.root_ms) |rm| {
            try writer.print("{d:.3}", .{rm});
        }
        try writer.print(",{d:.3},{d}\n", .{ r.verify_ms, r.iterations });
    }
}

fn writeJsonReport(
    writer: *std.Io.Writer,
    args: Args,
    num_keys: usize,
    single_sig: ?SingleSigMetrics,
    results: []const WorkloadResult,
) !void {
    try writer.writeAll("{\n");
    try writer.print("  \"log_inv_rate\": {d},\n", .{args.log_inv_rate});
    try writer.print("  \"iters\": {d},\n", .{args.iters});
    try writer.print("  \"num_distinct_keys\": {d},\n", .{num_keys});
    try writer.writeAll("  \"keys_dir\": ");
    try std.json.Stringify.value(args.keys_dir, .{}, writer);
    try writer.writeAll(",\n");
    try writer.writeAll("  \"sigs_dir\": ");
    try std.json.Stringify.value(args.sigs_dir, .{}, writer);
    try writer.writeAll(",\n");
    try writer.print("  \"epoch\": {d},\n", .{args.epoch});

    if (single_sig) |sb| {
        try writer.writeAll("  \"single_sig\": {\n");
        try writer.print("    \"samples\": {d},\n", .{sb.samples});
        try writer.print("    \"iters_per_sample\": {d},\n", .{sb.iters_per_sample});
        try writer.print("    \"sign_ms\": {d:.3},\n", .{sb.sign_ms});
        try writer.print("    \"sign_min_ms\": {d:.3},\n", .{sb.sign_min_ms});
        try writer.print("    \"sign_max_ms\": {d:.3},\n", .{sb.sign_max_ms});
        try writer.print("    \"verify_ms\": {d:.3},\n", .{sb.verify_ms});
        try writer.print("    \"verify_min_ms\": {d:.3},\n", .{sb.verify_min_ms});
        try writer.print("    \"verify_max_ms\": {d:.3}\n", .{sb.verify_max_ms});
        try writer.writeAll("  },\n");
    } else {
        try writer.writeAll("  \"single_sig\": null,\n");
    }

    try writer.writeAll("  \"results\": [\n");
    for (results, 0..) |r, i| {
        const kind: []const u8 = switch (r.shape.kind) {
            .flat => "flat",
            .tree => "tree",
        };
        try writer.writeAll("    {\n");
        try writer.print("      \"workload\": \"{s}\",\n", .{r.name});
        try writer.print("      \"shape\": {{ \"kind\": \"{s}\", \"children\": {d}, \"per_child\": {d} }},\n", .{
            kind,
            r.shape.children,
            r.shape.per_child,
        });
        try writer.print("      \"signers\": {d},\n", .{r.total_signers});
        try writer.print("      \"log_inv_rate\": {d},\n", .{r.log_inv_rate});
        try writer.print("      \"leaf_size_bytes\": {d},\n", .{r.leaf_size_bytes});
        try writer.print("      \"root_size_bytes\": {d},\n", .{r.root_size_bytes});
        try writer.print("      \"leaf_total_ms\": {d:.3},\n", .{r.leaf_total_ms});
        try writer.print("      \"leaf_avg_ms\": {d:.3},\n", .{r.leaf_avg_ms});
        if (r.root_ms) |rm| {
            try writer.print("      \"root_ms\": {d:.3},\n", .{rm});
        } else {
            try writer.writeAll("      \"root_ms\": null,\n");
        }
        try writer.print("      \"verify_ms\": {d:.3},\n", .{r.verify_ms});
        try writer.print("      \"iterations\": {d}\n", .{r.iterations});
        try writer.writeAll("    }");
        if (i + 1 < results.len) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("  ]\n");
    try writer.writeAll("}\n");
}

fn writeReportsToDisk(
    allocator: Allocator,
    args: Args,
    num_keys: usize,
    single_sig: ?SingleSigMetrics,
    results: []const WorkloadResult,
) !void {
    if (args.json_path) |path| {
        var alloc_writer: std.Io.Writer.Allocating = .init(allocator);
        defer alloc_writer.deinit();
        try writeJsonReport(&alloc_writer.writer, args, num_keys, single_sig, results);
        try writeFileAtPath(path, alloc_writer.writer.buffered());
        std.debug.print("wrote JSON report to {s}\n", .{path});
    }
    if (args.csv_path) |path| {
        var alloc_writer: std.Io.Writer.Allocating = .init(allocator);
        defer alloc_writer.deinit();
        try writeCsvReport(&alloc_writer.writer, results);
        try writeFileAtPath(path, alloc_writer.writer.buffered());
        std.debug.print("wrote CSV report to {s}\n", .{path});
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const args = parseArgs(init) catch |err| {
        std.debug.print("error: failed to parse args: {s}\n", .{@errorName(err)});
        printHelp();
        std.process.exit(2);
    };

    if (args.print_help) {
        printHelp();
        return;
    }

    // Compute the maximum signer count across workloads we will actually
    // run, and pick the key-pool size from it.
    var max_signers: usize = 0;
    var workload_count: usize = 0;
    if (!args.skip_aggregate_bench) {
        for (default_workloads) |w| {
            if (!workloadMatchesFilter(args.filter, w.base_name, args.log_inv_rate)) continue;
            workload_count += 1;
            const n = w.shape.totalSigners();
            if (n > max_signers) max_signers = n;
        }
        if (workload_count == 0) {
            std.debug.print("error: filter '{?s}' matched no workloads\n", .{args.filter});
            std.process.exit(2);
        }
    }

    // The XMSS aggregate prover/verifier reject duplicate pubkeys, so we
    // must have at least `max_signers` distinct keys in the pool. A smaller
    // value causes tree workloads to abort inside the Rust prover with an
    // InvalidProof unwrap, so we reject it up-front rather than letting
    // the CLI hand control to a path that can panic across the FFI.
    const num_keys = if (args.skip_aggregate_bench)
        (args.num_distinct_keys orelse 0)
    else
        (args.num_distinct_keys orelse max_signers);
    if (!args.skip_aggregate_bench) {
        if (num_keys == 0) {
            std.debug.print("error: num_distinct_keys must be > 0\n", .{});
            std.process.exit(2);
        }
        if (num_keys < max_signers) {
            std.debug.print(
                "error: --num-distinct-keys ({d}) is less than the largest signer count across the selected workloads ({d}). The XMSS aggregator rejects duplicate pubkeys, so a smaller pool causes tree workloads to abort in the Rust prover. Re-run with --num-distinct-keys >= {d}, narrow the workload set with --filter, or pass --skip-aggregate-bench.\n",
                .{ num_keys, max_signers, max_signers },
            );
            std.process.exit(2);
        }
    }

    const default_threads = @max(@as(usize, 1), @min(@as(usize, 8), std.Thread.getCpuCount() catch 1));
    const keygen_threads = args.keygen_threads orelse default_threads;
    const sign_bench_iters = if (args.sign_bench_iters == 0) args.iters else args.sign_bench_iters;

    // XMSS keys are one-time per epoch. To sign at `args.epoch`, the key
    // must be generated with `num_active_epochs >= epoch + 1` — otherwise
    // the Rust signer aborts on an out-of-range epoch. Keys are cached on
    // disk keyed by this lifetime so a later run at a higher epoch does
    // not consume a shorter-lived cached key.
    const num_active_epochs: usize = @as(usize, args.epoch) + 1;

    std.debug.print("xmss benchmark\n", .{});
    std.debug.print("  log_inv_rate = {d}\n", .{args.log_inv_rate});
    std.debug.print("  iters = {d}\n", .{args.iters});
    if (!args.skip_aggregate_bench) {
        std.debug.print("  num_distinct_keys = {d} (max signers across workloads = {d})\n", .{ num_keys, max_signers });
    }
    std.debug.print("  keygen_threads = {d}\n", .{keygen_threads});
    std.debug.print("  keys_dir = {s}\n", .{args.keys_dir});
    std.debug.print("  sigs_dir = {s}\n", .{args.sigs_dir});
    std.debug.print("  matching aggregation workloads = {d}\n", .{workload_count});
    if (!args.skip_single_bench) {
        std.debug.print("  single-sig bench = {d} samples × {d} iters = {d} measurements\n", .{
            args.sign_bench_samples, sign_bench_iters, args.sign_bench_samples * sign_bench_iters,
        });
    }

    // Rayon must be configured before the prover is initialized.
    if (args.rayon_threads) |t| {
        xmss.setRayonThreads(t);
    }

    // setupProver / setupVerifier are aggregation-only prerequisites — the
    // single-sig path uses hashsig_verify directly without these. Skipping
    // them when the aggregation phase is off keeps "single-sig only" mode
    // usable on hosts where aggregation setup would otherwise fail.
    if (!args.skip_aggregate_bench) {
        std.debug.print("setting up XMSS prover...\n", .{});
        xmss.setupProver() catch |err| {
            std.debug.print("fatal: setupProver failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        std.debug.print("setting up XMSS verifier...\n", .{});
        xmss.setupVerifier() catch |err| {
            std.debug.print("fatal: setupVerifier failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    }

    const message_hash = [_]u8{0xab} ** 32;

    // Single-sig sign + verify bench runs before pool build so a partial
    // run still emits a useful number even if the aggregation phase is
    // killed midway (e.g. by the OOM killer on a tiny machine).
    var single_sig: ?SingleSigMetrics = null;
    if (!args.skip_single_bench) {
        try ensureDir(args.keys_dir);
        std.debug.print("running single sign/verify bench ({d} samples × {d} iters)...\n", .{
            args.sign_bench_samples, sign_bench_iters,
        });
        const t0 = nowNs();
        const m = try runSingleSigBench(
            allocator,
            args.keys_dir,
            args.sign_bench_samples,
            sign_bench_iters,
            &message_hash,
            args.epoch,
            num_active_epochs,
        );
        const elapsed_s = @as(f64, @floatFromInt(elapsedNs(t0))) / std.time.ns_per_s;
        std.debug.print("  single-sig bench done in {d:.1}s (sign median={d:.2}ms, verify median={d:.2}ms)\n", .{
            elapsed_s, m.sign_ms, m.verify_ms,
        });
        single_sig = m;
    }

    var results: std.ArrayList(WorkloadResult) = .empty;
    defer {
        for (results.items) |r| allocator.free(r.name);
        results.deinit(allocator);
    }

    if (!args.skip_aggregate_bench) {
        std.debug.print("building signer pool of {d} signers ({d} thread(s); keys: {s}; sigs: {s})...\n", .{
            num_keys, keygen_threads, args.keys_dir, args.sigs_dir,
        });
        const pool_start_ns = nowNs();
        var pool = try buildSignerPool(
            allocator,
            args.keys_dir,
            args.sigs_dir,
            num_keys,
            &message_hash,
            args.epoch,
            num_active_epochs,
            keygen_threads,
        );
        defer pool.deinit();
        std.debug.print("  signer pool ready in {d:.1}s\n", .{nsToMs(elapsedNs(pool_start_ns)) / 1000.0});

        for (default_workloads) |w| {
            if (!workloadMatchesFilter(args.filter, w.base_name, args.log_inv_rate)) continue;
            std.debug.print("running {s} (signers={d}, iters={d})...\n", .{ w.base_name, w.shape.totalSigners(), args.iters });
            const wl_start = nowNs();
            const result = try runWorkload(allocator, &pool, w, &message_hash, args.epoch, args.log_inv_rate, args.iters);
            try results.append(allocator, result);
            std.debug.print("  done in {d:.1}s (leaf {d:.2} KiB, root {d:.2} KiB)\n", .{
                nsToMs(elapsedNs(wl_start)) / 1000.0,
                bytesToKib(result.leaf_size_bytes),
                bytesToKib(result.root_size_bytes),
            });
        }
    }

    // Print markdown report to stdout.
    var stdout_buf: [16 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(threadedIo(), &stdout_buf);
    try writeMarkdownReport(&stdout_writer.interface, args, num_keys, single_sig, results.items);
    try stdout_writer.interface.flush();

    try writeReportsToDisk(allocator, args, num_keys, single_sig, results.items);
}
