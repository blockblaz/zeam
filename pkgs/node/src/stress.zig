// Single-node ingestion stress harness — issue #803 slice (b).
//
// Per the design doc (`docs/threading_refactor_slice_a.md` §"Stress test
// plan", merge gate for slice a-3 / absorbed into slice b):
//
//   "Synthetic gossip-block flood + concurrent `blocks_by_root` RPC against
//    the same node. Run 30+ minutes; assert no `state-map-key-not-found`
//    panics, no assertion failures, no `MissingPreState`."
//
// What this harness does:
//
//   1. Builds a real `BeamChain` on top of an in-process database against a
//      `MockChainData` of N blocks. We do NOT spin up a libp2p backend in
//      this harness — the goal is to exercise BeamChain's per-resource
//      locks (states / pending_blocks / pubkey_cache / root_to_slot /
//      events / block_cache) under realistic concurrent contention. The
//      libp2p bridge thread's role is purely an FFI invoker of the same
//      `chain.onGossip*` / `chain.onBlock` / `chain.onGossipAttestation`
//      entry points exercised here directly. End-to-end devnet smoke is
//      covered separately by the existing devnet runner; this harness is
//      the lock-correctness merge gate.
//
//   2. Pre-imports the chain serially so `states`, `forkChoice`, `db` are
//      populated.
//
//   3. Launches concurrent worker threads:
//        * gossip-flood threads: re-call `chain.onBlock(block_i)` cycling
//          through the chain, exercising the kept_existing path on
//          `statesCommitKeepExisting` (the long-hold-across-DB-write site
//          issue #821 cares about).
//        * rpc-reader threads: call `chain.db.loadBlock(...)` for known
//          and random unknown roots — mirrors the lock-free
//          `onReqRespRequest{blocks_by_root}` path (slice a-3 PR #820).
//        * attestation-spammer threads: build attestations and call
//          `chain.onGossipAttestation`, exercising `events_lock`.
//        * borrow-reader threads: call `chain.statesGet(root)` +
//          `cloneAndRelease` — mirrors the HTTP-API-shaped reader pattern
//          and the BorrowedState long-hold path (#820).
//        * block-cache-churner: insert/remove fake-rooted blocks via
//          `BlockCache` directly, exercising the network-side cache that
//          `onReqRespRequest` reads.
//        * watchdog: aborts via `@panic` if the global op counter doesn't
//          advance for more than 60s.
//
//   4. After the configured duration (default 1800s = 30min, override via
//      env `ZEAM_STRESS_DURATION_SECS`), all workers stop. Final summary
//      is printed: total ops, ops/sec, per-worker counts. Exit 0 on
//      clean run; non-zero exit / panic on any assertion failure.
//
// What this harness does NOT do:
//
//   * It does not start a libp2p backend. The slice (a-3) lock-free
//     `onReqRespRequest` path is exercised via direct DB reads since the
//     RPC handler body is a pure DB read after the lock-free conversion.
//   * It does not exercise multi-node gossip propagation. That's the
//     10-node devnet under jitter scenario — separate, runs in nightly.
//   * It does not exercise XMSS proposer-signature verification at full
//     volume — `chain.onBlock` does verify proposer signature each call,
//     but we cycle through a fixed set of pre-signed blocks rather than
//     producing fresh signatures every iteration (which would be ~700ms
//     per block and dominate runtime). The XMSS verify path is hit
//     enough at this volume to validate the lock interactions; the slow
//     XMSS path is covered by the existing `pkgs/xmss` stress tests.

const std = @import("std");
const Allocator = std.mem.Allocator;

const configs = @import("@zeam/configs");
const database = @import("@zeam/database");
const keymanager = @import("@zeam/key-manager");
const networks = @import("@zeam/network");
const params = @import("@zeam/params");
const ssz = @import("ssz");
const stf = @import("@zeam/state-transition");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");

const chain_mod = @import("./chain.zig");
const constants = @import("./constants.zig");
const locking = @import("./locking.zig");
const networkFactory = @import("./network.zig");

const BeamChain = chain_mod.BeamChain;
const ChainOpts = chain_mod.ChainOpts;
const ConnectedPeers = networkFactory.ConnectedPeers;

const NodeNameRegistry = networks.NodeNameRegistry;

/// Sleep helper. zig 0.16 dropped `std.Thread.sleep`; we use the libc
/// nanosleep(2) directly. Caller passes whole seconds; we cap at
/// reasonable values so signed conversion is fine.
fn sleepSecs(secs: u64) void {
    var ts: std.c.timespec = .{
        .sec = @intCast(secs),
        .nsec = 0,
    };
    _ = std.c.nanosleep(&ts, &ts);
}

/// Stress configuration. Defaults are the design-doc merge-gate values;
/// override via env vars for shorter dev runs.
const StressConfig = struct {
    duration_secs: u64,
    num_blocks: usize,
    gossip_threads: usize,
    rpc_threads: usize,
    attestation_threads: usize,
    borrow_threads: usize,
    cache_churn_threads: usize,
    watchdog_stall_secs: u64,

    fn readEnvU64(name: [*:0]const u8, default: u64) u64 {
        const ptr = std.c.getenv(name) orelse return default;
        const slice = std.mem.sliceTo(ptr, 0);
        return std.fmt.parseInt(u64, slice, 10) catch default;
    }

    fn readEnvUsize(name: [*:0]const u8, default: usize) usize {
        const ptr = std.c.getenv(name) orelse return default;
        const slice = std.mem.sliceTo(ptr, 0);
        return std.fmt.parseInt(usize, slice, 10) catch default;
    }

    fn fromEnv(allocator: Allocator) !StressConfig {
        _ = allocator;
        return StressConfig{
            .duration_secs = readEnvU64("ZEAM_STRESS_DURATION_SECS", 1800),
            .num_blocks = readEnvUsize("ZEAM_STRESS_NUM_BLOCKS", 6),
            .gossip_threads = readEnvUsize("ZEAM_STRESS_GOSSIP_THREADS", 3),
            .rpc_threads = readEnvUsize("ZEAM_STRESS_RPC_THREADS", 4),
            .attestation_threads = readEnvUsize("ZEAM_STRESS_ATTN_THREADS", 2),
            .borrow_threads = readEnvUsize("ZEAM_STRESS_BORROW_THREADS", 2),
            .cache_churn_threads = readEnvUsize("ZEAM_STRESS_CACHE_THREADS", 1),
            .watchdog_stall_secs = readEnvU64("ZEAM_STRESS_WATCHDOG_SECS", 60),
        };
    }

    fn dump(self: StressConfig) void {
        std.debug.print(
            "stress config: duration={d}s num_blocks={d} gossip={d} rpc={d} attn={d} borrow={d} cache={d} watchdog={d}s\n",
            .{
                self.duration_secs,
                self.num_blocks,
                self.gossip_threads,
                self.rpc_threads,
                self.attestation_threads,
                self.borrow_threads,
                self.cache_churn_threads,
                self.watchdog_stall_secs,
            },
        );
    }
};

/// Shared context between every worker thread. All counters are atomic so
/// the watchdog and the final summary can read them without locking.
const StressCtx = struct {
    chain: *BeamChain,
    blocks: []types.SignedBlock,
    block_roots: []types.Root,
    cache: *locking.BlockCache,
    template_block: types.SignedBlock,
    template_parent: types.Root,
    key_manager: *keymanager.KeyManager,
    deadline_ns: i128,
    /// Configured stall threshold (ns). Driven by `ZEAM_STRESS_WATCHDOG_SECS`
    /// via `StressConfig.watchdog_stall_secs`; the watchdog reads this rather
    /// than a hardcoded constant so dev runs can shorten the deadlock window.
    watchdog_stall_ns: i128,
    /// Configured stall threshold echoed back in seconds for log/fatal
    /// messages. Stored separately so we don't divide an i128 in the hot path.
    watchdog_stall_secs: u64,
    /// Highest block slot in the pre-imported chain. Used by
    /// `borrowReaderWorker` for an O(1) coherence bound on observed
    /// post-state slots; see the worker for rationale.
    last_imported_slot: types.Slot,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // op counters
    gossip_ops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rpc_ops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    attn_ops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    borrow_ops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    cache_ops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // error counters — non-fatal expected races
    gossip_errs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    attn_errs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    borrow_errs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // fatal error flag — any worker that observes a state-coherence
    // violation flips this and the harness exits non-zero.
    fatal: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fatal_msg: [256]u8 = undefined,
    fatal_msg_len: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn totalOps(self: *StressCtx) u64 {
        return self.gossip_ops.load(.monotonic) +
            self.rpc_ops.load(.monotonic) +
            self.attn_ops.load(.monotonic) +
            self.borrow_ops.load(.monotonic) +
            self.cache_ops.load(.monotonic);
    }

    fn shouldStop(self: *StressCtx) bool {
        if (self.stop.load(.acquire)) return true;
        const now = zeam_utils.monotonicTimestampNs();
        if (now >= self.deadline_ns) {
            self.stop.store(true, .release);
            return true;
        }
        return false;
    }

    fn recordFatal(self: *StressCtx, comptime fmt: []const u8, args: anytype) void {
        // Best-effort message capture. Writers race but only one wins;
        // the others' messages are discarded.
        if (self.fatal.swap(true, .acq_rel)) return;
        const msg = std.fmt.bufPrint(&self.fatal_msg, fmt, args) catch &self.fatal_msg;
        self.fatal_msg_len.store(msg.len, .release);
        self.stop.store(true, .release);
    }
};

fn gossipFloodWorker(ctx: *StressCtx, thread_id: usize) void {
    var i: usize = 0;
    while (!ctx.shouldStop()) {
        // Cycle through blocks 1..N. Block 0 is genesis (already in
        // states from chain.init). Each call exercises the kept_existing
        // path of statesCommitKeepExisting since the block was
        // pre-imported.
        const block_idx = (i % (ctx.blocks.len - 1)) + 1;
        const block = ctx.blocks[block_idx];

        const missing = ctx.chain.onBlock(block, .{ .pruneForkchoice = false }) catch |err| {
            // The design doc (`docs/threading_refactor_slice_a.md`
            // §Stress test plan) names the merge-gate invariants:
            //   * no `MissingPreState` (state-map race)
            //   * no assertion failures / panics
            //   * no UAF / deadlock
            //
            // This worker re-imports a pre-imported clean chain in a
            // tight loop. The expected outcome of every call is either
            //   * success (the `kept_existing` path in
            //     `statesCommitKeepExisting` returns an empty slice), or
            //   * `MissingPreState`, which means a writer mutated
            //     `chain.states` mid-import — the exact race the
            //     per-resource-locks slice is meant to eliminate.
            //
            // ANY error — `MissingPreState`, the other declared
            // `BlockProcessingError` tags (`InvalidSignatureGroups`,
            // `DuplicateAttestationData`, `TooManyAttestationData`), or
            // an unexpected error tag introduced by future changes — is
            // a regression on this codepath. Fail the run inline so CI
            // catches it, mirroring the recommendation in the
            // slice-(b) review.
            //
            // (`BlockAlreadyKnown` is intentionally NOT special-cased
            // — duplicate imports go through the `kept_existing`
            // success path and return an empty slice, never an error
            // tag. See chain.zig `statesCommitKeepExisting`.)
            switch (err) {
                error.MissingPreState => {
                    ctx.recordFatal(
                        "gossip-flood (thread {d}): MissingPreState — design-doc gate violation (states-map race)",
                        .{thread_id},
                    );
                },
                else => {
                    ctx.recordFatal(
                        "gossip-flood (thread {d}): unexpected error from chain.onBlock on pre-imported chain: {s}",
                        .{ thread_id, @errorName(err) },
                    );
                },
            }
            _ = ctx.gossip_errs.fetchAdd(1, .monotonic);
            _ = ctx.gossip_ops.fetchAdd(1, .monotonic);
            return;
        };
        ctx.chain.allocator.free(missing);
        _ = ctx.gossip_ops.fetchAdd(1, .monotonic);
        i += 1;
    }
}

fn rpcReaderWorker(ctx: *StressCtx, thread_id: usize) void {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE ^ @as(u64, @intCast(thread_id)));
    const rand = prng.random();
    while (!ctx.shouldStop()) {
        // Mix known and unknown roots. ~75% known (DB hit), ~25%
        // synthetic random (DB miss) — exercises both arms of the
        // lock-free RPC handler.
        const choice = rand.uintAtMost(u8, 99);
        var root: types.Root = undefined;
        if (choice < 75) {
            const idx = rand.uintLessThan(usize, ctx.block_roots.len);
            root = ctx.block_roots[idx];
        } else {
            rand.bytes(&root);
        }

        if (ctx.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
            var sb = signed_block_value;
            sb.deinit();
        }
        _ = ctx.rpc_ops.fetchAdd(1, .monotonic);
    }
}

fn attestationSpammerWorker(ctx: *StressCtx, thread_id: usize) void {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF ^ @as(u64, @intCast(thread_id)));
    const rand = prng.random();
    const allocator = ctx.chain.allocator;

    while (!ctx.shouldStop()) {
        // Pick a target slot from blocks[1..]. Use validator_id = 0..3
        // matching the 4-validator default in genMockChain.
        const slot_idx = 1 + rand.uintLessThan(usize, ctx.blocks.len - 1);
        const target_root = ctx.block_roots[slot_idx];
        const target_slot: types.Slot = ctx.blocks[slot_idx].block.slot;
        const source_idx = if (slot_idx > 1) slot_idx - 1 else 0;
        const validator_id = rand.uintLessThan(usize, 4);

        const message = types.Attestation{
            .validator_id = @intCast(validator_id),
            .data = .{
                .slot = target_slot,
                .head = .{ .root = target_root, .slot = target_slot },
                .source = .{ .root = ctx.block_roots[source_idx], .slot = ctx.blocks[source_idx].block.slot },
                .target = .{ .root = target_root, .slot = target_slot },
            },
        };

        const signature = ctx.key_manager.signAttestation(&message, allocator) catch {
            _ = ctx.attn_errs.fetchAdd(1, .monotonic);
            _ = ctx.attn_ops.fetchAdd(1, .monotonic);
            continue;
        };

        const valid_attestation = types.SignedAttestation{
            .validator_id = message.validator_id,
            .message = message.data,
            .signature = signature,
        };
        const subnet_id = types.computeSubnetId(
            @intCast(valid_attestation.validator_id),
            ctx.chain.config.spec.attestation_committee_count,
        ) catch {
            _ = ctx.attn_errs.fetchAdd(1, .monotonic);
            _ = ctx.attn_ops.fetchAdd(1, .monotonic);
            continue;
        };
        const gossip_attestation = networks.AttestationGossip{
            .subnet_id = @intCast(subnet_id),
            .message = valid_attestation,
        };

        ctx.chain.onGossipAttestation(gossip_attestation) catch {
            // Many expected races here (FutureSlot, etc.) — count but
            // don't treat as fatal.
            _ = ctx.attn_errs.fetchAdd(1, .monotonic);
        };
        _ = ctx.attn_ops.fetchAdd(1, .monotonic);
    }
}

fn borrowReaderWorker(ctx: *StressCtx, thread_id: usize) void {
    var prng = std.Random.DefaultPrng.init(0xBADCAFE ^ @as(u64, @intCast(thread_id)));
    const rand = prng.random();
    const allocator = ctx.chain.allocator;

    while (!ctx.shouldStop()) {
        // ~80% known root (borrow + clone hit), ~20% unknown root
        // (borrow returns null → noop).
        const choice = rand.uintAtMost(u8, 99);
        var root: types.Root = undefined;
        if (choice < 80) {
            const idx = rand.uintLessThan(usize, ctx.block_roots.len);
            root = ctx.block_roots[idx];
        } else {
            rand.bytes(&root);
        }

        var borrow = ctx.chain.statesGet(root) orelse {
            _ = ctx.borrow_ops.fetchAdd(1, .monotonic);
            continue;
        };
        // cloneAndRelease consumes the borrow and releases the lock.
        const owned = borrow.cloneAndRelease(allocator) catch {
            _ = ctx.borrow_errs.fetchAdd(1, .monotonic);
            _ = ctx.borrow_ops.fetchAdd(1, .monotonic);
            continue;
        };
        // Coherence sanity: O(1) bound check. The post-state's slot
        // must lie within `[0, last_imported_slot]` — the chain has
        // never advanced past the last block we pre-imported, and a
        // negative / wraparound slot would indicate a torn read.
        //
        // Earlier versions of this check linear-scanned `ctx.blocks`
        // for an exact slot match per iteration. That had two
        // problems: O(N) per check, and a false-positive risk on
        // future fixtures with skipped slots (where a legitimate
        // post-state slot need not equal any block.slot). The
        // bounded invariant catches torn reads (the ones that
        // matter — slot field corrupted by a writer mid-clone)
        // without depending on slot-to-block bijection.
        if (owned.slot > ctx.last_imported_slot) {
            ctx.recordFatal(
                "borrow reader: incoherent slot={d} (last_imported={d})",
                .{ owned.slot, ctx.last_imported_slot },
            );
        }
        owned.deinit();
        allocator.destroy(owned);
        _ = ctx.borrow_ops.fetchAdd(1, .monotonic);
    }
}

fn cacheChurnWorker(ctx: *StressCtx, thread_id: usize) void {
    var prng = std.Random.DefaultPrng.init(0xF00DBABE ^ @as(u64, @intCast(thread_id)));
    const rand = prng.random();
    const allocator = ctx.chain.allocator;

    var insert_counter: u32 = 1;
    while (!ctx.shouldStop()) {
        // Randomly insert or remove. Use synthetic non-aliasing roots
        // (high u32 in first 4 bytes) so we don't collide with real
        // chain roots. Each insertion is a fresh sszClone of the
        // template + serialized ssz buffer.
        const op = rand.uintAtMost(u8, 99);
        if (op < 50) {
            var root: types.Root = std.mem.zeroes(types.Root);
            const key: u32 = 0x80000000 + insert_counter;
            std.mem.writeInt(u32, root[0..4], key, .little);
            insert_counter +%= 1;

            const block_ptr = allocator.create(types.SignedBlock) catch {
                _ = ctx.cache_ops.fetchAdd(1, .monotonic);
                continue;
            };
            types.sszClone(allocator, types.SignedBlock, ctx.template_block, block_ptr) catch {
                allocator.destroy(block_ptr);
                _ = ctx.cache_ops.fetchAdd(1, .monotonic);
                continue;
            };

            var ssz_buf: std.ArrayList(u8) = .empty;
            ssz.serialize(types.SignedBlock, ctx.template_block, &ssz_buf, allocator) catch {
                block_ptr.deinit();
                allocator.destroy(block_ptr);
                ssz_buf.deinit(allocator);
                _ = ctx.cache_ops.fetchAdd(1, .monotonic);
                continue;
            };
            const ssz_bytes = ssz_buf.toOwnedSlice(allocator) catch {
                block_ptr.deinit();
                allocator.destroy(block_ptr);
                ssz_buf.deinit(allocator);
                _ = ctx.cache_ops.fetchAdd(1, .monotonic);
                continue;
            };

            ctx.cache.insertBlockPtr(root, block_ptr, ctx.template_parent, ssz_bytes) catch {
                block_ptr.deinit();
                allocator.destroy(block_ptr);
                allocator.free(ssz_bytes);
                _ = ctx.cache_ops.fetchAdd(1, .monotonic);
                continue;
            };
            allocator.destroy(block_ptr);
        } else {
            // Try to remove a recently-inserted root.
            var root: types.Root = std.mem.zeroes(types.Root);
            const probe_key: u32 = 0x80000000 + rand.uintAtMost(u32, insert_counter +| 1);
            std.mem.writeInt(u32, root[0..4], probe_key, .little);
            _ = ctx.cache.removeFetchedBlock(root);
        }

        // Also exercise the read path under the same lock.
        var probe_root: types.Root = std.mem.zeroes(types.Root);
        const read_key: u32 = 0x80000000 + rand.uintAtMost(u32, insert_counter +| 1);
        std.mem.writeInt(u32, probe_root[0..4], read_key, .little);
        if (ctx.cache.cloneBlockAndSsz(probe_root, allocator)) |cloned_opt| {
            if (cloned_opt) |cloned_const| {
                var entry = cloned_const;
                if (entry.ssz == null or entry.ssz.?.len == 0) {
                    ctx.recordFatal("cache reader: triple-atomic invariant broken", .{});
                }
                entry.deinit(allocator);
            }
        } else |_| {}

        _ = ctx.cache_ops.fetchAdd(1, .monotonic);
    }
}

fn watchdogWorker(ctx: *StressCtx) void {
    var last_ops: u64 = 0;
    var last_progress_ns: i128 = zeam_utils.monotonicTimestampNs();

    while (!ctx.shouldStop()) {
        sleepSecs(2);
        const now = zeam_utils.monotonicTimestampNs();
        const cur = ctx.totalOps();
        if (cur != last_ops) {
            last_ops = cur;
            last_progress_ns = now;
            continue;
        }
        // Configured stall threshold is set by `runStress` on `ctx` from
        // `StressConfig.watchdog_stall_secs` (env: ZEAM_STRESS_WATCHDOG_SECS,
        // default 60s).
        if (now - last_progress_ns > ctx.watchdog_stall_ns) {
            ctx.recordFatal(
                "watchdog: no progress for {d}s — likely deadlock",
                .{ctx.watchdog_stall_secs},
            );
            return;
        }
    }
}

/// Run the stress harness end-to-end. Returns a StressSummary.
const StressSummary = struct {
    duration_secs: f64,
    gossip_ops: u64,
    rpc_ops: u64,
    attn_ops: u64,
    borrow_ops: u64,
    cache_ops: u64,
    gossip_errs: u64,
    attn_errs: u64,
    borrow_errs: u64,
    fatal: bool,
    fatal_msg: []const u8,
    final_states_len: usize,
    final_pending_blocks_len: usize,
    final_block_cache_len: usize,
};

fn runStress(allocator: Allocator, cfg: StressConfig) !StressSummary {
    cfg.dump();

    // 1. Build mock chain.
    std.debug.print("building mock chain ({d} blocks)...\n", .{cfg.num_blocks});
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, cfg.num_blocks, null);

    // 2. Build BeamChain.
    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 16,
        },
    };

    var beam_state: types.BeamState = undefined;
    try types.sszClone(allocator, types.BeamState, mock_chain.genesis_state, &beam_state);
    defer beam_state.deinit();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    // Build a unique tmp data dir under .zig-cache/tmp/. Use the
    // monotonic timestamp + pid to avoid collisions across reruns.
    var data_dir_buf: [256]u8 = undefined;
    const ts: u64 = @as(u64, @intCast(@max(zeam_utils.monotonicTimestampNs(), 0)));
    const pid: u64 = @intCast(std.c.getpid());
    const data_dir = try std.fmt.bufPrint(&data_dir_buf, ".zig-cache/tmp/zeam-stress-{d}-{d}", .{ pid, ts });
    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().createDirPath(io, data_dir);
    defer std.Io.Dir.cwd().deleteTree(io, data_dir) catch {};

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    defer allocator.destroy(connected_peers);
    connected_peers.* = ConnectedPeers.init(allocator);
    defer connected_peers.deinit();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{
        .config = chain_config,
        .anchorState = &beam_state,
        .nodeId = 99,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    // 3. Pre-import all blocks.
    std.debug.print("pre-importing blocks...\n", .{});
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing = try beam_chain.onBlock(block, .{ .pruneForkchoice = false });
        allocator.free(missing);
    }
    // Bump forkchoice clock past the last block's slot so future
    // attestation gossip isn't FutureSlot-rejected.
    const last_slot = mock_chain.blocks[mock_chain.blocks.len - 1].block.slot;
    try beam_chain.forkChoice.onInterval((last_slot + 4) * constants.INTERVALS_PER_SLOT, false);

    std.debug.print("pre-imported {d} blocks; states.count={d}\n", .{
        mock_chain.blocks.len - 1,
        beam_chain.states.count(),
    });

    // 4. Build a separate BlockCache for the cache-churn worker so it
    // doesn't fight with `beam_chain.db`. This matches the production
    // shape — `network.zig` owns a BlockCache instance distinct from
    // the chain's `states` map.
    var block_cache = locking.BlockCache.init(allocator);
    defer {
        // Drain any remaining synthetic entries.
        var i: u32 = 0;
        while (i < 100_000) : (i += 1) {
            var root: types.Root = std.mem.zeroes(types.Root);
            std.mem.writeInt(u32, root[0..4], 0x80000000 + i, .little);
            _ = block_cache.removeFetchedBlock(root);
        }
        block_cache.deinit();
    }

    // 5. Build a separate KeyManager for attestation signing — the
    // chain's internal pubkey cache is read by chain.onGossipAttestation
    // but we do the signing here.
    var attn_keymanager = try keymanager.getTestKeyManager(allocator, 4, cfg.num_blocks);
    defer attn_keymanager.deinit();

    // 6. Spin up workers.
    const start_ns = zeam_utils.monotonicTimestampNs();
    const deadline_ns = start_ns + @as(i128, @intCast(cfg.duration_secs)) * std.time.ns_per_s;

    var ctx = StressCtx{
        .chain = &beam_chain,
        .blocks = mock_chain.blocks,
        .block_roots = mock_chain.blockRoots,
        .cache = &block_cache,
        .template_block = mock_chain.blocks[1],
        .template_parent = mock_chain.blocks[1].block.parent_root,
        .key_manager = &attn_keymanager,
        .deadline_ns = deadline_ns,
        .watchdog_stall_ns = @as(i128, @intCast(cfg.watchdog_stall_secs)) *
            std.time.ns_per_s,
        .watchdog_stall_secs = cfg.watchdog_stall_secs,
        .last_imported_slot = mock_chain.blocks[mock_chain.blocks.len - 1].block.slot,
    };

    const total_threads = cfg.gossip_threads + cfg.rpc_threads + cfg.attestation_threads +
        cfg.borrow_threads + cfg.cache_churn_threads + 1; // +1 watchdog
    const threads = try allocator.alloc(std.Thread, total_threads);
    defer allocator.free(threads);

    var ti: usize = 0;
    for (0..cfg.gossip_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, gossipFloodWorker, .{ &ctx, k });
        ti += 1;
    }
    for (0..cfg.rpc_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, rpcReaderWorker, .{ &ctx, k });
        ti += 1;
    }
    for (0..cfg.attestation_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, attestationSpammerWorker, .{ &ctx, k });
        ti += 1;
    }
    for (0..cfg.borrow_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, borrowReaderWorker, .{ &ctx, k });
        ti += 1;
    }
    for (0..cfg.cache_churn_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, cacheChurnWorker, .{ &ctx, k });
        ti += 1;
    }
    threads[ti] = try std.Thread.spawn(.{}, watchdogWorker, .{&ctx});
    ti += 1;

    // 7. Periodic progress prints (every 60s) until deadline.
    const progress_interval_ns: i128 = 60 * std.time.ns_per_s;
    var next_progress_ns = start_ns + progress_interval_ns;
    while (!ctx.shouldStop()) {
        sleepSecs(1);
        const now = zeam_utils.monotonicTimestampNs();
        if (now >= next_progress_ns) {
            const elapsed_s: f64 = @as(f64, @floatFromInt(now - start_ns)) / @as(f64, std.time.ns_per_s);
            std.debug.print(
                "[+{d:.0}s] gossip={d} rpc={d} attn={d} borrow={d} cache={d} (errs g={d} a={d} b={d})\n",
                .{
                    elapsed_s,
                    ctx.gossip_ops.load(.monotonic),
                    ctx.rpc_ops.load(.monotonic),
                    ctx.attn_ops.load(.monotonic),
                    ctx.borrow_ops.load(.monotonic),
                    ctx.cache_ops.load(.monotonic),
                    ctx.gossip_errs.load(.monotonic),
                    ctx.attn_errs.load(.monotonic),
                    ctx.borrow_errs.load(.monotonic),
                },
            );
            next_progress_ns += progress_interval_ns;
        }
    }

    // 8. Join.
    for (threads) |t| t.join();

    const end_ns = zeam_utils.monotonicTimestampNs();
    const duration_secs: f64 = @as(f64, @floatFromInt(end_ns - start_ns)) / @as(f64, std.time.ns_per_s);

    // Snapshot final chain state under the chain's own locks.
    beam_chain.states_lock.lockShared();
    const final_states_len = beam_chain.states.count();
    beam_chain.states_lock.unlockShared();

    beam_chain.pending_blocks_lock.lock();
    const final_pending_blocks_len = beam_chain.pending_blocks.items.len;
    beam_chain.pending_blocks_lock.unlock();

    const fatal_len = ctx.fatal_msg_len.load(.acquire);
    const fatal_msg_slice: []const u8 = if (fatal_len > 0) ctx.fatal_msg[0..fatal_len] else "";

    return StressSummary{
        .duration_secs = duration_secs,
        .gossip_ops = ctx.gossip_ops.load(.monotonic),
        .rpc_ops = ctx.rpc_ops.load(.monotonic),
        .attn_ops = ctx.attn_ops.load(.monotonic),
        .borrow_ops = ctx.borrow_ops.load(.monotonic),
        .cache_ops = ctx.cache_ops.load(.monotonic),
        .gossip_errs = ctx.gossip_errs.load(.monotonic),
        .attn_errs = ctx.attn_errs.load(.monotonic),
        .borrow_errs = ctx.borrow_errs.load(.monotonic),
        .fatal = ctx.fatal.load(.acquire),
        .fatal_msg = fatal_msg_slice,
        .final_states_len = final_states_len,
        .final_pending_blocks_len = final_pending_blocks_len,
        .final_block_cache_len = block_cache.count(),
    };
}

// =====================================================================
// Saturation mode — slice (c-2c) commit 6 of #803.
//
// The default mode above (`runStress`) drives `chain.onBlock` /
// `chain.onGossipAttestation` directly on producer threads, exercising
// the per-resource locks under contention. The saturation mode here
// drives the chain-worker QUEUES instead, by calling `submitBlock` /
// `submitGossipAttestation` from N producer threads while a single
// chain-worker thread drains. The queues are bounded; producers are
// expected to observe `error.QueueFull` whenever they outpace the
// drainer. The mode verifies:
//
//   * Backpressure is correctly observed (QueueFull seen on both
//     queues).
//   * No lost producer-side accounting (every send_attempt accounted
//     for as ok|queue_full|other_err).
//   * The drainer makes progress (some sends succeed on both queues,
//     so the worker is not deadlocked behind something else).
//   * No panic / UAF (DebugAllocator + testing.allocator-grade
//     bookkeeping in the chain).
//
// This is the c-2c part-1 deliverable. Part-2 is the devnet4 burn-in,
// which is NOT gated on this PR.
//
// Producers that observe `error.QueueFull` retain ownership of their
// payload (per the c-2b commit-3 contract on `submitBlock` /
// `submitGossipAttestation`) and must `deinit()` the payload. The
// success path transfers ownership to the worker (which calls
// `Message.deinit` after dispatch) so the producer must NOT also free
// it. Both code paths below honor that contract — review them when
// touching the cleanup logic.

const SaturationConfig = struct {
    duration_secs: u64,
    num_blocks: usize,
    block_producer_threads: usize,
    attestation_producer_threads: usize,
    watchdog_stall_secs: u64,

    fn fromEnv(allocator: Allocator) !SaturationConfig {
        _ = allocator;
        return SaturationConfig{
            .duration_secs = StressConfig.readEnvU64("ZEAM_STRESS_DURATION_SECS", 30),
            .num_blocks = StressConfig.readEnvUsize("ZEAM_STRESS_NUM_BLOCKS", 6),
            // 4 producers per queue is enough to outpace the single
            // worker on every devnet-class machine we've measured. The
            // env knobs let CI dial down on slower runners.
            .block_producer_threads = StressConfig.readEnvUsize("ZEAM_STRESS_SAT_BLOCK_PRODUCERS", 4),
            .attestation_producer_threads = StressConfig.readEnvUsize("ZEAM_STRESS_SAT_ATTN_PRODUCERS", 4),
            .watchdog_stall_secs = StressConfig.readEnvU64("ZEAM_STRESS_WATCHDOG_SECS", 60),
        };
    }

    fn dump(self: SaturationConfig) void {
        std.debug.print(
            "saturation config: duration={d}s num_blocks={d} block_producers={d} attn_producers={d} watchdog={d}s\n",
            .{
                self.duration_secs,
                self.num_blocks,
                self.block_producer_threads,
                self.attestation_producer_threads,
                self.watchdog_stall_secs,
            },
        );
    }
};

const SaturationCtx = struct {
    chain: *BeamChain,
    blocks: []types.SignedBlock,
    block_roots: []types.Root,
    key_manager: *keymanager.KeyManager,
    deadline_ns: i128,
    watchdog_stall_ns: i128,
    watchdog_stall_secs: u64,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Per-queue counters. Every producer attempt lands in exactly one
    // of {send_ok, queue_full, other_err}. The summary asserts
    // attempts == ok + queue_full + other_err so a regression that
    // "loses" a producer-side count is visible.
    block_attempts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    block_send_ok: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    block_queue_full: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    block_other_err: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    attn_attempts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    attn_send_ok: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    attn_queue_full: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    attn_other_err: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fatal: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fatal_msg: [256]u8 = undefined,
    fatal_msg_len: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn shouldStop(self: *SaturationCtx) bool {
        if (self.stop.load(.acquire)) return true;
        const now = zeam_utils.monotonicTimestampNs();
        if (now >= self.deadline_ns) {
            self.stop.store(true, .release);
            return true;
        }
        return false;
    }

    fn totalSendOk(self: *SaturationCtx) u64 {
        return self.block_send_ok.load(.monotonic) + self.attn_send_ok.load(.monotonic);
    }
    fn totalQueueFull(self: *SaturationCtx) u64 {
        return self.block_queue_full.load(.monotonic) + self.attn_queue_full.load(.monotonic);
    }

    fn recordFatal(self: *SaturationCtx, comptime fmt: []const u8, args: anytype) void {
        if (self.fatal.swap(true, .acq_rel)) return;
        const msg = std.fmt.bufPrint(&self.fatal_msg, fmt, args) catch &self.fatal_msg;
        self.fatal_msg_len.store(msg.len, .release);
        self.stop.store(true, .release);
    }
};

fn saturationBlockProducerWorker(ctx: *SaturationCtx, thread_id: usize) void {
    const allocator = ctx.chain.allocator;
    var i: usize = 0;
    while (!ctx.shouldStop()) : (i += 1) {
        // Cycle through pre-imported blocks (skip genesis at index 0).
        const block_idx = (i % (ctx.blocks.len - 1)) + 1;
        const template = ctx.blocks[block_idx];

        // Clone: submitBlock takes ownership of the SignedBlock on a
        // successful send (the worker calls Message.deinit after
        // dispatch). On QueueFull / QueueClosed / ChainWorkerDisabled,
        // the producer retains ownership and MUST deinit the clone.
        var cloned: types.SignedBlock = undefined;
        types.sszClone(allocator, types.SignedBlock, template, &cloned) catch {
            _ = ctx.block_attempts.fetchAdd(1, .monotonic);
            _ = ctx.block_other_err.fetchAdd(1, .monotonic);
            continue;
        };

        _ = ctx.block_attempts.fetchAdd(1, .monotonic);
        // Slice (e) of #803: pass `null` for `block_root` so the
        // worker recomputes — the stress harness deliberately
        // exercises the fallback path. Real producers always pass
        // a precomputed root.
        ctx.chain.submitBlock(cloned, false, null) catch |err| {
            // We retain ownership on every error path — free the clone.
            cloned.deinit();
            switch (err) {
                error.QueueFull => _ = ctx.block_queue_full.fetchAdd(1, .monotonic),
                error.QueueClosed => _ = ctx.block_other_err.fetchAdd(1, .monotonic),
                error.ChainWorkerDisabled => {
                    ctx.recordFatal(
                        "sat-block-producer (thread {d}): submitBlock returned ChainWorkerDisabled — chain-worker MUST be running for the saturation mode",
                        .{thread_id},
                    );
                    _ = ctx.block_other_err.fetchAdd(1, .monotonic);
                    return;
                },
            }
            continue;
        };
        _ = ctx.block_send_ok.fetchAdd(1, .monotonic);
    }
}

fn saturationAttestationProducerWorker(ctx: *SaturationCtx, thread_id: usize) void {
    const allocator = ctx.chain.allocator;
    var prng = std.Random.DefaultPrng.init(0xA77E57 ^ @as(u64, @intCast(thread_id)));
    const rand = prng.random();
    while (!ctx.shouldStop()) {
        // Pick a random valid (block_idx, validator_id) pair like the
        // default attestationSpammerWorker does. We only need
        // submit-side throughput here; the worker thread does the
        // real verification work.
        const slot_idx = rand.uintAtMost(usize, ctx.block_roots.len - 1);
        const target_root = ctx.block_roots[slot_idx];
        const target_slot: types.Slot = ctx.blocks[slot_idx].block.slot;
        const source_idx = if (slot_idx > 1) slot_idx - 1 else 0;
        const validator_id = rand.uintLessThan(usize, 4);

        const message = types.Attestation{
            .validator_id = @intCast(validator_id),
            .data = .{
                .slot = target_slot,
                .head = .{ .root = target_root, .slot = target_slot },
                .source = .{
                    .root = ctx.block_roots[source_idx],
                    .slot = ctx.blocks[source_idx].block.slot,
                },
                .target = .{ .root = target_root, .slot = target_slot },
            },
        };

        const signature = ctx.key_manager.signAttestation(&message, allocator) catch {
            _ = ctx.attn_attempts.fetchAdd(1, .monotonic);
            _ = ctx.attn_other_err.fetchAdd(1, .monotonic);
            continue;
        };

        const valid_attestation = types.SignedAttestation{
            .validator_id = message.validator_id,
            .message = message.data,
            .signature = signature,
        };
        const subnet_id = types.computeSubnetId(
            @intCast(valid_attestation.validator_id),
            ctx.chain.config.spec.attestation_committee_count,
        ) catch {
            _ = ctx.attn_attempts.fetchAdd(1, .monotonic);
            _ = ctx.attn_other_err.fetchAdd(1, .monotonic);
            continue;
        };
        const gossip_attestation = networks.AttestationGossip{
            .subnet_id = @intCast(subnet_id),
            .message = valid_attestation,
        };

        _ = ctx.attn_attempts.fetchAdd(1, .monotonic);
        // submitGossipAttestation takes the AttestationGossip by
        // value; on QueueFull it returns and the producer retains the
        // value. AttestationGossip currently has no owned heap fields
        // (the SignedAttestation payload is a value type with a fixed
        // signature buffer), so there is nothing to free on the error
        // path — the value goes out of scope. If a future change
        // adds heap-bearing fields, this branch needs a corresponding
        // deinit().
        ctx.chain.submitGossipAttestation(gossip_attestation) catch |err| {
            switch (err) {
                error.QueueFull => _ = ctx.attn_queue_full.fetchAdd(1, .monotonic),
                error.QueueClosed => _ = ctx.attn_other_err.fetchAdd(1, .monotonic),
                error.ChainWorkerDisabled => {
                    ctx.recordFatal(
                        "sat-attn-producer (thread {d}): submitGossipAttestation returned ChainWorkerDisabled — chain-worker MUST be running for the saturation mode",
                        .{thread_id},
                    );
                    _ = ctx.attn_other_err.fetchAdd(1, .monotonic);
                    return;
                },
            }
            continue;
        };
        _ = ctx.attn_send_ok.fetchAdd(1, .monotonic);
    }
}

fn saturationWatchdogWorker(ctx: *SaturationCtx) void {
    // Saturation-specific watchdog: progress = sends OR queue-fulls.
    // "No queue-fulls AND no sends" for >stall_secs means producers
    // are deadlocked. Either signal alone is fine — sends-only means
    // the worker is keeping up, queue-fulls-only means the producers
    // are running but the worker is stalled (which is also caught by
    // the post-run assertion that some sends succeeded).
    var last_progress = ctx.totalSendOk() + ctx.totalQueueFull();
    var last_progress_ns: i128 = zeam_utils.monotonicTimestampNs();

    while (!ctx.shouldStop()) {
        sleepSecs(2);
        const now = zeam_utils.monotonicTimestampNs();
        const cur = ctx.totalSendOk() + ctx.totalQueueFull();
        if (cur != last_progress) {
            last_progress = cur;
            last_progress_ns = now;
            continue;
        }
        if (now - last_progress_ns > ctx.watchdog_stall_ns) {
            ctx.recordFatal(
                "saturation watchdog: no producer progress for {d}s — likely deadlock (send_ok + queue_full counters not advancing)",
                .{ctx.watchdog_stall_secs},
            );
            return;
        }
    }
}

const SaturationSummary = struct {
    duration_secs: f64,
    block_attempts: u64,
    block_send_ok: u64,
    block_queue_full: u64,
    block_other_err: u64,
    attn_attempts: u64,
    attn_send_ok: u64,
    attn_queue_full: u64,
    attn_other_err: u64,
    fatal: bool,
    fatal_msg: []const u8,
    final_states_len: usize,
};

fn runStressSaturation(allocator: Allocator, cfg: SaturationConfig) !SaturationSummary {
    cfg.dump();

    // 1. Build mock chain.
    std.debug.print("building mock chain ({d} blocks)...\n", .{cfg.num_blocks});
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, cfg.num_blocks, null);

    const spec_name = try allocator.dupe(u8, "beamdev");
    const fork_digest = try allocator.dupe(u8, "12345678");
    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 16,
        },
    };

    var beam_state: types.BeamState = undefined;
    try types.sszClone(allocator, types.BeamState, mock_chain.genesis_state, &beam_state);
    defer beam_state.deinit();

    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var data_dir_buf: [256]u8 = undefined;
    const ts: u64 = @as(u64, @intCast(@max(zeam_utils.monotonicTimestampNs(), 0)));
    const pid: u64 = @intCast(std.c.getpid());
    const data_dir = try std.fmt.bufPrint(&data_dir_buf, ".zig-cache/tmp/zeam-stress-sat-{d}-{d}", .{ pid, ts });
    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().createDirPath(io, data_dir);
    defer std.Io.Dir.cwd().deleteTree(io, data_dir) catch {};

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    defer allocator.destroy(connected_peers);
    connected_peers.* = ConnectedPeers.init(allocator);
    defer connected_peers.deinit();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{
        .config = chain_config,
        .anchorState = &beam_state,
        .nodeId = 99,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    // 2. Pre-import all blocks (synchronously, before starting the
    // worker). This populates `states`, forkChoice, db with valid
    // entries so the worker's onBlock calls hit the kept_existing
    // path of statesCommitKeepExisting.
    std.debug.print("pre-importing blocks...\n", .{});
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing = try beam_chain.onBlock(block, .{ .pruneForkchoice = false });
        allocator.free(missing);
    }
    const last_slot = mock_chain.blocks[mock_chain.blocks.len - 1].block.slot;
    try beam_chain.forkChoice.onInterval((last_slot + 4) * constants.INTERVALS_PER_SLOT, false);

    // 3. Start the chain-worker. Saturation mode REQUIRES the worker
    // to be running — producers route through `submitBlock` /
    // `submitGossipAttestation` which return `ChainWorkerDisabled`
    // when no worker is set. The deinit ordering above is correct:
    // BeamChain.deinit calls chain_worker.stop() first.
    try beam_chain.startChainWorker();
    std.debug.print("chain-worker started; entering saturation mode\n", .{});

    // 4. KeyManager for attestation signing.
    var attn_keymanager = try keymanager.getTestKeyManager(allocator, 4, cfg.num_blocks);
    defer attn_keymanager.deinit();

    // 5. Spin up workers.
    const start_ns = zeam_utils.monotonicTimestampNs();
    const deadline_ns = start_ns + @as(i128, @intCast(cfg.duration_secs)) * std.time.ns_per_s;

    var ctx = SaturationCtx{
        .chain = &beam_chain,
        .blocks = mock_chain.blocks,
        .block_roots = mock_chain.blockRoots,
        .key_manager = &attn_keymanager,
        .deadline_ns = deadline_ns,
        .watchdog_stall_ns = @as(i128, @intCast(cfg.watchdog_stall_secs)) *
            std.time.ns_per_s,
        .watchdog_stall_secs = cfg.watchdog_stall_secs,
    };

    const total_threads = cfg.block_producer_threads + cfg.attestation_producer_threads + 1;
    const threads = try allocator.alloc(std.Thread, total_threads);
    defer allocator.free(threads);

    var ti: usize = 0;
    for (0..cfg.block_producer_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, saturationBlockProducerWorker, .{ &ctx, k });
        ti += 1;
    }
    for (0..cfg.attestation_producer_threads) |k| {
        threads[ti] = try std.Thread.spawn(.{}, saturationAttestationProducerWorker, .{ &ctx, k });
        ti += 1;
    }
    threads[ti] = try std.Thread.spawn(.{}, saturationWatchdogWorker, .{&ctx});
    ti += 1;

    // 6. Periodic progress prints (every 10s for the typically-short
    // saturation runs). Final summary line MUST include
    // `errs g=N a=M b=K queue_full_b=X queue_full_a=Y` so a CI grep
    // can spot regressions easily.
    const progress_interval_ns: i128 = 10 * std.time.ns_per_s;
    var next_progress_ns = start_ns + progress_interval_ns;
    while (!ctx.shouldStop()) {
        sleepSecs(1);
        const now = zeam_utils.monotonicTimestampNs();
        if (now >= next_progress_ns) {
            const elapsed_s: f64 = @as(f64, @floatFromInt(now - start_ns)) / @as(f64, std.time.ns_per_s);
            std.debug.print(
                "[+{d:.0}s] block(ok={d} qfull={d} err={d}) attn(ok={d} qfull={d} err={d})\n",
                .{
                    elapsed_s,
                    ctx.block_send_ok.load(.monotonic),
                    ctx.block_queue_full.load(.monotonic),
                    ctx.block_other_err.load(.monotonic),
                    ctx.attn_send_ok.load(.monotonic),
                    ctx.attn_queue_full.load(.monotonic),
                    ctx.attn_other_err.load(.monotonic),
                },
            );
            next_progress_ns += progress_interval_ns;
        }
    }

    // 7. Join.
    for (threads) |t| t.join();

    const end_ns = zeam_utils.monotonicTimestampNs();
    const duration_secs: f64 = @as(f64, @floatFromInt(end_ns - start_ns)) / @as(f64, std.time.ns_per_s);

    beam_chain.states_lock.lockShared();
    const final_states_len = beam_chain.states.count();
    beam_chain.states_lock.unlockShared();

    const fatal_len = ctx.fatal_msg_len.load(.acquire);
    const fatal_msg_slice: []const u8 = if (fatal_len > 0) ctx.fatal_msg[0..fatal_len] else "";

    return SaturationSummary{
        .duration_secs = duration_secs,
        .block_attempts = ctx.block_attempts.load(.monotonic),
        .block_send_ok = ctx.block_send_ok.load(.monotonic),
        .block_queue_full = ctx.block_queue_full.load(.monotonic),
        .block_other_err = ctx.block_other_err.load(.monotonic),
        .attn_attempts = ctx.attn_attempts.load(.monotonic),
        .attn_send_ok = ctx.attn_send_ok.load(.monotonic),
        .attn_queue_full = ctx.attn_queue_full.load(.monotonic),
        .attn_other_err = ctx.attn_other_err.load(.monotonic),
        .fatal = ctx.fatal.load(.acquire),
        .fatal_msg = fatal_msg_slice,
        .final_states_len = final_states_len,
    };
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{
        .safety = true,
        .thread_safe = true,
    }).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== zeam single-node ingestion stress harness ===\n", .{});
    std.debug.print("issue #803 slice (b)/(c-2c) merge gates. design doc:\n", .{});
    std.debug.print("  docs/threading_refactor_slice_a.md §Stress test plan\n", .{});

    // Mode dispatch: ZEAM_STRESS_MODE=default (the slice-(b) merge
    // gate, default) or ZEAM_STRESS_MODE=saturation (slice (c-2c)
    // commit 6 — chain-worker queue saturation).
    const mode_ptr = std.c.getenv("ZEAM_STRESS_MODE");
    const mode: []const u8 = if (mode_ptr) |p| std.mem.sliceTo(p, 0) else "default";

    if (std.mem.eql(u8, mode, "saturation")) {
        try runSaturationMain(allocator);
        return;
    }
    if (!std.mem.eql(u8, mode, "default")) {
        std.debug.print(
            "FATAL: unknown ZEAM_STRESS_MODE={s} (expected: default|saturation)\n",
            .{mode},
        );
        std.process.exit(2);
    }

    const cfg = try StressConfig.fromEnv(allocator);

    const summary = runStress(allocator, cfg) catch |err| {
        std.debug.print("FATAL: stress harness errored: {s}\n", .{@errorName(err)});
        return err;
    };

    const total = summary.gossip_ops + summary.rpc_ops + summary.attn_ops +
        summary.borrow_ops + summary.cache_ops;
    const ops_per_sec: f64 = if (summary.duration_secs > 0)
        @as(f64, @floatFromInt(total)) / summary.duration_secs
    else
        0;

    std.debug.print("\n=== stress run summary ===\n", .{});
    std.debug.print("duration: {d:.1}s ({d:.1} min)\n", .{ summary.duration_secs, summary.duration_secs / 60.0 });
    std.debug.print("total ops: {d} ({d:.0} ops/sec)\n", .{ total, ops_per_sec });
    std.debug.print("  gossip-flood   : {d} ({d} errs)\n", .{ summary.gossip_ops, summary.gossip_errs });
    std.debug.print("  rpc-readers    : {d}\n", .{summary.rpc_ops});
    std.debug.print("  attn-spammer   : {d} ({d} errs)\n", .{ summary.attn_ops, summary.attn_errs });
    std.debug.print("  borrow-readers : {d} ({d} errs)\n", .{ summary.borrow_ops, summary.borrow_errs });
    std.debug.print("  cache-churn    : {d}\n", .{summary.cache_ops});
    std.debug.print("final state: states_len={d} pending_blocks_len={d} block_cache_len={d}\n", .{
        summary.final_states_len,
        summary.final_pending_blocks_len,
        summary.final_block_cache_len,
    });
    if (summary.fatal) {
        std.debug.print("\nFATAL: {s}\n", .{summary.fatal_msg});
        std.process.exit(1);
    }
    // Soft errors collected by the workers (e.g. unexpected
    // `BlockProcessingError` variants in gossip-flood, attestation- or
    // borrow-reader errors) are not panics, but on a pre-imported clean
    // chain they still indicate a regression worth failing CI on. The
    // design-doc gate says "assert no MissingPreState" — that is already
    // fatal above; any *other* unexpected error from these workers is
    // treated as a softer-but-still-CI-blocking signal here.
    if (summary.gossip_errs > 0 or summary.attn_errs > 0 or summary.borrow_errs > 0) {
        std.debug.print(
            "\nFATAL: worker error counters non-zero (g={d} a={d} b={d}) — see per-worker counts above\n",
            .{ summary.gossip_errs, summary.attn_errs, summary.borrow_errs },
        );
        std.process.exit(1);
    }
    std.debug.print("\nclean exit — no panics, no UAFs, no deadlocks observed\n", .{});
}

/// Saturation-mode entry point. Mirrors `main()`'s default-mode flow
/// but runs the saturation harness, prints a saturation-shaped
/// summary, and applies the saturation-mode assertions.
fn runSaturationMain(allocator: Allocator) !void {
    std.debug.print("mode: saturation (slice c-2c commit 6 of #803)\n", .{});

    const cfg = try SaturationConfig.fromEnv(allocator);

    const summary = runStressSaturation(allocator, cfg) catch |err| {
        std.debug.print("FATAL: saturation harness errored: {s}\n", .{@errorName(err)});
        return err;
    };

    const total_attempts = summary.block_attempts + summary.attn_attempts;
    const total_ok = summary.block_send_ok + summary.attn_send_ok;
    const total_qfull = summary.block_queue_full + summary.attn_queue_full;
    const total_err = summary.block_other_err + summary.attn_other_err;
    const ops_per_sec: f64 = if (summary.duration_secs > 0)
        @as(f64, @floatFromInt(total_attempts)) / summary.duration_secs
    else
        0;

    std.debug.print("\n=== saturation run summary ===\n", .{});
    std.debug.print("duration: {d:.1}s\n", .{summary.duration_secs});
    std.debug.print("total attempts: {d} ({d:.0} attempts/sec)\n", .{ total_attempts, ops_per_sec });
    std.debug.print("  block: attempts={d} ok={d} queue_full={d} other_err={d}\n", .{
        summary.block_attempts,
        summary.block_send_ok,
        summary.block_queue_full,
        summary.block_other_err,
    });
    std.debug.print("  attn : attempts={d} ok={d} queue_full={d} other_err={d}\n", .{
        summary.attn_attempts,
        summary.attn_send_ok,
        summary.attn_queue_full,
        summary.attn_other_err,
    });
    std.debug.print("final state: states_len={d}\n", .{summary.final_states_len});
    // Compact CI-friendly summary line. Match the shape used by the
    // default-mode summary so a single grep pattern catches both
    // mode regressions:
    //   `errs g=N a=M b=K queue_full_b=X queue_full_a=Y`
    // (g/a/b are inherited names from the slice-(b) summary; we map
    //  block_other_err→g, attn_other_err→a, total—b stays 0 here
    //  since saturation has no borrow worker).
    std.debug.print(
        "errs g={d} a={d} b=0 queue_full_b={d} queue_full_a={d}\n",
        .{
            summary.block_other_err,
            summary.attn_other_err,
            summary.block_queue_full,
            summary.attn_queue_full,
        },
    );

    if (summary.fatal) {
        std.debug.print("\nFATAL: {s}\n", .{summary.fatal_msg});
        std.process.exit(1);
    }

    // Saturation-mode invariants. Each one is a regression on a
    // separate property of the chain-worker queue plumbing; group
    // failures so a CI failure is self-explaining.
    var failed = false;

    // (1) Producer-side accounting balances: attempts == ok + qfull + other_err.
    if (summary.block_attempts != summary.block_send_ok + summary.block_queue_full + summary.block_other_err) {
        std.debug.print(
            "\nFATAL: block accounting mismatch — attempts={d} but ok+qfull+err={d}+{d}+{d}={d}\n",
            .{
                summary.block_attempts,
                summary.block_send_ok,
                summary.block_queue_full,
                summary.block_other_err,
                summary.block_send_ok + summary.block_queue_full + summary.block_other_err,
            },
        );
        failed = true;
    }
    if (summary.attn_attempts != summary.attn_send_ok + summary.attn_queue_full + summary.attn_other_err) {
        std.debug.print(
            "\nFATAL: attn accounting mismatch — attempts={d} but ok+qfull+err={d}+{d}+{d}={d}\n",
            .{
                summary.attn_attempts,
                summary.attn_send_ok,
                summary.attn_queue_full,
                summary.attn_other_err,
                summary.attn_send_ok + summary.attn_queue_full + summary.attn_other_err,
            },
        );
        failed = true;
    }

    // (2) Backpressure was actually exercised: at least one
    // QueueFull on each queue. If neither queue ever filled, the
    // run did not actually saturate — either the producers were
    // too slow or the worker is starting from a closed/disabled
    // state. Fail loudly so the test can be tuned (more producers,
    // shorter duration, smaller queue capacity).
    if (summary.block_queue_full == 0) {
        std.debug.print(
            "\nFATAL: block queue never saturated (queue_full=0) — increase ZEAM_STRESS_SAT_BLOCK_PRODUCERS or extend duration\n",
            .{},
        );
        failed = true;
    }
    if (summary.attn_queue_full == 0) {
        std.debug.print(
            "\nFATAL: attn queue never saturated (queue_full=0) — increase ZEAM_STRESS_SAT_ATTN_PRODUCERS or extend duration\n",
            .{},
        );
        failed = true;
    }

    // (3) The worker drained at least some messages on each queue.
    // "queue_full only, no successful sends" means the worker is
    // dead/deadlocked behind something other than the queue itself.
    if (summary.block_send_ok == 0) {
        std.debug.print(
            "\nFATAL: chain-worker drained zero block messages — likely deadlock or worker startup failure\n",
            .{},
        );
        failed = true;
    }
    if (summary.attn_send_ok == 0) {
        std.debug.print(
            "\nFATAL: chain-worker drained zero attestation messages — likely deadlock or worker startup failure\n",
            .{},
        );
        failed = true;
    }

    // (4) Soft-error counters non-zero is a regression — any
    // unexpected `submitBlock` / `submitGossipAttestation` error
    // tag (today only `QueueClosed` and `ChainWorkerDisabled`
    // would land in `other_err`). The first is observable only
    // mid-shutdown; the second is the recordFatal path above.
    if (summary.block_other_err > 0 or summary.attn_other_err > 0) {
        std.debug.print(
            "\nFATAL: producer-side other_err counters non-zero (block={d} attn={d}) — see per-queue counts above\n",
            .{ summary.block_other_err, summary.attn_other_err },
        );
        failed = true;
    }

    _ = total_ok;
    _ = total_qfull;
    _ = total_err;

    if (failed) std.process.exit(1);

    std.debug.print(
        "\nclean exit — chain-worker queues saturated and drained as expected, no UAF/deadlock observed\n",
        .{},
    );
}
