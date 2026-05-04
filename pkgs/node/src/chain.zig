const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const configs = @import("@zeam/configs");
const types = @import("@zeam/types");
const stf = @import("@zeam/state-transition");
const ssz = @import("ssz");
const networks = @import("@zeam/network");
const params = @import("@zeam/params");
const api = @import("@zeam/api");
const zeam_metrics = @import("@zeam/metrics");
const database = @import("@zeam/database");

const event_broadcaster = api.event_broadcaster;

const zeam_utils = @import("@zeam/utils");
const keymanager = @import("@zeam/key-manager");
const xmss = @import("@zeam/xmss");
const ThreadPool = @import("@zeam/thread-pool").ThreadPool;

pub const fcFactory = @import("./forkchoice.zig");
const constants = @import("./constants.zig");
const tree_visualizer = @import("./tree_visualizer.zig");
const locking = @import("./locking.zig");
const BorrowedState = locking.BorrowedState;
const LockTimer = locking.LockTimer;

const networkFactory = @import("./network.zig");
const PeerInfo = networkFactory.PeerInfo;
const ConnectedPeers = networkFactory.ConnectedPeers;

const NodeNameRegistry = networks.NodeNameRegistry;
const ZERO_SIGBYTES = types.ZERO_SIGBYTES;

pub const BlockProductionParams = struct {
    slot: usize,
    proposer_index: usize,

    pub fn format(self: BlockProductionParams, writer: anytype) !void {
        try writer.print("BlockProductionParams{{ slot={d}, proposer_index={d} }}", .{ self.slot, self.proposer_index });
    }
};

pub const AttestationConstructionParams = struct {
    slot: types.Slot,
};

pub const ChainOpts = struct {
    config: configs.ChainConfig,
    anchorState: *types.BeamState,
    nodeId: u32,
    logger_config: *zeam_utils.ZeamLoggerConfig,
    db: database.Db,
    node_registry: *const NodeNameRegistry,
    force_block_production: bool = false,
    // Seeds the runtime aggregator role. The role can be toggled at runtime
    // via `setAggregator`; the CLI `--is-aggregator` flag only supplies the
    // initial value. See `BeamChain.is_aggregator_enabled`.
    is_aggregator: bool = false,
    // Optional shared worker pool for CPU-bound work (signature verification).
    // When null, the chain falls back to the serial code paths.
    thread_pool: ?*ThreadPool = null,
};

pub const CachedProcessedBlockInfo = struct {
    postState: ?*types.BeamState = null,
    blockRoot: ?types.Root = null,
    pruneForkchoice: bool = true,
    // Pre-serialized SSZ bytes for the block.  When set, onBlock uses them directly
    // for database persistence and skips re-serializing the live SignedBlock, which
    // has been observed to corrupt in-memory List/Bitlist state on subsequent access.
    sszBytes: ?[]const u8 = null,
};

pub const GossipProcessingResult = struct {
    processed_block_root: ?types.Root = null,
    missing_attestation_roots: []types.Root = &[_]types.Root{},
};

pub const ProducedBlock = struct {
    block: types.BeamBlock,
    blockRoot: types.Root,

    // Aggregated signatures corresponding to attestations in the block body.
    attestation_signatures: types.AttestationSignatures,

    pub fn deinit(self: *ProducedBlock) void {
        self.block.deinit();
        for (self.attestation_signatures.slice()) |*sig_group| {
            sig_group.deinit();
        }
        self.attestation_signatures.deinit();
    }
};

pub const BeamChain = struct {
    config: configs.ChainConfig,
    anchor_state: *types.BeamState,

    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,
    // from finalized onwards to recent
    states: std.AutoHashMap(types.Root, *types.BeamState),
    nodeId: u32,
    // This struct needs to contain the zeam_logger_config to be able to call `maybeRotate`
    // For all other modules, we just need logger
    zeam_logger_config: *zeam_utils.ZeamLoggerConfig,
    logger: zeam_utils.ModuleLogger,
    stf_logger: zeam_utils.ModuleLogger,
    block_building_logger: zeam_utils.ModuleLogger,
    registered_validator_ids: []usize = &[_]usize{},
    db: database.Db,
    // Track last-emitted checkpoints to avoid duplicate SSE events (e.g., genesis spam)
    last_emitted_justified: types.Checkpoint,
    last_emitted_finalized: types.Checkpoint,
    /// Read-only handle to the network's connected-peer registry. The
    /// chain reads `count()` (atomic, lock-free) and iterates via
    /// `iterateLocked()` for sync-status decisions. Mutation is the
    /// network's responsibility — the chain only consumes.
    connected_peers: *ConnectedPeers,
    node_registry: *const NodeNameRegistry,
    force_block_production: bool,
    // Aggregator role flag, toggleable at runtime via `setAggregator`.
    // Read from gossip handlers, the tick loop, and the network subscribe
    // phase, so it is stored as an atomic to permit lock-free reads while
    // the admin API flips the flag.
    //
    // Note: network subnet subscriptions are decided once at startup based
    // on the initial value. Flipping this at runtime affects gossip import
    // and aggregation duties for subnets the node is already subscribed to,
    // matching the hot-standby model documented in leanEthereum/leanSpec#636.
    is_aggregator_enabled: std.atomic.Value(bool),
    // Cached finalized state loaded from database (separate from states map to avoid affecting pruning)
    cached_finalized_state: ?*types.BeamState = null,
    // Cache for validator public keys to avoid repeated SSZ deserialization during signature verification.
    // Significantly reduces CPU overhead when processing blocks with many attestations.
    public_key_cache: xmss.PublicKeyCache,
    // Cache for root to slot mapping to optimize block processing performance.
    root_to_slot_cache: types.RootToSlotCache,
    /// Optional worker pool for parallelizing CPU-bound steps (currently:
    /// attestation signature verification and `compactAttestations`). Owned
    /// by the caller (e.g. the CLI's main), not by the chain.
    ///
    /// Thread-safety invariants required of the pool's environment when set:
    ///
    ///   1. `chain.allocator` MUST be safe to use concurrently from worker
    ///      threads. The CLI today wires this to a `GeneralPurposeAllocator`
    ///      whose `alloc`/`free` are internally serialized; an `ArenaAllocator`
    ///      or any custom non-thread-safe allocator would race. If a future
    ///      change swaps the allocator, audit every consumer of `thread_pool`
    ///      (`stf.verifySignaturesParallel`, `types.compactAttestations`).
    ///   2. The XMSS verifier must be set up before the pool's first verify.
    ///      The CLI calls `xmss.setupVerifier()` on the main thread right after
    ///      pool construction; without that pre-warm, concurrent first-time
    ///      verifies could race the Rust-side initialization.
    ///   3. `xmss.PublicKeyCache` is documented NOT thread-safe. Workers must
    ///      not call its `getOrPut` directly. The current parallel paths
    ///      respect this: cache access is confined to a serial pre-phase.
    ///
    /// New consumers of `thread_pool` should preserve all three invariants.
    thread_pool: ?*ThreadPool = null,

    // Callback for pruning cached blocks after finalization advances
    prune_cached_blocks_ctx: ?*anyopaque = null,
    prune_cached_blocks_fn: ?PruneCachedBlocksFn = null,

    // Queue for blocks that arrived before forkchoice had ticked to their slot.
    // When a peer gossips a block for the current slot before our local interval
    // timer fires, the forkchoice rejects it with FutureSlot.  We hold such
    // blocks here and replay them in onInterval once the clock has caught up.
    pending_blocks: std.ArrayList(types.SignedBlock),

    // Per-resource locks (slice a-2 of #803). See
    // `docs/threading_refactor_slice_a.md` for the lock-hierarchy contract:
    //   tier 3: states_lock
    //   tier 4: pending_blocks_lock
    //   tier 5a: pubkey_cache_lock     (sibling — never co-held with 5b/5c)
    //   tier 5b: root_to_slot_lock     (sibling — never co-held with 5a/5c)
    //   tier 5c: events_lock           (sibling — never co-held with 5a/5b)
    //   tier 6: forkChoice (own RwLock, innermost)
    //
    // As of slice a-3 the previous coarse `BeamNode.mutex` is gone; these
    // per-resource locks are now the actual synchronisation between the
    // libxev tick path and the libp2p worker on every chain entry point.
    // (Slice (c) will reintroduce a finalization-scoped multi-resource
    // lock when its first real user — the chain-worker `processFinalization
    // Followup` move-off path — lands.)
    states_lock: zeam_utils.SyncRwLock = .{},
    pending_blocks_lock: zeam_utils.SyncMutex = .{},
    pubkey_cache_lock: zeam_utils.SyncMutex = .{},
    root_to_slot_lock: zeam_utils.SyncMutex = .{},
    events_lock: zeam_utils.SyncMutex = .{},

    pub const PruneCachedBlocksFn = *const fn (ptr: *anyopaque, finalized: types.Checkpoint) usize;

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        opts: ChainOpts,
        connected_peers: *ConnectedPeers,
    ) !Self {
        const logger_config = opts.logger_config;
        const fork_choice = try fcFactory.ForkChoice.init(allocator, .{
            .config = opts.config,
            .anchorState = opts.anchorState,
            .logger = logger_config.logger(.forkchoice),
            .thread_pool = opts.thread_pool,
        });

        var states = std.AutoHashMap(types.Root, *types.BeamState).init(allocator);
        const cloned_anchor_state = try allocator.create(types.BeamState);
        // Destroy outer allocation if sszClone fails (interior not yet allocated).
        errdefer allocator.destroy(cloned_anchor_state);
        try types.sszClone(allocator, types.BeamState, opts.anchorState.*, cloned_anchor_state);
        // Interior fields are now allocated; deinit them if states.put fails (LIFO order).
        errdefer cloned_anchor_state.deinit();
        try states.put(fork_choice.head.blockRoot, cloned_anchor_state);

        var chain = Self{
            .nodeId = opts.nodeId,
            .config = opts.config,
            .forkChoice = fork_choice,
            .allocator = allocator,
            .states = states,
            .anchor_state = opts.anchorState,
            .zeam_logger_config = logger_config,
            .logger = logger_config.logger(.chain),
            .stf_logger = logger_config.logger(.state_transition),
            .block_building_logger = logger_config.logger(.state_transition_block_building),
            .db = opts.db,
            .last_emitted_justified = fork_choice.fcStore.latest_justified,
            .last_emitted_finalized = fork_choice.fcStore.latest_finalized,
            .connected_peers = connected_peers,
            .node_registry = opts.node_registry,
            .force_block_production = opts.force_block_production,
            .is_aggregator_enabled = std.atomic.Value(bool).init(opts.is_aggregator),
            .public_key_cache = xmss.PublicKeyCache.init(allocator),
            .root_to_slot_cache = types.RootToSlotCache.init(allocator),
            .pending_blocks = .empty,
            .thread_pool = opts.thread_pool,
            // Per-resource locks default-initialised. RwLock and Mutex have
            // no special init; init() runs single-threaded so no acquire
            // here.
            .states_lock = .{},
            .pending_blocks_lock = .{},
            .pubkey_cache_lock = .{},
            .root_to_slot_lock = .{},
            .events_lock = .{},
        };
        // Initialize cache with anchor block root and any post-finalized entries from state
        try chain.root_to_slot_cache.put(fork_choice.head.blockRoot, opts.anchorState.slot);
        try chain.anchor_state.initRootToSlotCache(&chain.root_to_slot_cache);
        return chain;
    }

    pub fn setPruneCachedBlocksCallback(self: *Self, ctx: *anyopaque, func: PruneCachedBlocksFn) void {
        self.prune_cached_blocks_ctx = ctx;
        self.prune_cached_blocks_fn = func;
    }

    pub fn deinit(self: *Self) void {
        // Clean up forkchoice resources (attestation_signatures, aggregated_payloads)
        self.forkChoice.deinit();

        var it = self.states.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.states.deinit();

        // Clean up cached finalized state if present
        if (self.cached_finalized_state) |cached_state| {
            cached_state.deinit();
            self.allocator.destroy(cached_state);
        }

        // Clean up public key cache
        self.public_key_cache.deinit();

        // Clean up root to slot cache
        self.root_to_slot_cache.deinit();
        // Clean up any blocks that were queued waiting for the forkchoice clock
        for (self.pending_blocks.items) |*block| {
            block.deinit();
        }
        self.pending_blocks.deinit(self.allocator);

        // assume the allocator of config is same as self.allocator
        self.config.deinit(self.allocator);
        // self.anchor_state.deinit();
    }

    /// Returns the current aggregator role flag.
    pub fn isAggregator(self: *const Self) bool {
        return self.is_aggregator_enabled.load(.acquire);
    }

    /// Atomically flips the aggregator role and returns the previous value.
    /// Both the gossip import path and the tick-driven aggregation path pick
    /// up the new value on their next read, so no restart is required.
    ///
    /// Logs transitions at info and no-op writes at debug so operators can
    /// trace toggles (from the admin API or any other caller) in the node
    /// logs without needing to cross-reference request logs.
    pub fn setAggregator(self: *Self, enabled: bool) bool {
        const previous = self.is_aggregator_enabled.swap(enabled, .acq_rel);
        if (previous != enabled) {
            self.logger.info("aggregator role changed: {any} -> {any}", .{ previous, enabled });
        } else {
            self.logger.debug("aggregator role set to {any} (no change)", .{enabled});
        }
        return previous;
    }

    // ------------------------------------------------------------------
    // Lock helpers (slice a-2)
    //
    // These thin wrappers keep callsites readable AND ensure every lock
    // acquire is observed via `LockTimer` so we can attribute contention
    // by lock + site in `zeam_lock_{wait,hold}_seconds`. The legacy
    // `zeam_node_mutex_*` series is double-emitted by LockTimer for one
    // release.
    // ------------------------------------------------------------------

    /// Acquire the shared (read) side of `states_lock` and return a
    /// `BorrowedState` for the requested root, or null if the state is not
    /// in the in-memory map. Caller MUST call either `borrow.deinit()` or
    /// `borrow.cloneAndRelease(allocator)` exactly once before the borrow
    /// goes out of scope. Debug builds enforce one-release via
    /// `BorrowedState.released`.
    pub fn statesGet(self: *Self, root: types.Root) ?BorrowedState {
        var t = LockTimer.start("states", "statesGet");
        self.states_lock.lockShared();
        t.acquired();
        if (self.states.get(root)) |state| {
            // Hand the lock off to the borrow. The borrow's deinit calls
            // states_lock.unlockShared() AND closes the LockTimer
            // observation — so the hold-span histogram correctly
            // attributes the entire borrow lifetime to this site.
            return BorrowedState{
                .state = state,
                .backing = .{ .states_shared_rwlock = &self.states_lock },
                .timer = t,
            };
        }
        // No entry — release the shared lock since we are not handing out
        // a borrow.
        self.states_lock.unlockShared();
        t.released();
        return null;
    }

    /// Take the exclusive side of `states_lock` and `put` the entry. Used
    /// by produceBlock / onBlock STF commit and similar single-key writes.
    fn statesPutExclusive(self: *Self, comptime site: []const u8, root: types.Root, state_ptr: *types.BeamState) !void {
        var t = LockTimer.start("states", site);
        self.states_lock.lock();
        t.acquired();
        defer t.released();
        defer self.states_lock.unlock();
        try self.states.put(root, state_ptr);
    }

    /// Insert under `states_lock.exclusive` if the entry is not already in
    /// the map; otherwise keep the existing pointer untouched. The exclusive
    /// lock is HANDED OFF to the returned `BorrowedState` and is held until
    /// the caller invokes `borrow.deinit()` — callers MUST keep the borrow
    /// alive across any subsequent deref of `borrow.state` (DB writes,
    /// forkchoice updates, etc.).
    ///
    /// Why hold the exclusive lock across the borrow? See PR #820 / issue
    /// #803: with `BeamNode.mutex` removed from the gossip / req-resp /
    /// interval paths, two threads can be inside `chain.onBlock`
    /// concurrently. Thread A's `onBlockFollowup -> processFinalizationAdvancement
    /// -> pruneStates` (also exclusive on `states_lock`) can `fetchRemove`
    /// + free the very entry Thread B is about to deref for the post-commit
    /// DB write + `forkChoice.confirmBlock`. Holding the exclusive lock
    /// across that whole window is the fix — we cannot downgrade-then-
    /// reacquire-shared because the unlock/reacquire gap is exactly the UAF
    /// race we are closing. (A native RwLock downgrade primitive would let
    /// us hold shared instead; that is a separate change.)
    ///
    /// Returns:
    ///   * `borrow` — RAII wrapper. `borrow.state` is the pointer the
    ///     caller should USE for any subsequent reads. When the entry
    ///     already existed this is the in-map pointer, NOT the `state_ptr`
    ///     argument; the in-map pointer outlives the borrow handed out by
    ///     `statesGet`, so other readers don't observe a freed pointer.
    ///     Caller MUST keep `borrow` alive until done dereferencing
    ///     `borrow.state`, then call `borrow.deinit()`.
    ///   * `kept_existing` — true when the entry already existed and
    ///     `state_ptr` was discarded (caller is responsible for freeing
    ///     `state_ptr` if it owns it). False when `state_ptr` was inserted.
    fn statesCommitKeepExisting(
        self: *Self,
        comptime site: []const u8,
        root: types.Root,
        state_ptr: *types.BeamState,
    ) !struct { borrow: BorrowedState, kept_existing: bool } {
        var t = LockTimer.start("states", site);
        self.states_lock.lock();
        t.acquired();
        // NOTE: NO `defer self.states_lock.unlock()` here — the exclusive
        // lock is owned by the returned BorrowedState and released by its
        // deinit. errdefer below covers the OOM path on `getOrPut`. The
        // LockTimer is moved into the borrow as well so the hold-span
        // observation closes at the deinit site, not here. PR #820.
        errdefer {
            self.states_lock.unlock();
            t.released();
        }
        const gop = try self.states.getOrPut(root);
        const effective_ptr: *types.BeamState = if (gop.found_existing) blk: {
            // Decision policy: keep the existing pointer (it's referenced
            // elsewhere — e.g. produceBlock just inserted it before
            // publishBlock landed here) and tell the caller to free the
            // freshly-computed copy. We never want to invalidate a pointer
            // that other borrows might still observe through
            // `states_lock.shared`.
            break :blk gop.value_ptr.*;
        } else blk: {
            gop.value_ptr.* = state_ptr;
            break :blk state_ptr;
        };
        return .{
            .borrow = BorrowedState{
                .state = effective_ptr,
                .backing = .{ .states_exclusive_rwlock = &self.states_lock },
                .timer = t,
            },
            .kept_existing = gop.found_existing,
        };
    }

    /// Take the exclusive side of `states_lock` and remove the entry.
    /// Returns the removed pointer (or null) so the caller can free it.
    fn statesFetchRemoveExclusivePtr(self: *Self, comptime site: []const u8, root: types.Root) ?*types.BeamState {
        var t = LockTimer.start("states", site);
        self.states_lock.lock();
        t.acquired();
        defer t.released();
        defer self.states_lock.unlock();
        if (self.states.fetchRemove(root)) |entry| {
            return entry.value;
        }
        return null;
    }

    pub fn registerValidatorIds(self: *Self, validator_ids: []usize) void {
        // right now it's simple assignment but eventually it should be a set
        // tacking registrations and keeping it alive for 3*2=6 slots
        self.registered_validator_ids = validator_ids;
        zeam_metrics.metrics.lean_validators_count.set(self.registered_validator_ids.len);
    }

    /// Replay blocks that were queued because the forkchoice clock hadn't yet
    /// reached their slot.  Called from onInterval after advancing the clock.
    /// Returns a slice of all missing attestation roots encountered while
    /// processing queued blocks; the caller owns and must free the slice.
    ///
    /// One-at-a-time iteration (slice a-2): each loop iteration reacquires
    /// `pending_blocks_lock`, rescans from index 0 for the first ready
    /// block, removes it, releases the lock, then replays via `onBlock`.
    /// This trades O(n²) worst case for safety — indices are never assumed
    /// stable across an unlock, so the gossip thread is free to append to
    /// the queue between iterations. The `lean_pending_blocks_drain_iters`
    /// histogram measures how often this matters in practice; current
    /// devnet workloads keep n small.
    pub fn processPendingBlocks(self: *Self) []types.Root {
        var all_missing_roots: std.ArrayListUnmanaged(types.Root) = .empty;
        var iter_count: usize = 0;
        defer {
            const iter_f: f32 = @floatFromInt(iter_count);
            zeam_metrics.lean_pending_blocks_drain_iters.record(iter_f);
        }

        while (true) {
            const fc_time = self.forkChoice.fcStore.slot_clock.time.load(.monotonic);

            // Pop the first ready block under the lock; release before any
            // heavy work so gossip-thread appends can proceed.
            var ready: ?types.SignedBlock = null;
            {
                var t = LockTimer.start("pending_blocks", "processPendingBlocks.scan");
                self.pending_blocks_lock.lock();
                t.acquired();
                defer t.released();
                defer self.pending_blocks_lock.unlock();

                for (self.pending_blocks.items, 0..) |b, i| {
                    if (b.block.slot * constants.INTERVALS_PER_SLOT <= fc_time) {
                        ready = self.pending_blocks.orderedRemove(i);
                        break;
                    }
                }
            }

            if (ready) |unwrapped| {
                iter_count += 1;
                var queued_block = unwrapped;
                defer queued_block.deinit();

                const queued_slot = queued_block.block.slot;
                var block_root: types.Root = undefined;
                zeam_utils.hashTreeRoot(types.BeamBlock, queued_block.block, &block_root, self.allocator) catch |err| {
                    self.logger.err("queued block slot={d}: failed to compute block root: {any}", .{ queued_slot, err });
                    continue;
                };

                self.logger.info(
                    "replaying queued block slot={d} blockroot=0x{x} (fc_time now={d})",
                    .{ queued_slot, &block_root, fc_time },
                );

                const missing_roots = self.onBlock(queued_block, .{
                    .blockRoot = block_root,
                }) catch |err| {
                    self.logger.err("queued block slot={d} root=0x{x}: processing failed: {any}", .{ queued_slot, &block_root, err });
                    continue;
                };
                defer self.allocator.free(missing_roots);

                self.onBlockFollowup(true, &queued_block);

                // Accumulate missing roots so the caller can fetch them.
                all_missing_roots.appendSlice(self.allocator, missing_roots) catch {};
            } else {
                break;
            }
        }
        return all_missing_roots.toOwnedSlice(self.allocator) catch &.{};
    }

    pub fn onInterval(self: *Self, time_intervals: usize) !void {
        // see if the node has a proposal this slot to properly tick
        // forkchoice head
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        const interval = time_intervals % constants.INTERVALS_PER_SLOT;

        // Update current slot metric (wall-clock time slot)
        zeam_metrics.metrics.lean_current_slot.set(slot);
        // Update sync status metric: labeled gauge, 1 for active state
        {
            const sync_status = self.getSyncStatus();
            zeam_metrics.metrics.lean_node_sync_status.set(.{ .status = "idle" }, if (sync_status == .no_peers or sync_status == .fc_initing) 1 else 0) catch {};
            zeam_metrics.metrics.lean_node_sync_status.set(.{ .status = "syncing" }, if (sync_status == .behind_peers) 1 else 0) catch {};
            zeam_metrics.metrics.lean_node_sync_status.set(.{ .status = "synced" }, if (sync_status == .synced) 1 else 0) catch {};
        }

        var has_proposal = false;
        if (interval == 0) {
            const num_validators: usize = @intCast(self.config.genesis.numValidators());
            const slot_proposer_id = slot % num_validators;
            if (std.mem.indexOfScalar(usize, self.registered_validator_ids, slot_proposer_id)) |index| {
                _ = index;
                has_proposal = true;
            }
        }

        self.logger.debug("ticking chain to time(intervals)={d} = slot={d} interval={d} has_proposal={any}", .{
            time_intervals,
            slot,
            interval,
            has_proposal,
        });

        try self.forkChoice.onInterval(time_intervals, has_proposal);
        if (interval == 1) {
            // interval to attest so we should put out the chain status information to the user along with
            // latest head which most likely should be the new block received and processed
            const islot: isize = @intCast(slot);
            self.printSlot(islot, constants.MAX_FC_CHAIN_PRINT_DEPTH, self.connected_peers.count());

            // Periodic pruning: prune old non-canonical states every N slots
            // This ensures we prune even when finalization doesn't advance
            if (slot > 0 and slot % constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS == 0) {
                const finalized = self.forkChoice.getLatestFinalized();
                // no need to work extra if finalization is not far behind
                if (finalized.slot + 2 * constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS < slot) {
                    self.logger.warn("finalization slot={d} too far behind the current slot={d}", .{ finalized.slot, slot });
                    const pruningAnchor = try self.forkChoice.getCanonicalAncestorAtDepth(constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS);

                    // prune if finalization hasn't happened since a long time
                    if (pruningAnchor.slot > finalized.slot) {
                        self.logger.info("periodic pruning triggered at slot {d} (finalized slot={d} pruning anchor={d})", .{
                            slot,
                            finalized.slot,
                            pruningAnchor.slot,
                        });
                        const analysis_result = try self.forkChoice.getCanonicalityAnalysis(pruningAnchor.blockRoot, finalized.root, null);
                        const depth_confirmed_roots = analysis_result[0];
                        const non_finalized_descendants = analysis_result[1];
                        const non_canonical_roots = analysis_result[2];
                        defer self.allocator.free(depth_confirmed_roots);
                        defer self.allocator.free(non_finalized_descendants);
                        defer self.allocator.free(non_canonical_roots);

                        const states_count_before: isize = self.states.count();
                        _ = self.pruneStates(depth_confirmed_roots[1..depth_confirmed_roots.len], "confirmed ancestors");
                        _ = self.pruneStates(non_canonical_roots, "confirmed non canonical");
                        const pruned_count = states_count_before - self.states.count();
                        self.logger.info("pruned states={d} at slot={d} (finalized slot={d} pruning anchor={d})", .{
                            //
                            pruned_count,
                            slot,
                            finalized.slot,
                            pruningAnchor.slot,
                        });
                    } else {
                        self.logger.info("skipping periodic pruning at slot={d} since finalization not behind pruning anchor (finalized slot={d} pruning anchor={d})", .{
                            slot,
                            finalized.slot,
                            pruningAnchor.slot,
                        });
                    }
                } else {
                    self.logger.info("skipping periodic pruning at current slot={d} since finalization slot={d} not behind", .{
                        slot,
                        finalized.slot,
                    });
                }
            }
        }
        // check if log rotation is needed
        self.zeam_logger_config.maybeRotate() catch |err| {
            self.logger.err("error rotating log file: {any}", .{err});
        };
    }

    pub fn produceBlock(self: *Self, opts: BlockProductionParams) !ProducedBlock {
        // Block building total time timer
        const block_building_timer = zeam_metrics.lean_block_building_time_seconds.start();
        errdefer {
            _ = block_building_timer.observe();
            zeam_metrics.metrics.lean_block_building_failures_total.incr();
        }
        // dump the vote tracker, letting this stay here commented for handy debugging activation
        // var iterator = self.forkChoice.attestations.iterator();
        // while (iterator.next()) |entry| {
        //     var latest_new: []const u8 = "null";
        //     if (entry.value_ptr.latestNew) |latest_new_in| {
        //         if (latest_new_in.attestation) |latest_new_att| {
        //             latest_new = try latest_new_att.message.toJsonString(self.allocator);
        //         }
        //     }
        //     self.logger.warn("validator id={d} vote is={s}", .{ entry.key_ptr.*, latest_new });
        // }

        // right now with integrated validator into node produceBlock is always gurranteed to be
        // called post ticking the chain to the correct time, but once validator is separated
        // one must make the forkchoice tick to the right time if there is a race condition
        // however in that scenario forkchoice also needs to be protected by mutex/kept thread safe
        // Align with leanSpec: accept new aggregated payloads before proposing.
        // This ensures the proposer builds on the latest proposal head derived
        // from known aggregated payloads.
        const proposal_head = try self.forkChoice.getProposalHead(opts.slot);
        const parent_root = proposal_head.root;

        // Snapshot-then-release: the FFI inside getProposalAttestations can
        // run for hundreds of milliseconds. Holding `states_lock.shared` for
        // that window would force any block-import path waiting on
        // `states_lock.exclusive` to stall behind the aggregator. Instead
        // clone the pre-state into an owned snapshot under the borrow,
        // release the lock, then run the FFI against the snapshot.
        var pre_borrow = self.statesGet(parent_root) orelse return BlockProductionError.MissingPreState;
        // assertReleasedOrPanic registered FIRST so it runs LAST (LIFO);
        // cloneAndRelease drops the lock on success/error, so by the time
        // the assert runs `released` must be true. Catches a future
        // helper that forgets to release before scope exit.
        defer pre_borrow.assertReleasedOrPanic();
        const pre_snapshot = try pre_borrow.cloneAndRelease(self.allocator);
        defer {
            pre_snapshot.deinit();
            self.allocator.destroy(pre_snapshot);
        }

        var post_state_opt: ?*types.BeamState = try self.allocator.create(types.BeamState);
        errdefer if (post_state_opt) |post_state_ptr| {
            post_state_ptr.deinit();
            self.allocator.destroy(post_state_ptr);
        };
        const post_state = post_state_opt.?;
        try types.sszClone(self.allocator, types.BeamState, pre_snapshot.*, post_state);

        const payload_agg_timer = zeam_metrics.lean_block_building_payload_aggregation_time_seconds.start();
        // FFI call against the owned snapshot — no lock held during this
        // window.
        const proposal_atts = try self.forkChoice.getProposalAttestations(pre_snapshot, opts.slot, opts.proposer_index, parent_root);
        _ = payload_agg_timer.observe();

        var agg_attestations = proposal_atts.attestations;
        var agg_att_cleanup = true;
        errdefer if (agg_att_cleanup) {
            for (agg_attestations.slice()) |*att| att.deinit();
            agg_attestations.deinit();
        };

        var attestation_signatures = proposal_atts.signatures;
        var agg_sig_cleanup = true;
        errdefer if (agg_sig_cleanup) {
            for (attestation_signatures.slice()) |*sig| sig.deinit();
            attestation_signatures.deinit();
        };

        // Record aggregated signature metrics
        const num_agg_sigs = attestation_signatures.len();
        zeam_metrics.metrics.lean_pq_sig_aggregated_signatures_total.incrBy(num_agg_sigs);

        var total_attestations_in_agg: u64 = 0;
        for (agg_attestations.constSlice()) |agg_att| {
            const bits_len = agg_att.aggregation_bits.len();
            for (0..bits_len) |i| {
                if (agg_att.aggregation_bits.get(i) catch false) {
                    total_attestations_in_agg += 1;
                }
            }
        }
        zeam_metrics.metrics.lean_pq_sig_attestations_in_aggregated_signatures_total.incrBy(total_attestations_in_agg);

        // keeping for later when execution will be integrated into lean
        // const timestamp = self.config.genesis.genesis_time + opts.slot * params.SECONDS_PER_SLOT;

        var block = types.BeamBlock{
            .slot = opts.slot,
            .proposer_index = opts.proposer_index,
            .parent_root = parent_root,
            .state_root = undefined,
            .body = types.BeamBlockBody{
                // .execution_payload_header = .{ .timestamp = timestamp },
                .attestations = agg_attestations,
            },
        };
        agg_att_cleanup = false; // Ownership moved to block.body.attestations
        errdefer block.deinit();

        agg_sig_cleanup = false; // Ownership moved to attestation_signatures
        errdefer {
            for (attestation_signatures.slice()) |*sig_group| {
                sig_group.deinit();
            }
            attestation_signatures.deinit();
        }

        const block_str = try block.toJsonString(self.allocator);
        defer self.allocator.free(block_str);

        self.logger.debug("node-{d}::going for block production opts={f} raw block={s}", .{ self.nodeId, opts, block_str });

        // 2. apply STF to get post state & update post state root & cache it.
        // Hold `root_to_slot_lock` for the STF window since
        // `apply_raw_block` reaches into the cache via the pointer for
        // historical-block lookups. The hot attestation-validation paths
        // do not touch this cache, so contention stays bounded to STF +
        // the small number of cache writes around block import.
        {
            var t_rts = LockTimer.start("root_to_slot", "produceBlock.stf");
            locking.assertNoTier5SiblingHeld("produceBlock.stf");
            self.root_to_slot_lock.lock();
            locking.enterTier5();
            t_rts.acquired();
            defer {
                self.root_to_slot_lock.unlock();
                locking.leaveTier5();
                t_rts.released();
            }
            try stf.apply_raw_block(self.allocator, post_state, &block, self.block_building_logger, &self.root_to_slot_cache);
        }

        const block_str_2 = try block.toJsonString(self.allocator);
        defer self.allocator.free(block_str_2);

        self.logger.debug("applied raw block opts={f} raw block={s}", .{ opts, block_str_2 });

        // 3. cache state to save recompute while adding the block on publish
        var block_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);

        try self.statesPutExclusive("produceBlock.commit", block_root, post_state);
        post_state_opt = null;

        var forkchoice_added = false;
        errdefer if (!forkchoice_added) {
            if (self.statesFetchRemoveExclusivePtr("produceBlock.errdefer", block_root)) |entry_ptr| {
                entry_ptr.deinit();
                self.allocator.destroy(entry_ptr);
            }
        };

        // 4. Advance fork choice to this block's slot so the block is not rejected as FutureSlot
        // PS: this isn't required because forkchoice is already ticked before validator's oninterval is called
        // which then leads to block production call
        //
        // try self.forkChoice.onInterval(block.slot * constants.INTERVALS_PER_SLOT, false);

        // 5. Add the block to directly forkchoice as this proposer will next need to construct its vote
        //   note - attestations packed in the block are already in the knownVotes so we don't need to re-import
        //   them in the forkchoice
        _ = try self.forkChoice.onBlock(block, post_state, .{
            .currentSlot = block.slot,
            .blockDelayMs = 0,
            .blockRoot = block_root,
            // confirmed in publish
            .confirmed = false,
        });
        forkchoice_added = true;
        _ = try self.forkChoice.updateHead();

        // Record block production success metrics
        _ = block_building_timer.observe();
        zeam_metrics.metrics.lean_block_building_success_total.incr();
        zeam_metrics.lean_block_aggregated_payloads.record(@floatFromInt(attestation_signatures.len()));

        return .{
            .block = block,
            .blockRoot = block_root,
            .attestation_signatures = attestation_signatures,
        };
    }

    pub fn constructAttestationData(self: *Self, opts: AttestationConstructionParams) !types.AttestationData {
        const slot = opts.slot;

        const head_proto = self.forkChoice.getHead();
        const head: types.Checkpoint = .{
            .root = head_proto.blockRoot,
            .slot = head_proto.slot,
        };
        const head_str = try head.toJsonString(self.allocator);
        defer self.allocator.free(head_str);

        const safe_target_proto = self.forkChoice.getSafeTarget();
        const safe_target: types.Checkpoint = .{
            .root = safe_target_proto.blockRoot,
            .slot = safe_target_proto.slot,
        };
        const safe_target_str = try safe_target.toJsonString(self.allocator);
        defer self.allocator.free(safe_target_str);

        self.logger.info("constructing attestation data at slot={d} with chain head={s} safe_target={s}", .{
            slot,
            head_str,
            safe_target_str,
        });

        const target = try self.forkChoice.getAttestationTarget();
        const target_str = try target.toJsonString(self.allocator);
        defer self.allocator.free(target_str);

        self.logger.info("calculated target for attestations at slot={d}: {s}", .{ slot, target_str });

        const attestation_data = types.AttestationData{
            .slot = slot,
            .head = head,
            .target = target,
            .source = self.forkChoice.getLatestJustified(),
        };

        return attestation_data;
    }

    pub fn printSlot(self: *Self, islot: isize, tree_depth: ?usize, peer_count: usize) void {
        // head should be auto updated if receieved a block or block proposal done
        // however it doesn't get updated unless called updatehead even though process block
        // logs show it has been updated. debug and fix the call below
        const fc_head = if (islot > 0)
            self.forkChoice.updateHead() catch |err| {
                self.logger.err("forkchoice updatehead error={any}", .{err});
                return;
            }
        else
            self.forkChoice.getHead();

        // Get additional chain information
        const justified = self.forkChoice.getLatestJustified();
        const finalized = self.forkChoice.getLatestFinalized();

        // Calculate chain progress
        const slot: usize = if (islot < 0) 0 else @intCast(islot);
        const blocks_behind = if (slot > fc_head.slot) slot - fc_head.slot else 0;
        const is_timely = fc_head.timeliness;

        const states_count = self.states.count();
        const fc_nodes_count = self.forkChoice.getNodeCount();

        self.logger.debug("cached states={d}, forkchoice nodes={d}", .{ states_count, fc_nodes_count });
        self.logger.info(
            \\
            \\+===============================================================+
            \\  CHAIN STATUS: Current Slot: {d} | Head Slot: {d} | Behind: {d}
            \\+---------------------------------------------------------------+
            \\  Connected Peers:    {d}
            \\+---------------------------------------------------------------+
            \\  Head Block Root:    0x{x}
            \\  Parent Block Root:  0x{x}
            \\  State Root:         0x{x}
            \\  Timely:             {s}
            \\+---------------------------------------------------------------+
            \\  Latest Justified:   Slot {d:>6} | Root: 0x{x}
            \\  Latest Finalized:   Slot {d:>6} | Root: 0x{x}
            \\+===============================================================+
        , .{
            islot,
            fc_head.slot,
            blocks_behind,
            peer_count,
            &fc_head.blockRoot,
            &fc_head.parentRoot,
            &fc_head.stateRoot,
            if (is_timely) "YES" else "NO",
            justified.slot,
            &justified.root,
            finalized.slot,
            &finalized.root,
        });

        // Build tree visualization (thread-safe snapshot)
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const tree_visual = blk: {
            const snapshot = self.forkChoice.snapshot(arena.allocator()) catch {
                break :blk "Failed to get fork choice snapshot";
            };
            defer snapshot.deinit(arena.allocator());
            break :blk tree_visualizer.buildTreeVisualization(arena.allocator(), snapshot.nodes, tree_depth, null) catch "Tree visualization failed";
        };
        // Print forkchoice tree separate because when it gets big the logger skips the entire log
        self.logger.info(
            \\  ForkChoice Tree:
            \\{s}
            \\
        , .{
            tree_visual,
        });
    }

    pub fn onGossip(self: *Self, data: *const networks.GossipMessage, sender_peer_id: []const u8) !GossipProcessingResult {
        switch (data.*) {
            .block => |signed_block| {
                const block = signed_block.block;
                var block_root: [32]u8 = undefined;
                try zeam_utils.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);

                //check if we have the block already in forkchoice
                const hasBlock = self.forkChoice.hasBlock(block_root);

                self.logger.debug("chain received gossip block for slot={d} blockroot=0x{x} proposer={d}{f} hasBlock={} from peer={s}{f}", .{
                    block.slot,
                    &block_root,
                    block.proposer_index,
                    self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
                    hasBlock,
                    sender_peer_id,
                    self.node_registry.getNodeNameFromPeerId(sender_peer_id),
                });

                if (!hasBlock) {
                    // Validation errors propagate to node.zig for context-aware logging
                    try self.validateBlock(block, true);

                    // If the forkchoice clock hasn't yet ticked to this block's slot,
                    // onBlock would reject it with FutureSlot.  Queue the block and
                    // replay it from onInterval once the clock has advanced.
                    if (block.slot * constants.INTERVALS_PER_SLOT > self.forkChoice.fcStore.slot_clock.time.load(.monotonic)) {
                        self.logger.debug(
                            "queuing gossip block slot={d} blockroot=0x{x}: forkchoice time={d} < slot_start={d}",
                            .{ block.slot, &block_root, self.forkChoice.fcStore.slot_clock.time.load(.monotonic), block.slot * constants.INTERVALS_PER_SLOT },
                        );
                        var cloned: types.SignedBlock = undefined;
                        try types.sszClone(self.allocator, types.SignedBlock, signed_block, &cloned);

                        // TODO: in beam sim, it seems to have queued after the oninterval fires even if block arrives pre on interval
                        // because of race conditions between competing threads as the above sszClone aparently takes too much time
                        // currently managing this by checking condition again but ideally fix it by identifying chain entrypoints and
                        // holding mutex between then for chain modification sections
                        if (block.slot * constants.INTERVALS_PER_SLOT > self.forkChoice.fcStore.slot_clock.time.load(.monotonic)) {
                            {
                                var t = LockTimer.start("pending_blocks", "onGossip.append");
                                self.pending_blocks_lock.lock();
                                t.acquired();
                                defer t.released();
                                defer self.pending_blocks_lock.unlock();
                                try self.pending_blocks.append(self.allocator, cloned);
                            }

                            self.logger.info(
                                "queued gossip block slot={d} blockroot=0x{x}: forkchoice time={d} < slot_start={d}",
                                .{ block.slot, &block_root, self.forkChoice.fcStore.slot_clock.time.load(.monotonic), block.slot * constants.INTERVALS_PER_SLOT },
                            );
                            return .{};
                        } else {
                            self.logger.debug(
                                //
                                "chain already ticked while cloning block for queuing, skipping queuing and directly processing slot={d} blockroot=0x{x}: forkchoice time={d} < slot_start={d}",
                                //
                                .{ block.slot, &block_root, self.forkChoice.fcStore.slot_clock.time.load(.monotonic), block.slot * constants.INTERVALS_PER_SLOT });
                            // by the time we cloned, chain ticked, so we can directly add and deinit clone
                            cloned.deinit();
                        }
                    }

                    const missing_roots = self.onBlock(signed_block, .{
                        .blockRoot = block_root,
                    }) catch |err| {
                        // we will not catch and enqueue block for FutureSlot error because this error here means
                        // that the block's slot is 2 ahead of the local because we have tolerance of 1 in case of
                        // clock skew or race between oninterval and block arrival
                        self.logger.err("error processing block for slot={d} root=0x{x}: {any}", .{
                            block.slot,
                            &block_root,
                            err,
                        });
                        return err;
                    };
                    // followup with additional housekeeping tasks
                    self.onBlockFollowup(true, &signed_block);
                    // NOTE: ownership of `missing_roots` is transferred to the caller (BeamNode),
                    // which is responsible for freeing it after optionally fetching those roots.

                    // Return both the block root and missing attestation roots so the node can:
                    // 1. Call processCachedDescendants(block_root) to retry any cached children
                    // 2. Fetch missing attestation head blocks via RPC
                    return .{
                        .processed_block_root = block_root,
                        .missing_attestation_roots = missing_roots,
                    };
                } else {
                    self.logger.debug("skipping processing the already present block slot={d} blockroot=0x{x}", .{
                        block.slot,
                        &block_root,
                    });
                }
                return .{};
            },
            .attestation => |signed_attestation| {
                const slot = signed_attestation.message.message.slot;
                const validator_id = signed_attestation.message.validator_id;
                const validator_node_name = self.node_registry.getNodeNameFromValidatorIndex(validator_id);

                const sender_node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
                self.logger.debug("chain received gossip attestation for subnet={d} slot={d} validator={d}{f} from peer={s}{f}", .{
                    signed_attestation.subnet_id,
                    slot,
                    validator_id,
                    validator_node_name,
                    sender_peer_id,
                    sender_node_name,
                });

                // Validate attestation before processing (gossip = not from block)
                self.validateAttestationData(signed_attestation.message.message, false) catch |err| {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                    switch (err) {
                        error.UnknownHeadBlock, error.UnknownSourceBlock, error.UnknownTargetBlock => {
                            // Add the missing root to the result so node's onGossip can enqueue it for fetching
                            const att_data = signed_attestation.message.message;
                            const missing_root = if (err == error.UnknownHeadBlock)
                                att_data.head.root
                            else if (err == error.UnknownSourceBlock)
                                att_data.source.root
                            else
                                att_data.target.root;
                            var roots: std.ArrayListUnmanaged(types.Root) = .empty;
                            errdefer roots.deinit(self.allocator);
                            try roots.append(self.allocator, missing_root);
                            return .{ .missing_attestation_roots = try roots.toOwnedSlice(self.allocator) };
                        },
                        else => {
                            self.logger.warn("gossip attestation validation failed: {any}", .{err});
                            return .{};
                        },
                    }
                };

                if (self.is_aggregator_enabled.load(.acquire)) {
                    // Process validated attestation
                    self.onGossipAttestation(signed_attestation) catch |err| {
                        zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                        self.logger.err("attestation processing error: {any}", .{err});
                        return err;
                    };
                    self.logger.info("processed gossip attestation for slot={d} validator={d}{f}", .{
                        slot,
                        validator_id,
                        validator_node_name,
                    });
                } else {
                    self.logger.debug("skipping gossip attestation import (not aggregator): subnet={d} slot={d} validator={d}", .{
                        signed_attestation.subnet_id,
                        slot,
                        validator_id,
                    });
                }
                zeam_metrics.metrics.lean_attestations_valid_total.incr(.{ .source = "gossip" }) catch {};
                return .{};
            },
            .aggregation => |signed_aggregation| {
                self.logger.debug("chain received gossip aggregation for slot={d} from peer={s}{f}", .{
                    signed_aggregation.data.slot,
                    sender_peer_id,
                    self.node_registry.getNodeNameFromPeerId(sender_peer_id),
                });

                // Validate attestation data before processing (same rules as individual gossip attestations)
                self.validateAttestationData(signed_aggregation.data, false) catch |err| {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                    switch (err) {
                        error.UnknownHeadBlock, error.UnknownSourceBlock, error.UnknownTargetBlock => {
                            // Add the missing root to the result so node's onGossip can enqueue it for fetching
                            const att_data = signed_aggregation.data;
                            const missing_root = if (err == error.UnknownHeadBlock)
                                att_data.head.root
                            else if (err == error.UnknownSourceBlock)
                                att_data.source.root
                            else
                                att_data.target.root;
                            var roots: std.ArrayListUnmanaged(types.Root) = .empty;
                            errdefer roots.deinit(self.allocator);
                            try roots.append(self.allocator, missing_root);
                            return .{ .missing_attestation_roots = try roots.toOwnedSlice(self.allocator) };
                        },
                        else => {
                            self.logger.warn("gossip aggregation validation failed: {any}", .{err});
                            return .{};
                        },
                    }
                };

                self.onGossipAggregatedAttestation(signed_aggregation) catch |err| {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "aggregation" }) catch {};
                    switch (err) {
                        // Propagate unknown block errors to node.zig for context-aware logging
                        error.UnknownHeadBlock, error.UnknownSourceBlock, error.UnknownTargetBlock => return err,
                        else => {
                            self.logger.warn("gossip aggregation processing error: {any}", .{err});
                            return .{};
                        },
                    }
                };
                zeam_metrics.metrics.lean_attestations_valid_total.incr(.{ .source = "aggregation" }) catch {};
                return .{};
            },
        }
    }

    // import block assuming it is gossip validated or synced
    // this onBlock corresponds to spec's forkchoice's onblock with some functionality split between this and
    // our implemented forkchoice's onblock. this is to parallelize "apply transition" with other verifications
    // Returns a list of missing block roots that need to be fetched from the network
    pub fn onBlock(self: *Self, signedBlock: types.SignedBlock, blockInfo: CachedProcessedBlockInfo) ![]types.Root {
        const onblock_timer = zeam_metrics.zeam_chain_onblock_duration_seconds.start();

        const block = signedBlock.block;

        const block_root: types.Root = blockInfo.blockRoot orelse computedroot: {
            var cblock_root: [32]u8 = undefined;
            try zeam_utils.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
            break :computedroot cblock_root;
        };

        const post_state_owned = blockInfo.postState == null;
        const post_state = if (blockInfo.postState) |post_state_ptr| post_state_ptr else computedstate: {
            // 1. Snapshot parent state under `states_lock.shared`, then
            //    release. Verify + STF run on the owned snapshot so we
            //    don't hold the read lock across the long FFI window.
            var parent_borrow = self.statesGet(block.parent_root) orelse return BlockProcessingError.MissingPreState;
            defer parent_borrow.assertReleasedOrPanic();
            const pre_snapshot = try parent_borrow.cloneAndRelease(self.allocator);
            defer {
                pre_snapshot.deinit();
                self.allocator.destroy(pre_snapshot);
            }

            const cpost_state = try self.allocator.create(types.BeamState);
            // If sszClone or anything after fails, destroy the outer allocation.
            errdefer self.allocator.destroy(cpost_state);

            try types.sszClone(self.allocator, types.BeamState, pre_snapshot.*, cpost_state);
            // sszClone succeeded — interior heap fields are now allocated.
            // If anything below fails, deinit interior first (LIFO: deinit runs before destroy above).
            errdefer cpost_state.deinit();

            // 2. verify XMSS signatures (independent step; placed before STF so an invalid block is
            // rejected without mutating post state). Uses the shared thread pool when available to
            // parallelize per-attestation verification across CPU workers.
            //
            // The XMSS pubkey cache is documented NOT thread-safe; today the
            // parallel path only consumes the cache from a serial pre-phase.
            // Slice (a-2) wraps the cache calls in `pubkey_cache_lock`. Tier-5
            // sibling rule: `root_to_slot_lock` (5b) and `events_lock` (5c)
            // must NOT be held at this point.
            {
                var t_pk = LockTimer.start("pubkey_cache", "onBlock.verifySignatures");
                locking.assertNoTier5SiblingHeld("onBlock.verifySignatures");
                self.pubkey_cache_lock.lock();
                locking.enterTier5();
                t_pk.acquired();
                defer {
                    self.pubkey_cache_lock.unlock();
                    locking.leaveTier5();
                    t_pk.released();
                }
                if (self.thread_pool) |pool| {
                    try stf.verifySignaturesParallel(self.allocator, pre_snapshot, &signedBlock, &self.public_key_cache, pool);
                } else {
                    try stf.verifySignatures(self.allocator, pre_snapshot, &signedBlock, &self.public_key_cache);
                }
            }

            // 3. apply state transition assuming signatures are valid (STF does not re-verify).
            //    Hold `root_to_slot_lock` for the STF window: STF reads/writes
            //    the cache via the pointer. Sibling rule: pubkey_cache_lock
            //    (5a) is already released above; events_lock (5c) is not
            //    held on any onBlock path.
            {
                var t_rts = LockTimer.start("root_to_slot", "onBlock.stf");
                locking.assertNoTier5SiblingHeld("onBlock.stf");
                self.root_to_slot_lock.lock();
                locking.enterTier5();
                t_rts.acquired();
                defer {
                    self.root_to_slot_lock.unlock();
                    locking.leaveTier5();
                    t_rts.released();
                }
                try stf.apply_transition(self.allocator, cpost_state, block, .{
                    .logger = self.stf_logger,
                    .validSignatures = true,
                    .rootToSlotCache = &self.root_to_slot_cache,
                });
            }
            break :computedstate cpost_state;
        };
        // If post_state was freshly allocated above and a later step errors (e.g. forkChoice.onBlock,
        // updateHead, or InvalidSignatureGroups), we must free it before returning the error.
        // `post_state_settled` flips to true once ownership has been resolved
        // by `statesPutOrSwap` below — either the pointer moved into the map
        // (insert path) or we already explicitly freed it (existing-kept
        // path). Either way, the errdefer must not run afterwards.
        var post_state_settled = false;
        errdefer if (post_state_owned and !post_state_settled) {
            post_state.deinit();
            self.allocator.destroy(post_state);
        };

        // Add current block's root to cache AFTER STF (ensures cache stays in sync with historical_block_hashes)
        {
            var t_rts = LockTimer.start("root_to_slot", "onBlock.cachePut");
            locking.assertNoTier5SiblingHeld("onBlock.cachePut");
            self.root_to_slot_lock.lock();
            locking.enterTier5();
            t_rts.acquired();
            defer {
                self.root_to_slot_lock.unlock();
                locking.leaveTier5();
                t_rts.released();
            }
            try self.root_to_slot_cache.put(block_root, block.slot);
        }

        // Obtain SSZ bytes for RocksDB persistence.
        //
        // Prefer the pre-serialized bytes captured at cache time (blockInfo.sszBytes).
        // Using those bytes avoids calling ssz.serialize on the live `signedBlock` here,
        // which has been observed to corrupt in-memory List/Bitlist state (aggregation_bits,
        // proof_data) and cause segfaults on the next cached block's processing.
        //
        // If no pre-serialized bytes are available (e.g. locally produced blocks), fall back
        // to serializing a disposable deep clone so the live block is never passed to serialize.
        var fallback_ssz: std.ArrayList(u8) = .empty;
        defer fallback_ssz.deinit(self.allocator);

        var fallback_clone: types.SignedBlock = undefined;
        var fallback_clone_initialized = false;
        defer if (fallback_clone_initialized) fallback_clone.deinit();

        const block_ssz_for_db: []const u8 = if (blockInfo.sszBytes) |precomputed| precomputed else blk: {
            // No pre-serialized bytes: clone the block and serialize the clone only.
            try types.sszClone(self.allocator, types.SignedBlock, signedBlock, &fallback_clone);
            fallback_clone_initialized = true;
            try ssz.serialize(types.SignedBlock, fallback_clone, &fallback_ssz, self.allocator);
            break :blk fallback_ssz.items;
        };

        var missing_roots: std.ArrayList(types.Root) = .empty;
        errdefer missing_roots.deinit(self.allocator);

        // 3. fc onblock if the block was not pre added by the block production
        const fcBlock = self.forkChoice.getBlock(block_root) orelse fcprocessing: {
            const freshFcBlock = try self.forkChoice.onBlock(block, post_state, .{
                .currentSlot = block.slot,
                .blockDelayMs = 0,
                .blockRoot = block_root,
                // confirmed in next steps post written to db
                .confirmed = false,
            });

            // 4. fc onattestations
            self.logger.debug("processing attestations of block with root=0x{x} slot={d}", .{
                &freshFcBlock.blockRoot,
                block.slot,
            });

            const aggregated_attestations = block.body.attestations.constSlice();
            const signature_groups = signedBlock.signature.attestation_signatures.constSlice();

            if (aggregated_attestations.len != signature_groups.len) {
                self.logger.err(
                    "signature group count mismatch for block root=0x{x}: attestations={d} signature_groups={d}",
                    .{ &freshFcBlock.blockRoot, aggregated_attestations.len, signature_groups.len },
                );
                return BlockProcessingError.InvalidSignatureGroups;
            }

            // Each unique AttestationData must appear at most once per block.
            {
                var att_data_set = std.AutoHashMap(types.AttestationData, void).init(self.allocator);
                defer att_data_set.deinit();
                for (aggregated_attestations) |agg_att| {
                    const result = try att_data_set.getOrPut(agg_att.data);
                    if (result.found_existing) {
                        self.logger.err(
                            "block contains duplicate AttestationData entries for block root=0x{x}",
                            .{&freshFcBlock.blockRoot},
                        );
                        return BlockProcessingError.DuplicateAttestationData;
                    }
                }
                if (att_data_set.count() > self.config.spec.max_attestations_data) {
                    self.logger.err(
                        "block contains {d} distinct AttestationData entries (max {d}) for block root=0x{x}",
                        .{ att_data_set.count(), self.config.spec.max_attestations_data, &freshFcBlock.blockRoot },
                    );
                    return BlockProcessingError.TooManyAttestationData;
                }
            }

            for (aggregated_attestations, 0..) |aggregated_attestation, index| {
                var validator_indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, self.allocator);
                defer validator_indices.deinit(self.allocator);

                // Get participant indices from the signature proof, length already validated
                const signature_proof = &signature_groups[index];

                var participant_indices: std.ArrayList(usize) = try types.aggregationBitsToValidatorIndices(&signature_proof.participants, self.allocator);
                defer participant_indices.deinit(self.allocator);

                if (validator_indices.items.len != participant_indices.items.len) {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "block" }) catch {};
                    self.logger.err(
                        "attestation signature mismatch index={d} validators={d} participants={d}",
                        .{ index, validator_indices.items.len, participant_indices.items.len },
                    );
                    continue;
                }

                // Validate aggregated attestation data once before processing individual validators
                self.validateAttestationData(aggregated_attestation.data, true) catch |e| {
                    zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "block" }) catch {};
                    if (e == AttestationValidationError.UnknownHeadBlock) {
                        try missing_roots.append(self.allocator, aggregated_attestation.data.head.root);
                    }
                    self.logger.err("invalid aggregated attestation data in block: error={any}", .{e});
                    continue;
                };

                for (validator_indices.items) |validator_index| {
                    const validator_id: types.ValidatorIndex = @intCast(validator_index);
                    const attestation = types.Attestation{
                        .validator_id = validator_id,
                        .data = aggregated_attestation.data,
                    };

                    self.forkChoice.onAttestation(attestation, true) catch |e| {
                        zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "block" }) catch {};
                        self.logger.err(
                            "failed to apply block attestation to forkchoice tracker: validator={d} slot={d} error={any}",
                            .{ validator_index, attestation.data.slot, e },
                        );
                        continue;
                    };

                    zeam_metrics.metrics.lean_attestations_valid_total.incr(.{ .source = "block" }) catch {};
                }

                // store the aggregated payloads in known
                var validator_ids = try self.allocator.alloc(types.ValidatorIndex, validator_indices.items.len);
                defer self.allocator.free(validator_ids);
                for (validator_indices.items, 0..) |vi, i| {
                    validator_ids[i] = @intCast(vi);
                }
                self.forkChoice.storeAggregatedPayload(&aggregated_attestation.data, signature_proof.*, true) catch |e| {
                    self.logger.warn("failed to store aggregated payload for attestation index={d}: {any}", .{ index, e });
                };
            }

            // 5. fc update head
            _ = try self.forkChoice.updateHead();

            break :fcprocessing freshFcBlock;
        };
        // Commit post-state under `states_lock.exclusive`. If the entry
        // already exists (locally produced block path), keep the existing
        // pointer and free the freshly-computed one — borrows already
        // observe the existing pointer through `states_lock.shared`, so
        // overwriting would create a UAF window.
        //
        // The exclusive lock is HELD across the post-commit deref window
        // (DB write + forkchoice confirm) via the returned BorrowedState.
        // This blocks `pruneStates` (also exclusive on `states_lock`) from
        // racing in via another thread's `onBlockFollowup` and freeing the
        // entry under us. See PR #820 / issue #803.
        var commit = try self.statesCommitKeepExisting("onBlock.commit", fcBlock.blockRoot, post_state);
        // Release the exclusive lock on every exit path (success or error).
        defer commit.borrow.assertReleasedOrPanic();
        defer commit.borrow.deinit();
        if (commit.kept_existing and post_state_owned) {
            // Existing entry kept — free the freshly-computed (and now
            // redundant) post_state. The borrow points at the in-map
            // pointer (a different allocation), so this free does not
            // invalidate `commit.borrow.state`. Caller-supplied post-states
            // (i.e. `post_state_owned == false`) belong to the caller; we
            // don't touch them.
            post_state.deinit();
            self.allocator.destroy(post_state);
        }
        // From here on use the borrow's pointer (the in-map one): if the
        // commit kept an existing entry, our `post_state` is freed and
        // unsafe to deref. The borrow keeps the in-map pointer alive for
        // the duration of this scope.
        const effective_post_state: *const types.BeamState = commit.borrow.state;
        // Past this point post_state ownership is settled — either the
        // pointer is in the states map (insert path) or it was explicitly
        // freed above (existing-kept path). The top-level errdefer must
        // not double-free, so flip the gate.
        post_state_settled = true;

        const processing_time = onblock_timer.observe();

        // 6. Save block and state to database and confirm the block in forkchoice
        self.updateBlockDb(block_ssz_for_db, fcBlock.blockRoot, effective_post_state.*, block.slot) catch |err| {
            self.logger.err("failed to update block database for block root=0x{x}: {any}", .{
                &fcBlock.blockRoot,
                err,
            });
        };
        try self.forkChoice.confirmBlock(block_root);

        self.logger.info("processed block with root=0x{x} slot={d} processing time={d} (computed root={any} computed state={any})", .{
            &fcBlock.blockRoot,
            block.slot,
            processing_time,
            blockInfo.blockRoot == null,
            blockInfo.postState == null,
        });
        return missing_roots.toOwnedSlice(self.allocator);
    }

    pub fn onBlockFollowup(self: *Self, pruneForkchoice: bool, signedBlock: ?*const types.SignedBlock) void {
        _ = signedBlock;
        // 7. Asap emit new events via SSE (use forkchoice ProtoBlock directly)
        const new_head = self.forkChoice.getHead();
        if (api.events.NewHeadEvent.fromProtoBlock(self.allocator, new_head)) |head_event| {
            var chain_event = api.events.ChainEvent{ .new_head = head_event };
            event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                self.logger.warn("failed to broadcast head event: {any}", .{err});
                chain_event.deinit(self.allocator);
            };
        } else |err| {
            self.logger.warn("failed to create head event: {any}", .{err});
        }

        const latest_justified = self.forkChoice.getLatestJustified();
        const latest_finalized = self.forkChoice.getLatestFinalized();

        // 8. Asap emit justification/finalization events based on forkchoice store.
        //    `events_lock` (tier 5c) covers the read-modify-write of
        //    `last_emitted_justified`, `last_emitted_finalized`, and (later)
        //    `cached_finalized_state`. Sibling rule: pubkey_cache_lock (5a)
        //    and root_to_slot_lock (5b) must NOT be held here.
        const last_emitted_finalized: types.Checkpoint = blk: {
            var t_ev = LockTimer.start("events", "onBlockFollowup");
            locking.assertNoTier5SiblingHeld("onBlockFollowup");
            self.events_lock.lock();
            locking.enterTier5();
            t_ev.acquired();
            defer {
                self.events_lock.unlock();
                locking.leaveTier5();
                t_ev.released();
            }

            // Emit justification event only when slot increases beyond last emitted
            if (latest_justified.slot > self.last_emitted_justified.slot) {
                if (api.events.NewJustificationEvent.fromCheckpoint(self.allocator, latest_justified, new_head.slot, self.nodeId)) |just_event| {
                    var chain_event = api.events.ChainEvent{ .new_justification = just_event };
                    event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                        self.logger.warn("failed to broadcast justification event: {any}", .{err});
                        chain_event.deinit(self.allocator);
                    };
                    self.last_emitted_justified = latest_justified;
                } else |err| {
                    self.logger.warn("failed to create justification event: {any}", .{err});
                }
            }

            // Emit finalization event only when slot increases beyond last emitted
            const prev_last_emitted_finalized = self.last_emitted_finalized;
            if (latest_finalized.slot > prev_last_emitted_finalized.slot) {
                if (api.events.NewFinalizationEvent.fromCheckpoint(self.allocator, latest_finalized, new_head.slot, self.nodeId)) |final_event| {
                    var chain_event = api.events.ChainEvent{ .new_finalization = final_event };
                    event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
                        self.logger.warn("failed to broadcast finalization event: {any}", .{err});
                        chain_event.deinit(self.allocator);
                    };
                    self.last_emitted_finalized = latest_finalized;
                } else |err| {
                    self.logger.warn("failed to create finalization event: {any}", .{err});
                }
            }
            break :blk prev_last_emitted_finalized;
        };

        // Update finalized slot indices and cleanup if finalization has advanced
        // note use presaved local last_emitted_finalized as self.last_emitted_finalized has been updated above.
        // processFinalizationAdvancement runs OUTSIDE events_lock because
        // it grabs root_to_slot_lock (5b) and may take the states_lock
        // exclusive for prune — holding events_lock (5c) across that would
        // violate the tier-5 sibling rule.
        if (latest_finalized.slot > last_emitted_finalized.slot) {
            self.processFinalizationAdvancement(last_emitted_finalized, latest_finalized, pruneForkchoice) catch |err| {
                // Record failed finalization attempt
                zeam_metrics.metrics.lean_finalizations_total.incr(.{ .result = "error" }) catch {};
                self.logger.err("failed to process finalization advancement from slot {d} to {d}: {any}", .{
                    last_emitted_finalized.slot,
                    latest_finalized.slot,
                    err,
                });
            };

            // Prune stale attestation data when finalization advances
            self.forkChoice.pruneStaleAttestationData(latest_finalized.slot) catch |err| {
                self.logger.warn("failed to prune stale attestation data: {any}", .{err});
            };

            // Prune cached blocks at or before finalized slot
            if (self.prune_cached_blocks_fn) |prune_fn| {
                if (self.prune_cached_blocks_ctx) |ctx| {
                    const pruned = prune_fn(ctx, latest_finalized);
                    if (pruned > 0) {
                        self.logger.info("pruned {d} cached blocks at finalized slot {d}", .{ pruned, latest_finalized.slot });
                    }
                }
            }
        }

        const states_count_after_block = self.states.count();
        const fc_nodes_count_after_block = self.forkChoice.getNodeCount();
        self.logger.info("completed on block followup with states_count={d} fc_nodes_count={d}", .{
            states_count_after_block,
            fc_nodes_count_after_block,
        });

        zeam_metrics.metrics.lean_latest_justified_slot.set(latest_justified.slot);
        zeam_metrics.metrics.lean_latest_finalized_slot.set(latest_finalized.slot);
    }

    /// Update block database with block, state, and slot indices.
    /// `signed_block_ssz` must be the SSZ encoding of `SignedBlock` (see onBlock).
    fn updateBlockDb(self: *Self, signed_block_ssz: []const u8, blockRoot: types.Root, postState: types.BeamState, slot: types.Slot) !void {
        var batch = try self.db.initWriteBatch();
        defer batch.deinit();

        // Store block and state
        batch.putBlockSerialized(database.DbBlocksNamespace, blockRoot, signed_block_ssz);
        batch.putState(database.DbStatesNamespace, blockRoot, postState);

        // TODO: uncomment this code if there is a need of slot to unfinalized index
        _ = slot;
        // primarily this is served by the forkchoice
        // update unfinalized slot index
        // if (slot > finalizedSlot) {
        //     const existing_blockroots = self.db.loadUnfinalizedSlotIndex(database.DbUnfinalizedSlotsNamespace, slot) orelse &[_]types.Root{};
        //     if (existing_blockroots.len > 0) {
        //         defer self.allocator.free(existing_blockroots);
        //     }
        //     var updated_blockroots = std.ArrayList(types.Root).init(self.allocator);
        //     defer updated_blockroots.deinit();

        //     updated_blockroots.appendSlice(existing_blockroots) catch {};
        //     updated_blockroots.append(blockRoot) catch {};

        //     batch.putUnfinalizedSlotIndex(database.DbUnfinalizedSlotsNamespace, slot, updated_blockroots.items);
        // }

        try self.db.commit(&batch);
    }

    /// Prune old non-canonical states from memory
    /// canonical_blocks: set of block roots that should be kept (e.g., canonical chain from finalized to head)
    ///                    All states in canonical_blocks are kept, all others are pruned
    fn pruneStates(self: *Self, roots: []types.Root, pruneType: []const u8) usize {
        // Single critical section under `states_lock.exclusive` for the whole
        // prune. Holding the exclusive lock blocks any new borrow until we
        // finish, so an in-flight `BorrowedState` cannot observe a freed
        // pointer mid-prune.
        var t = LockTimer.start("states", "pruneStates");
        self.states_lock.lock();
        t.acquired();
        defer t.released();
        defer self.states_lock.unlock();

        const states_count_before = self.states.count();
        self.logger.debug("pruning for {s} (states_count={d}, roots={d})", .{
            pruneType,
            states_count_before,
            roots.len,
        });

        // We keep the canonical chain from finalized to head, so we can safely prune all non-canonical states
        // Actually remove and deallocate the pruned states
        for (roots) |root| {
            if (self.states.fetchRemove(root)) |entry| {
                const state_ptr = entry.value;
                state_ptr.deinit();
                self.allocator.destroy(state_ptr);
                self.logger.debug("pruned state for root 0x{x}", .{
                    &root,
                });
            }
        }

        const states_count_after = self.states.count();
        const pruned_count = states_count_before - states_count_after;
        self.logger.debug("pruning completed for {s} removed {d} states (states: {d} -> {d})", .{
            pruneType,
            pruned_count,
            states_count_before,
            states_count_after,
        });
        return pruned_count;
    }

    /// Process finalization advancement: move canonical blocks to finalized index and cleanup unfinalized indices
    fn processFinalizationAdvancement(self: *Self, previousFinalized: types.Checkpoint, latestFinalized: types.Checkpoint, pruneForkchoice: bool) !void {
        var batch = try self.db.initWriteBatch();
        defer batch.deinit();

        self.logger.debug("processing finalization advancement from slot={d} to slot={d}", .{ previousFinalized.slot, latestFinalized.slot });

        // 1. Do canonoical analysis to segment forkchoice
        var canonical_view = std.AutoHashMap(types.Root, void).init(self.allocator);
        defer canonical_view.deinit();
        const analysis_result = try self.forkChoice.getCanonicalViewAndAnalysis(&canonical_view, latestFinalized.root, null);

        const finalized_roots = analysis_result[0];
        const non_finalized_descendants = analysis_result[1];
        const non_canonical_roots = analysis_result[2];
        defer self.allocator.free(finalized_roots);
        defer self.allocator.free(non_finalized_descendants);
        defer self.allocator.free(non_canonical_roots);

        // getCanonicalViewAndAnalysis should always include the new finalized root itself.
        // If it returns empty the fork choice has already been rebased past this root — bail
        // out rather than performing an out-of-bounds slice on finalized_roots[1..].
        if (finalized_roots.len == 0) {
            self.logger.warn("finalization advancement from slot={d} to slot={d} skipped: canonical analysis returned no roots (fork choice may have already been rebased past this checkpoint)", .{
                previousFinalized.slot,
                latestFinalized.slot,
            });
            return;
        }

        // finalized_ancestor_roots has the previous finalized included
        const newly_finalized_count = finalized_roots.len - 1;
        const slot_gap = latestFinalized.slot - previousFinalized.slot;
        const orphaned_count = if (slot_gap >= newly_finalized_count) slot_gap - newly_finalized_count else blk: {
            self.logger.debug("finalization: newly_finalized_count={d} exceeds slot_gap={d}; orphaned count clamped to 0 (fork choice may contain more canonical roots than slot distance)", .{
                newly_finalized_count,
                slot_gap,
            });
            break :blk @as(u64, 0);
        };
        self.logger.info("finalization canonicality analysis (previousFinalized slot={d} to latestFinalized slot={d}): newly finalized={d}, orphaned/missing={d}, non finalized descendants={d} & finalized non canonical={d}", .{
            previousFinalized.slot,
            latestFinalized.slot,
            newly_finalized_count,
            orphaned_count,
            non_finalized_descendants.len,
            non_canonical_roots.len,
        });

        // 2. Put all newly finalized roots in DbFinalizedSlotsNamespace
        for (finalized_roots) |root| {
            const slot = self.forkChoice.getBlockSlot(root) orelse return error.FinalizedBlockNotInForkChoice;
            batch.putFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, slot, root);
            self.logger.debug("added block 0x{x} at slot {d} to finalized index", .{
                &root,
                slot,
            });
        }

        // Update the latest finalized slot metadata
        batch.putLatestFinalizedSlot(database.DbDefaultNamespace, latestFinalized.slot);

        // 3. commit all batch ops for finalized indices before we prune
        try self.db.commit(&batch);

        // 4. Prunestates from memory
        // Get all canonical blocks from finalized to head (not just newly finalized)
        const states_count_before: isize = self.states.count();
        // first root is the new finalized, we need to retain it and will be pruned in the next round
        _ = self.pruneStates(finalized_roots[1..finalized_roots.len], "finalized ancestors");
        _ = self.pruneStates(non_canonical_roots, "finalized non canonical");
        const pruned_count = states_count_before - self.states.count();
        self.logger.info("state pruning completed (slots latestFinalized={d} to latestFinalized={d}) removed {d} states", .{
            previousFinalized.slot,
            latestFinalized.slot,
            pruned_count,
        });

        // 5 Rebase forkchouce
        if (pruneForkchoice)
            try self.forkChoice.rebase(latestFinalized.root, &canonical_view);

        // TODO:
        // 6. Remove orphaned blocks from database and cleanup unfinalized indices of there are any
        // for (previousFinalizedSlot + 1..finalizedSlot + 1) |slot| {
        //     var slot_orphaned_count: usize = 0;
        //     // Get all unfinalized blocks at this slot before deleting the index
        //     if (self.db.loadUnfinalizedSlotIndex(database.DbUnfinalizedSlotsNamespace, slot)) |unfinalized_blockroots| {
        //         defer self.allocator.free(unfinalized_blockroots);
        //         // Remove blocks not in the canonical finalized chain
        //         for (unfinalized_blockroots) |blockroot| {
        //             if (!canonical_blocks.contains(blockroot)) {
        //                 // This block is orphaned - remove it from database
        //                 batch.delete(database.DbBlocksNamespace, &blockroot);
        //                 batch.delete(database.DbStatesNamespace, &blockroot);
        //                 slot_orphaned_count += 1;
        //             }
        //         }
        //         if (slot_orphaned_count > 0) {
        //             self.logger.debug("Removed {d} orphaned block at slot {d} from database", .{
        //                 slot_orphaned_count,
        //                 slot,
        //             });
        //         }

        //         // Remove the unfinalized slot index
        //         batch.deleteUnfinalizedSlotIndexFromBatch(database.DbUnfinalizedSlotsNamespace, slot);
        //         self.logger.debug("Removed {d} unfinalized index for slot {d}", .{ unfinalized_blockroots.len, slot });
        //     }
        // }

        // Prune root-to-slot cache up to the PREVIOUS finalized slot, not the
        // new one. Cached post-states retained in `self.states` (block.slot >
        // latestFinalized.slot survived `pruneStates` above) can still hold
        // `justifications_roots` whose slots lie in
        // (state.latest_finalized.slot, state.slot]. When a later block is
        // imported on top of such a state and its STF advances finality, the
        // post-finalization cleanup loop in `BeamState.processAttestations`
        // looks those roots up in this cache — so the cache must keep them
        // reachable across one finalization boundary. Pruning on
        // `latestFinalized.slot` drops exactly the roots in
        // (previousFinalized.slot, latestFinalized.slot] that such states can
        // reference, which wedged zeam_0 on devnet-4 via a cross-fork reorg
        // (see issue #771 and the complementary STF hotfix in #772).
        {
            var t_rts = LockTimer.start("root_to_slot", "processFinalizationAdvancement.prune");
            locking.assertNoTier5SiblingHeld("processFinalizationAdvancement.prune");
            self.root_to_slot_lock.lock();
            locking.enterTier5();
            t_rts.acquired();
            defer {
                self.root_to_slot_lock.unlock();
                locking.leaveTier5();
                t_rts.released();
            }
            try self.root_to_slot_cache.prune(previousFinalized.slot);
        }

        // Record successful finalization
        zeam_metrics.metrics.lean_finalizations_total.incr(.{ .result = "success" }) catch {};

        self.logger.debug("finalization advanced  previousFinalized slot={d} to latestFinalized slot={d}", .{ previousFinalized.slot, latestFinalized.slot });
    }

    /// Validate incoming block before expensive processing.
    ///
    /// These checks are cheap and help prevent DoS attacks from malicious peers
    /// flooding the node with invalid blocks.
    ///
    /// Validations performed:
    /// 1. Future slot check: block.slot must not be too far in the future
    /// 2. Pre-finalized slot check: block.slot must be >= finalized_slot
    /// 3. Proposer index bounds check: proposer_index must be < validator_count
    /// 4. Parent existence check: parent_root must be known
    /// 5. Slot ordering check: block.slot must be > parent.slot
    pub fn validateBlock(self: *Self, block: types.BeamBlock, is_from_gossip: bool) !void {
        _ = is_from_gossip;

        const current_slot = self.forkChoice.fcStore.slot_clock.timeSlots.load(.monotonic);
        // latest_finalized is a multi-field Checkpoint written under
        // forkChoice.mutex (exclusive). Take the shared lock via the
        // accessor to avoid a torn (slot, root) pair. PR #820 / #803.
        const finalized_slot = self.forkChoice.getLatestFinalized().slot;

        // 1. Future slot check - reject blocks too far in the future
        // Allow a small tolerance for clock skew, but reject clearly invalid future slots
        // this can also happen because of race conditions between oninterval and block arrival
        const max_future_tolerance: types.Slot = constants.MAX_FUTURE_SLOT_TOLERANCE;
        if (block.slot > current_slot + max_future_tolerance) {
            self.logger.debug("block validation failed: future slot {d} > max allowed {d} time(intervals)={d}", .{
                block.slot,
                current_slot + max_future_tolerance,
                self.forkChoice.fcStore.slot_clock.time.load(.monotonic),
            });
            return BlockValidationError.FutureSlot;
        }

        // 2. Pre-finalized slot check - reject blocks before finalized slot
        if (block.slot < finalized_slot) {
            self.logger.debug("block validation failed: pre-finalized slot {d} < finalized {d}", .{
                block.slot,
                finalized_slot,
            });
            return BlockValidationError.PreFinalizedSlot;
        }

        // 3. Proposer index bounds check - sanity check against registry limit
        // This is a fast pre-check; actual proposer validity is verified during signature verification
        // We use VALIDATOR_REGISTRY_LIMIT as the upper bound since the validator set can grow beyond genesis
        if (block.proposer_index >= params.VALIDATOR_REGISTRY_LIMIT) {
            self.logger.debug("block validation failed: proposer_index {d} >= VALIDATOR_REGISTRY_LIMIT {d}", .{
                block.proposer_index,
                params.VALIDATOR_REGISTRY_LIMIT,
            });
            return BlockValidationError.InvalidProposerIndex;
        }

        // 4. Parent existence check
        const parent_block = self.forkChoice.getBlock(block.parent_root);
        if (parent_block == null) {
            // Log decision moved to node.zig where we can check if parent is already being fetched
            return BlockValidationError.UnknownParentBlock;
        }

        // 5. Slot ordering check - block slot must be greater than parent slot
        if (block.slot <= parent_block.?.slot) {
            self.logger.debug("block validation failed: slot {d} <= parent slot {d}", .{
                block.slot,
                parent_block.?.slot,
            });
            return BlockValidationError.SlotNotAfterParent;
        }
    }

    /// Validate incoming attestation before processing.
    ///
    /// is_from_block: true if attestation came from a block, false if from network gossip
    ///
    /// Per leanSpec:
    /// - Gossip attestations (is_from_block=false): attestation.slot <= current_slot (no future tolerance)
    /// - Block attestations (is_from_block=true): attestation.slot <= current_slot + 1 (lenient)
    pub fn validateAttestationData(self: *Self, data: types.AttestationData, is_from_block: bool) !void {
        const timer = zeam_metrics.lean_attestation_validation_time_seconds.start();
        defer _ = timer.observe();

        // 1. Validate that source, target, and head blocks exist in proto array (thread-safe)
        const source_block = self.forkChoice.getProtoNode(data.source.root) orelse {
            self.logger.debug("Attestation validation failed: unknown source block root=0x{x}", .{
                &data.source.root,
            });
            return AttestationValidationError.UnknownSourceBlock;
        };

        const target_block = self.forkChoice.getProtoNode(data.target.root) orelse {
            self.logger.debug("attestation validation failed: unknown target block slot={d} root=0x{x}", .{
                data.target.slot,
                &data.target.root,
            });
            return AttestationValidationError.UnknownTargetBlock;
        };

        const head_block = self.forkChoice.getProtoNode(data.head.root) orelse {
            self.logger.debug("attestation validation failed: unknown head block slot={d} root=0x{x}", .{
                data.head.slot,
                &data.head.root,
            });
            return AttestationValidationError.UnknownHeadBlock;
        };
        _ = head_block; // Will be used in future validations

        // 2. Validate slot relationships
        if (source_block.slot > target_block.slot) {
            self.logger.debug("attestation validation failed: source slot {d} > target slot {d}", .{
                source_block.slot,
                target_block.slot,
            });
            return AttestationValidationError.SourceSlotExceedsTarget;
        }

        //    This corresponds to leanSpec's: assert attestation.source.slot <= attestation.target.slot
        if (data.source.slot > data.target.slot) {
            self.logger.debug("attestation validation failed: source checkpoint slot {d} > target checkpoint slot {d}", .{
                data.source.slot,
                data.target.slot,
            });
            return AttestationValidationError.SourceCheckpointExceedsTarget;
        }

        // 3. Validate checkpoint slots match block slots
        if (source_block.slot != data.source.slot) {
            self.logger.debug("attestation validation failed: source block slot {d} != source checkpoint slot {d}", .{
                source_block.slot,
                data.source.slot,
            });
            return AttestationValidationError.SourceCheckpointSlotMismatch;
        }

        //    This corresponds to leanSpec's: assert target_block.slot == attestation.target.slot
        if (target_block.slot != data.target.slot) {
            self.logger.debug("attestation validation failed: target block slot {d} != target checkpoint slot {d}", .{
                target_block.slot,
                data.target.slot,
            });
            return AttestationValidationError.TargetCheckpointSlotMismatch;
        }

        // 4. Validate attestation is not too far in the future
        //
        //    Gossip attestations must be for current or past slots only. Validators attest
        //    in interval 1 of the current slot, so they cannot attest for future slots.
        //    Block attestations can be more lenient since the block itself was validated.
        const current_slot = self.forkChoice.getCurrentSlot();
        const max_allowed_slot = if (is_from_block)
            current_slot + constants.MAX_FUTURE_SLOT_TOLERANCE // Block attestations: allow +1
        else
            current_slot; // Gossip attestations: no future slots allowed

        if (data.slot > max_allowed_slot) {
            self.logger.debug("attestation validation failed: attestation slot {d} > max allowed slot {d} (is_from_block={any})", .{
                data.slot,
                max_allowed_slot,
                is_from_block,
            });
            return AttestationValidationError.AttestationTooFarInFuture;
        }
        self.logger.debug("attestation validation passed: slot={d} source={d} target={d} is_from_block={any}", .{
            data.slot,
            data.source.slot,
            data.target.slot,
            is_from_block,
        });
    }

    pub fn onGossipAttestation(self: *Self, signedAttestation: networks.AttestationGossip) !void {
        // Validation is done upstream in onGossip before this function is called.
        const attestation = signedAttestation.message.toAttestation();

        // Borrow-only — verifySingleAttestation reads the state for the
        // duration of this call, then we drop the borrow before passing the
        // attestation to forkChoice. The XMSS verify is short (~few ms);
        // holding `states_lock.shared` over it does not stall importers
        // because they only need exclusive access for STF commits, which
        // happen later under their own snapshot.
        var borrow = self.statesGet(attestation.data.target.root) orelse return AttestationValidationError.MissingState;
        defer borrow.assertReleasedOrPanic();
        defer borrow.deinit();

        try stf.verifySingleAttestation(
            self.allocator,
            borrow.state,
            @intCast(signedAttestation.message.validator_id),
            &signedAttestation.message.message,
            &signedAttestation.message.signature,
        );

        return self.forkChoice.onSignedAttestation(signedAttestation.message);
    }

    pub fn onGossipAggregatedAttestation(self: *Self, signedAggregation: types.SignedAggregatedAttestation) !void {
        // Validate the attestation data first (same rules as individual gossip attestations)
        try self.validateAttestationData(signedAggregation.data, false);

        try self.verifyAggregatedAttestation(signedAggregation);

        var validator_indices = try types.aggregationBitsToValidatorIndices(&signedAggregation.proof.participants, self.allocator);
        defer validator_indices.deinit(self.allocator);

        var validator_ids = try self.allocator.alloc(types.ValidatorIndex, validator_indices.items.len);
        defer self.allocator.free(validator_ids);
        for (validator_indices.items, 0..) |vi, i| {
            validator_ids[i] = @intCast(vi);
        }

        // Update attestation trackers for gossip attestations so fork choice sees these votes
        for (validator_ids) |validator_id| {
            const attestation = types.Attestation{
                .validator_id = validator_id,
                .data = signedAggregation.data,
            };
            self.forkChoice.onAttestation(attestation, false) catch |err| {
                self.logger.debug("skip tracker update for aggregated attestation validator={d}: {any}", .{
                    validator_id, err,
                });
            };
        }

        try self.forkChoice.storeAggregatedPayload(&signedAggregation.data, signedAggregation.proof, false);
    }

    fn verifyAggregatedAttestation(self: *Self, signedAggregation: types.SignedAggregatedAttestation) !void {
        const data = signedAggregation.data;
        const proof = signedAggregation.proof;

        var validator_indices = try types.aggregationBitsToValidatorIndices(&proof.participants, self.allocator);
        defer validator_indices.deinit(self.allocator);

        // Borrow-only: short read of `state.validators` to look up pubkey
        // bytes. Drop the borrow before the XMSS verify since the borrow
        // only protects the validator-list pointer.
        var borrow = self.statesGet(data.target.root) orelse return error.MissingState;
        defer borrow.assertReleasedOrPanic();
        var public_keys = try std.ArrayList(*const xmss.HashSigPublicKey).initCapacity(self.allocator, validator_indices.items.len);
        defer public_keys.deinit(self.allocator);

        {
            defer borrow.deinit();
            const validators = borrow.state.validators.constSlice();

            // pubkey_cache lookup needs the lock; tier-5 sibling rule says
            // root_to_slot_lock and events_lock must NOT be held here.
            var t_pk = LockTimer.start("pubkey_cache", "verifyAggregatedAttestation");
            locking.assertNoTier5SiblingHeld("verifyAggregatedAttestation");
            self.pubkey_cache_lock.lock();
            locking.enterTier5();
            t_pk.acquired();
            defer {
                self.pubkey_cache_lock.unlock();
                locking.leaveTier5();
                t_pk.released();
            }

            for (validator_indices.items) |validator_index| {
                if (validator_index >= validators.len) {
                    return error.InvalidValidatorId;
                }
                const pubkey_bytes = validators[validator_index].getAttestationPubkey();
                const pk_handle = self.public_key_cache.getOrPut(validator_index, pubkey_bytes) catch {
                    return error.InvalidBlockSignatures;
                };
                try public_keys.append(self.allocator, pk_handle);
            }
        }

        var message_hash: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.AttestationData, data, &message_hash, self.allocator);

        const epoch: u64 = data.slot;
        proof.verify(public_keys.items, &message_hash, epoch) catch {
            return error.InvalidAggregationSignature;
        };
    }

    pub fn aggregate(self: *Self) ![]types.SignedAggregatedAttestation {
        // forkChoice.head is a multi-field ProtoBlock written under
        // forkChoice.mutex (exclusive). Snapshot once via the shared-
        // locked accessor; reading `.blockRoot` directly would tear
        // against a concurrent updateHead. PR #820 / #803.
        const head_root = self.forkChoice.getHead().blockRoot;
        // Snapshot-then-release: forkChoice.aggregate runs an FFI window
        // (~700ms) over `state.validators`. Holding `states_lock.shared`
        // for that window would force any STF commit to wait. Clone first,
        // release the lock, then run the FFI on the owned snapshot.
        var borrow = self.statesGet(head_root) orelse return error.MissingState;
        defer borrow.assertReleasedOrPanic();
        const snapshot = try borrow.cloneAndRelease(self.allocator);
        defer {
            snapshot.deinit();
            self.allocator.destroy(snapshot);
        }
        return self.forkChoice.aggregate(snapshot);
    }

    pub fn maybeAggregateOnInterval(self: *Self, time_intervals: usize) !?[]types.SignedAggregatedAttestation {
        const slot = @divFloor(time_intervals, constants.INTERVALS_PER_SLOT);
        if (!self.is_aggregator_enabled.load(.acquire) or self.registered_validator_ids.len == 0) return null;

        const sync_status = self.getSyncStatus();
        switch (sync_status) {
            .synced => {},
            .fc_initing => {
                self.logger.warn("skipping aggregation production for slot={d}: forkchoice initializing", .{slot});
                return null;
            },
            .no_peers => {
                self.logger.warn("skipping aggregation production for slot={d}: no peers connected", .{slot});
                return null;
            },
            .behind_peers => |info| {
                self.logger.warn("skipping aggregation production for slot={d}: behind peers (head_slot={d}, finalized_slot={d}, max_peer_finalized_slot={d})", .{
                    slot,
                    info.head_slot,
                    info.finalized_slot,
                    info.max_peer_finalized_slot,
                });
                return null;
            },
        }

        const aggregations = self.aggregate() catch |err| {
            self.logger.warn("failed to aggregate attestation signatures for slot={d}: {any}", .{ slot, err });
            return null;
        };

        if (aggregations.len == 0) {
            self.allocator.free(aggregations);
            return null;
        }

        return aggregations;
    }

    pub fn getStatus(self: *Self) types.Status {
        const finalized = self.forkChoice.getLatestFinalized();
        const head = self.forkChoice.getHead();

        return .{
            .finalized_root = finalized.root,
            .finalized_slot = finalized.slot,
            .head_root = head.blockRoot,
            .head_slot = head.slot,
        };
    }

    /// Get the finalized checkpoint state (BeamState) if available.
    /// First checks the in-memory `states` map, then the `cached_finalized_state`
    /// field, then falls back to a database load. Returns null if the state
    /// is not available in any location.
    ///
    /// Slice (a-2) migration: this used to return a raw `*const BeamState`
    /// borrowed from the in-memory map under `BeamNode.mutex`. After (a-2)
    /// it returns a `BorrowedState` whose backing lock depends on which
    /// path produced the result:
    ///   * In-memory map hit  → backed by `states_lock` (shared).
    ///   * Cache hit / DB load → backed by `events_lock` (mutex), since
    ///     `cached_finalized_state` is mutated under `events_lock` (the
    ///     DB-load path also writes the cache field, and that write is
    ///     guarded by the mutex). Callers MUST release the borrow exactly
    ///     once via `deinit()` or `cloneAndRelease(allocator)`.
    ///
    /// PR description (a-2) enumerates every caller migrated under this
    /// API change — grepping `states.get` will not find them.
    pub fn getFinalizedState(self: *Self) ?BorrowedState {
        // latest_finalized is a multi-field Checkpoint written under
        // forkChoice.mutex (exclusive); use the shared-locked accessor
        // so we don't pair `slot` with a different update's `root`.
        // PR #820 / #803.
        const finalized_checkpoint = self.forkChoice.getLatestFinalized();

        // First try the in-memory states map under `states_lock.shared`.
        if (self.statesGet(finalized_checkpoint.root)) |borrow| {
            return borrow;
        }

        // Cache / DB-load path under `events_lock`. Tier-5 sibling rule:
        // pubkey_cache_lock (5a) and root_to_slot_lock (5b) must NOT be
        // held by the caller. Callers today are HTTP / RPC threads that
        // never hold those locks.
        var t_ev = LockTimer.start("events", "getFinalizedState");
        locking.assertNoTier5SiblingHeld("getFinalizedState");
        self.events_lock.lock();
        locking.enterTier5();
        t_ev.acquired();

        // From this point onward the lock is owned by either the returned
        // borrow (handed off to the caller via `BorrowedState.deinit`) or
        // by an explicit `unlock()` on the not-found path. Track via a
        // local flag so a `return null` cannot accidentally leak the lock.
        var lock_held = true;
        defer {
            if (lock_held) {
                self.events_lock.unlock();
                locking.leaveTier5();
                t_ev.released();
            }
        }

        // Check if we already have a cached state. Invalidate if it's behind
        // the current finalized checkpoint (can happen if the cache was
        // seeded from the DB at startup before any in-memory finalization
        // happened).
        if (self.cached_finalized_state) |cached_state| {
            if (std.mem.eql(u8, &cached_state.latest_finalized.root, &finalized_checkpoint.root)) {
                lock_held = false; // ownership of the lock moves into the borrow
                // tier-5 depth and LockTimer are HANDED OFF to the borrow:
                // BorrowedState.deinit calls leaveTier5() and t.released()
                // after unlocking. Do NOT close them here.
                return BorrowedState{
                    .state = cached_state,
                    .backing = .{ .events_mutex = &self.events_lock },
                    .tier5_held = true,
                    .timer = t_ev,
                };
            }
            // Stale — fall through to DB load below.
        }

        // Fallback: try to load from database. Allocate the cache slot, load,
        // store in `cached_finalized_state`, return a borrow over it.
        const state_ptr = self.allocator.create(types.BeamState) catch |err| {
            self.logger.warn("failed to allocate memory for finalized state: {any}", .{err});
            return null;
        };

        self.db.loadLatestFinalizedState(state_ptr) catch |err| {
            self.allocator.destroy(state_ptr);
            self.logger.warn("finalized state not available in database: {any}", .{err});
            return null;
        };

        // If a previous cached state is being replaced, free it now (we
        // hold events_lock so no concurrent borrow of the old pointer can
        // exist past this critical section).
        if (self.cached_finalized_state) |old_cached| {
            old_cached.deinit();
            self.allocator.destroy(old_cached);
        }

        // Cache in separate field (not in states map to avoid affecting pruning)
        self.cached_finalized_state = state_ptr;

        self.logger.info("loaded finalized state from database at slot {d}", .{state_ptr.slot});

        lock_held = false;
        // tier-5 depth + LockTimer handed off to the borrow; deinit will
        // leaveTier5() and t.released() after unlocking.
        return BorrowedState{
            .state = state_ptr,
            .backing = .{ .events_mutex = &self.events_lock },
            .tier5_held = true,
            .timer = t_ev,
        };
    }

    /// Get the latest justified checkpoint.
    /// Returns the checkpoint with slot and root of the most recent
    /// justified checkpoint, snapshotted under forkChoice.mutex.lockShared
    /// so callers see a coherent (slot, root) pair. PR #820 / #803.
    pub fn getJustifiedCheckpoint(self: *Self) types.Checkpoint {
        return self.forkChoice.getLatestJustified();
    }

    pub const SyncStatus = union(enum) {
        synced,
        no_peers,
        /// Forkchoice is in its init phase (checkpoint-sync or DB restore): it has not yet
        /// observed a real justified checkpoint via block processing.  Validator duties must
        /// not run until the first onBlock-driven justified update transitions FC to ready.
        fc_initing,
        behind_peers: struct {
            head_slot: types.Slot,
            finalized_slot: types.Slot,
            max_peer_finalized_slot: types.Slot,
        },
    };

    /// Returns detailed sync status information.
    pub fn getSyncStatus(self: *Self) SyncStatus {
        // If forkchoice is still initializing (checkpoint-sync / DB-restore), block production
        // and attestation must be deferred until we observe the first real justified checkpoint.
        if (!self.forkChoice.isReady()) {
            return .fc_initing;
        }

        // If no peers connected, we can't verify sync status - assume not synced
        // Unless force_block_production is enabled, which allows block generation without peers
        if (self.connected_peers.count() == 0 and !self.force_block_production) {
            return .no_peers;
        }

        // forkChoice.head and fcStore.latest_finalized are multi-field
        // structs written under forkChoice.mutex.lock(). Snapshot via the
        // shared-locked accessors so callers see coherent values.
        // PR #820 / #803.
        const our_head_slot = self.forkChoice.getHead().slot;
        const our_finalized_slot = self.forkChoice.getLatestFinalized().slot;

        // Find the maximum finalized slot reported by any peer
        var max_peer_finalized_slot: types.Slot = our_finalized_slot;

        var peer_guard = self.connected_peers.iterateLocked();
        defer peer_guard.deinit();
        var peer_iter = peer_guard.iter;
        while (peer_iter.next()) |entry| {
            const peer_info = entry.value_ptr;
            if (peer_info.latest_status) |status| {
                if (status.finalized_slot > max_peer_finalized_slot) {
                    max_peer_finalized_slot = status.finalized_slot;
                }
            }
        }

        // Check 1: our head is behind peer finalization — we don't even have finalized blocks
        if (our_head_slot < max_peer_finalized_slot) {
            return .{ .behind_peers = .{
                .head_slot = our_head_slot,
                .finalized_slot = our_finalized_slot,
                .max_peer_finalized_slot = max_peer_finalized_slot,
            } };
        }

        // Check 2: our finalization is behind peer finalization — we may be on a divergent fork
        if (our_finalized_slot < max_peer_finalized_slot) {
            return .{ .behind_peers = .{
                .head_slot = our_head_slot,
                .finalized_slot = our_finalized_slot,
                .max_peer_finalized_slot = max_peer_finalized_slot,
            } };
        }

        return .synced;
    }
};

pub const BlockProcessingError = error{
    MissingPreState,
    InvalidSignatureGroups,
    DuplicateAttestationData,
    TooManyAttestationData,
};
const BlockProductionError = error{ NotImplemented, MissingPreState };
const AttestationValidationError = error{
    MissingState,
    UnknownSourceBlock,
    UnknownTargetBlock,
    UnknownHeadBlock,
    SourceSlotExceedsTarget,
    SourceCheckpointExceedsTarget,
    SourceCheckpointSlotMismatch,
    TargetCheckpointSlotMismatch,
    AttestationTooFarInFuture,
};
pub const BlockValidationError = error{
    UnknownParentBlock,
    /// Block slot is too far in the future
    FutureSlot,
    /// Block slot is before the finalized slot
    PreFinalizedSlot,
    /// Block proposer_index exceeds validator count
    InvalidProposerIndex,
    /// Block slot is not greater than parent slot
    SlotNotAfterParent,
};

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_attestation_pubkeys instead of num_validators
test "process and add mock blocks into a node's chain" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Generate a mock chain with validator pubkeys baked into the genesis spec.
    const mock_chain = try stf.genMockChain(allocator, 5, null);
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
    var beam_state = mock_chain.genesis_state;
    const nodeId = 10; // random value
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    connected_peers.* = ConnectedPeers.init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.getLatestFinalized().root, &mock_chain.blockRoots[0]));
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == 1);
    try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.getLatestFinalized().root, &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));
    try std.testing.expect(std.mem.eql(u8, mock_chain.blocks[0].block.state_root[0..], &beam_chain.forkChoice.protoArray.nodes.items[0].stateRoot));
    try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[0], &beam_chain.forkChoice.protoArray.nodes.items[0].blockRoot));

    for (1..mock_chain.blocks.len) |i| {
        // get the block post state
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.block;
        const block_root = mock_chain.blockRoots[i];
        const current_slot = block.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{ .pruneForkchoice = false });
        allocator.free(missing_roots);

        try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == i + 1);
        try std.testing.expect(std.mem.eql(u8, &mock_chain.blockRoots[i], &beam_chain.forkChoice.protoArray.nodes.items[i].blockRoot));
        const searched_idx = beam_chain.forkChoice.protoArray.indices.get(mock_chain.blockRoots[i]);
        try std.testing.expect(searched_idx == i);

        // should have matching states in the state
        // SAFETY: test-only, single-threaded — no states_lock acquisition
        // needed (the chain under test has no concurrent mutators).
        const block_state = beam_chain.states.get(block_root) orelse @panic("state root should have been found");
        var state_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(*types.BeamState, block_state, &state_root, allocator);
        try std.testing.expect(std.mem.eql(u8, &state_root, &block.state_root));

        // fcstore checkpoints should match
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.getLatestJustified().root, &mock_chain.latestJustified[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.getLatestFinalized().root, &mock_chain.latestFinalized[i].root));
        try std.testing.expect(std.mem.eql(u8, &beam_chain.forkChoice.getHead().blockRoot, &mock_chain.latestHead[i].root));
    }

    const num_validators: usize = @intCast(mock_chain.genesis_config.numValidators());
    for (0..num_validators) |validator_id| {
        // all validators should have attested as per the mock chain
        const attestations_tracker = beam_chain.forkChoice.attestations.get(validator_id);
        try std.testing.expect(attestations_tracker != null);
    }
}

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_attestation_pubkeys instead of num_validators
test "printSlot output demonstration" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Create a mock chain with some blocks
    const mock_chain = try stf.genMockChain(allocator, 3, null);
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
    var beam_state = mock_chain.genesis_state;
    const nodeId = 42; // Test node ID
    var zeam_logger_config = zeam_utils.getLoggerConfig(.info, null);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    // Initialize the beam chain
    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, blk: {
        const cp = try allocator.create(ConnectedPeers);
        cp.* = ConnectedPeers.init(allocator);
        break :blk cp;
    });

    // Process some blocks to have a more interesting chain state
    for (1..mock_chain.blocks.len) |i| {
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.block;
        const current_slot = block.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{});
        allocator.free(missing_roots);
    }

    // Register some validators to make the output more interesting
    var validator_ids = [_]usize{ 0, 1, 2 };
    beam_chain.registerValidatorIds(&validator_ids);

    // Test printSlot at different slots to see the output
    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 0 ===\n", .{});
    beam_chain.printSlot(0, null, beam_chain.connected_peers.count());

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 1 ===\n", .{});
    beam_chain.printSlot(1, null, beam_chain.connected_peers.count());

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 2 ===\n", .{});
    beam_chain.printSlot(2, null, beam_chain.connected_peers.count());

    std.debug.print("\n=== PRINTING CHAIN STATUS AT SLOT 5 (BEHIND) ===\n", .{});
    beam_chain.printSlot(5, null, beam_chain.connected_peers.count());

    // Verify that the chain state is as expected
    try std.testing.expect(beam_chain.forkChoice.protoArray.nodes.items.len == mock_chain.blocks.len);
    try std.testing.expect(beam_chain.registered_validator_ids.len == 3);
}

test "buildTreeVisualization integration test" {
    // Integration test for buildTreeVisualization through the real chain pipeline
    // This tests the visualization with real block roots from processed blocks
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    // Create a mock chain with some blocks
    const mock_chain = try stf.genMockChain(allocator, 3, null);
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
    var beam_state = mock_chain.genesis_state;
    const nodeId = 42;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    // Initialize the beam chain
    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = nodeId, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, blk: {
        const cp = try allocator.create(ConnectedPeers);
        cp.* = ConnectedPeers.init(allocator);
        break :blk cp;
    });

    // Process blocks to build the forkchoice tree
    for (1..mock_chain.blocks.len) |i| {
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.block;
        const current_slot = block.slot;

        try beam_chain.forkChoice.onInterval(current_slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{});
        allocator.free(missing_roots);
    }

    // Get forkchoice snapshot and build tree visualization
    // Uses .snapshot() — same method as printSlot (see line ~535)
    const snapshot = try beam_chain.forkChoice.snapshot(allocator);
    defer snapshot.deinit(allocator);

    const tree_output = try tree_visualizer.buildTreeVisualization(allocator, snapshot.nodes, 10, null);
    defer allocator.free(tree_output);

    std.debug.print("\n=== INTEGRATION TEST: buildTreeVisualization ===\n", .{});
    std.debug.print("ForkChoice Tree:\n{s}\n", .{tree_output});

    // Verify the output format:
    // 1. Output should not be empty (we have 3 blocks)
    try std.testing.expect(tree_output.len > 0);

    // 2. Should contain slot numbers in parentheses for each block
    try std.testing.expect(std.mem.indexOf(u8, tree_output, "(0)") != null); // genesis
    try std.testing.expect(std.mem.indexOf(u8, tree_output, "(1)") != null); // slot 1
    try std.testing.expect(std.mem.indexOf(u8, tree_output, "(2)") != null); // slot 2

    // 3. Should contain the chain connector for linear chain
    try std.testing.expect(std.mem.indexOf(u8, tree_output, "─") != null);

    // 4. Should NOT contain fork indicators (we have a linear chain)
    try std.testing.expect(std.mem.indexOf(u8, tree_output, "├──") == null);
    try std.testing.expect(std.mem.indexOf(u8, tree_output, "└──") == null);

    // 5. Verify node count matches blocks processed
    try std.testing.expect(snapshot.nodes.len == mock_chain.blocks.len);
}

// Attestation Validation Tests
// These tests align with leanSpec's test_attestation_processing.py

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_attestation_pubkeys instead of num_validators
test "attestation validation - comprehensive" {
    // Comprehensive test covering all attestation validation rules
    // This consolidates multiple validation checks into one test to avoid redundant setup
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 3, null);
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
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    connected_peers.* = ConnectedPeers.init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain (slots 1 and 2)
    for (1..mock_chain.blocks.len) |i| {
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.block;
        try beam_chain.forkChoice.onInterval(block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{});
        allocator.free(missing_roots);
    }

    // Test 1: Valid attestation (baseline - should pass)
    {
        const source_slot: types.Slot = 1;
        const target_slot: types.Slot = 2;
        const valid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = target_slot,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[target_slot],
                    .slot = target_slot,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[source_slot],
                    .slot = source_slot,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[target_slot],
                    .slot = target_slot,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        // Should pass validation
        try beam_chain.validateAttestationData(valid_attestation.message, false);
    }

    // Test 2: Unknown source block
    {
        const unknown_root = [_]u8{0xFF} ** 32;
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = unknown_root, // Unknown block
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.UnknownSourceBlock, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }

    // Test 3: Unknown target block
    {
        const unknown_root = [_]u8{0xEE} ** 32;
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = unknown_root, // Unknown block
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.UnknownTargetBlock, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }

    // Test 4: Unknown head block
    {
        const unknown_root = [_]u8{0xDD} ** 32;
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = unknown_root, // Unknown block
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.UnknownHeadBlock, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }
    // Test 5: Source slot exceeds target slot (block slots)
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.SourceSlotExceedsTarget, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }

    // Test 6: Source checkpoint slot exceeds target checkpoint slot
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.SourceSlotExceedsTarget, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }

    // Test 7: Source checkpoint slot mismatch
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 0,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.SourceCheckpointSlotMismatch, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }

    // Test 8: Target checkpoint slot mismatch
    {
        const invalid_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 2,
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 1, // Checkpoint claims slot 1 (mismatch)
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.TargetCheckpointSlotMismatch, beam_chain.validateAttestationData(invalid_attestation.message, false));
    }

    // Test 9: Attestation too far in future (for gossip)
    {
        const future_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 3, // Future slot (current is 2)
                .head = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
                .source = types.Checkpoint{
                    .root = mock_chain.blockRoots[1],
                    .slot = 1,
                },
                .target = types.Checkpoint{
                    .root = mock_chain.blockRoots[2],
                    .slot = 2,
                },
            },
            .signature = ZERO_SIGBYTES,
        };
        try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestationData(future_attestation.message, false));
    }
}

// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_attestation_pubkeys instead of num_validators
test "attestation validation - gossip vs block future slot handling" {
    // Test that gossip and block attestations have different future slot tolerances
    // Gossip: must be <= current_slot
    // Block: can be <= current_slot + 1
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 2, null);
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
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    connected_peers.* = ConnectedPeers.init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Add one block (slot 1)
    const block = mock_chain.blocks[1];
    try beam_chain.forkChoice.onInterval(block.block.slot * constants.INTERVALS_PER_SLOT, false);
    const missing_roots = try beam_chain.onBlock(block, .{});
    allocator.free(missing_roots);

    // Current time is at slot 1, create attestation for slot 2 (next slot)
    const next_slot_attestation: types.SignedAttestation = .{
        .validator_id = 0,
        .message = .{
            .slot = 2,
            .head = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Checkpoint{
                .root = mock_chain.blockRoots[0],
                .slot = 0,
            },
            .target = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
        },
        .signature = ZERO_SIGBYTES,
    };

    // Gossip attestations: should FAIL for next slot (current + 1)
    // Per spec store.py:177: assert attestation.slot <= time_slots
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestationData(next_slot_attestation.message, false));

    // Block attestations: should PASS for next slot (current + 1)
    // Per spec store.py:140: assert attestation.slot <= Slot(current_slot + Slot(1))
    try beam_chain.validateAttestationData(next_slot_attestation.message, true);
    const too_far_attestation: types.SignedAttestation = .{
        .validator_id = 0,
        .message = .{
            .slot = 3, // Too far in future
            .head = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .source = types.Checkpoint{
                .root = mock_chain.blockRoots[0],
                .slot = 0,
            },
            .target = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
        },
        .signature = ZERO_SIGBYTES,
    };
    // Both should fail for slot 3 when current is slot 1
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestationData(too_far_attestation.message, false));
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestationData(too_far_attestation.message, true));
}
// TODO: Enable and update this test once the keymanager file-reading PR is added
// JSON parsing for chain config needs to support validator_attestation_pubkeys instead of num_validators
test "attestation processing - valid block attestation" {
    // Test that valid attestations from blocks are processed correctly
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 3, null);
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
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    connected_peers.* = ConnectedPeers.init(allocator);

    // Create empty node registry for test
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Add blocks to chain
    for (1..mock_chain.blocks.len) |i| {
        const block = mock_chain.blocks[i];
        try beam_chain.forkChoice.onInterval(block.block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(block, .{});
        allocator.free(missing_roots);
    }

    // Create a valid attestation
    const message = types.Attestation{
        .validator_id = 1,
        .data = .{
            .slot = 2,
            .head = types.Checkpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
            .source = types.Checkpoint{
                .root = mock_chain.blockRoots[1],
                .slot = 1,
            },
            .target = types.Checkpoint{
                .root = mock_chain.blockRoots[2],
                .slot = 2,
            },
        },
    };

    var key_manager = try keymanager.getTestKeyManager(allocator, 4, 3);
    defer key_manager.deinit();

    const signature = try key_manager.signAttestation(&message, allocator);

    const valid_attestation: types.SignedAttestation = .{
        .validator_id = message.validator_id,
        .message = message.data,
        .signature = signature,
    };

    const subnet_id = try types.computeSubnetId(
        @intCast(valid_attestation.validator_id),
        beam_chain.config.spec.attestation_committee_count,
    );
    const gossip_attestation = networks.AttestationGossip{
        .subnet_id = @intCast(subnet_id),
        .message = valid_attestation,
    };

    // Process attestation through chain (this validates and then processes)
    try beam_chain.onGossipAttestation(gossip_attestation);

    // Verify the attestation data was recorded for aggregation
    try std.testing.expect(beam_chain.forkChoice.attestation_signatures.getPtr(valid_attestation.message) != null);
}

test "produceBlock - greedy selection by latest slot is suboptimal when attestation references unseen block" {
    // Demonstrates that selecting attestation_data entries by latest slot is not the
    // best strategy for block production. An attestation_data with a higher slot may
    // reference a block on a different fork that this node has never seen locally.
    // The STF will skip such attestations (has_known_root check in process_attestations),
    // wasting block space. Lower-slot attestations referencing locally-known blocks
    // are the ones that actually contribute to justification.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 3, null);
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
    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try allocator.create(ConnectedPeers);
    connected_peers.* = ConnectedPeers.init(allocator);

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(allocator, ChainOpts{ .config = chain_config, .anchorState = &beam_state, .nodeId = 0, .logger_config = &zeam_logger_config, .db = db, .node_registry = test_registry }, connected_peers);
    defer beam_chain.deinit();

    // Process blocks at slots 1 and 2
    for (1..mock_chain.blocks.len) |i| {
        const signed_block = mock_chain.blocks[i];
        const block = signed_block.block;
        try beam_chain.forkChoice.onInterval(block.slot * constants.INTERVALS_PER_SLOT, false);
        const missing_roots = try beam_chain.onBlock(signed_block, .{ .pruneForkchoice = false });
        allocator.free(missing_roots);
    }

    // After processing blocks 0-2, latest_justified should be at slot 1.
    const justified_root = mock_chain.latestJustified[2].root;

    // att_data_unseen: higher slot, but references a block on a fork we haven't seen.
    // A greedy-by-slot approach would prefer this over lower-slot alternatives.
    const unknown_root = [_]u8{0xAB} ** 32;
    const att_data_unseen = types.AttestationData{
        .slot = 2,
        .head = .{ .root = unknown_root, .slot = 2 },
        .target = .{ .root = unknown_root, .slot = 2 },
        .source = .{ .root = justified_root, .slot = 1 },
    };

    // att_data_known: references a locally-known block at slot 2.
    const att_data_known = types.AttestationData{
        .slot = 1,
        .head = .{ .root = mock_chain.blockRoots[2], .slot = 2 },
        .target = .{ .root = mock_chain.blockRoots[2], .slot = 2 },
        .source = .{ .root = justified_root, .slot = 1 },
    };

    // Create mock proofs with all 4 validators participating
    var proof_unseen = try types.AggregatedSignatureProof.init(allocator);
    for (0..4) |i| {
        try types.aggregationBitsSet(&proof_unseen.participants, i, true);
    }
    try beam_chain.forkChoice.storeAggregatedPayload(&att_data_unseen, proof_unseen, true);

    var proof_known = try types.AggregatedSignatureProof.init(allocator);
    for (0..4) |i| {
        try types.aggregationBitsSet(&proof_known.participants, i, true);
    }
    try beam_chain.forkChoice.storeAggregatedPayload(&att_data_known, proof_known, true);

    // Produce block at slot 3 (proposer_index = 3 % 4 = 3)
    const proposal_slot: types.Slot = 3;
    const num_validators: u64 = @intCast(mock_chain.genesis_config.numValidators());
    var produced = try beam_chain.produceBlock(.{
        .slot = proposal_slot,
        .proposer_index = proposal_slot % num_validators,
    });
    defer produced.deinit();

    // The block should contain attestation entries for both att_data since both
    // have source matching the justified checkpoint.
    const block_attestations = produced.block.body.attestations.constSlice();

    // However, after STF processing, only the attestation referencing the known
    // block contributes to justification. The unseen-fork attestation is silently
    // skipped by process_attestations (has_known_root check).
    //
    // This demonstrates why greedy-by-latest-slot is suboptimal: if we had only
    // selected the highest-slot attestation (att_data_unseen at slot=2), the block
    // would contribute zero attestation weight. The lower-slot attestation
    // (att_data_known at slot=1) is the one that actually matters.
    // SAFETY: test-only, single-threaded — no states_lock acquisition
    // needed (the chain under test has no concurrent mutators).
    const post_state = beam_chain.states.get(produced.blockRoot) orelse @panic("post state should exist");
    try std.testing.expect(post_state.latest_justified.slot >= 1);

    // Count how many attestation entries reference the unseen vs known block
    var unseen_count: usize = 0;
    var known_count: usize = 0;
    for (block_attestations) |att| {
        if (std.mem.eql(u8, &att.data.target.root, &unknown_root)) {
            unseen_count += 1;
        } else if (std.mem.eql(u8, &att.data.target.root, &mock_chain.blockRoots[2])) {
            known_count += 1;
        }
    }
    // Only the known attestation is included in the block
    try std.testing.expect(unseen_count == 0);
    try std.testing.expect(known_count > 0);
}

// =====================================================================
// Slice (a-2) primitive tests — these exercise BorrowedState and the
// BlockCache helper against real BeamState / SignedBlock values produced
// by `stf.genMockChain`. The corresponding API-level tests in
// `pkgs/node/src/locking.zig` cover the FailingAllocator / OOM paths,
// double-deinit, and tier-5 depth counter without needing a mock chain.
// =====================================================================

test "BorrowedState: cloneAndRelease success path against real BeamState" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(allocator, 2, null);
    var beam_state = mock_chain.genesis_state;

    var rwl: zeam_utils.SyncRwLock = .{};
    rwl.lockShared();

    var borrow = locking.BorrowedState{
        .state = &beam_state,
        .backing = .{ .states_shared_rwlock = &rwl },
    };

    const owned = try borrow.cloneAndRelease(allocator);
    defer {
        owned.deinit();
        allocator.destroy(owned);
    }
    try std.testing.expect(borrow.released);
    try std.testing.expect(owned.slot == beam_state.slot);

    // Lock has been released — we should be able to grab it exclusively.
    rwl.lock();
    rwl.unlock();
}

test "BlockCache: insert + get + removeChildrenOf bounded" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var bc = locking.BlockCache.init(std.testing.allocator);
    defer bc.deinit();

    const mock_chain = try stf.genMockChain(allocator, 3, null);

    // Insert each block into the cache as a child of its parent. The cache
    // takes ownership of the block + ssz buffer; clone both so the mock
    // chain's storage stays valid for assertions.
    for (1..mock_chain.blocks.len) |i| {
        var clone: types.SignedBlock = undefined;
        try types.sszClone(std.testing.allocator, types.SignedBlock, mock_chain.blocks[i], &clone);

        var ssz_buf: std.ArrayList(u8) = .empty;
        defer ssz_buf.deinit(std.testing.allocator);
        try ssz.serialize(types.SignedBlock, mock_chain.blocks[i], &ssz_buf, std.testing.allocator);
        const ssz_bytes = try ssz_buf.toOwnedSlice(std.testing.allocator);

        try bc.insert(
            mock_chain.blockRoots[i],
            clone,
            ssz_bytes,
            mock_chain.blocks[i].block.parent_root,
        );
    }

    try std.testing.expect(bc.count() == mock_chain.blocks.len - 1);

    // Every inserted root should be retrievable.
    for (1..mock_chain.blocks.len) |i| {
        const got_opt = try bc.cloneBlockAndSsz(mock_chain.blockRoots[i], std.testing.allocator);
        try std.testing.expect(got_opt != null);
        var got = got_opt.?;
        defer got.deinit(std.testing.allocator);
        try std.testing.expect(got.ssz != null);
    }

    // removeChildrenOf the genesis root should drop the entire chain.
    const removed = bc.removeChildrenOf(mock_chain.blockRoots[0]);
    try std.testing.expect(removed > 0);
    try std.testing.expect(removed <= locking.MAX_CACHED_BLOCKS);
}

test "BlockCache: partial-state invariant (re-insert leaves no orphans)" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var bc = locking.BlockCache.init(std.testing.allocator);
    defer bc.deinit();

    const mock_chain = try stf.genMockChain(allocator, 2, null);

    // Two consecutive inserts at the same root must leave the cache in a
    // consistent triple-present state — in particular, the second insert
    // must free the previous block + ssz so a leak detector stays happy.
    for (0..2) |_| {
        var clone: types.SignedBlock = undefined;
        try types.sszClone(std.testing.allocator, types.SignedBlock, mock_chain.blocks[1], &clone);

        var ssz_buf: std.ArrayList(u8) = .empty;
        defer ssz_buf.deinit(std.testing.allocator);
        try ssz.serialize(types.SignedBlock, mock_chain.blocks[1], &ssz_buf, std.testing.allocator);
        const ssz_bytes = try ssz_buf.toOwnedSlice(std.testing.allocator);

        try bc.insert(
            mock_chain.blockRoots[1],
            clone,
            ssz_bytes,
            mock_chain.blocks[1].block.parent_root,
        );
    }

    // After two inserts: exactly one entry under the root in `blocks` and
    // `ssz_bytes`, and the children list under the parent has the root
    // listed twice (since we appended on both inserts — documented
    // behaviour: `insert` does not de-dup, callers manage that). Either
    // way `cloneBlockAndSsz` must return the latest entry.
    const got_opt = try bc.cloneBlockAndSsz(mock_chain.blockRoots[1], std.testing.allocator);
    try std.testing.expect(got_opt != null);
    var got = got_opt.?;
    defer got.deinit(std.testing.allocator);
    try std.testing.expect(got.ssz != null);
    try std.testing.expect(bc.count() == 1);
}

test "BlockCache: insertBlockPtr+ssz atomic visibility" {
    // Triple-atomic invariant: a reader using cloneBlockAndSsz must
    // observe either both-Some or both-null, never a partial state.
    // With the ssz-arg variant of insertBlockPtr the atomic case is
    // the new path.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var bc = locking.BlockCache.init(std.testing.allocator);
    defer bc.deinit();

    const mock_chain = try stf.genMockChain(allocator, 2, null);
    const root = mock_chain.blockRoots[1];

    // Pre-allocate the heap pointer + ssz buffer the way Network does.
    const block_ptr = try std.testing.allocator.create(types.SignedBlock);
    errdefer std.testing.allocator.destroy(block_ptr);
    try types.sszClone(std.testing.allocator, types.SignedBlock, mock_chain.blocks[1], block_ptr);

    var ssz_buf: std.ArrayList(u8) = .empty;
    defer ssz_buf.deinit(std.testing.allocator);
    try ssz.serialize(types.SignedBlock, mock_chain.blocks[1], &ssz_buf, std.testing.allocator);
    const ssz_bytes = try ssz_buf.toOwnedSlice(std.testing.allocator);

    // Before insert: both-null.
    try std.testing.expect((try bc.cloneBlockAndSsz(root, std.testing.allocator)) == null);

    try bc.insertBlockPtr(root, block_ptr, mock_chain.blocks[1].block.parent_root, ssz_bytes);
    // Cache took the inner SignedBlock value (struct copy). Free the outer
    // heap pointer; the inner allocations and ssz bytes are owned by the
    // cache now.
    std.testing.allocator.destroy(block_ptr);

    // After atomic insert: both-Some.
    const got_opt = try bc.cloneBlockAndSsz(root, std.testing.allocator);
    try std.testing.expect(got_opt != null);
    var got = got_opt.?;
    defer got.deinit(std.testing.allocator);
    try std.testing.expect(got.ssz != null);
    try std.testing.expect(got.ssz.?.len > 0);
}

test "BlockCache: insertBlockPtr null-ssz then attachSsz still observable atomically" {
    // The partial-state window between insertBlockPtr(ssz=null,...) and
    // attachSsz is documented; readers must use cloneBlockAndSsz to
    // safely observe whichever atomic snapshot is current. After both
    // calls, the atomic accessor must report both-Some.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var bc = locking.BlockCache.init(std.testing.allocator);
    defer bc.deinit();

    const mock_chain = try stf.genMockChain(allocator, 2, null);
    const root = mock_chain.blockRoots[1];

    const block_ptr = try std.testing.allocator.create(types.SignedBlock);
    try types.sszClone(std.testing.allocator, types.SignedBlock, mock_chain.blocks[1], block_ptr);

    try bc.insertBlockPtr(root, block_ptr, mock_chain.blocks[1].block.parent_root, null);
    std.testing.allocator.destroy(block_ptr);

    // Block-only window: clone reports block-Some, ssz-null.
    {
        const partial_opt = try bc.cloneBlockAndSsz(root, std.testing.allocator);
        try std.testing.expect(partial_opt != null);
        var partial = partial_opt.?;
        defer partial.deinit(std.testing.allocator);
        try std.testing.expect(partial.ssz == null);
    }

    var ssz_buf: std.ArrayList(u8) = .empty;
    defer ssz_buf.deinit(std.testing.allocator);
    try ssz.serialize(types.SignedBlock, mock_chain.blocks[1], &ssz_buf, std.testing.allocator);
    const ssz_bytes = try ssz_buf.toOwnedSlice(std.testing.allocator);

    try bc.attachSsz(root, ssz_bytes);

    // Now both-Some.
    const full_opt = try bc.cloneBlockAndSsz(root, std.testing.allocator);
    try std.testing.expect(full_opt != null);
    var full = full_opt.?;
    defer full.deinit(std.testing.allocator);
    try std.testing.expect(full.ssz != null);
}

test "BlockCache: removeFetchedBlock atomically clears entry + parent link" {
    // Smoke test for the TOCTOU-free remove path. After the call:
    //   * blocks.get(root) == null
    //   * ssz_bytes.get(root) == null
    //   * the parent's children list does not contain `root`
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var bc = locking.BlockCache.init(std.testing.allocator);
    defer bc.deinit();

    const mock_chain = try stf.genMockChain(allocator, 2, null);
    const root = mock_chain.blockRoots[1];
    const parent_root = mock_chain.blocks[1].block.parent_root;

    const block_ptr = try std.testing.allocator.create(types.SignedBlock);
    try types.sszClone(std.testing.allocator, types.SignedBlock, mock_chain.blocks[1], block_ptr);

    var ssz_buf: std.ArrayList(u8) = .empty;
    defer ssz_buf.deinit(std.testing.allocator);
    try ssz.serialize(types.SignedBlock, mock_chain.blocks[1], &ssz_buf, std.testing.allocator);
    const ssz_bytes = try ssz_buf.toOwnedSlice(std.testing.allocator);

    try bc.insertBlockPtr(root, block_ptr, parent_root, ssz_bytes);
    std.testing.allocator.destroy(block_ptr);

    {
        const present_opt = try bc.cloneBlockAndSsz(root, std.testing.allocator);
        try std.testing.expect(present_opt != null);
        var present = present_opt.?;
        present.deinit(std.testing.allocator);
    }
    try std.testing.expect(bc.hasChildren(parent_root));

    try std.testing.expect(bc.removeFetchedBlock(root));
    try std.testing.expect((try bc.cloneBlockAndSsz(root, std.testing.allocator)) == null);
    try std.testing.expect(!bc.hasChildren(parent_root));

    // Idempotent: second call returns false (no leak / panic).
    try std.testing.expect(!bc.removeFetchedBlock(root));
}

// ---------------------------------------------------------------------
// Concurrent stress tests for slice (a-3): exercise the UAF surface
// directly at the unit level, so future regressions surface here without
// needing the sim package. PR #820 / bug 14.
//
// All three tests use `std.testing.allocator` (thread-safe wrapper over
// GeneralPurposeAllocator) for the BeamChain / cache. mock_chain inputs
// can use an arena because they are read-only across threads.
// ---------------------------------------------------------------------

test "BlockCache: 3-thread stress — insert / read / remove preserves invariants" {
    // Test A: three threads hammer a single BlockCache. One inserts blocks
    // (insertBlockPtr with ssz), one reads via cloneBlockAndSsz, one removes
    // via removeFetchedBlock. The triple-atomic invariant from #803 says a
    // reader must see {block-Some, ssz-Some} or {block-null, ssz-null} —
    // never the partial state. Removing must not double-free.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // One real signed block as the template — we'll synthesize fake
    // distinct roots by mutating only the key, not the SignedBlock value.
    const mock_chain = try stf.genMockChain(arena, 2, null);
    const tmpl = mock_chain.blocks[1];
    const parent_root = tmpl.block.parent_root;

    var bc = locking.BlockCache.init(std.testing.allocator);
    defer bc.deinit();

    // N reduced from 1500 to 200 in PR #820 follow-up: the reader now
    // uses `cloneBlockAndSsz`, which performs a full SSZ round-trip
    // (serialize + deserialize) per successful probe under the cache
    // mutex. That's the production-relevant API and the only safe
    // shape across the unlock — see `OwnedBlockAndSsz` docstring —
    // but it dramatically increases per-probe cost vs the old
    // borrow-shape getter. Lower N keeps wall-time reasonable while
    // still exercising the 3-thread interleaving that's the actual
    // contract under test.
    const N: usize = 200;

    const Worker = struct {
        // Insert N blocks under fake roots key=base..base+N. Each block
        // is a fresh sszClone of the template + a fresh ssz buffer so
        // ownership transfers cleanly to the cache (matches the
        // production insertBlockPtr contract).
        fn insert(cache: *locking.BlockCache, base: u32, count: usize, template: types.SignedBlock, parent: types.Root) void {
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                var root: types.Root = std.mem.zeroes(types.Root);
                std.mem.writeInt(u32, root[0..4], base + i, .little);

                const block_ptr = std.testing.allocator.create(types.SignedBlock) catch continue;
                types.sszClone(std.testing.allocator, types.SignedBlock, template, block_ptr) catch {
                    std.testing.allocator.destroy(block_ptr);
                    continue;
                };

                var ssz_buf: std.ArrayList(u8) = .empty;
                ssz.serialize(types.SignedBlock, template, &ssz_buf, std.testing.allocator) catch {
                    block_ptr.deinit();
                    std.testing.allocator.destroy(block_ptr);
                    ssz_buf.deinit(std.testing.allocator);
                    continue;
                };
                const ssz_bytes = ssz_buf.toOwnedSlice(std.testing.allocator) catch {
                    block_ptr.deinit();
                    std.testing.allocator.destroy(block_ptr);
                    ssz_buf.deinit(std.testing.allocator);
                    continue;
                };

                cache.insertBlockPtr(root, block_ptr, parent, ssz_bytes) catch {
                    // Either AlreadyCached (race with self after remove +
                    // re-insert by another iteration — won't happen with
                    // non-overlapping bases) or OOM. Either way, free and
                    // skip.
                    block_ptr.deinit();
                    std.testing.allocator.destroy(block_ptr);
                    std.testing.allocator.free(ssz_bytes);
                    std.testing.allocator.destroy(block_ptr);
                    continue;
                };
                // After insertBlockPtr success the cache took the inner
                // SignedBlock value (struct copy). Free the outer heap
                // pointer; inner allocations + ssz bytes belong to the
                // cache.
                std.testing.allocator.destroy(block_ptr);
            }
        }

        // Read random roots within [0, total). Asserts the triple-atomic
        // invariant: cloneBlockAndSsz must return either both-Some or null.
        fn read(cache: *locking.BlockCache, total: u32) !void {
            var prng = std.Random.DefaultPrng.init(0xCAFEBABE);
            const rand = prng.random();
            var i: u32 = 0;
            while (i < total * 2) : (i += 1) {
                var root: types.Root = std.mem.zeroes(types.Root);
                std.mem.writeInt(u32, root[0..4], rand.intRangeLessThan(u32, 0, total), .little);
                // OOM under stress — skip this probe, keep going.
                const cloned_opt = cache.cloneBlockAndSsz(root, std.testing.allocator) catch continue;
                if (cloned_opt) |cloned_const| {
                    var entry = cloned_const;
                    defer entry.deinit(std.testing.allocator);
                    // Triple-atomic invariant: when block is observable
                    // ssz must also be observable (after the atomic
                    // insertBlockPtr path).
                    try std.testing.expect(entry.ssz != null);
                    try std.testing.expect(entry.ssz.?.len > 0);
                }
            }
        }

        // Remove every root in the inserter's range. Some may not be
        // present yet (insert thread hasn't reached them); those return
        // false. Idempotent — calling remove twice on the same root
        // returns false the second time without UAF.
        fn remove(cache: *locking.BlockCache, base: u32, count: usize) void {
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                var root: types.Root = std.mem.zeroes(types.Root);
                std.mem.writeInt(u32, root[0..4], base + i, .little);
                _ = cache.removeFetchedBlock(root);
            }
        }
    };

    var t_ins = try std.Thread.spawn(.{}, Worker.insert, .{ &bc, 0, N, tmpl, parent_root });
    var t_read = try std.Thread.spawn(.{}, Worker.read, .{ &bc, @as(u32, @intCast(N)) });
    var t_rem = try std.Thread.spawn(.{}, Worker.remove, .{ &bc, 0, N });

    t_ins.join();
    t_read.join();
    t_rem.join();

    // Final cleanup pass: any remaining entries get removed under the
    // single-threaded invariant. After this, the cache must be empty —
    // no orphan parent-link entries.
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        var root: types.Root = std.mem.zeroes(types.Root);
        std.mem.writeInt(u32, root[0..4], i, .little);
        _ = bc.removeFetchedBlock(root);
    }

    try std.testing.expect(bc.count() == 0);
    // Parent links list must also be cleared — removeFetchedBlock keeps
    // the parent-children map consistent.
    try std.testing.expect(!bc.hasChildren(parent_root));
}

test "BorrowedState: cloneAndRelease vs concurrent statesFetchRemoveExclusivePtr" {
    // Test B: thread A grabs a BorrowedState via statesGet and calls
    // cloneAndRelease; thread B spins doing
    // statesFetchRemoveExclusivePtr + free against an UNRELATED set of
    // roots (so they never alias the in-flight clone). The contract:
    // thread A's clone must always observe coherent state (slot matches
    // expected), and thread B's frees must never UAF the in-flight clone
    // (which is guaranteed because cloneAndRelease either copies under
    // shared lock or upgrades safely; thread B holds the exclusive lock
    // while freeing).
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 2, null);
    // spec_name / fork_digest are owned by std.testing.allocator since
    // BeamChain.deinit calls config.deinit(self.allocator) which frees
    // them via the same allocator BeamChain.init was called with.
    const spec_name = try std.testing.allocator.dupe(u8, "beamdev");
    const fork_digest = try std.testing.allocator.dupe(u8, "12345678");
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

    var beam_state = mock_chain.genesis_state;
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});

    var db = try database.Db.open(std.testing.allocator, zeam_logger_config.logger(.database_test), data_dir);
    defer db.deinit();

    const connected_peers = try std.testing.allocator.create(ConnectedPeers);
    defer std.testing.allocator.destroy(connected_peers);
    connected_peers.* = ConnectedPeers.init(std.testing.allocator);
    defer connected_peers.deinit();

    const test_registry = try std.testing.allocator.create(NodeNameRegistry);
    defer std.testing.allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(std.testing.allocator);
    defer test_registry.deinit();

    var beam_chain = try BeamChain.init(std.testing.allocator, ChainOpts{
        .config = chain_config,
        .anchorState = &beam_state,
        .nodeId = 11,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    // The genesis state is already in beam_chain.states under the genesis
    // root. We'll use the genesis root for thread A (the long-lived
    // borrow), and a set of synthetic roots populated with cloned states
    // for thread B to remove.
    const target_root = mock_chain.blockRoots[0];
    const expected_slot = mock_chain.genesis_state.slot;

    // Populate the chain's states map with N "unrelated" entries that
    // thread B will fetch-remove + free.
    const N: usize = 64;
    const unrelated_roots = try std.testing.allocator.alloc(types.Root, N);
    defer std.testing.allocator.free(unrelated_roots);
    for (0..N) |k| {
        var r = std.mem.zeroes(types.Root);
        std.mem.writeInt(u64, r[0..8], @as(u64, @intCast(k + 1)), .little);
        // The 0-keyed root would alias genesis (zeroes); we offset by +1.
        unrelated_roots[k] = r;

        const cloned_state = try std.testing.allocator.create(types.BeamState);
        try types.sszClone(std.testing.allocator, types.BeamState, mock_chain.genesis_state, cloned_state);
        // Insert directly under exclusive lock (test-internal access).
        beam_chain.states_lock.lock();
        try beam_chain.states.put(r, cloned_state);
        beam_chain.states_lock.unlock();
    }

    const TestCtx = struct {
        chain: *BeamChain,
        target: types.Root,
        unrelated: []types.Root,
        expected_slot: types.Slot,
        iters: usize,
        a_done: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        b_done: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        a_failures: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        start_barrier: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

        fn waitForStart(self: *@This()) void {
            while (self.start_barrier.load(.acquire) == 0) {
                std.Thread.yield() catch {};
            }
        }
    };
    const Worker = struct {
        // A: clone-and-release the target state in a tight loop.
        fn cloner(ctx: *TestCtx) void {
            ctx.waitForStart();
            var i: usize = 0;
            while (i < ctx.iters) : (i += 1) {
                var borrow = ctx.chain.statesGet(ctx.target) orelse {
                    _ = ctx.a_failures.fetchAdd(1, .monotonic);
                    continue;
                };
                const owned = borrow.cloneAndRelease(std.testing.allocator) catch {
                    _ = ctx.a_failures.fetchAdd(1, .monotonic);
                    continue;
                };
                if (owned.slot != ctx.expected_slot) {
                    _ = ctx.a_failures.fetchAdd(1, .monotonic);
                }
                owned.deinit();
                std.testing.allocator.destroy(owned);
                _ = ctx.a_done.fetchAdd(1, .monotonic);
            }
        }
        // B: drain unrelated entries via the exclusive fetch-remove path
        // that mirrors pruneStates' free pattern.
        fn pruner(ctx: *TestCtx) void {
            ctx.waitForStart();
            for (ctx.unrelated) |r| {
                if (ctx.chain.statesFetchRemoveExclusivePtr("test.pruner", r)) |state_ptr| {
                    state_ptr.deinit();
                    std.testing.allocator.destroy(state_ptr);
                    _ = ctx.b_done.fetchAdd(1, .monotonic);
                }
            }
        }
    };

    var ctx = TestCtx{
        .chain = &beam_chain,
        .target = target_root,
        .unrelated = unrelated_roots,
        .expected_slot = expected_slot,
        .iters = 1000,
    };

    var t_a = try std.Thread.spawn(.{}, Worker.cloner, .{&ctx});
    var t_b = try std.Thread.spawn(.{}, Worker.pruner, .{&ctx});
    // Release both threads simultaneously.
    ctx.start_barrier.store(1, .release);

    t_a.join();
    t_b.join();

    // No A failure means every clone observed a coherent state with the
    // expected slot. (A failure here would imply the in-flight state was
    // freed under us — i.e. UAF.)
    try std.testing.expectEqual(@as(usize, 0), ctx.a_failures.load(.monotonic));
    try std.testing.expect(ctx.a_done.load(.monotonic) == ctx.iters);
    try std.testing.expect(ctx.b_done.load(.monotonic) == N);
    // Genesis must still be in the map — thread B never touched it.
    beam_chain.states_lock.lockShared();
    const still_present = beam_chain.states.get(target_root) != null;
    beam_chain.states_lock.unlockShared();
    try std.testing.expect(still_present);
}

test "chain.onBlock: two-thread concurrent import of same block — no UAF, coherent state" {
    // Test C: the unit-level chain.onBlock concurrency surface.
    //
    // Two threads call onBlock(blocks[1]) on the same BeamChain at the
    // same time. Only one wins the forkChoice insert; the other observes
    // the existing fc block and skips that step but still does STF +
    // statesCommitKeepExisting. The kept_existing path is exactly what
    // the slice (a-2) `cloneAndRelease` + slice (a-3) holds-exclusive-
    // until-deref fix is protecting.
    //
    // Per-iteration cost is dominated by two parallel STF runs +
    // signature verification; iter=30 keeps end-to-end runtime under a
    // few seconds in Debug. Less than the 100 originally targeted —
    // documented here so future tightenings know what to bump.
    //
    // Use a shared start_barrier to make sure both threads enter
    // onBlock around the same moment; otherwise one trivially completes
    // first and the test serialises (proving nothing about racing
    // mutators).
    //
    // SLOW: 30 iters; if a future XMSS-bypass shows up, raise to 100.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 2, null);
    // spec_name / fork_digest must be std.testing.allocator-owned because
    // BeamChain.deinit frees them via self.allocator (= std.testing.allocator
    // here). We share one allocation across all iterations and free in the
    // outer defer below; each iteration's BeamChain receives the SAME slice
    // pointer, but since chains are deinit'd one at a time and the slice is
    // re-dupe'd per iteration, ownership stays clean.
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    const ITERS: usize = 30;

    var iter: usize = 0;
    while (iter < ITERS) : (iter += 1) {
        // Each iteration uses a fresh BeamChain so independent
        // interleavings exercise the lock interactions from a clean
        // initial state. Re-dupe spec_name + fork_digest each iteration
        // because BeamChain.deinit frees them via self.allocator.
        const spec_name = try std.testing.allocator.dupe(u8, "beamdev");
        const fork_digest = try std.testing.allocator.dupe(u8, "12345678");
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
        try types.sszClone(std.testing.allocator, types.BeamState, mock_chain.genesis_state, &beam_state);
        defer beam_state.deinit();

        var tmp_dir = std.testing.tmpDir(.{});
        defer tmp_dir.cleanup();
        var path_buf: [128]u8 = undefined;
        const data_dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});

        var db = try database.Db.open(std.testing.allocator, zeam_logger_config.logger(.database_test), data_dir);
        defer db.deinit();

        const connected_peers = try std.testing.allocator.create(ConnectedPeers);
        defer std.testing.allocator.destroy(connected_peers);
        connected_peers.* = ConnectedPeers.init(std.testing.allocator);
        defer connected_peers.deinit();

        const test_registry = try std.testing.allocator.create(NodeNameRegistry);
        defer std.testing.allocator.destroy(test_registry);
        test_registry.* = NodeNameRegistry.init(std.testing.allocator);
        defer test_registry.deinit();

        var beam_chain = try BeamChain.init(std.testing.allocator, ChainOpts{
            .config = chain_config,
            .anchorState = &beam_state,
            .nodeId = 12,
            .logger_config = &zeam_logger_config,
            .db = db,
            .node_registry = test_registry,
        }, connected_peers);
        defer beam_chain.deinit();

        const signed_block = mock_chain.blocks[1];
        const block_root = mock_chain.blockRoots[1];

        // Advance forkchoice clock to the slot of the block under test
        // so onBlock isn't rejected with FutureSlot.
        try beam_chain.forkChoice.onInterval(signed_block.block.slot * constants.INTERVALS_PER_SLOT, false);

        const Ctx = struct {
            chain: *BeamChain,
            block: types.SignedBlock,
            errors: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            already_known: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            success: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            start_barrier: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
            ready_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        };
        const Worker = struct {
            fn run(ctx: *Ctx) void {
                _ = ctx.ready_count.fetchAdd(1, .acq_rel);
                while (ctx.start_barrier.load(.acquire) == 0) {
                    std.Thread.yield() catch {};
                }
                const missing = ctx.chain.onBlock(ctx.block, .{ .pruneForkchoice = false }) catch {
                    _ = ctx.errors.fetchAdd(1, .monotonic);
                    return;
                };
                ctx.chain.allocator.free(missing);
                _ = ctx.success.fetchAdd(1, .monotonic);
            }
        };

        var ctx = Ctx{ .chain = &beam_chain, .block = signed_block };
        var t1 = try std.Thread.spawn(.{}, Worker.run, .{&ctx});
        var t2 = try std.Thread.spawn(.{}, Worker.run, .{&ctx});

        // Spin until both threads are at the barrier, then release.
        while (ctx.ready_count.load(.acquire) < 2) {
            std.Thread.yield() catch {};
        }
        ctx.start_barrier.store(1, .release);

        t1.join();
        t2.join();

        // Both threads must complete without crashing. At least one
        // must have committed the block (success>=1). The other might
        // also succeed (kept_existing path) or have caught an expected
        // error like BlockAlreadyKnown — but it must not have panicked
        // / segfaulted, which the test would observe by failing to
        // reach this assertion.
        try std.testing.expect(ctx.success.load(.monotonic) >= 1);

        // After commit, the post-state for block_root must be in the
        // states map and forkchoice head must point to either the
        // imported block root or the genesis root (in the rare case
        // both threads' onBlock paths failed before the kept_existing
        // commit landed; that should not happen in practice).
        beam_chain.states_lock.lockShared();
        const post_present = beam_chain.states.get(block_root) != null;
        beam_chain.states_lock.unlockShared();
        try std.testing.expect(post_present);

        // forkChoice.head should be one of {block_root, genesis_root}
        // (we don't drive updateHead in this test so head is whatever
        // was set during onBlock + onAttestations side effects).
        // We just assert the imported block is known to forkchoice.
        try std.testing.expect(beam_chain.forkChoice.hasBlock(block_root));
    }
}
