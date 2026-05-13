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
const rc_beam_state = @import("./rc_beam_state.zig");
const RcBeamState = rc_beam_state.RcBeamState;
const chain_worker = @import("./chain_worker.zig");

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

/// Future-block queue entry. Used by both #788 (clock-lag
/// future-block buffering) and slice (e) of #803 (centralised
/// hash-root cache). Stores the producer's already-computed
/// hash-tree root alongside the block so the gossip-path dedup
/// loop, the `enqueuePendingBlock` cap-eviction sweep, and the
/// drain (`processPendingBlocks`) all compare 32 bytes instead of
/// re-hashing the full block body.
///
/// PR #841 review: `hashTreeRoot(BeamBlock, ...)` is a full SSZ
/// tree walk — doing it 1024 times per duplicate-check is
/// observable under a sustained clock-lag flood, which is the exact
/// scenario the future-block queue exists to handle. Storing the
/// 32-byte root here drops dedup from O(N·hash) to O(N·memcmp).
///
/// Mirrors leanSpec's `PendingBlock` shape
/// (subspecs/sync/block_cache.py:55) for the load-bearing `root`
/// field. Other PendingBlock fields (`received_from`, `received_at`,
/// `backfill_depth`) are deliberately omitted in this PR — they hook
/// into peer scoring + staleness detection that don't have consumers
/// in zeam yet. Tracked as follow-up cleanup in #788's PR thread.
///
/// Heap-owning data is the `signed_block` SSZ slices; the entry must
/// be `signed_block.deinit()`d when removed.
pub const PendingBlockEntry = struct {
    signed_block: types.SignedBlock,
    block_root: types.Root,
};

pub const BeamChain = struct {
    config: configs.ChainConfig,
    anchor_state: *types.BeamState,

    forkChoice: fcFactory.ForkChoice,
    allocator: Allocator,
    // from finalized onwards to recent
    /// Cached post-states keyed by block root. Migrated to
    /// `*RcBeamState` in slice c-2b (#803): refcounted state
    /// pointers let the chain worker (sole writer under c-2b) and
    /// cross-thread readers (HTTP API, metrics, broadcaster)
    /// share state without copying. Until commit 4 of this PR
    /// drops the rwlock, `states_lock` continues to gate
    /// concurrent map mutation — the rc handles only address
    /// state-pointer lifetime, not map-shape mutation.
    states: std.AutoHashMap(types.Root, *RcBeamState),
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
    /// Counter incremented every time `statesCommitKeepExisting` lands
    /// on the duplicate / kept-existing branch (i.e. the entry was
    /// already in `states` when the second writer arrived). Used by the
    /// concurrent re-import test to assert that the race surface was
    /// actually exercised — without this, a test that imports the same
    /// blocks twice would silently pass even if one importer was
    /// completely starved.
    ///
    /// Lock-free monotonic counter; safe to read from any thread.
    states_kept_existing_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    // Cached finalized state loaded from database (separate from states
    // map to avoid affecting pruning).
    //
    // Slice c-2b commit 4 of #803: migrated from raw `*types.BeamState`
    // to `*RcBeamState` (Option B from the PR #828 review thread) so the
    // cache-hit path in `getFinalizedState` can use the same
    // tryAcquire-then-drop-lock dance as `statesGet` when chain-worker
    // is enabled. Mutation is still gated by `events_lock`.
    cached_finalized_state: ?*RcBeamState = null,
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
    //
    // Each entry carries the producer's already-computed hash-tree root
    // alongside the block so dedup checks compare 32 bytes instead of
    // re-hashing the full block body. See `PendingBlockEntry` doc above for
    // the per-field rationale. Re-finalized eviction (when finalization
    // advances past a queued slot) happens both on enqueue (gossip path) and
    // during `processPendingBlocks` (drain path) so the queue self-cleans.
    pending_blocks: std.ArrayList(PendingBlockEntry),

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

    /// Optional chain-worker thread (slice c-2b commit 3 of #803).
    /// When non-null, `BeamChain` exposes the `submit*` family of
    /// methods which enqueue work onto the worker's queues; the
    /// worker thread serialises the actual chain mutations.
    /// When null, callers fall through to the synchronous path
    /// (current behavior). Surface flipped by
    /// `ChainOpts.chain_worker_enabled`; CLI flag
    /// `--chain-worker=on|off`.
    ///
    /// Lifecycle: allocated + started in `init` when
    /// `chain_worker_enabled` is true; stopped + freed in `deinit`.
    /// The worker borrows `*BeamChain` as its handler ctx, so the
    /// chain MUST outlive the worker — hence the strict
    /// stop/deinit/destroy ordering at the top of `BeamChain.deinit`.
    chain_worker: ?*chain_worker.ChainWorker = null,

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

        var states = std.AutoHashMap(types.Root, *RcBeamState).init(allocator);
        // Build the anchor state on the stack via sszClone, then
        // hand it to RcBeamState.create which embeds it into the
        // heap allocation (and consumes it on either success or
        // OOM — always-consume contract per c-2a).
        var cloned_anchor_state: types.BeamState = undefined;
        try types.sszClone(
            allocator,
            types.BeamState,
            opts.anchorState.*,
            &cloned_anchor_state,
        );
        // Past this line, `cloned_anchor_state` owns interior
        // allocations. RcBeamState.create takes ownership; on OOM
        // it will deinit them for us.
        const anchor_rc = try RcBeamState.create(allocator, cloned_anchor_state);
        errdefer anchor_rc.release();
        try states.put(fork_choice.head.blockRoot, anchor_rc);

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
            .thread_pool = opts.thread_pool,
            // pending_blocks is the future-slot queue (issue #788). It's an
            // unmanaged ArrayList, so default-init to `.empty`; the lock
            // below guards mutation. Required field — without it the
            // struct literal fails to compile under the merged main
            // pending-blocks plumbing.
            .pending_blocks = .empty,
            // Per-resource locks default-initialised. RwLock and Mutex have
            // no special init; init() runs single-threaded so no acquire
            // here.
            .states_lock = .{},
            .pending_blocks_lock = .{},
            .pubkey_cache_lock = .{},
            .root_to_slot_lock = .{},
            .events_lock = .{},
            // chain_worker is started below (after the chain value is
            // at its final heap location), so the worker's ctx pointer
            // remains stable for its entire lifetime.
            .chain_worker = null,
        };
        // Initialize cache with anchor block root and any post-finalized entries from state
        try chain.root_to_slot_cache.put(fork_choice.head.blockRoot, opts.anchorState.slot);
        try chain.anchor_state.initRootToSlotCache(&chain.root_to_slot_cache);

        // Check whether the anchor block is already in the DB.
        // NodeRunner.downloadAndStoreCheckpointBlock fetches the real block from the
        // checkpoint provider before BeamChain.init is called, so the common path here
        // is the non-null branch (block already present).
        //
        // Memory note: loadBlock returns an owned SignedBlock by value.  The non-null
        // branch must call deinit to release the heap-allocated attestation lists;
        // previously this branch dropped the value silently, leaking on every warm-start.
        if (chain.db.loadBlock(database.DbBlocksNamespace, fork_choice.head.blockRoot)) |loaded| {
            var owned = loaded;
            owned.deinit();
        } else {
            // Anchor block not in DB.  NodeRunner tries to fetch it from the checkpoint
            // provider during startup; if that fetch failed (provider doesn't expose
            // /lean/v0/blocks/finalized, or timed out) we log and continue.
            // blocks_by_root returns empty for this root until the real block arrives
            // via reqresp or gossip from a peer.
            logger_config.logger(.chain).warn(
                "anchor block root=0x{x} slot={d} not in DB — blocks_by_root will return empty for this root until real block is received",
                .{ &fork_choice.head.blockRoot, opts.anchorState.slot },
            );
        }

        return chain;
    }

    /// Allocate, initialise, and start a `chain_worker.ChainWorker`
    /// against this chain. Called from `BeamNode.init` after the
    /// chain is at its final heap address — the worker stores `self`
    /// as its handler ctx, so the chain pointer must NOT move
    /// afterwards.
    ///
    /// On error the partially-allocated worker is freed before
    /// returning so the caller can treat init as all-or-nothing.
    /// On success the worker thread is running and ready to drain;
    /// calling code can now invoke `submit*` to route producer-side
    /// work through the queue.
    pub fn startChainWorker(self: *Self) !void {
        std.debug.assert(self.chain_worker == null);
        const w = try self.allocator.create(chain_worker.ChainWorker);
        errdefer self.allocator.destroy(w);
        w.* = try chain_worker.ChainWorker.init(self.allocator, .{
            .logger = self.zeam_logger_config.logger(.chain),
            .handlers = .{
                .ctx = self,
                .on_block = chainWorkerOnBlockThunk,
                .on_gossip_attestation = chainWorkerOnGossipAttestationThunk,
                .on_gossip_aggregated_attestation = chainWorkerOnGossipAggregatedAttestationThunk,
                .process_pending_blocks = chainWorkerProcessPendingBlocksThunk,
                .process_finalization_followup = chainWorkerProcessFinalizationFollowupThunk,
            },
        });
        errdefer w.deinit();
        try w.start();
        self.chain_worker = w;
        self.logger.info("chain-worker: started (block_q={d}, att_q={d})", .{
            chain_worker.DEFAULT_BLOCK_QUEUE_CAPACITY,
            chain_worker.DEFAULT_ATTESTATION_QUEUE_CAPACITY,
        });
    }

    // ------------------------------------------------------------------
    // chain_worker handler thunks (slice c-2b commit 3)
    // ------------------------------------------------------------------
    //
    // These thunks adapt the worker's type-erased vtable shape
    // (`*anyopaque` ctx + value-typed payloads) to the real
    // `BeamChain` methods. Each one:
    //
    //   1. Casts ctx back to `*BeamChain` (debug-build alignment
    //      asserts via `@alignCast`).
    //   2. Calls the synchronous chain method.
    //   3. Catches and logs any error — the producer side already
    //      fired-and-forgot, so there is no upstream error channel.
    //   4. Frees any heap returned by the method (e.g. the
    //      `missing_roots` slice from `onBlock` /
    //      `processPendingBlocks`). In the chain-worker path, the
    //      missing-attestation-roots feedback loop into the gossip
    //      layer's RPC fetch is intentionally dropped — a follow-up
    //      commit can plumb a back-channel if it proves necessary
    //      on devnet, but for c-2b's narrow gossip-block-and-
    //      attestation migration the loss is the same as a dropped
    //      gossip message.
    //
    // The thunks live in `chain.zig` (not `chain_worker.zig`)
    // because they need access to `BeamChain` and its private
    // method `processFinalizationAdvancement`. Putting them here
    // also keeps `chain_worker.zig` free of any `chain.zig`
    // import — the layering this whole vtable design exists to
    // preserve.

    fn chainWorkerOnBlockThunk(
        ctx: *anyopaque,
        signed_block: types.SignedBlock,
        prune_forkchoice: bool,
        block_root: ?types.Root,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        // Slice (e) of #803: forward the producer's already-computed
        // block_root (when present) into `onBlock` via
        // `CachedProcessedBlockInfo.blockRoot`. Saves the worker thread
        // a redundant `hashTreeRoot(BeamBlock)` call — a non-trivial
        // SSZ traversal on a wide block body. `null` falls back to the
        // pre-existing in-`onBlock` recompute path; this keeps callers
        // that legitimately have no precomputed root (the c-1 stub /
        // any future producer) working unchanged.
        const missing_roots = self.onBlock(signed_block, .{
            .pruneForkchoice = prune_forkchoice,
            .blockRoot = block_root,
        }) catch |err| {
            self.logger.err("chain-worker: onBlock failed slot={d}: {any}", .{
                signed_block.block.slot,
                err,
            });
            return;
        };
        defer self.allocator.free(missing_roots);
        // Mirror the gossip path: followup runs after a successful
        // import. We pass the (immutable) signed_block by reference
        // for symmetry with chain.onGossip; current onBlockFollowup
        // ignores the parameter (see the explicit `_ = signedBlock`
        // at its top), so the value is functionally unused here.
        self.onBlockFollowup(prune_forkchoice, &signed_block);
    }

    fn chainWorkerOnGossipAttestationThunk(
        ctx: *anyopaque,
        gossip: networks.AttestationGossip,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.onGossipAttestation(gossip) catch |err| {
            self.logger.warn(
                "chain-worker: onGossipAttestation failed slot={d} validator={d}: {any}",
                .{ gossip.message.message.slot, gossip.message.validator_id, err },
            );
        };
    }

    fn chainWorkerOnGossipAggregatedAttestationThunk(
        ctx: *anyopaque,
        agg: types.SignedAggregatedAttestation,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.onGossipAggregatedAttestation(agg) catch |err| {
            self.logger.warn(
                "chain-worker: onGossipAggregatedAttestation failed slot={d}: {any}",
                .{ agg.data.slot, err },
            );
        };
    }

    fn chainWorkerProcessPendingBlocksThunk(
        ctx: *anyopaque,
        current_slot: types.Slot,
    ) void {
        // current_slot is unused by the current `processPendingBlocks`
        // implementation (it consults `forkChoice.fcStore.slot_clock`
        // directly), but kept on the message so a future refactor
        // that wants the producer's view of the slot doesn't need
        // a Message-shape change.
        _ = current_slot;
        const self: *Self = @ptrCast(@alignCast(ctx));
        const missing_roots = self.processPendingBlocks();
        self.allocator.free(missing_roots);
    }

    fn chainWorkerProcessFinalizationFollowupThunk(
        ctx: *anyopaque,
        previous_finalized: types.Checkpoint,
        latest_finalized: types.Checkpoint,
        prune_forkchoice: bool,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.processFinalizationAdvancement(
            previous_finalized,
            latest_finalized,
            prune_forkchoice,
        ) catch |err| {
            self.logger.err(
                "chain-worker: processFinalizationAdvancement failed prev={d} latest={d}: {any}",
                .{ previous_finalized.slot, latest_finalized.slot, err },
            );
        };
    }

    // ------------------------------------------------------------------
    // submit* family (slice c-2b commit 3)
    // ------------------------------------------------------------------
    //
    // These wrappers route producer-side work through the
    // chain_worker queues. They are ALWAYS available (the chain
    // exposes them regardless of whether the worker is running);
    // when the worker is disabled they return
    // `error.ChainWorkerDisabled` so the caller can fall back to
    // the direct synchronous path. This keeps the off-mode
    // semantics identical to slice (b) — the call site decides
    // which path to take, the submit* wrappers never silently
    // change behaviour.
    //
    // Ownership contract on success: the caller transfers ownership
    // of any heap-bearing payload (currently `signed_block` and
    // `signed_aggregation`) to the worker. The worker calls
    // `Message.deinit` after dispatch. On `error.QueueFull`,
    // `error.QueueClosed`, or `error.ChainWorkerDisabled` the
    // caller retains ownership and is responsible for cleanup
    // (including calling `.deinit()` on the payload).

    pub const SubmitError = chain_worker.BlockQueue.TrySendError || error{ChainWorkerDisabled};

    /// Route a block import through the chain-worker queue.
    ///
    /// Slice (e) of #803: `block_root` is the producer's already-
    /// computed hash-tree root of `signed_block.block`. Pass `null`
    /// only when the producer truly does not have one (and the
    /// worker will recompute it inside `onBlock`). All current
    /// production producers DO have a precomputed root — see
    /// `BeamNode.onGossip`, `processBlockByRoot|RangeChunk`,
    /// `publishBlock`, and `chain.onGossip` itself — so the
    /// `null` path is a fallback for tests / future variants.
    pub fn submitBlock(
        self: *Self,
        signed_block: types.SignedBlock,
        prune_forkchoice: bool,
        block_root: ?types.Root,
    ) SubmitError!void {
        const w = self.chain_worker orelse return error.ChainWorkerDisabled;
        try w.sendBlock(.{ .on_block = .{
            .signed_block = signed_block,
            .prune_forkchoice = prune_forkchoice,
            .block_root = block_root,
        } });
    }

    /// Route a gossip-attestation through the chain-worker queue.
    pub fn submitGossipAttestation(
        self: *Self,
        gossip: networks.AttestationGossip,
    ) SubmitError!void {
        const w = self.chain_worker orelse return error.ChainWorkerDisabled;
        try w.sendAttestation(.{ .on_gossip_attestation = gossip });
    }

    /// Route a gossip aggregated-attestation through the worker's
    /// aggregated-attestation queue so backlog/drop metrics stay labelable.
    pub fn submitGossipAggregatedAttestation(
        self: *Self,
        agg: types.SignedAggregatedAttestation,
    ) SubmitError!void {
        const w = self.chain_worker orelse return error.ChainWorkerDisabled;
        try w.sendAggregatedAttestation(.{ .on_gossip_aggregated_attestation = agg });
    }

    /// Route a `processPendingBlocks` tick through the worker queue.
    /// (Not migrated by any caller in commit 3 — included so the
    /// vtable + queue plumbing is exercised end-to-end and the API
    /// shape is stable for the follow-up commit that migrates the
    /// libxev tick path.)
    pub fn submitProcessPendingBlocks(self: *Self, current_slot: types.Slot) SubmitError!void {
        const w = self.chain_worker orelse return error.ChainWorkerDisabled;
        try w.sendBlock(.{ .process_pending_blocks = .{ .current_slot = current_slot } });
    }

    /// Route a `processFinalizationFollowup` move-off through the worker queue.
    /// (Not migrated by any caller in commit 3; see
    /// `submitProcessPendingBlocks` for the rationale.)
    pub fn submitProcessFinalizationFollowup(
        self: *Self,
        previous_finalized: types.Checkpoint,
        latest_finalized: types.Checkpoint,
        prune_forkchoice: bool,
    ) SubmitError!void {
        const w = self.chain_worker orelse return error.ChainWorkerDisabled;
        try w.sendBlock(.{ .process_finalization_followup = .{
            .previous_finalized = previous_finalized,
            .latest_finalized = latest_finalized,
            .prune_forkchoice = prune_forkchoice,
        } });
    }

    pub fn setPruneCachedBlocksCallback(self: *Self, ctx: *anyopaque, func: PruneCachedBlocksFn) void {
        self.prune_cached_blocks_ctx = ctx;
        self.prune_cached_blocks_fn = func;
    }

    pub fn deinit(self: *Self) void {
        // Clear the refcount-distribution scrape refresher BEFORE any
        // chain state is torn down so the metrics endpoint cannot call
        // back into freed memory between deinit phases. (Idempotent:
        // safe to call even if startChainStateRefcountObserver was
        // never called.)
        self.stopChainStateRefcountObserver();

        // Stop and free the chain-worker FIRST (before any chain
        // state the worker's handler thunks may touch is freed).
        // `stop()` is idempotent and joins the worker thread; after
        // it returns no handler can re-enter `self`. Only then is
        // it safe to tear down `forkChoice`, `states`, etc.
        if (self.chain_worker) |w| {
            w.stop();
            w.deinit();
            self.allocator.destroy(w);
            self.chain_worker = null;
        }

        // Clean up forkchoice resources (attestation_signatures, aggregated_payloads)
        self.forkChoice.deinit();

        // Each entry holds an RcBeamState we own a reference on.
        // release() drops the count and frees the wrapper +
        // interior state when refcount reaches 0. Under c-2b
        // commit 2 nothing else takes acquires on map-resident
        // states yet, so refcount is always 1 at deinit time.
        var it = self.states.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.release();
        }
        self.states.deinit();

        // Clean up cached finalized state if present.
        // Slice c-2b commit 4: cached_finalized_state is an
        // RcBeamState now — release drives state.deinit + destroy when
        // refcount reaches 0. Under chain_worker_enabled the cache may
        // have outstanding reader acquires; the rc keeps the underlying
        // allocation alive until the last reader releases. (At deinit
        // time we are single-threaded by contract, so refcount=1 in
        // practice.)
        if (self.cached_finalized_state) |cached_rc| {
            cached_rc.release();
        }

        // Clean up public key cache
        self.public_key_cache.deinit();

        // Clean up root to slot cache
        self.root_to_slot_cache.deinit();
        // Clean up any blocks that were queued waiting for the forkchoice clock
        // (each entry wraps the SignedBlock + its precomputed root).
        for (self.pending_blocks.items) |*entry| {
            entry.signed_block.deinit();
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

    /// Return a `BorrowedState` for the requested root, or null if the
    /// state is not in the in-memory map. Caller MUST call either
    /// `borrow.deinit()` or `borrow.cloneAndRelease(allocator)` exactly
    /// once before the borrow goes out of scope. Debug builds enforce
    /// one-release via `BorrowedState.released`.
    ///
    /// Two paths, gated by chain-worker mode (slice c-2b commit 4 of #803):
    ///
    ///   * `chain_worker != null` (chain-worker is the sole writer to
    ///     `BeamChain.states`): take the shared lock for the lookup,
    ///     `tryAcquire` the rc, drop the lock, and return a
    ///     `Backing.none` borrow whose lifetime is gated by the rc
    ///     refcount. Cross-thread readers (HTTP API, metrics scrape,
    ///     event broadcaster) NO LONGER hold `states_lock.shared` for
    ///     the borrow lifetime, so a long-lived read does not block the
    ///     chain worker's next exclusive-side mutation. This is the
    ///     entire point of the c-2b migration.
    ///
    ///   * `chain_worker == null` (kill-switch / backward-compat under
    ///     `--chain-worker=off`): keep the legacy lock-based borrow.
    ///     The shared lock is held for the borrow lifetime; map mutation
    ///     by the gossip/req-resp paths is gated by the exclusive side
    ///     as before. Slice (b) semantics are preserved exactly.
    pub fn statesGet(self: *Self, root: types.Root) ?BorrowedState {
        var t = LockTimer.start("states", "statesGet");
        self.states_lock.lockShared();
        t.acquired();
        if (self.states.get(root)) |rc| {
            if (self.chain_worker != null) {
                // Lock-free read path: tryAcquire under the shared
                // lock to defeat any concurrent free race, then drop
                // the lock so the borrow lifetime no longer pins
                // `states_lock`. The LockTimer ends HERE because the
                // hold span is over; we do not hand it off to the
                // borrow.
                const acq = rc.tryAcquire();
                self.states_lock.unlockShared();
                t.released();
                if (acq) |acquired_rc| {
                    return BorrowedState{
                        .state = &acquired_rc.state,
                        .backing = .none,
                        .acquired_rc = acquired_rc,
                    };
                }
                // tryAcquire returned null: rc is in the freeing
                // process (refcount→0 elsewhere). Today this should
                // never happen because the only acquires today come
                // from the worker thread itself, but the safe-by-
                // default behavior is to report the entry as missing
                // rather than dereference a dying allocation. The
                // c-2b removal protocol ("remove-from-map then
                // release") is what makes this branch theoretically
                // reachable in the future without a UAF.
                return null;
            }
            // Legacy lock-based path: hand the shared lock off to the
            // borrow.  Backward-compat with --chain-worker=off; PR
            // #820 / #803 kill-switch.
            return BorrowedState{
                .state = &rc.state,
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

    /// Move the value out of a heap-allocated `*BeamState` wrapper
    /// into a freshly-`create`d `RcBeamState`, freeing the now-empty
    /// wrapper. Centralises the value-copy + destroy + create dance
    /// shared by `produceBlock` and `onBlock`'s owned-post_state path.
    ///
    /// Ownership story (single, identical at every call site):
    ///
    ///   * Pre-call: caller owns `post_state` (a `*BeamState`
    ///     pointing at heap memory). The interior of the BeamState
    ///     value (lists, slices, etc.) is also caller-owned. Caller
    ///     has an upstream errdefer gated by `gate_consumed.* == false`
    ///     that frees both the wrapper and the interior on early
    ///     return.
    ///
    ///   * Post-call (success): the BeamState value has been moved
    ///     into the rc; the wrapper has been freed. `gate_consumed`
    ///     has been set to `true` so the caller's upstream errdefer
    ///     does not fire. The caller now owns the returned
    ///     `*RcBeamState` and must transfer it (e.g. via
    ///     `statesPutExclusive` / `statesCommitKeepExisting`) or
    ///     release it.
    ///
    ///   * Post-call (error): the wrapper has been freed (we
    ///     destroyed it BEFORE the create attempt so an OOM cannot
    ///     leave a wrapper-allocator leak); the BeamState value's
    ///     interior has been consumed by `RcBeamState.create`'s
    ///     always-consume contract. `gate_consumed` has still been
    ///     set to `true` (BEFORE the create call) so the caller's
    ///     upstream errdefer does NOT run — it would deref the
    ///     freed wrapper. Net: nothing leaks, the caller's gate
    ///     correctly suppresses the upstream cleanup, and the
    ///     caller propagates the error.
    ///
    /// Why a `*bool` gate parameter rather than nulling an
    /// `?*BeamState` (the original `produceBlock` shape)? The
    /// `onBlock` path also distinguishes a NOT-OWNED case (caller
    /// supplied `post_state` and we sszClone before wrapping) where
    /// the upstream errdefer is gated by an additional
    /// `post_state_owned` flag, not by an optional. A bool gate
    /// matches both call sites; the optional gate did not. Pre-c-2b
    /// the two sites used different mechanisms for identical work
    /// (PR #828 review by @ch4r10t33r) — this helper unifies them.
    ///
    /// NOTE: the helper is for the OWNED case only. `onBlock`'s
    /// caller-supplied path still does its own `sszClone` +
    /// `RcBeamState.create` inline because the value-source there
    /// is not a heap wrapper to free.
    fn wrapOwnedStateIntoRc(
        self: *Self,
        post_state: *types.BeamState,
        gate_consumed: *bool,
    ) !*RcBeamState {
        // Move the BeamState value out of the heap wrapper into a
        // local. After this point the wrapper memory holds a stale
        // shallow copy whose interior pointers have been logically
        // transferred to `value`.
        const value = post_state.*;
        // Free the wrapper BEFORE attempting create so an OOM in
        // create does not leave a wrapper-allocator leak. The
        // value's interior is consumed by create's always-consume
        // contract on either success or its own OOM path.
        self.allocator.destroy(post_state);
        // Set the gate BEFORE the (fallible) create call: on
        // failure the upstream errdefer must not run (it would
        // deref the now-freed wrapper); on success the gate stays
        // true forever. Either way the caller's gate is correctly
        // false ONLY for the window between heap-wrapper-allocation
        // and this helper call.
        gate_consumed.* = true;
        return RcBeamState.create(self.allocator, value);
    }

    /// Take the exclusive side of `states_lock` and `put` the entry.
    /// Used by produceBlock / onBlock STF commit and similar
    /// single-key writes.
    ///
    /// Under c-2b commit 2 the helper takes `*RcBeamState` directly
    /// (callers wrap their `*BeamState` via `RcBeamState.create`
    /// before calling). Map ownership transfers in: on success the
    /// map holds the rc and will release it on `deinit`. On
    /// `map.put` OOM the helper releases `rc` so the caller never
    /// has to clean up.
    fn statesPutExclusive(self: *Self, comptime site: []const u8, root: types.Root, rc: *RcBeamState) !void {
        var t = LockTimer.start("states", site);
        self.states_lock.lock();
        t.acquired();
        defer t.released();
        defer self.states_lock.unlock();
        errdefer rc.release();
        try self.states.put(root, rc);
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
        rc: *RcBeamState,
    ) !struct { borrow: BorrowedState, kept_existing: bool } {
        // INTENTIONAL: this helper holds the EXCLUSIVE side of
        // `states_lock` across the returned borrow even when chain-
        // worker mode is enabled. Slice c-2b commit 4 of #803 dropped
        // the rwlock for `statesGet` / `getFinalizedState` cache-hit
        // borrows, but the cross-call write barrier rationale from
        // PR #820 / #803 still applies here: the borrow lifetime
        // spans (DB write → forkChoice.confirmBlock); both must
        // observe the in-map pointer atomically, so unlock/reacquire
        // is exactly the UAF race we are closing. The chain-worker
        // is the only writer to `states` under c-2b, but that does
        // NOT make the cross-call barrier redundant — the worker
        // executes its own helpers serially, and the barrier is
        // about ordering against `pruneStates` (also exclusive),
        // which can run from the same worker between this helper's
        // borrow handoff and the caller's last deref. Switching to
        // a Backing.none / tryAcquire shape here would re-open
        // exactly the issue PR #820 fixed.
        var t = LockTimer.start("states", site);
        self.states_lock.lock();
        t.acquired();
        // NOTE: NO `defer self.states_lock.unlock()` here — the
        // exclusive lock is owned by the returned BorrowedState and
        // released by its deinit. errdefer below covers the OOM path
        // on `getOrPut`. The LockTimer is moved into the borrow as
        // well so the hold-span observation closes at the deinit
        // site, not here. PR #820.
        //
        // Ownership: the helper takes responsibility for `rc` cleanup
        // on every error path (mirroring `statesPutExclusive`). The
        // `rc_owned` flag is cleared before each path that explicitly
        // disposes of `rc` (the kept-existing release, the new-insert
        // hand-off into the map) so the errdefer below cannot
        // double-release. After the function returns successfully,
        // ownership has either been transferred into the map
        // (new-insert path) or dropped via `rc.release()`
        // (kept-existing path) — `rc_owned` is false in both cases.
        // Without this flag, an OOM in `states.getOrPut` would leak
        // the freshly-`create`d rc + its heap-owned BeamState
        // interior; the caller has no way to recover the pointer
        // because the helper consumes it on success.
        var rc_owned = true;
        errdefer {
            self.states_lock.unlock();
            t.released();
            if (rc_owned) rc.release();
        }
        const gop = try self.states.getOrPut(root);
        // After this point getOrPut succeeded; on either branch the
        // helper now disposes of `rc` (release-or-transfer), so the
        // errdefer must NOT double-act on it. Clear `rc_owned`
        // BEFORE the synchronous release / map write so the cleared
        // flag is observed even if the map write itself were ever
        // changed to be fallible (currently `value_ptr.* = rc;` is
        // infallible, but pinning the invariant here keeps the
        // pattern safe under future edits).
        rc_owned = false;
        const effective_rc: *RcBeamState = if (gop.found_existing) blk: {
            // Decision policy: keep the existing rc (other readers
            // may still hold acquires on it) and release the
            // freshly-computed copy the caller handed us. The
            // "kept_existing" return tells the caller their rc was
            // dropped so they don't double-release.
            //
            // Lock-hold note: when this release drops the refcount
            // to 0 (the common case under c-2b commit 2 — the only
            // acquires today come from the chain worker thread
            // itself, which is the SAME thread executing this
            // helper, so no concurrent acquire holds the rc alive),
            // `release()` synchronously runs `state.deinit()` +
            // `allocator.destroy(rc)` while holding
            // `states_lock.exclusive`. For production-sized states
            // BeamState.deinit walks every interior list/slice and
            // is non-trivial work. Pre-c-2b the equivalent free was
            // done by the CALLER outside the lock.
            //
            // The hold span is observable via
            // `zeam_lock_hold_seconds{lock="states", site=...}` —
            // the `site` argument differentiates `onBlock.commit`
            // from `produceBlock.commit`, so a regression vs slice
            // (b) baselines is visible per call site without any
            // new instrumentation. Devnet should watch the
            // `onBlock.commit` p99 across the slice (b)→(c-2b) cut.
            //
            // TODO(slice-c-2c): if the kept-existing free shows up
            // as a hold-span regression on devnet, switch the
            // helper to return the to-be-released rc alongside the
            // borrow and have the caller release after dropping the
            // lock (option (b) in the PR #828 review thread). Adds
            // API surface but moves deinit work out of the critical
            // section. Tracking-only until devnet has data; the
            // single-writer assumption above means the cost is
            // entirely allocator work, not contention with other
            // chain mutators.
            rc.release();
            break :blk gop.value_ptr.*;
        } else blk: {
            gop.value_ptr.* = rc;
            break :blk rc;
        };
        if (gop.found_existing) {
            _ = self.states_kept_existing_count.fetchAdd(1, .monotonic);
        }
        return .{
            .borrow = BorrowedState{
                .state = &effective_rc.state,
                .backing = .{ .states_exclusive_rwlock = &self.states_lock },
                .timer = t,
            },
            .kept_existing = gop.found_existing,
        };
    }

    /// Take the exclusive side of `states_lock` and remove the entry.
    /// Returns the removed `*RcBeamState` (or null) so the caller can
    /// release it. Under c-2b the caller MUST call `.release()` on
    /// the returned rc to drop the map's reference; if other readers
    /// hold acquires the underlying state stays alive until the last
    /// release.
    fn statesFetchRemoveExclusivePtr(self: *Self, comptime site: []const u8, root: types.Root) ?*RcBeamState {
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

    /// Sample `rc.count()` for every entry in `BeamChain.states` and
    /// emit one observation per entry into the
    /// `lean_chain_state_refcount_distribution` histogram. Slice c-2b
    /// commit 5 of #803.
    ///
    /// Pattern: take `states_lock.shared` for the iteration only, drop
    /// the lock before observing values (no allocations or fallible
    /// ops happen inside the critical section). The lock hold span is
    /// O(N) in the number of map entries; under c-2b this stays small
    /// (≤ the un-pruned post-finalized state set, typically O(1) to O(10)).
    ///
    /// Infallible: any iteration failure path would silently drop the
    /// scrape sample rather than crash the metrics endpoint. The
    /// histogram observe() call is itself infallible (the metrics-lib
    /// histogram type is non-vector, so no labels-allocation).
    ///
    /// Wired into the `/metrics` pre-scrape path via a context-bearing
    /// scrape refresher: `BeamChain.startChainStateRefcountObserver()`
    /// (called from `init` after the chain is at its final heap
    /// address) registers this method against `zeam_metrics`'s
    /// `g_scrape_refresher_ctx` slot.
    pub fn recordChainStateRefcountDistribution(self: *Self) void {
        // Snapshot the per-entry counts under the shared lock into a
        // small stack buffer when possible. For larger maps we fall
        // back to observing under the lock; the observe call is just
        // an atomic-ish bucket increment, no allocations, no IO.
        //
        // The buffered-snapshot path is the safer shape: it minimizes
        // the lock hold span. The on-stack buffer is sized for the
        // expected upper bound on devnet (un-pruned post-finalized
        // states + cached anchor) plus headroom.
        var buf: [128]u32 = undefined;
        var n: usize = 0;
        var overflow = false;

        self.states_lock.lockShared();
        var it = self.states.valueIterator();
        while (it.next()) |rc_ptr| {
            const rc: *RcBeamState = rc_ptr.*;
            if (n < buf.len) {
                buf[n] = rc.count();
                n += 1;
            } else {
                // Map has more entries than the stack buffer can
                // hold; emit the rest under the lock. This is a
                // graceful degradation — the lock hold span grows
                // with map size, but since we don't allocate or do
                // IO it stays bounded by the map size.
                overflow = true;
                zeam_metrics.metrics.lean_chain_state_refcount_distribution.observe(
                    @floatFromInt(rc.count()),
                );
            }
        }
        self.states_lock.unlockShared();

        // Observe the buffered samples outside the critical section.
        for (buf[0..n]) |c| {
            zeam_metrics.metrics.lean_chain_state_refcount_distribution.observe(
                @floatFromInt(c),
            );
        }
        // Log the overflow case once per scrape so devnet operators
        // notice maps growing past the buffer; not fatal.
        if (overflow) {
            self.logger.debug(
                "recordChainStateRefcountDistribution: map size exceeded stack buffer ({d}), emitted overflow samples under lock",
                .{buf.len},
            );
        }
    }

    /// Trampoline for the context-bearing scrape refresher. The opaque
    /// `ctx` pointer is the `*BeamChain` registered in `init`.
    fn chainStateRefcountScrapeRefresher(ctx: ?*anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx orelse return));
        self.recordChainStateRefcountDistribution();
    }

    /// Register this chain as the source for the
    /// `lean_chain_state_refcount_distribution` scrape refresher.
    /// Called from `init` after the chain is at its final heap address
    /// so the refresher's ctx pointer is stable.
    ///
    /// Idempotent across init/deinit cycles within a single process:
    /// `deinit` clears the refresher slot. Note that the metrics
    /// module holds a single context-bearing refresher slot; if a
    /// second BeamChain is initialized in the same process (e.g. test
    /// harnesses spinning multiple chains) the second init silently
    /// replaces the first registration. Today only one chain is alive
    /// per process; revisit if that changes.
    pub fn startChainStateRefcountObserver(self: *Self) void {
        zeam_metrics.registerScrapeRefresherCtx(self, &chainStateRefcountScrapeRefresher);
    }

    /// Clear this chain's refcount-distribution scrape refresher. Idempotent.
    /// Called from `deinit` so the metrics module does not call back into
    /// freed chain memory after teardown.
    pub fn stopChainStateRefcountObserver(_: *Self) void {
        zeam_metrics.registerScrapeRefresherCtx(null, null);
    }

    pub fn registerValidatorIds(self: *Self, validator_ids: []usize) void {
        // right now it's simple assignment but eventually it should be a set
        // tacking registrations and keeping it alive for 3*2=6 slots
        self.registered_validator_ids = validator_ids;
        zeam_metrics.metrics.lean_validators_count.set(self.registered_validator_ids.len);
    }

    /// Append a block to `pending_blocks` for later replay.
    ///
    /// Issue #788: under mutex contention the forkchoice clock can lag
    /// wall-time by tens of slots; gossip blocks for those slots arrive at
    /// the wall-clock time and would otherwise be rejected as `FutureSlot`,
    /// causing the forkchoice head to fall back to `latest_finalized` (no
    /// descendants exist in protoArray). Buffering them here lets
    /// `processPendingBlocks` replay them once the clock catches up.
    ///
    /// **Complexity** (PR #841 review #5/#6): all sub-passes are O(N) in
    /// the queue length, no O(N²) anywhere.
    ///   * Pre-finalized eviction is a single in-place compaction pass
    ///     using a write-pointer (preserves receive order; no per-removal
    ///     `orderedRemove` shift).
    ///   * Dedup is `memcmp` against the cached root in each
    ///     `PendingBlockEntry`, not a re-hash of the full block body. The
    ///     review explicitly called out the prior O(N·hash) loop as a
    ///     blocking issue under sustained gossip floods.
    ///   * Cap-eviction uses `orderedRemove(0)` for the FIFO drop and is
    ///     O(N) for the single shift.
    ///
    /// **Append OOM safety** (PR #841 review #7): we reserve space *before*
    /// the cap-eviction. If the reservation itself OOMs we return early
    /// without evicting anything — the prior shape would free the oldest
    /// entry, then OOM on the append, losing two blocks per OOM event.
    /// `ensureUnusedCapacity(1)` is a no-op in steady state because the
    /// ArrayList's underlying buffer was already sized to the cap on a
    /// previous append.
    ///
    /// Bounded by `MAX_PENDING_BLOCKS`. When the cap is hit we evict the
    /// oldest entry by *receive order* (front of queue) rather than the
    /// lowest slot, because:
    ///   * a peer flooding with high-slot fake-future blocks should not
    ///     starve a legitimate near-future block out of the queue;
    ///   * receive-order eviction is FIFO-fair and trivial to reason about.
    /// In practice the queue is drained on every `onInterval` tick so the
    /// cap is only hit during a sustained large clock lag, and the lost
    /// block can always be re-fetched via `blocks_by_range` once the node
    /// catches up.
    ///
    /// Dedup: if a block with the same root is already queued (a peer can
    /// gossip the same block multiple times during the lag window), the
    /// duplicate is discarded so we do not pay the cost of re-running it.
    /// Each entry caches its root in `PendingBlockEntry.block_root`, so
    /// dedup is a 32-byte `memcmp` per entry.
    ///
    /// Pre-finalized eviction: drop any queued block with
    /// `slot < latest_finalized.slot` opportunistically while we're under
    /// the lock — these can never become canonical and would be rejected
    /// by `validateBlock` on replay anyway.
    ///
    /// Returns `true` if the block was queued, `false` if it was dropped
    /// (cap reservation failed, or duplicate). `cloned` is `deinit`'d in
    /// the failure path; on success the queue takes ownership.
    fn enqueuePendingBlock(
        self: *Self,
        cloned: types.SignedBlock,
        block_root: types.Root,
    ) bool {
        const finalized_slot = self.forkChoice.getLatestFinalized().slot;

        var t = LockTimer.start("pending_blocks", "enqueuePendingBlock");
        self.pending_blocks_lock.lock();
        t.acquired();
        defer t.released();
        defer self.pending_blocks_lock.unlock();

        // Pre-finalized in-place compaction (PR #841 review #6 — prior
        // `orderedRemove(i)` per dropped entry was O(N²) under flood).
        // Walk forward, copy keepers down to a write pointer, deinit
        // dropped entries as we pass over them. Receive order is preserved
        // because the relative order of survivors is unchanged.
        {
            const items = self.pending_blocks.items;
            var write: usize = 0;
            var read: usize = 0;
            while (read < items.len) : (read += 1) {
                if (items[read].signed_block.block.slot < finalized_slot) {
                    var dropped = items[read];
                    dropped.signed_block.deinit();
                    zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "pre_finalized" }) catch {};
                    continue;
                }
                if (write != read) {
                    items[write] = items[read];
                }
                write += 1;
            }
            self.pending_blocks.shrinkRetainingCapacity(write);
        }

        // Dedup by cached root — PR #841 review #5: was an O(N) re-hash
        // per check, now an O(N) memcmp.
        for (self.pending_blocks.items) |existing| {
            if (std.mem.eql(u8, &existing.block_root, &block_root)) {
                self.logger.debug(
                    "pending_blocks: duplicate slot={d} root=0x{x} dropped",
                    .{ cloned.block.slot, &block_root },
                );
                var dup = cloned;
                dup.deinit();
                zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "duplicate" }) catch {};
                return false;
            }
        }

        // PR #841 review #7: reserve append capacity BEFORE evicting so an
        // allocator failure in the reservation step does not lose the
        // oldest entry too. In steady state this is a no-op (the ArrayList
        // was already grown to MAX_PENDING_BLOCKS on a prior append). If
        // the reservation fails we return without touching the queue —
        // the caller's `cloned` is freed below.
        self.pending_blocks.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.logger.err(
                "pending_blocks: capacity reservation failed for slot={d} root=0x{x}: {any}",
                .{ cloned.block.slot, &block_root, err },
            );
            var failed = cloned;
            failed.deinit();
            zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "append_oom" }) catch {};
            return false;
        };

        // Cap eviction: drop the oldest by receive order if at capacity.
        if (self.pending_blocks.items.len >= constants.MAX_PENDING_BLOCKS) {
            var oldest = self.pending_blocks.orderedRemove(0);
            self.logger.warn(
                "pending_blocks: cap={d} hit; evicting oldest slot={d} to make room for slot={d}",
                .{ constants.MAX_PENDING_BLOCKS, oldest.signed_block.block.slot, cloned.block.slot },
            );
            oldest.signed_block.deinit();
            zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "cap" }) catch {};
        }

        // Reservation above guarantees this `appendAssumeCapacity` cannot
        // fail — even after an `orderedRemove` (which only shrinks `len`,
        // not `capacity`).
        self.pending_blocks.appendAssumeCapacity(.{
            .signed_block = cloned,
            .block_root = block_root,
        });

        zeam_metrics.metrics.lean_pending_blocks_depth.set(self.pending_blocks.items.len);
        return true;
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
            // Refresh the depth gauge so a busy drain leaves the gauge
            // accurate for the next scrape (avoids "queue stayed at depth
            // N forever" reads when the drain actually emptied it).
            self.pending_blocks_lock.lock();
            const depth = self.pending_blocks.items.len;
            self.pending_blocks_lock.unlock();
            zeam_metrics.metrics.lean_pending_blocks_depth.set(depth);
        }

        while (true) {
            const fc_time = self.forkChoice.fcStore.slot_clock.time.load(.monotonic);
            const finalized_slot = self.forkChoice.getLatestFinalized().slot;
            const current_slot = self.forkChoice.fcStore.slot_clock.timeSlots.load(.monotonic);
            // PR #841 review #8: drain-side eviction of "too-far-future"
            // entries whose slot the forkchoice clock has not yet caught
            // up to and is unlikely to ever (an adversary can flood with
            // blocks at `current_slot + 250` that are within the
            // queueable window at enqueue time but stay un-replayable
            // until the clock advances by 250 slots). Saturating add
            // avoids u64 wrap-around on adversarial input — see PR #841
            // review #8.
            const too_far_future_slot: types.Slot = current_slot +| constants.MAX_FUTURE_SLOT_QUEUE_TOLERANCE;

            // Pop the first ready entry under the lock; release before any
            // heavy work so gossip-thread appends can proceed.
            //
            // The scan is an in-place compaction (PR #841 review #6: prior
            // `orderedRemove(i)` per dropped entry was O(N²) under flood).
            // Walk forward, copy keepers down to a write pointer; when we
            // see the first "ready" block (slot * intervals <= fc_time)
            // we pop it into `ready` and continue compacting the tail.
            // Pre-finalized and too-far-future entries are dropped
            // in-line; receive order is preserved for survivors.
            var ready: ?PendingBlockEntry = null;
            {
                var t = LockTimer.start("pending_blocks", "processPendingBlocks.scan");
                self.pending_blocks_lock.lock();
                t.acquired();
                defer t.released();
                defer self.pending_blocks_lock.unlock();

                const items = self.pending_blocks.items;
                var write: usize = 0;
                var read: usize = 0;
                while (read < items.len) : (read += 1) {
                    const entry_slot = items[read].signed_block.block.slot;
                    if (entry_slot < finalized_slot) {
                        var dropped = items[read];
                        dropped.signed_block.deinit();
                        zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "pre_finalized" }) catch {};
                        continue;
                    }
                    if (entry_slot > too_far_future_slot) {
                        var dropped = items[read];
                        dropped.signed_block.deinit();
                        zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "too_far_future" }) catch {};
                        continue;
                    }
                    if (ready == null and entry_slot * constants.INTERVALS_PER_SLOT <= fc_time) {
                        ready = items[read];
                        continue;
                    }
                    if (write != read) {
                        items[write] = items[read];
                    }
                    write += 1;
                }
                self.pending_blocks.shrinkRetainingCapacity(write);
            }

            if (ready) |unwrapped| {
                iter_count += 1;
                var queued_entry = unwrapped;
                defer queued_entry.signed_block.deinit();

                const queued_slot = queued_entry.signed_block.block.slot;
                // PR #841 review #5 + slice (e) of #803: use the cached
                // root from the queue entry instead of re-hashing the
                // block. The root was stamped at gossip ingress — SSZ is
                // collision-resistant, so this is identical to what the
                // pre-cache path computed at this point.
                const block_root: types.Root = queued_entry.block_root;
                zeam_metrics.metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "chain.processPendingBlocks" }) catch {};

                self.logger.info(
                    "replaying queued block slot={d} blockroot=0x{x} (fc_time now={d})",
                    .{ queued_slot, &block_root, fc_time },
                );

                const missing_roots = self.onBlock(queued_entry.signed_block, .{
                    .blockRoot = block_root,
                }) catch |err| {
                    self.logger.err("queued block slot={d} root=0x{x}: processing failed: {any}", .{ queued_slot, &block_root, err });
                    zeam_metrics.metrics.lean_pending_blocks_replayed_total.incr(.{ .result = "rejected" }) catch {};
                    continue;
                };
                defer self.allocator.free(missing_roots);

                zeam_metrics.metrics.lean_pending_blocks_replayed_total.incr(.{ .result = "accepted" }) catch {};
                self.onBlockFollowup(true, &queued_entry.signed_block);

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

        // Only forkchoice tick failure means the chain clock did not advance.
        try self.forkChoice.onInterval(time_intervals, has_proposal);

        if (interval == 1) {
            // interval to attest so we should put out the chain status information to the user along with
            // latest head which most likely should be the new block received and processed
            const islot: isize = @intCast(slot);
            self.printSlot(islot, constants.MAX_FC_CHAIN_PRINT_DEPTH, self.connected_peers.count());

            // Pruning is housekeeping; do not fail the already-applied tick.
            if (slot > 0 and slot % constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS == 0) {
                self.runPeriodicPruning(slot) catch |err| {
                    self.logger.err(
                        "periodic pruning failed at slot={d}: {any} (continuing tick)",
                        .{ slot, err },
                    );
                    zeam_metrics.metrics.lean_node_interval_error_total.incr(
                        .{ .site = "chain.runPeriodicPruning" },
                    ) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                };
            }
        }
        // check if log rotation is needed
        self.zeam_logger_config.maybeRotate() catch |err| {
            self.logger.err("error rotating log file: {any}", .{err});
        };
    }

    /// Periodic pruning helper; caller logs and continues on failure.
    fn runPeriodicPruning(self: *Self, slot: types.Slot) !void {
        const finalized = self.forkChoice.getLatestFinalized();
        // no need to work extra if finalization is not far behind
        if (finalized.slot + 2 * constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS >= slot) {
            self.logger.info("skipping periodic pruning at current slot={d} since finalization slot={d} not behind", .{
                slot,
                finalized.slot,
            });
            return;
        }

        self.logger.warn("finalization slot={d} too far behind the current slot={d}", .{ finalized.slot, slot });
        const pruningAnchor = try self.forkChoice.getCanonicalAncestorAtDepth(constants.FORKCHOICE_PRUNING_INTERVAL_SLOTS);

        // prune if finalization hasn't happened since a long time
        if (pruningAnchor.slot <= finalized.slot) {
            self.logger.info("skipping periodic pruning at slot={d} since finalization not behind pruning anchor (finalized slot={d} pruning anchor={d})", .{
                slot,
                finalized.slot,
                pruningAnchor.slot,
            });
            return;
        }

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
            pruned_count,
            slot,
            finalized.slot,
            pruningAnchor.slot,
        });
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

        const post_state = try self.allocator.create(types.BeamState);
        // c-2b: switched from `?*BeamState` (nulled on consume) to a
        // bool gate to match `onBlock`'s post_state_settled shape.
        // `wrapOwnedStateIntoRc` flips this on consume; the upstream
        // errdefer below covers every early-return path before the
        // wrap, including a partial sszClone that left interior
        // allocations behind (BeamState.deinit is tolerant of
        // partial init by design).
        var post_state_consumed = false;
        errdefer if (!post_state_consumed) {
            post_state.deinit();
            self.allocator.destroy(post_state);
        };
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

        // c-2b: move the heap-allocated post_state into a freshly-
        // `create`d RcBeamState via the shared helper that
        // centralises the value-copy + destroy + create dance.
        // Helper sets `post_state_consumed = true` BEFORE its
        // (fallible) create call, so the upstream errdefer does
        // not deref freed memory on OOM and does not double-free
        // on success. PR #828 review by @ch4r10t33r.
        const post_state_rc = try self.wrapOwnedStateIntoRc(post_state, &post_state_consumed);
        // statesPutExclusive takes ownership of the rc on success;
        // releases on its own OOM path.
        try self.statesPutExclusive("produceBlock.commit", block_root, post_state_rc);

        var forkchoice_added = false;
        errdefer if (!forkchoice_added) {
            if (self.statesFetchRemoveExclusivePtr("produceBlock.errdefer", block_root)) |rc_ptr| {
                rc_ptr.release();
            }
        };

        // 4. Add the block directly to forkchoice as this proposer will next need to construct its vote
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

    /// Process an incoming gossip message.
    ///
    /// Slice (e) of #803: `precomputed_block_root` is the producer's
    /// already-computed `hashTreeRoot(BeamBlock, signed_block.block)`.
    /// Pass `null` only when the producer truly does not have one
    /// — every current production gossip producer DOES (see
    /// `BeamNode.onGossip` which computes it before taking any
    /// per-resource lock so it can be reused across the lock-free
    /// pre-check fan-out and this call). The block branch threads the
    /// root through `validateBlock` → `enqueuePendingBlock` →
    /// `submitBlock`/`onBlock` so a single block traversal is paid
    /// once per ingress, not 3–4 times.
    pub fn onGossip(
        self: *Self,
        data: *const networks.GossipMessage,
        sender_peer_id: []const u8,
        precomputed_block_root: ?types.Root,
    ) !GossipProcessingResult {
        switch (data.*) {
            .block => |signed_block| {
                const block = signed_block.block;
                const block_root: [32]u8 = if (precomputed_block_root) |r| r else r: {
                    var cblock_root: [32]u8 = undefined;
                    try zeam_utils.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
                    break :r cblock_root;
                };
                if (precomputed_block_root != null) {
                    zeam_metrics.metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "chain.onGossip" }) catch {};
                }

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
                    // Validate the block. `validateBlock` distinguishes
                    // three future-slot cases (issue #788):
                    //   * within `MAX_FUTURE_SLOT_TOLERANCE` — fall through
                    //     to the existing per-interval pending-queue check
                    //     and either queue or process now.
                    //   * within `MAX_FUTURE_SLOT_QUEUE_TOLERANCE` (but not
                    //     the small immediate tolerance) — surfaced as
                    //     `FutureSlotQueueable`; we clone + queue and exit.
                    //   * beyond `MAX_FUTURE_SLOT_QUEUE_TOLERANCE` —
                    //     surfaced as `FutureSlot`; hard-rejected with a
                    //     metric bump for visibility.
                    self.validateBlock(block, true) catch |err| switch (err) {
                        error.FutureSlotQueueable => {
                            var cloned: types.SignedBlock = undefined;
                            try types.sszClone(self.allocator, types.SignedBlock, signed_block, &cloned);
                            const queued = self.enqueuePendingBlock(cloned, block_root);
                            if (queued) {
                                self.logger.info(
                                    "queued future-slot gossip block slot={d} blockroot=0x{x}: current_slot={d}",
                                    .{
                                        block.slot,
                                        &block_root,
                                        self.forkChoice.fcStore.slot_clock.timeSlots.load(.monotonic),
                                    },
                                );
                            }
                            return .{};
                        },
                        error.FutureSlot => {
                            zeam_metrics.metrics.lean_blocks_future_slot_dropped_total.incr();
                            return err;
                        },
                        else => return err,
                    };

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

                        // Re-check after the clone in case `onInterval`
                        // ticked the clock past this block's slot while
                        // we were cloning. If it did, fall through and
                        // process the block directly; otherwise enqueue.
                        if (block.slot * constants.INTERVALS_PER_SLOT > self.forkChoice.fcStore.slot_clock.time.load(.monotonic)) {
                            const queued = self.enqueuePendingBlock(cloned, block_root);
                            if (queued) {
                                self.logger.info(
                                    "queued gossip block slot={d} blockroot=0x{x}: forkchoice time={d} < slot_start={d}",
                                    .{ block.slot, &block_root, self.forkChoice.fcStore.slot_clock.time.load(.monotonic), block.slot * constants.INTERVALS_PER_SLOT },
                                );
                            }
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

                    // Slice c-2b commit 3 of #803: route through the
                    // chain-worker queue when enabled. We clone
                    // `signed_block` here — the gossip layer owns the
                    // borrowed copy for the duration of this callback,
                    // but the worker takes ownership and runs
                    // asynchronously, so it needs an independent
                    // allocation. On `submitBlock` success the worker
                    // owns the clone (and will deinit it after
                    // dispatch); on failure the errdefer frees it.
                    //
                    // Trade-offs of the worker path:
                    //   * `missing_attestation_roots` feedback is
                    //     dropped — the worker thunk swallows the
                    //     return value because there is no upstream
                    //     channel to surface it on. The same dataset
                    //     is rediscovered on the next attestation
                    //     gossip whose `head/source/target` is still
                    //     unknown (gossip clients re-broadcast
                    //     liberally), so this is observably equivalent
                    //     to a dropped first attempt.
                    //   * `processed_block_root` is returned
                    //     immediately so `BeamNode.onGossip` can still
                    //     fan out `processCachedDescendants(root)` and
                    //     give cached children a retry chance.
                    if (self.chain_worker != null) {
                        var cloned: types.SignedBlock = undefined;
                        try types.sszClone(self.allocator, types.SignedBlock, signed_block, &cloned);
                        var cloned_consumed = false;
                        errdefer if (!cloned_consumed) cloned.deinit();
                        // Slice (e): forward the block_root we already computed
                        // above so the worker thread doesn't re-hash the block.
                        self.submitBlock(cloned, true, block_root) catch |err| switch (err) {
                            error.QueueFull => {
                                self.logger.warn(
                                    "chain-worker: block queue full, dropping slot={d} root=0x{x}",
                                    .{ block.slot, &block_root },
                                );
                                return .{};
                            },
                            error.QueueClosed => {
                                self.logger.warn(
                                    "chain-worker: block queue closed, dropping slot={d} root=0x{x}",
                                    .{ block.slot, &block_root },
                                );
                                return .{};
                            },
                            error.ChainWorkerDisabled => unreachable,
                        };
                        cloned_consumed = true;
                        return .{ .processed_block_root = block_root };
                    }

                    const missing_roots = self.onBlock(signed_block, .{
                        .blockRoot = block_root,
                    }) catch |err| {
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
                    // Slice c-2b commit 3 of #803: when the chain-worker
                    // is enabled, route the validated attestation
                    // through its queue. `AttestationGossip` is plain-
                    // old-data (see `Message.deinit` in chain_worker.zig),
                    // so no clone is required — the value is copied into
                    // the `Message` enum at queue push time.
                    if (self.chain_worker != null) {
                        self.submitGossipAttestation(signed_attestation) catch |err| switch (err) {
                            error.QueueFull => {
                                zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                                self.logger.warn(
                                    "chain-worker: attestation queue full, dropping slot={d} validator={d}",
                                    .{ slot, validator_id },
                                );
                                return .{};
                            },
                            error.QueueClosed => {
                                self.logger.warn(
                                    "chain-worker: attestation queue closed, dropping slot={d} validator={d}",
                                    .{ slot, validator_id },
                                );
                                return .{};
                            },
                            error.ChainWorkerDisabled => unreachable,
                        };
                    } else {
                        // Process validated attestation synchronously.
                        self.onGossipAttestation(signed_attestation) catch |err| {
                            zeam_metrics.metrics.lean_attestations_invalid_total.incr(.{ .source = "gossip" }) catch {};
                            self.logger.err("attestation processing error: {any}", .{err});
                            return err;
                        };
                    }
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

        const block_root: types.Root = if (blockInfo.blockRoot) |r| r else r: {
            var cblock_root: [32]u8 = undefined;
            try zeam_utils.hashTreeRoot(types.BeamBlock, block, &cblock_root, self.allocator);
            break :r cblock_root;
        };
        if (blockInfo.blockRoot != null) {
            zeam_metrics.metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "chain.onBlock" }) catch {};
            // PR #842 review #2: see the rationale in
            // `forkchoice.onBlock`. Same trust-but-verify pattern at
            // the chain-level public API boundary; debug + ReleaseSafe
            // only, free in `ReleaseFast` / `ReleaseSmall`.
            if (std.debug.runtime_safety) verify: {
                var verify_root: [32]u8 = undefined;
                zeam_utils.hashTreeRoot(types.BeamBlock, block, &verify_root, self.allocator) catch |err| {
                    self.logger.warn(
                        "chain.onBlock: blockRoot verification re-hash failed: {any}",
                        .{err},
                    );
                    break :verify;
                };
                if (!std.mem.eql(u8, &block_root, &verify_root)) {
                    std.debug.panic(
                        "chain.onBlock: caller-supplied blockRoot=0x{x} does NOT match recomputed=0x{x} for block slot={d} — forkchoice protoArray would be silently corrupted; call site bug",
                        .{ &block_root, &verify_root, block.slot },
                    );
                }
            }
        }

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
                var att_data_map = std.AutoHashMap(types.AttestationData, usize).init(self.allocator);
                defer att_data_map.deinit();
                for (aggregated_attestations, 0..) |agg_att, idx| {
                    const result = try att_data_map.getOrPut(agg_att.data);
                    if (result.found_existing) {
                        const first_idx = result.value_ptr.*;
                        self.logger.err(
                            "duplicate AttestationData rejected: blockroot=0x{x} slot={d} proposer={d}" ++
                                " duplicate_indices=[{d},{d}] data.slot={d}" ++
                                " data.head.blockroot=0x{x}@{d}" ++
                                " data.target.checkpoint_root=0x{x}@{d}" ++
                                " data.source.checkpoint_root=0x{x}@{d}",
                            .{
                                &freshFcBlock.blockRoot,
                                block.slot,
                                block.proposer_index,
                                first_idx,
                                idx,
                                agg_att.data.slot,
                                &agg_att.data.head.root,
                                agg_att.data.head.slot,
                                &agg_att.data.target.root,
                                agg_att.data.target.slot,
                                &agg_att.data.source.root,
                                agg_att.data.source.slot,
                            },
                        );
                        return BlockProcessingError.DuplicateAttestationData;
                    }
                    result.value_ptr.* = idx;
                }
                if (att_data_map.count() > self.config.spec.max_attestations_data) {
                    self.logger.err(
                        "block contains {d} distinct AttestationData entries (max {d}) for block root=0x{x}",
                        .{ att_data_map.count(), self.config.spec.max_attestations_data, &freshFcBlock.blockRoot },
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
        // c-2b: wrap post_state in an RcBeamState before commit.
        // Two paths depending on ownership:
        //   * post_state_owned (we allocated it locally above):
        //     route through `wrapOwnedStateIntoRc` — it does the
        //     value-move + wrapper-destroy + create + gate-flip
        //     dance, identical to `produceBlock`'s commit path.
        //   * !post_state_owned (caller supplied a *BeamState we
        //     don't own): sszClone into a fresh value, then
        //     `RcBeamState.create` consumes that. The caller's
        //     allocation is left untouched; nothing to free, no
        //     gate to flip (post_state_settled stays false here
        //     and is flipped after the commit succeeds because the
        //     gate's errdefer is gated on `post_state_owned` too).
        //
        // PR #828 review by @ch4r10t33r: pre-c-2b the owned path
        // used a different gate mechanism than `produceBlock`
        // (post_state_settled bool vs ?*BeamState nulling); the
        // helper unifies them.
        var post_state_rc: *RcBeamState = undefined;
        if (post_state_owned) {
            // Helper flips `post_state_settled = true` BEFORE the
            // create call so the upstream errdefer at line ~1712
            // does not deref the freed wrapper if create OOMs.
            post_state_rc = try self.wrapOwnedStateIntoRc(post_state, &post_state_settled);
        } else {
            // Caller owns post_state; clone its value into a fresh
            // BeamState, then wrap. Past sszClone success, `value`
            // owns interior allocations; `RcBeamState.create`'s
            // always-consume contract handles cleanup on OOM.
            var value: types.BeamState = undefined;
            try types.sszClone(self.allocator, types.BeamState, post_state.*, &value);
            post_state_rc = try RcBeamState.create(self.allocator, value);
        }
        // statesCommitKeepExisting takes the rc on either path:
        //   kept-existing: helper releases our rc, returns a
        //     borrow on the in-map rc;
        //   new-insert:    helper transfers our rc into the map.
        // On the helper's own OOM path it releases the rc for us.
        var commit = try self.statesCommitKeepExisting("onBlock.commit", fcBlock.blockRoot, post_state_rc);
        // Release the exclusive lock on every exit path (success or error).
        defer commit.borrow.assertReleasedOrPanic();
        defer commit.borrow.deinit();
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
        // Actually remove and deallocate the pruned states (under
        // c-2b: release the rc — the underlying state may stay
        // alive if other readers hold acquires; freed when last
        // release runs).
        for (roots) |root| {
            if (self.states.fetchRemove(root)) |entry| {
                entry.value.release();
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

        // 5 Rebase forkchoice on finalization advance.
        if (pruneForkchoice) {
            try self.forkChoice.rebase(latestFinalized.root, &canonical_view);
        }

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
    /// 1. Pre-finalized slot check: block.slot must be >= finalized_slot
    /// 2. Proposer index bounds check: proposer_index must be < validator_count
    /// 3. Parent existence check: parent_root must be known
    /// 4. Slot ordering check: block.slot must be > parent.slot
    /// 5. Finalized-descendant check: parent chain must reach the finalized
    ///    checkpoint (DoS defense — forks off pre-finalization ancestors are
    ///    rejected here so they never enter the fork choice store).
    ///
    /// Block admission is gated by parent / signature / STF; the slot is only
    /// checked relative to the finalized boundary and to the parent block.
    pub fn validateBlock(self: *Self, block: types.BeamBlock, is_from_gossip: bool) !void {
        _ = is_from_gossip;

        const current_slot = self.forkChoice.fcStore.slot_clock.timeSlots.load(.monotonic);
        // latest_finalized is a multi-field Checkpoint written under
        // forkChoice.mutex (exclusive). Take the shared lock via the
        // accessor to avoid a torn (slot, root) pair. PR #820 / #803.
        const finalized_slot = self.forkChoice.getLatestFinalized().slot;

        // 1. Future slot check.
        //
        // Issue #788: under heavy mutex contention (#786) the forkchoice's
        // local clock (`timeSlots`) can lag wall-time by tens of slots.
        // Gossip blocks for those slots arrive at wall-time and would
        // otherwise be rejected as `FutureSlot`, causing the head to fall
        // back to the latest finalized checkpoint (no descendants in
        // protoArray). We split the future-slot range into two windows:
        //
        //   * `block.slot <= current_slot + MAX_FUTURE_SLOT_TOLERANCE` is
        //     immediately processable; the existing per-interval
        //     `pending_blocks` boundary handler will queue it if the
        //     interval-level clock isn't quite caught up.
        //   * `block.slot <= current_slot + MAX_FUTURE_SLOT_QUEUE_TOLERANCE`
        //     is queueable in `pending_blocks` for replay once the
        //     forkchoice clock catches up. The caller (`onGossip` block
        //     branch) is responsible for the actual queuing; we surface
        //     this case as `FutureSlotQueueable` so the caller can
        //     distinguish it from a hard `FutureSlot` reject.
        //   * Anything beyond `MAX_FUTURE_SLOT_QUEUE_TOLERANCE` is almost
        //     certainly malicious/buggy and is hard-rejected with
        //     `FutureSlot`.
        //
        // Note: the queueable window deliberately includes blocks already
        // covered by the small `MAX_FUTURE_SLOT_TOLERANCE`; the call site
        // queues only when `onBlock` would actually reject (i.e. when the
        // forkchoice's interval-level clock disagrees), so this is just an
        // upper bound, not a routing decision.
        const max_future_tolerance: types.Slot = constants.MAX_FUTURE_SLOT_TOLERANCE;
        const max_future_queue: types.Slot = constants.MAX_FUTURE_SLOT_QUEUE_TOLERANCE;
        // PR #841 review #8: `current_slot + max_future_*` can overflow
        // `types.Slot` (u64) on adversarial input. Practically safe — slots
        // stay well below 2^32 for centuries — but Zig 0.16 release-mode
        // arithmetic doesn't trap, so a wrap-around could silently flip the
        // comparison and either reject valid blocks or accept impossible
        // ones. Use saturating add (`+|`) so the upper bound is always at
        // least as large as any real slot.
        const tolerance_threshold: types.Slot = current_slot +| max_future_tolerance;
        const queue_threshold: types.Slot = current_slot +| max_future_queue;
        if (block.slot > tolerance_threshold) {
            if (block.slot <= queue_threshold) {
                self.logger.debug(
                    "block queueable as future-slot: slot={d} current_slot={d} queue_tolerance={d} time(intervals)={d}",
                    .{
                        block.slot,
                        current_slot,
                        max_future_queue,
                        self.forkChoice.fcStore.slot_clock.time.load(.monotonic),
                    },
                );
                return BlockValidationError.FutureSlotQueueable;
            }
            self.logger.debug("block validation failed: future slot {d} > max allowed {d} time(intervals)={d}", .{
                block.slot,
                queue_threshold,
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

        // 2. Proposer index bounds check - sanity check against registry limit
        // This is a fast pre-check; actual proposer validity is verified during signature verification
        // We use VALIDATOR_REGISTRY_LIMIT as the upper bound since the validator set can grow beyond genesis
        if (block.proposer_index >= params.VALIDATOR_REGISTRY_LIMIT) {
            self.logger.debug("block validation failed: proposer_index {d} >= VALIDATOR_REGISTRY_LIMIT {d}", .{
                block.proposer_index,
                params.VALIDATOR_REGISTRY_LIMIT,
            });
            return BlockValidationError.InvalidProposerIndex;
        }

        // 3. Parent existence check
        const parent_block = self.forkChoice.getBlock(block.parent_root);
        if (parent_block == null) {
            // Log decision moved to node.zig where we can check if parent is already being fetched
            return BlockValidationError.UnknownParentBlock;
        }

        // 4. Slot ordering check - block slot must be greater than parent slot
        if (block.slot <= parent_block.?.slot) {
            self.logger.debug("block validation failed: slot {d} <= parent slot {d}", .{
                block.slot,
                parent_block.?.slot,
            });
            return BlockValidationError.SlotNotAfterParent;
        }

        // 5. Finalized-descendant check - reject forks that branch off from
        // pre-finalization ancestors. This is the gossip-level DoS defense that
        // prevents malicious peers from flooding the fork choice store with
        // blocks whose parent chain cannot reach the finalized checkpoint.
        // forkchoice.onBlock is intentionally permissive here (matching
        // leanSpec store.on_block semantics), so the check must live at this
        // attack surface.
        if (!self.forkChoice.isFinalizedDescendant(block.parent_root)) {
            self.logger.debug("block validation failed: parent 0x{x} does not descend from finalized root", .{
                &block.parent_root,
            });
            return BlockValidationError.NotFinalizedDescendant;
        }
    }

    /// Validate incoming attestation before processing.
    ///
    /// The time check applies only to the gossip path: admit a vote iff
    /// `data.slot * INTERVALS_PER_SLOT <= store.time + GOSSIP_DISPARITY_INTERVALS`.
    /// The bound is in intervals, not slots: a whole-slot margin would let an
    /// adversary pre-publish next-slot aggregates ahead of any honest validator.
    ///
    /// Block-included attestations skip the time check; they are trusted under
    /// the block's own validation. `is_from_block` is retained as a log marker.
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

        //    This corresponds to leanSpec's: assert data.head.slot >= data.target.slot
        if (data.head.slot < data.target.slot) {
            self.logger.debug("attestation validation failed: head slot {d} < target slot {d}", .{
                data.head.slot,
                data.target.slot,
            });
            return AttestationValidationError.HeadOlderThanTarget;
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

        //    This corresponds to leanSpec's: assert head_block.slot == attestation.head.slot
        if (head_block.slot != data.head.slot) {
            self.logger.debug("attestation validation failed: head block slot {d} != head checkpoint slot {d}", .{
                head_block.slot,
                data.head.slot,
            });
            return AttestationValidationError.HeadCheckpointSlotMismatch;
        }

        // 4. Validate gossip attestation is not too far in the future.
        //
        //    Bound is in intervals, not slots, and only applies to the gossip
        //    path. Block-included attestations are trusted under the block's
        //    own validation (matching leanSpec on_block, which doesn't run
        //    validate_attestation on block-body attestations at all).
        if (!is_from_block) {
            const current_time = self.forkChoice.fcStore.slot_clock.time.load(.monotonic);
            const attestation_start_interval = data.slot * constants.INTERVALS_PER_SLOT;
            const max_allowed_interval = current_time + constants.GOSSIP_DISPARITY_INTERVALS;
            if (attestation_start_interval > max_allowed_interval) {
                self.logger.debug("attestation validation failed: gossip attestation start interval {d} > max allowed interval {d} (slot={d}, time={d})", .{
                    attestation_start_interval,
                    max_allowed_interval,
                    data.slot,
                    current_time,
                });
                return AttestationValidationError.AttestationTooFarInFuture;
            }
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
                // Aggregate even with no peers: local fork-choice benefits from aggregated
                // attestation weight, and aggregates will propagate once peers connect.
                // Consistent with proposer and attester which also proceed through .no_peers.
                //
                // No double-counting: aggregate() maps per-AttestationData key, replacing
                // raw attestations with their aggregate. Fork-choice counts each
                // AttestationData key once regardless of whether the raw or aggregated
                // form arrived first.
                self.logger.info("aggregating for slot={d} with no peers (local only)", .{slot});
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
    ///   * In-memory map hit  → backed by `states_lock` (shared) when
    ///     `--chain-worker=off`; `Backing.none` (rc-only lifetime)
    ///     when `--chain-worker=on` (slice c-2b commit 4 of #803).
    ///   * Cache hit / DB load → backed by `events_lock` (mutex) when
    ///     `--chain-worker=off`, since `cached_finalized_state` is
    ///     mutated under `events_lock` (the DB-load path also writes
    ///     the cache field, and that write is guarded by the mutex).
    ///     When `--chain-worker=on`, the cache hit path tryAcquires the
    ///     RcBeamState refcount and drops `events_lock` before
    ///     returning, mirroring the lock-free path in `statesGet`.
    /// Callers MUST release the borrow exactly once via `deinit()` or
    /// `cloneAndRelease(allocator)`.
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
        if (self.cached_finalized_state) |cached_rc| {
            if (std.mem.eql(u8, &cached_rc.state.latest_finalized.root, &finalized_checkpoint.root)) {
                if (self.chain_worker != null) {
                    // Lock-free read path: tryAcquire under the events
                    // lock to defeat any concurrent free race, then drop
                    // the lock so the borrow lifetime no longer pins
                    // `events_lock`. Tier-5 depth must be decremented
                    // BEFORE we return because we are NOT handing off
                    // the lock to the borrow; the next tier-5 acquire
                    // on this thread should see depth=0.
                    const acq = cached_rc.tryAcquire();
                    self.events_lock.unlock();
                    locking.leaveTier5();
                    t_ev.released();
                    lock_held = false;
                    if (acq) |acquired_rc| {
                        return BorrowedState{
                            .state = &acquired_rc.state,
                            .backing = .none,
                            .acquired_rc = acquired_rc,
                        };
                    }
                    // tryAcquire returned null — freeing thread won.
                    // Today this should never happen (refcount stays
                    // at 1 in production), but the safe-by-default
                    // behavior is to report no entry.
                    return null;
                }
                // Legacy lock-based path: hand the events_lock off to
                // the borrow.  Backward-compat with --chain-worker=off.
                lock_held = false; // ownership of the lock moves into the borrow
                // tier-5 depth and LockTimer are HANDED OFF to the borrow:
                // BorrowedState.deinit calls leaveTier5() and t.released()
                // after unlocking. Do NOT close them here.
                return BorrowedState{
                    .state = &cached_rc.state,
                    .backing = .{ .events_mutex = &self.events_lock },
                    .tier5_held = true,
                    .timer = t_ev,
                };
            }
            // Stale — fall through to DB load below.
        }

        // Fallback: try to load from database. Allocate a BeamState
        // value on the stack (well — a local), load into it, then
        // hand it to RcBeamState.create which embeds it into the heap
        // allocation (always-consume contract per c-2a).
        var loaded_state: types.BeamState = undefined;
        self.db.loadLatestFinalizedState(&loaded_state) catch |err| {
            self.logger.warn("finalized state not available in database: {any}", .{err});
            return null;
        };
        // Past this line `loaded_state` owns interior allocations.
        // RcBeamState.create takes ownership; on OOM it deinits the
        // interior for us.
        const new_rc = RcBeamState.create(self.allocator, loaded_state) catch |err| {
            self.logger.warn("failed to allocate RcBeamState for finalized state: {any}", .{err});
            return null;
        };

        // If a previous cached state is being replaced, release the old
        // rc now (we hold events_lock so any concurrent reader either
        // tryAcquired before this critical section — in which case its
        // acquire keeps the underlying allocation alive past our release
        // — or will look it up after our store below and observe the
        // new rc).
        if (self.cached_finalized_state) |old_cached_rc| {
            old_cached_rc.release();
        }

        // Cache in separate field (not in states map to avoid affecting pruning)
        self.cached_finalized_state = new_rc;

        self.logger.info("loaded finalized state from database at slot {d}", .{new_rc.state.slot});

        if (self.chain_worker != null) {
            // Lock-free read path: bump the refcount we just stored and
            // drop the lock so the borrow lifetime is gated by the
            // refcount alone. The cache field holds one reference, the
            // borrow holds another. tryAcquire is guaranteed to succeed
            // here — we own the only reference and we hold events_lock.
            const acq = new_rc.tryAcquire() orelse unreachable;
            self.events_lock.unlock();
            locking.leaveTier5();
            t_ev.released();
            lock_held = false;
            return BorrowedState{
                .state = &acq.state,
                .backing = .none,
                .acquired_rc = acq,
            };
        }
        // Legacy lock-based path: hand the events_lock off to the borrow.
        lock_held = false;
        // tier-5 depth + LockTimer handed off to the borrow; deinit will
        // leaveTier5() and t.released() after unlocking.
        return BorrowedState{
            .state = &new_rc.state,
            .backing = .{ .events_mutex = &self.events_lock },
            .tier5_held = true,
            .timer = t_ev,
        };
    }

    /// Load a block from the DB and return its raw SSZ bytes, or null if not found.
    /// Uses `Db.loadBlockBytes` to avoid a deserialise+reserialise round-trip.
    /// Caller must free the returned slice with `allocator.free`.
    pub fn loadBlockSsz(self: *Self, root: types.Root, allocator: Allocator) ?[]u8 {
        return self.db.loadBlockBytes(database.DbBlocksNamespace, root, allocator);
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
    HeadCheckpointSlotMismatch,
    HeadOlderThanTarget,
    AttestationTooFarInFuture,
};
pub const BlockValidationError = error{
    UnknownParentBlock,
    /// Block slot is too far in the future and cannot be reasonably queued
    /// (beyond `MAX_FUTURE_SLOT_QUEUE_TOLERANCE`). Hard reject.
    FutureSlot,
    /// Block slot is in the future but within the `pending_blocks`
    /// queueing window. The caller should clone + queue the block for
    /// later replay rather than treating it as an error. See #788 for
    /// the rationale (forkchoice clock can lag wall-time under mutex
    /// contention; we should not drop otherwise-valid gossip).
    FutureSlotQueueable,
    /// Block slot is before the finalized slot
    PreFinalizedSlot,
    /// Block proposer_index exceeds validator count
    InvalidProposerIndex,
    /// Block slot is not greater than parent slot
    SlotNotAfterParent,
    /// Block's parent chain does not descend from the finalized checkpoint
    NotFinalizedDescendant,
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
        const block_state_rc = beam_chain.states.get(block_root) orelse @panic("state root should have been found");
        var state_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.BeamState, block_state_rc.state, &state_root, allocator);
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

    // Test 9: Attestation too far in future (gossip path)
    //
    // Setup ended at time = 2 * INTERVALS_PER_SLOT = 10 (slot 2, interval 0).
    // Gossip bound: data.slot * INTERVALS_PER_SLOT <= time + GOSSIP_DISPARITY_INTERVALS
    //               → max admitted slot here is ⌊(10 + 1) / 5⌋ = 2.
    // slot 4 → start interval 20, well beyond 11. Rejected.
    {
        const future_attestation: types.SignedAttestation = .{
            .validator_id = 0,
            .message = .{
                .slot = 4,
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
test "attestation validation - gossip future-slot bound" {
    // Gossip path is interval-grained:
    //
    //   data.slot * INTERVALS_PER_SLOT <= time + GOSSIP_DISPARITY_INTERVALS
    //
    // Block-included attestations skip the time check entirely.
    //
    // Scenario:
    //   - Setup leaves the chain at slot 1, time = 5 (slot 1, interval 0).
    //   - A slot-2 vote at time = 5: gossip rejects (10 > 5 + 1 = 6).
    //   - Tick to time = 9 (slot 1, interval 4 — disparity boundary):
    //     gossip accepts (10 <= 9 + 1 = 10).
    //   - A slot-3 vote at time = 9: gossip rejects (15 > 9 + 1 = 10).
    //   - Block-included path admits the slot-3 vote at every tick.

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

    // Add one block (slot 1). Forkchoice ticks to time = INTERVALS_PER_SLOT (slot 1, interval 0).
    const block = mock_chain.blocks[1];
    try beam_chain.forkChoice.onInterval(block.block.slot * constants.INTERVALS_PER_SLOT, false);
    const missing_roots = try beam_chain.onBlock(block, .{});
    allocator.free(missing_roots);

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

    // At time = 5 the gossip path rejects a slot-2 vote (3 intervals shy of boundary).
    try std.testing.expectError(
        error.AttestationTooFarInFuture,
        beam_chain.validateAttestationData(next_slot_attestation.message, false),
    );

    // Block-included attestations skip the time check.
    try beam_chain.validateAttestationData(next_slot_attestation.message, true);

    // Tick to the gossip disparity boundary: time = 2 * INTERVALS_PER_SLOT - GOSSIP_DISPARITY_INTERVALS = 9.
    const boundary_time = 2 * constants.INTERVALS_PER_SLOT - constants.GOSSIP_DISPARITY_INTERVALS;
    try beam_chain.forkChoice.onInterval(boundary_time, false);

    // At the boundary the gossip path admits the same vote.
    try beam_chain.validateAttestationData(next_slot_attestation.message, false);

    // A slot-3 vote stays beyond the boundary on the gossip path but still admitted on the block path.
    const too_far_attestation: types.SignedAttestation = .{
        .validator_id = 0,
        .message = .{
            .slot = 3,
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
    try std.testing.expectError(error.AttestationTooFarInFuture, beam_chain.validateAttestationData(too_far_attestation.message, false));
    try beam_chain.validateAttestationData(too_far_attestation.message, true);
}

// ----------------------------------------------------------------------
// Issue #788 — future-slot block queueing tests
//
// Cover the FutureSlot/FutureSlotQueueable distinction added by
// `validateBlock` and the `enqueuePendingBlock` helper that backs the
// gossip path. The actual `onGossip` integration is exercised by the
// chain-worker / node tests; here we focus on the boundary conditions
// of the new logic so a regression that re-introduces the
// drop-on-future-slot pathway (#788) lights up immediately.
// ----------------------------------------------------------------------

const FutureSlotTestFixture = struct {
    arena: std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
    mock_chain: stf.MockChainData,
    chain_config: configs.ChainConfig,
    beam_state: types.BeamState,
    zeam_logger_config: zeam_utils.ZeamLoggerConfig,
    tmp_dir: std.testing.TmpDir,
    db: database.Db,
    connected_peers: *ConnectedPeers,
    test_registry: *NodeNameRegistry,
    beam_chain: *BeamChain,

    fn init(parent_allocator: std.mem.Allocator) !*FutureSlotTestFixture {
        const fx = try parent_allocator.create(FutureSlotTestFixture);
        fx.arena = std.heap.ArenaAllocator.init(parent_allocator);
        fx.allocator = fx.arena.allocator();

        fx.mock_chain = try stf.genMockChain(fx.allocator, 4, null);
        const spec_name = try fx.allocator.dupe(u8, "beamdev");
        const fork_digest = try fx.allocator.dupe(u8, "12345678");
        fx.chain_config = configs.ChainConfig{
            .id = configs.Chain.custom,
            .genesis = fx.mock_chain.genesis_config,
            .spec = .{
                .preset = params.Preset.mainnet,
                .name = spec_name,
                .fork_digest = fork_digest,
                .attestation_committee_count = 1,
                .max_attestations_data = 16,
            },
        };
        fx.beam_state = fx.mock_chain.genesis_state;
        fx.zeam_logger_config = zeam_utils.getTestLoggerConfig();

        fx.tmp_dir = std.testing.tmpDir(.{});
        const data_dir = try std.fmt.allocPrint(fx.allocator, ".zig-cache/tmp/{s}", .{fx.tmp_dir.sub_path});
        fx.db = try database.Db.open(fx.allocator, fx.zeam_logger_config.logger(.database_test), data_dir);

        fx.connected_peers = try fx.allocator.create(ConnectedPeers);
        fx.connected_peers.* = ConnectedPeers.init(fx.allocator);

        fx.test_registry = try fx.allocator.create(NodeNameRegistry);
        fx.test_registry.* = NodeNameRegistry.init(fx.allocator);

        fx.beam_chain = try fx.allocator.create(BeamChain);
        fx.beam_chain.* = try BeamChain.init(fx.allocator, ChainOpts{
            .config = fx.chain_config,
            .anchorState = &fx.beam_state,
            .nodeId = 0,
            .logger_config = &fx.zeam_logger_config,
            .db = fx.db,
            .node_registry = fx.test_registry,
        }, fx.connected_peers);
        return fx;
    }

    fn deinit(fx: *FutureSlotTestFixture, parent_allocator: std.mem.Allocator) void {
        fx.beam_chain.deinit();
        fx.test_registry.deinit();
        fx.db.deinit();
        fx.tmp_dir.cleanup();
        fx.arena.deinit();
        parent_allocator.destroy(fx);
    }
};

test "validateBlock #788: FutureSlotQueueable for block within queue tolerance" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    // Forkchoice clock starts at slot 0. A block at slot
    // MAX_FUTURE_SLOT_TOLERANCE + 1 (=2) is queueable but not immediately
    // processable; validateBlock should surface FutureSlotQueueable.
    var block = fx.mock_chain.blocks[1].block;
    block.slot = constants.MAX_FUTURE_SLOT_TOLERANCE + 1;

    try std.testing.expectError(
        error.FutureSlotQueueable,
        fx.beam_chain.validateBlock(block, true),
    );
}

test "validateBlock #788: FutureSlot hard-reject for block beyond queue tolerance" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    // Anything beyond MAX_FUTURE_SLOT_QUEUE_TOLERANCE is rejected as
    // FutureSlot — the hard reject that pre-#788 behaviour applied to
    // every future-slot block, now narrowed to the truly-bogus range.
    var block = fx.mock_chain.blocks[1].block;
    block.slot = constants.MAX_FUTURE_SLOT_QUEUE_TOLERANCE + 10;

    try std.testing.expectError(
        error.FutureSlot,
        fx.beam_chain.validateBlock(block, true),
    );
}

test "validateBlock #788: queue-tolerance boundary is inclusive" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    // current_slot=0 + MAX_FUTURE_SLOT_QUEUE_TOLERANCE is the highest
    // slot that should still be FutureSlotQueueable, not FutureSlot.
    // One slot beyond that flips to FutureSlot. Lock both sides of the
    // boundary so a future contributor cannot accidentally drop it by
    // one and silently re-introduce the #788 reset symptom.
    var block_at_boundary = fx.mock_chain.blocks[1].block;
    block_at_boundary.slot = constants.MAX_FUTURE_SLOT_QUEUE_TOLERANCE;
    try std.testing.expectError(
        error.FutureSlotQueueable,
        fx.beam_chain.validateBlock(block_at_boundary, true),
    );

    var block_just_past = fx.mock_chain.blocks[1].block;
    block_just_past.slot = constants.MAX_FUTURE_SLOT_QUEUE_TOLERANCE + 1;
    try std.testing.expectError(
        error.FutureSlot,
        fx.beam_chain.validateBlock(block_just_past, true),
    );
}

test "enqueuePendingBlock #788: deduplicates by root" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    const allocator = std.testing.allocator;

    // Clone the same block twice and enqueue both. Second enqueue
    // should be deduped — a peer can re-gossip the same block several
    // times during a clock-lag window and we must not pay the cost
    // (or memory) of re-running it.
    const signed = fx.mock_chain.blocks[1];
    var root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, signed.block, &root, allocator);

    var clone1: types.SignedBlock = undefined;
    try types.sszClone(allocator, types.SignedBlock, signed, &clone1);
    var clone2: types.SignedBlock = undefined;
    try types.sszClone(allocator, types.SignedBlock, signed, &clone2);

    // Stash the chain's allocator so we hand the clones to it (matches
    // how `onGossip` does it via `self.allocator`). Use that here too.
    const chain_allocator = fx.beam_chain.allocator;
    var clone1_in_chain: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, signed, &clone1_in_chain);
    var clone2_in_chain: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, signed, &clone2_in_chain);
    clone1.deinit();
    clone2.deinit();

    const first = fx.beam_chain.enqueuePendingBlock(clone1_in_chain, root);
    try std.testing.expect(first);
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);

    const second = fx.beam_chain.enqueuePendingBlock(clone2_in_chain, root);
    try std.testing.expect(!second);
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);
}

test "enqueuePendingBlock #788: cap eviction drops oldest by receive order" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    const chain_allocator = fx.beam_chain.allocator;

    // Fill the queue to capacity with synthetic distinct blocks (we
    // re-use the same block but bump `slot` to give each a distinct
    // root, since dedup is by root). Then push one more and verify
    // the queue stays at MAX_PENDING_BLOCKS and the new block is at
    // the tail.
    const base = fx.mock_chain.blocks[1];
    var i: usize = 0;
    while (i < constants.MAX_PENDING_BLOCKS) : (i += 1) {
        var clone: types.SignedBlock = undefined;
        try types.sszClone(chain_allocator, types.SignedBlock, base, &clone);
        // Distinct slot → distinct root after re-hash.
        clone.block.slot = @intCast(i + 100);
        var root: types.Root = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlock, clone.block, &root, chain_allocator);
        const ok = fx.beam_chain.enqueuePendingBlock(clone, root);
        try std.testing.expect(ok);
    }
    try std.testing.expectEqual(constants.MAX_PENDING_BLOCKS, fx.beam_chain.pending_blocks.items.len);

    // The first slot in the queue is currently 100 (the oldest by
    // receive order). Enqueue one more; the cap-evictor must drop
    // slot=100 and leave a length-MAX queue with slot=200..MAX+99.
    var newest: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, base, &newest);
    newest.block.slot = constants.MAX_PENDING_BLOCKS + 200;
    var newest_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, newest.block, &newest_root, chain_allocator);

    const ok = fx.beam_chain.enqueuePendingBlock(newest, newest_root);
    try std.testing.expect(ok);
    try std.testing.expectEqual(constants.MAX_PENDING_BLOCKS, fx.beam_chain.pending_blocks.items.len);
    // Front is no longer slot=100 (it was evicted).
    try std.testing.expect(fx.beam_chain.pending_blocks.items[0].signed_block.block.slot != 100);
    // Tail is the newly-inserted block.
    const last = fx.beam_chain.pending_blocks.items[constants.MAX_PENDING_BLOCKS - 1];
    try std.testing.expectEqual(@as(types.Slot, constants.MAX_PENDING_BLOCKS + 200), last.signed_block.block.slot);
}

test "enqueuePendingBlock #788: drops blocks before latest_finalized" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    const chain_allocator = fx.beam_chain.allocator;

    // Seed the queue with one fresh-slot entry, then artificially
    // raise `latest_finalized.slot` to a higher value to simulate the
    // case where queued entries fall behind finalization between
    // arrival and the next drain. enqueueing a new block triggers the
    // pre-finalized eviction sweep.
    var stale: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, fx.mock_chain.blocks[1], &stale);
    stale.block.slot = 5;
    var stale_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, stale.block, &stale_root, chain_allocator);
    try std.testing.expect(fx.beam_chain.enqueuePendingBlock(stale, stale_root));
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);

    // Move finalization forward past the queued entry (test-only
    // mutation; under the forkchoice's RwLock for the same reasons
    // the production path uses it).
    fx.beam_chain.forkChoice.mutex.lock();
    fx.beam_chain.forkChoice.fcStore.latest_finalized.slot = 100;
    fx.beam_chain.forkChoice.mutex.unlock();

    // Enqueue a fresh future block; the helper's pre-finalized sweep
    // should drop the stale entry and accept the fresh one, leaving
    // a length-1 queue with the newer block.
    var fresh: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, fx.mock_chain.blocks[1], &fresh);
    fresh.block.slot = 200;
    var fresh_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, fresh.block, &fresh_root, chain_allocator);
    try std.testing.expect(fx.beam_chain.enqueuePendingBlock(fresh, fresh_root));
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);
    try std.testing.expectEqual(@as(types.Slot, 200), fx.beam_chain.pending_blocks.items[0].signed_block.block.slot);
}

test "processPendingBlocks #788: evicts pre-finalized entries during scan" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    const chain_allocator = fx.beam_chain.allocator;

    // Queue an entry, then move finalization past it without going
    // through enqueue (so the gossip-path sweep doesn't get a chance).
    // processPendingBlocks must still drop it during its own scan.
    var stale: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, fx.mock_chain.blocks[1], &stale);
    stale.block.slot = 5;
    var stale_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, stale.block, &stale_root, chain_allocator);
    try std.testing.expect(fx.beam_chain.enqueuePendingBlock(stale, stale_root));

    fx.beam_chain.forkChoice.mutex.lock();
    fx.beam_chain.forkChoice.fcStore.latest_finalized.slot = 100;
    fx.beam_chain.forkChoice.mutex.unlock();

    const missing = fx.beam_chain.processPendingBlocks();
    defer chain_allocator.free(missing);
    try std.testing.expectEqual(@as(usize, 0), fx.beam_chain.pending_blocks.items.len);
}

// PR #841 review #10: drain-side eviction of "too-far-future" entries.
// An adversary that floods with blocks at `current_slot + 200` (within
// MAX_FUTURE_SLOT_QUEUE_TOLERANCE = 256 so accepted into queue) leaves
// them sitting in the queue forever — they never become processable
// until the forkchoice clock advances by 200 slots. The drain now
// evicts them in the same compaction pass that handles pre-finalized.
test "processPendingBlocks #788: evicts too-far-future entries during scan" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    const chain_allocator = fx.beam_chain.allocator;

    // Queue an entry near the queue's upper bound while the forkchoice
    // clock is still at slot 0. The bound is
    //   `current_slot + MAX_FUTURE_SLOT_QUEUE_TOLERANCE`
    // so anything strictly greater is "too far" by the drain's
    // contract. We pick `+ TOLERANCE + 1` to live exactly one slot
    // beyond the cutoff. enqueuePendingBlock itself does NOT enforce
    // this rule (validateBlock does at gossip ingress), so we can
    // legitimately have such an entry in the queue if e.g. a previous
    // build tolerated a wider window or finalization advancement
    // shifted the boundary.
    var entry: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, fx.mock_chain.blocks[1], &entry);
    entry.block.slot = constants.MAX_FUTURE_SLOT_QUEUE_TOLERANCE + 1;
    var entry_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, entry.block, &entry_root, chain_allocator);
    try std.testing.expect(fx.beam_chain.enqueuePendingBlock(entry, entry_root));
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);

    // current_slot stays at 0 (forkchoice clock has not advanced),
    // so the entry's slot strictly exceeds
    //   current_slot +| MAX_FUTURE_SLOT_QUEUE_TOLERANCE = 0 + 256 = 256.
    // The drain must evict it.
    const missing = fx.beam_chain.processPendingBlocks();
    defer chain_allocator.free(missing);
    try std.testing.expectEqual(@as(usize, 0), fx.beam_chain.pending_blocks.items.len);
}

// PR #841 review #9: append_oom path coverage. The capacity
// reservation in `enqueuePendingBlock` MUST fail before the
// cap-eviction so an allocator failure does not lose two blocks per
// OOM event (one evicted, one rejected). Use a FailingAllocator
// pinned to the chain's pending-blocks ArrayList so we can drive it
// to OOM on the reservation step deterministically.
test "enqueuePendingBlock #788: append_oom path returns false without evicting" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    // Construct a SignedBlock owned by a FailingAllocator. The clone
    // we pass into `enqueuePendingBlock` lives off `failing_alloc`;
    // failing_alloc.fail_index = 0 means "every alloc fails". The
    // ArrayList's `ensureUnusedCapacity(allocator, 1)` is the first
    // allocation it makes after the queue’s steady-state buffer is
    // already at MAX_PENDING_BLOCKS, so a fresh, empty queue with no
    // backing capacity will hit the failing-allocator on the
    // reservation step.
    //
    // We replace the chain's pending_blocks with a fresh ArrayList
    // backed by the FailingAllocator (its allocator is what the
    // helper passes through), then issue an enqueue and assert: (a)
    // returns false, (b) bumps `append_oom`, (c) does NOT bump `cap`
    // (no eviction took place), (d) the queue stays empty.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const failing_alloc = failing.allocator();

    // Swap in a fresh ArrayList allocated under the failing allocator.
    // The chain's lock isn't yet contended (single-threaded test) so
    // direct field assignment is safe; we restore the original at end.
    const orig = fx.beam_chain.pending_blocks;
    fx.beam_chain.pending_blocks = .empty;
    defer {
        // Drain whatever the failing-allocator queue ended up holding
        // (it should be empty post-test) and free its tiny backing
        // buffer through the same allocator. Then restore.
        for (fx.beam_chain.pending_blocks.items) |*e| e.signed_block.deinit();
        fx.beam_chain.pending_blocks.deinit(failing_alloc);
        fx.beam_chain.pending_blocks = orig;
    }

    // Stash the chain's allocator pointer so enqueuePendingBlock uses
    // the failing one for `ensureUnusedCapacity`. The chain stores
    // its allocator in a single field; flip it for the test only.
    const orig_alloc = fx.beam_chain.allocator;
    fx.beam_chain.allocator = failing_alloc;
    defer fx.beam_chain.allocator = orig_alloc;

    // Build the candidate clone using the parent (real) allocator so
    // its construction itself doesn't OOM.
    var clone: types.SignedBlock = undefined;
    try types.sszClone(orig_alloc, types.SignedBlock, fx.mock_chain.blocks[1], &clone);
    var clone_root: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, clone.block, &clone_root, orig_alloc);

    // ensureUnusedCapacity(failing_alloc, 1) hits the FailingAllocator
    // and returns error.OutOfMemory; enqueuePendingBlock catches it,
    // deinits the candidate, bumps the metric, returns false.
    const queued = fx.beam_chain.enqueuePendingBlock(clone, clone_root);
    try std.testing.expect(!queued);

    // Queue stayed empty (no eviction happened on the way in).
    try std.testing.expectEqual(@as(usize, 0), fx.beam_chain.pending_blocks.items.len);

    // Sanity: the FailingAllocator saw zero successful allocations
    // (the only attempt — the capacity reservation — was rejected).
    // The `allocations` counter on FailingAllocator only increments
    // on success; the rejection still counted as the `fail_index = 0`
    // branch, so this asserts the failure path was taken.
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
}

// PR #841 review #4/#5: dedup compares cached roots, not re-hashed
// blocks. The cap-1024 worst case used to do 1024 SSZ tree-hashes per
// duplicate-check; now it does 1024 32-byte memcmp's. Lock the
// behaviour in code so a future contributor cannot accidentally drop
// `PendingBlockEntry.block_root` and silently regress the perf.
test "enqueuePendingBlock #788: dedup uses cached root, not re-hash" {
    var fx = try FutureSlotTestFixture.init(std.testing.allocator);
    defer fx.deinit(std.testing.allocator);

    const chain_allocator = fx.beam_chain.allocator;

    // Enqueue one legitimate entry.
    var clone1: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, fx.mock_chain.blocks[1], &clone1);
    clone1.block.slot = 50;
    var root1: types.Root = undefined;
    try zeam_utils.hashTreeRoot(types.BeamBlock, clone1.block, &root1, chain_allocator);
    try std.testing.expect(fx.beam_chain.enqueuePendingBlock(clone1, root1));
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);

    // The queued entry should carry its precomputed root verbatim
    // (this is the data the dedup loop reads).
    try std.testing.expect(
        std.mem.eql(u8, &fx.beam_chain.pending_blocks.items[0].block_root, &root1),
    );

    // Enqueue a second clone of the SAME block (same root). The dedup
    // loop must hit on memcmp without re-hashing either side, and the
    // duplicate must be dropped (return false).
    var clone2: types.SignedBlock = undefined;
    try types.sszClone(chain_allocator, types.SignedBlock, clone1, &clone2);
    const dedup_result = fx.beam_chain.enqueuePendingBlock(clone2, root1);
    try std.testing.expect(!dedup_result);
    try std.testing.expectEqual(@as(usize, 1), fx.beam_chain.pending_blocks.items.len);
}

// PR #841 review #13: lock the metrics scrape contract for the
// future-block queue so a struct rename or serializer regression
// fails CI here, not silently in production. Mirrors the slice-(b)
// LockTimer → /metrics audit pattern (`pkgs/node/src/locking.zig`)
// and the slice-c-2b commit-5 refcount-distribution audit.
//
// We don't need to drive a real chain end-to-end — just exercise the
// Counter/Gauge handles the chain code uses and assert each metric
// name + every label appears in the Prometheus body. If any of the
// four metrics gets dropped from the `Metrics` struct, gets renamed,
// or loses a label, this test fails immediately.
test "#788 metrics: queue + drop counters appear in /metrics output" {
    if (zeam_metrics.isZKVM()) return;

    try zeam_metrics.init(std.heap.page_allocator);

    // Set / bump every label so the scrape body contains a sample
    // line for each. The `catch {}` mirrors production usage —
    // production code never fails-closed on a metric write.
    zeam_metrics.metrics.lean_pending_blocks_depth.set(7);
    zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "cap" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "pre_finalized" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "too_far_future" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "duplicate" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_evicted_total.incr(.{ .reason = "append_oom" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_replayed_total.incr(.{ .result = "accepted" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_replayed_total.incr(.{ .result = "rejected" }) catch {};
    zeam_metrics.metrics.lean_pending_blocks_replayed_total.incr(.{ .result = "error" }) catch {};
    zeam_metrics.metrics.lean_blocks_future_slot_dropped_total.incr();

    var alloc_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer alloc_writer.deinit();
    try zeam_metrics.writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    // Top-level metric families must be advertised.
    try std.testing.expect(std.mem.indexOf(u8, body, "lean_pending_blocks_depth") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "lean_pending_blocks_evicted_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "lean_pending_blocks_replayed_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "lean_blocks_future_slot_dropped_total") != null);

    // Every label used by the production code must show up at least
    // once — this is what catches a label rename / typo regression.
    const evict_labels = [_][]const u8{
        "reason=\"cap\"",
        "reason=\"pre_finalized\"",
        "reason=\"too_far_future\"",
        "reason=\"duplicate\"",
        "reason=\"append_oom\"",
    };
    for (evict_labels) |lbl| {
        try std.testing.expect(std.mem.indexOf(u8, body, lbl) != null);
    }
    const replay_labels = [_][]const u8{
        "result=\"accepted\"",
        "result=\"rejected\"",
        "result=\"error\"",
    };
    for (replay_labels) |lbl| {
        try std.testing.expect(std.mem.indexOf(u8, body, lbl) != null);
    }

    // Concrete value lines: locks the gauge↑/counter↑writeMetrics
    // contract beyond just "the name appears".
    try std.testing.expect(std.mem.indexOf(u8, body, "lean_pending_blocks_depth 7") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "lean_blocks_future_slot_dropped_total 1") != null);
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
    const post_state_rc = beam_chain.states.get(produced.blockRoot) orelse @panic("post state should exist");
    try std.testing.expect(post_state_rc.state.latest_justified.slot >= 1);

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

        var cloned_value: types.BeamState = undefined;
        try types.sszClone(std.testing.allocator, types.BeamState, mock_chain.genesis_state, &cloned_value);
        const cloned_rc = try RcBeamState.create(std.testing.allocator, cloned_value);
        // Insert directly under exclusive lock (test-internal access).
        beam_chain.states_lock.lock();
        try beam_chain.states.put(r, cloned_rc);
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
                if (ctx.chain.statesFetchRemoveExclusivePtr("test.pruner", r)) |rc_ptr| {
                    rc_ptr.release();
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

test "chain.statesCommitKeepExisting: getOrPut OOM releases caller rc (no leak)" {
    // Regression for the post_state_rc leak Partha caught on PR #828:
    // statesCommitKeepExisting flips its rc-ownership-transfer at the
    // `getOrPut` step; if `getOrPut` itself OOMs, the helper is the
    // ONLY place that knows about the rc (the upstream caller in
    // onBlock has already flipped `post_state_settled = true` to keep
    // the outer errdefer from double-freeing the now-Rc-wrapped
    // BeamState). Without an `errdefer rc.release()` covering the
    // OOM path, the freshly-`create`d rc + its heap-owned BeamState
    // interior leak permanently. testing.allocator's leak detector
    // catches the regression: this test passes ONLY when the helper
    // releases the rc on its own OOM path.
    //
    // Mechanism:
    //   1. Build a real BeamChain with testing.allocator so the chain
    //      is fully functional and tear-down works.
    //   2. Swap the chain's `states` map allocator with a
    //      FailingAllocator that fails its very first allocation.
    //      AutoHashMap exposes its allocator as a public field, so
    //      this is a one-line swap.
    //   3. Build a BeamState + RcBeamState the same way `onBlock`
    //      does (sszClone the genesis state, wrap with
    //      RcBeamState.create — both via testing.allocator so the
    //      FailingAllocator only affects the map).
    //   4. Pick a fresh root that is NOT already in the map (so the
    //      getOrPut triggers a backing-array grow that fails — the
    //      genesis root would hit the found_existing branch and not
    //      reach the OOM site).
    //   5. Call statesCommitKeepExisting and expect OutOfMemory. The
    //      helper must release the caller's rc; testing.allocator
    //      then verifies no leak at scope exit.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 2, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

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

    // To make `getOrPut` actually fail under the FailingAllocator we
    // need to FORCE a grow. After init, the states map has spare
    // capacity (only genesis is in it), so a single insert would just
    // land in the existing buffer with no allocation — bypassing the
    // FailingAllocator entirely.
    //
    // The hash map's `unmanaged.available` field tracks remaining
    // slots before a grow is triggered (see std/hash_map.zig
    // `growIfNeeded`: `new_count > self.available` → grow). Set it
    // to 0 so the very next insert MUST grow. This is white-box but
    // it's the cleanest deterministic way to put the map in the
    // "next insert grows" state without poking real-data invariants:
    // we never call any other map method between this poke and the
    // helper-under-test call, so the only thing observing
    // `available == 0` is `growIfNeeded` itself — exactly the path
    // we want to fail. Restore the original `available` before
    // deinit so the chain's teardown path doesn't trip on a stale
    // value (deinit only iterates and releases; it shouldn't matter
    // for the iteration walk, but defensive restoration is cheap).
    const original_available = beam_chain.states.unmanaged.available;
    beam_chain.states.unmanaged.available = 0;
    defer beam_chain.states.unmanaged.available = original_available;

    // Now swap the states map allocator with a FailingAllocator.
    // The next `getOrPut` of a NEW key will need to grow the backing
    // array; the very first allocation through the FailingAllocator
    // returns null → OutOfMemory. Restore before deinit so the chain's
    // own teardown path uses the real allocator.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const original_states_allocator = beam_chain.states.allocator;
    beam_chain.states.allocator = failing.allocator();
    defer beam_chain.states.allocator = original_states_allocator;

    // Build the rc the way onBlock does: clone genesis state into a
    // fresh value, hand to RcBeamState.create. Both via
    // testing.allocator so the FailingAllocator above only affects
    // the states map.
    var cloned_value: types.BeamState = undefined;
    try types.sszClone(std.testing.allocator, types.BeamState, mock_chain.genesis_state, &cloned_value);
    const post_state_rc = try RcBeamState.create(std.testing.allocator, cloned_value);
    // No errdefer post_state_rc.release() here — the helper under
    // test is responsible for releasing it on its own OOM path.
    // That IS the contract this test pins.

    // A root that is NOT already in the map (genesis root WOULD be
    // there, which would hit the found_existing branch and never
    // reach the OOM site). Use a synthetic non-zero root distinct
    // from any filler key.
    var fresh_root = std.mem.zeroes(types.Root);
    std.mem.writeInt(u64, fresh_root[0..8], 0xDEAD_BEEF_CAFE_BABE, .little);

    const result = beam_chain.statesCommitKeepExisting(
        "test.oom_regression",
        fresh_root,
        post_state_rc,
    );
    try std.testing.expectError(error.OutOfMemory, result);

    // states_lock must be released — try a quick exclusive
    // lock+unlock to prove no thread is hung on it. tryLock would be
    // ideal but SyncRwLock doesn't expose one; a successful
    // lock()/unlock() pair after the failed call is the same proof
    // (any leak of the lock would deadlock here forever; CI timeout
    // would catch that, but in practice the lock IS released by the
    // helper's errdefer). Doing a real lock here also means the
    // chain's deinit path doesn't have to fight a held lock.
    beam_chain.states_lock.lock();
    beam_chain.states_lock.unlock();

    // The freshly-created rc must NOT have made it into the map
    // (getOrPut failed before insertion). Genesis must still be the
    // sole entry under the genesis root.
    try std.testing.expect(beam_chain.states.get(fresh_root) == null);
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

test "chain: concurrent re-import pressure — kept_existing path race + attestation spam" {
    // Slice (b) cross-thread test scenario: two onBlock threads race
    // the import of the SAME block sequence in opposite orders
    // (forward 1..N, reverse N..1) while an attestation thread spams
    // mixed-validity attestations. This is NOT a reorg test — we
    // never build a divergent fork. What we exercise is the
    // statesCommitKeepExisting / kept_existing path under contention:
    // whichever importer wins the race for a given block populates
    // `states`; the loser then takes the kept_existing branch and
    // frees its redundantly-computed post-state. (A real reorg test
    // would need genMockChain to expose a fork-from-shared-parent
    // helper; not in scope for slice (b).)
    //
    // The contract under test:
    //
    //   * Forkchoice settles on a single head after all imports finish.
    //   * No panic / UAF in the attestation pool (events_lock +
    //     forkchoice attestation map are concurrently mutated).
    //   * statesGet on the eventual head root succeeds and the slot
    //     is coherent with one of the imported chain tips.
    //   * The kept_existing branch is actually exercised
    //     (`states_kept_existing_count` strictly increases) — without
    //     this, the test would silently pass on a serialized run.
    //
    // Iteration count is modest (50) so the whole test stays under ~30s
    // in Debug. Each iteration builds a fresh BeamChain, imports the
    // shared mock chain, and then concurrently re-imports + spams
    // attestations. The slow part is XMSS attestation signing; we limit
    // attestation messages per iteration to keep runtime sane.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // 4-block mock chain shared across all iterations as the import
    // template. We don't fork — see the test header for the rationale.
    const mock_chain = try stf.genMockChain(arena, 4, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    const ITERS: usize = 50;
    var iter: usize = 0;
    while (iter < ITERS) : (iter += 1) {
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
            .nodeId = 21,
            .logger_config = &zeam_logger_config,
            .db = db,
            .node_registry = test_registry,
        }, connected_peers);
        defer beam_chain.deinit();

        // Advance forkchoice clock past the last block's slot so block
        // imports are not FutureSlot-rejected and attestations are not
        // FutureSlot either.
        const last_slot = mock_chain.blocks[mock_chain.blocks.len - 1].block.slot;
        try beam_chain.forkChoice.onInterval((last_slot + 4) * constants.INTERVALS_PER_SLOT, false);

        const Ctx = struct {
            chain: *BeamChain,
            blocks: []types.SignedBlock,
            block_roots: []types.Root,
            attn_iters: usize,
            // counters
            imports_a: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            imports_b: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            attn_ok: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            // start barrier
            start: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
            ready: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
            fatal_msg: [128]u8 = undefined,
            fatal_set: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        };

        const Worker = struct {
            fn waitStart(ctx: *Ctx) void {
                _ = ctx.ready.fetchAdd(1, .acq_rel);
                while (ctx.start.load(.acquire) == 0) std.Thread.yield() catch {};
            }
            // Forward import 1..N
            fn importerForward(ctx: *Ctx) void {
                waitStart(ctx);
                for (1..ctx.blocks.len) |i| {
                    const missing = ctx.chain.onBlock(ctx.blocks[i], .{ .pruneForkchoice = false }) catch continue;
                    ctx.chain.allocator.free(missing);
                    _ = ctx.imports_a.fetchAdd(1, .monotonic);
                }
            }
            // Reverse import N..1 — different order = different
            // interleavings of forkchoice insert vs kept_existing.
            fn importerReverse(ctx: *Ctx) void {
                waitStart(ctx);
                var i: usize = ctx.blocks.len;
                while (i > 1) {
                    i -= 1;
                    const missing = ctx.chain.onBlock(ctx.blocks[i], .{ .pruneForkchoice = false }) catch continue;
                    ctx.chain.allocator.free(missing);
                    _ = ctx.imports_b.fetchAdd(1, .monotonic);
                }
            }
            fn attestationSpammer(ctx: *Ctx, key_manager: *keymanager.KeyManager) void {
                waitStart(ctx);
                const allocator = ctx.chain.allocator;
                var i: usize = 0;
                while (i < ctx.attn_iters) : (i += 1) {
                    const slot_idx = 1 + (i % (ctx.blocks.len - 1));
                    const target_root = ctx.block_roots[slot_idx];
                    const target_slot: types.Slot = ctx.blocks[slot_idx].block.slot;
                    const source_idx = if (slot_idx > 1) slot_idx - 1 else 0;
                    const validator_id: usize = i % 4;
                    const message = types.Attestation{
                        .validator_id = @intCast(validator_id),
                        .data = .{
                            .slot = target_slot,
                            .head = .{ .root = target_root, .slot = target_slot },
                            .source = .{ .root = ctx.block_roots[source_idx], .slot = ctx.blocks[source_idx].block.slot },
                            .target = .{ .root = target_root, .slot = target_slot },
                        },
                    };
                    const signature = key_manager.signAttestation(&message, allocator) catch continue;
                    const valid_attestation = types.SignedAttestation{
                        .validator_id = message.validator_id,
                        .message = message.data,
                        .signature = signature,
                    };
                    const subnet_id = types.computeSubnetId(
                        @intCast(valid_attestation.validator_id),
                        ctx.chain.config.spec.attestation_committee_count,
                    ) catch continue;
                    const gossip = networks.AttestationGossip{
                        .subnet_id = @intCast(subnet_id),
                        .message = valid_attestation,
                    };
                    ctx.chain.onGossipAttestation(gossip) catch continue;
                    _ = ctx.attn_ok.fetchAdd(1, .monotonic);
                }
            }
        };

        var key_manager = try keymanager.getTestKeyManager(std.testing.allocator, 4, mock_chain.blocks.len);
        defer key_manager.deinit();

        var ctx = Ctx{
            .chain = &beam_chain,
            .blocks = mock_chain.blocks,
            .block_roots = mock_chain.blockRoots,
            .attn_iters = 30,
        };

        var t_a = try std.Thread.spawn(.{}, Worker.importerForward, .{&ctx});
        var t_b = try std.Thread.spawn(.{}, Worker.importerReverse, .{&ctx});
        var t_c = try std.Thread.spawn(.{}, Worker.attestationSpammer, .{ &ctx, &key_manager });

        while (ctx.ready.load(.acquire) < 3) std.Thread.yield() catch {};
        ctx.start.store(1, .release);

        t_a.join();
        t_b.join();
        t_c.join();

        // Forkchoice must have settled on a single head.
        const head = beam_chain.forkChoice.getHead();
        // The head must be one of the imported block roots (or genesis
        // if every import failed, which would itself be a bug). At
        // minimum every block root must be observable in the chain.
        for (mock_chain.blockRoots[1..]) |r| {
            try std.testing.expect(beam_chain.forkChoice.hasBlock(r));
        }
        // The forward importer is deterministic on a fresh chain (each
        // parent is in `states` by the time we reach the next block),
        // so it MUST contribute every block. Use strict equality so a
        // future regression that breaks the forward path can't be
        // masked by the reverse importer's contributions.
        try std.testing.expectEqual(
            @as(u32, @intCast(mock_chain.blocks.len - 1)),
            ctx.imports_a.load(.monotonic),
        );
        // The kept_existing race surface MUST have been exercised at
        // least once during this iteration. This is the actual
        // assertion that distinguishes "two threads ran in parallel"
        // from "two threads serialized". The reverse importer's
        // success count is inherently racy (it depends on whether the
        // forward importer has populated states[block-1] yet) so we
        // assert via the kept_existing counter rather than
        // imports_b.
        try std.testing.expect(beam_chain.states_kept_existing_count.load(.monotonic) > 0);
        // Head's slot is finite and not in the future relative to last
        // imported slot.
        try std.testing.expect(head.slot <= last_slot);
        // statesGet on the head root must succeed.
        var head_borrow = beam_chain.statesGet(head.blockRoot) orelse {
            try std.testing.expect(false);
            unreachable;
        };
        const owned = try head_borrow.cloneAndRelease(std.testing.allocator);
        owned.deinit();
        std.testing.allocator.destroy(owned);
    }
}

test "chain: finalization race — onBlockFollowup + statesGet from API-shaped reader" {
    // Slice (b) cross-thread test scenario: while a writer thread imports
    // blocks and advances finalization (via onBlockFollowup), an
    // HTTP-API-shaped reader thread loops over chain.statesGet +
    // cloneAndRelease for both finalized and non-finalized roots.
    //
    // NOTE on iteration semantics: the writer's first pass over
    // blocks 1..N is the only pass that actually advances
    // finalization. Subsequent passes hit `kept_existing` in
    // statesCommitKeepExisting and onBlockFollowup is then a no-op
    // for finalization. The outer `iters` loop therefore exists to
    // give the readers enough wall-clock to race against the *first*
    // pass and to exercise the kept_existing-vs-statesGet contention
    // afterwards — it is NOT 20 independent finalization advances.
    // The `>0` finalized-observation assertion below ensures we
    // actually hit the racing window at least once; otherwise the
    // test would pass even if finalization never advanced.
    //
    // The contract under test:
    //
    //   * No UAF in the reader: every cloneAndRelease either returns a
    //     coherent state or null (entry pruned away during the borrow
    //     opportunity window — acceptable, the reader retries).
    //   * No torn read: every observed slot is one of the imported
    //     slots (or 0 for genesis).
    //   * No deadlock: the test must complete in well under 30s.
    //   * latest_finalized as observed via forkChoice.getLatestFinalized
    //     never goes backwards across reader observations.
    //   * At least one reader observation saw `latest_finalized.slot > 0`
    //     (proves finalization actually advanced during the race window;
    //     guards against a regression that silently never finalizes).
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 6, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

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
        .nodeId = 22,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    const last_slot = mock_chain.blocks[mock_chain.blocks.len - 1].block.slot;
    try beam_chain.forkChoice.onInterval((last_slot + 4) * constants.INTERVALS_PER_SLOT, false);

    const Ctx = struct {
        chain: *BeamChain,
        blocks: []types.SignedBlock,
        block_roots: []types.Root,
        iters: usize,
        writer_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        reader_ok: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        reader_null: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        reader_torn: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        finalized_regression: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        /// Maximum `latest_finalized.slot` observed by any reader
        /// across the whole run. Asserting this is `>0` guards
        /// against a regression where finalization silently never
        /// advances during the race window.
        max_observed_finalized_slot: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        start: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
        ready: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    };

    const Worker = struct {
        fn waitStart(ctx: *Ctx) void {
            _ = ctx.ready.fetchAdd(1, .acq_rel);
            while (ctx.start.load(.acquire) == 0) std.Thread.yield() catch {};
        }
        // Writer: import blocks 1..N, calling onBlockFollowup after
        // each. onBlockFollowup is what drives processFinalizationAdvancement.
        fn writer(ctx: *Ctx) void {
            waitStart(ctx);
            var i: usize = 0;
            while (i < ctx.iters) : (i += 1) {
                for (1..ctx.blocks.len) |k| {
                    const missing = ctx.chain.onBlock(ctx.blocks[k], .{ .pruneForkchoice = false }) catch continue;
                    ctx.chain.allocator.free(missing);
                    // Drive followup so finalization advances on the
                    // canonical chain. signedBlock parameter is unused
                    // by current impl (per source).
                    ctx.chain.onBlockFollowup(false, null);
                }
            }
            ctx.writer_done.store(true, .release);
        }
        // Reader: HTTP-API-shaped pattern — statesGet on a random known
        // root, cloneAndRelease, sanity-check the slot. Loop until
        // writer signals done. Also tracks latest_finalized monotonicity.
        fn reader(ctx: *Ctx) void {
            waitStart(ctx);
            var prng = std.Random.DefaultPrng.init(0x517A715A);
            const rand = prng.random();
            var last_finalized_slot: types.Slot = 0;
            const allocator = ctx.chain.allocator;
            while (!ctx.writer_done.load(.acquire)) {
                const idx = rand.uintLessThan(usize, ctx.block_roots.len);
                const root = ctx.block_roots[idx];
                if (ctx.chain.statesGet(root)) |b| {
                    var borrow = b;
                    const owned = borrow.cloneAndRelease(allocator) catch {
                        continue;
                    };
                    defer {
                        owned.deinit();
                        allocator.destroy(owned);
                    }
                    var coherent = owned.slot == 0;
                    if (!coherent) {
                        for (ctx.blocks) |bl| {
                            if (bl.block.slot == owned.slot) {
                                coherent = true;
                                break;
                            }
                        }
                    }
                    if (coherent) {
                        _ = ctx.reader_ok.fetchAdd(1, .monotonic);
                    } else {
                        _ = ctx.reader_torn.fetchAdd(1, .monotonic);
                    }
                } else {
                    _ = ctx.reader_null.fetchAdd(1, .monotonic);
                }
                // Monotonicity check on latest_finalized.
                const lf = ctx.chain.forkChoice.getLatestFinalized();
                if (lf.slot < last_finalized_slot) {
                    _ = ctx.finalized_regression.fetchAdd(1, .monotonic);
                }
                last_finalized_slot = lf.slot;
                // Track the highest finalized slot any reader has
                // observed (compare-and-swap loop; `max` is not yet
                // a built-in atomic op).
                var prev_max = ctx.max_observed_finalized_slot.load(.monotonic);
                while (lf.slot > prev_max) {
                    if (ctx.max_observed_finalized_slot.cmpxchgWeak(
                        prev_max,
                        lf.slot,
                        .monotonic,
                        .monotonic,
                    )) |actual| {
                        prev_max = actual;
                    } else break;
                }
            }
        }
    };

    var ctx = Ctx{
        .chain = &beam_chain,
        .blocks = mock_chain.blocks,
        .block_roots = mock_chain.blockRoots,
        .iters = 20,
    };

    var t_w = try std.Thread.spawn(.{}, Worker.writer, .{&ctx});
    var t_r1 = try std.Thread.spawn(.{}, Worker.reader, .{&ctx});
    var t_r2 = try std.Thread.spawn(.{}, Worker.reader, .{&ctx});

    while (ctx.ready.load(.acquire) < 3) std.Thread.yield() catch {};
    ctx.start.store(1, .release);

    t_w.join();
    t_r1.join();
    t_r2.join();

    // Contract: no torn reads, no finalization regressions.
    try std.testing.expectEqual(@as(u32, 0), ctx.reader_torn.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 0), ctx.finalized_regression.load(.monotonic));
    // Sanity: at least some successful reads happened (otherwise the
    // race window collapsed and the test proves nothing).
    try std.testing.expect(ctx.reader_ok.load(.monotonic) > 100);
    // Critical: the readers must have actually observed finalization
    // advance to a non-zero slot during the race window. Without this
    // assertion the test would pass on a regression that silently
    // failed to finalize — the no-torn-read + no-regression checks
    // would still trivially hold on a chain stuck at genesis.
    try std.testing.expect(ctx.max_observed_finalized_slot.load(.monotonic) > 0);
}

test "chain-worker: end-to-end submitBlock advances state via the worker thread" {
    // Slice c-2b commit 3 of #803 integration test.
    //
    // Boots a BeamChain with the chain-worker started, submits a real
    // block via `submitBlock` (the worker-routed producer wrapper),
    // waits for the worker to drain its queue, and asserts the chain
    // state advanced as if the synchronous path had been taken:
    //
    //   * `states` map gains an entry for the imported block root.
    //   * `forkChoice.hasBlock(root)` is true.
    //   * The post-state's slot matches the imported block.
    //
    // This exercises every layer the commit touches end-to-end:
    //
    //   producer thread (this test) ──submitBlock──▶ BlockQueue
    //   ChainWorker.runLoop ──tryRecv──▶ dispatch ──vtable──▶
    //   chainWorkerOnBlockThunk ──▶ BeamChain.onBlock + onBlockFollowup
    //
    // We deliberately do NOT use the BeamChain ctor's auto-start path
    // (there is none), instead calling `startChainWorker()` after the
    // chain is at its final stack address. This mirrors the production
    // call site in `BeamNode.init` which does the same after the chain
    // is at its heap address. (The chain in this test is on the test
    // function's stack, but doesn't move once allocated, which is
    // sufficient for the worker's lifetime here.)
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 3, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

    // spec_name + fork_digest live as long as the chain (BeamChain.deinit
    // frees them via self.allocator).
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

    var db = try database.Db.open(
        std.testing.allocator,
        zeam_logger_config.logger(.database_test),
        data_dir,
    );
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
        .nodeId = 0,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    // Start the chain-worker. After this point any submit* call may
    // race with the worker thread; deinit (via defer above) calls
    // `chain_worker.stop()` first which is the only safe shutdown
    // ordering.
    try beam_chain.startChainWorker();
    try std.testing.expect(beam_chain.chain_worker != null);

    // Advance forkchoice clock past the imported block's slot so the
    // worker's onBlock call doesn't reject with FutureSlot.
    const signed_block = mock_chain.blocks[1];
    const block_root = mock_chain.blockRoots[1];
    try beam_chain.forkChoice.onInterval(
        signed_block.block.slot * constants.INTERVALS_PER_SLOT,
        false,
    );

    // The worker takes ownership of the SignedBlock on a successful
    // send, so we must clone the mock-chain block (which is owned by
    // the arena and will be freed when the arena deinits, NOT by the
    // worker after dispatch).
    var cloned: types.SignedBlock = undefined;
    try types.sszClone(std.testing.allocator, types.SignedBlock, signed_block, &cloned);
    var cloned_consumed = false;
    errdefer if (!cloned_consumed) cloned.deinit();

    // Slice (e) of #803: pass `null` for `block_root` so the
    // worker recomputes — this test deliberately exercises the
    // fallback path. End-to-end gossip path coverage runs through
    // the chain-worker stress harness in `stress.zig`.
    try beam_chain.submitBlock(cloned, false, null);
    cloned_consumed = true;

    // Wait for the worker to drain the queue. We poll on the
    // states map (the post-condition we actually care about); the
    // forkchoice insert happens synchronously inside onBlock and
    // states is populated by `statesCommitKeepExisting` shortly
    // after, so observing the entry is the strongest single signal
    // that the message was processed end-to-end.
    //
    // 5s timeout is generous: a single STF on this 9-validator
    // mock chain is well under 100 ms in Debug.
    const start_ns = zeam_utils.monotonicTimestampNs();
    const deadline_ns: i128 = start_ns + 5 * std.time.ns_per_s;
    var observed = false;
    while (zeam_utils.monotonicTimestampNs() < deadline_ns) {
        beam_chain.states_lock.lockShared();
        const present = beam_chain.states.get(block_root) != null;
        beam_chain.states_lock.unlockShared();
        if (present) {
            observed = true;
            break;
        }
        std.Thread.yield() catch {};
    }
    try std.testing.expect(observed);

    // Forkchoice must have observed the import.
    try std.testing.expect(beam_chain.forkChoice.hasBlock(block_root));

    // Post-state slot must match the imported block.
    var borrow = beam_chain.statesGet(block_root) orelse {
        try std.testing.expect(false);
        unreachable;
    };
    defer borrow.deinit();
    try std.testing.expectEqual(signed_block.block.slot, borrow.state.slot);

    // Disabled-mode contract: with no worker, the submit* family
    // returns ChainWorkerDisabled rather than silently doing the
    // synchronous path. We can't test that on this chain (the
    // worker is started), so spot-check it on a fresh chain.
    var beam_state_2: types.BeamState = undefined;
    try types.sszClone(std.testing.allocator, types.BeamState, mock_chain.genesis_state, &beam_state_2);
    defer beam_state_2.deinit();

    const spec_name_2 = try std.testing.allocator.dupe(u8, "beamdev");
    const fork_digest_2 = try std.testing.allocator.dupe(u8, "12345678");
    const chain_config_2 = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name_2,
            .fork_digest = fork_digest_2,
            .attestation_committee_count = 1,
            .max_attestations_data = 16,
        },
    };

    var tmp_dir_2 = std.testing.tmpDir(.{});
    defer tmp_dir_2.cleanup();
    var path_buf_2: [128]u8 = undefined;
    const data_dir_2 = try std.fmt.bufPrint(&path_buf_2, ".zig-cache/tmp/{s}", .{tmp_dir_2.sub_path});
    var db2 = try database.Db.open(
        std.testing.allocator,
        zeam_logger_config.logger(.database_test),
        data_dir_2,
    );
    defer db2.deinit();

    const connected_peers_2 = try std.testing.allocator.create(ConnectedPeers);
    defer std.testing.allocator.destroy(connected_peers_2);
    connected_peers_2.* = ConnectedPeers.init(std.testing.allocator);
    defer connected_peers_2.deinit();

    const registry_2 = try std.testing.allocator.create(NodeNameRegistry);
    defer std.testing.allocator.destroy(registry_2);
    registry_2.* = NodeNameRegistry.init(std.testing.allocator);
    defer registry_2.deinit();

    var beam_chain_off = try BeamChain.init(std.testing.allocator, ChainOpts{
        .config = chain_config_2,
        .anchorState = &beam_state_2,
        .nodeId = 1,
        .logger_config = &zeam_logger_config,
        .db = db2,
        .node_registry = registry_2,
    }, connected_peers_2);
    defer beam_chain_off.deinit();

    try std.testing.expect(beam_chain_off.chain_worker == null);
    // Caller still owns this clone (errdefer below frees it after the
    // expected ChainWorkerDisabled comes back).
    var off_cloned: types.SignedBlock = undefined;
    try types.sszClone(std.testing.allocator, types.SignedBlock, signed_block, &off_cloned);
    defer off_cloned.deinit();
    try std.testing.expectError(
        error.ChainWorkerDisabled,
        beam_chain_off.submitBlock(off_cloned, false, null),
    );
}

test "chain.statesGet under chain_worker enabled returns Backing.none + acquired_rc (slice c-2b commit 4)" {
    // Slice c-2b commit 4 of #803: when chain_worker != null, statesGet
    // takes the lock-free path — it tryAcquires the rc under the shared
    // lock, drops the lock, and returns a Backing.none borrow. This
    // test verifies the contract: the borrow is Backing.none, has a
    // non-null acquired_rc, and the rc refcount tracks acquire/release.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 2, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

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
    var db = try database.Db.open(
        std.testing.allocator,
        zeam_logger_config.logger(.database_test),
        data_dir,
    );
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
        .nodeId = 42,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    // Start the worker so chain_worker != null (this is the
    // --chain-worker=on runtime indicator).
    try beam_chain.startChainWorker();
    try std.testing.expect(beam_chain.chain_worker != null);

    const target_root = mock_chain.blockRoots[0]; // genesis root, populated by init

    // Snapshot refcount before the borrow.
    beam_chain.states_lock.lockShared();
    const rc_before = beam_chain.states.get(target_root).?;
    const refcount_before = rc_before.count();
    beam_chain.states_lock.unlockShared();
    try std.testing.expectEqual(@as(u32, 1), refcount_before);

    // Take a borrow.
    var borrow = beam_chain.statesGet(target_root) orelse {
        try std.testing.expect(false);
        unreachable;
    };

    // Verify lock-free shape: Backing.none + non-null acquired_rc.
    try std.testing.expect(borrow.backing == .none);
    try std.testing.expect(borrow.acquired_rc != null);
    try std.testing.expect(borrow.acquired_rc.? == rc_before);

    // Refcount must have bumped to 2 (map=1 + borrow=1).
    try std.testing.expectEqual(@as(u32, 2), rc_before.count());

    // Drop the borrow — refcount returns to 1 (map only).
    borrow.deinit();
    try std.testing.expectEqual(@as(u32, 1), rc_before.count());
}

test "chain.statesGet under chain_worker enabled does not block exclusive writers (slice c-2b commit 4)" {
    // The whole point of slice c-2b commit 4: a long-lived reader borrow
    // must NOT block an exclusive-side mutation by the chain worker
    // path. We hold a Backing.none borrow open across the lifetime of
    // a writer thread that takes the exclusive lock and inserts an
    // unrelated entry; under the old shared-held-for-borrow behavior
    // the writer would deadlock against the reader (or rather, block
    // until the reader released). A 1-second watchdog asserts the
    // writer completed within bound; a regression hangs CI rather
    // than silently passing.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const mock_chain = try stf.genMockChain(arena, 2, null);
    var zeam_logger_config = zeam_utils.getTestLoggerConfig();

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
    var db = try database.Db.open(
        std.testing.allocator,
        zeam_logger_config.logger(.database_test),
        data_dir,
    );
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
        .nodeId = 43,
        .logger_config = &zeam_logger_config,
        .db = db,
        .node_registry = test_registry,
    }, connected_peers);
    defer beam_chain.deinit();

    try beam_chain.startChainWorker();
    try std.testing.expect(beam_chain.chain_worker != null);

    const target_root = mock_chain.blockRoots[0];

    // Reader: take a long-lived borrow.
    var borrow = beam_chain.statesGet(target_root) orelse {
        try std.testing.expect(false);
        unreachable;
    };
    defer borrow.deinit();
    try std.testing.expect(borrow.backing == .none);

    // Writer: take the exclusive lock + insert an unrelated entry.
    // Under the OLD shared-held-for-borrow behavior this would block
    // until the reader released; under c-2b commit 4 the reader's
    // borrow does NOT hold the lock, so the writer completes
    // immediately.
    const WriterCtx = struct {
        chain: *BeamChain,
        genesis_state: *const types.BeamState,
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn run(ctx: *@This()) void {
            // Synthetic root distinct from genesis (zeroes); first byte 0xab.
            var fake_root: types.Root = std.mem.zeroes(types.Root);
            fake_root[0] = 0xab;

            var cloned_value: types.BeamState = undefined;
            types.sszClone(std.testing.allocator, types.BeamState, ctx.genesis_state.*, &cloned_value) catch return;
            const new_rc = RcBeamState.create(std.testing.allocator, cloned_value) catch return;

            // Take the exclusive side. With the lock-free reader this
            // returns immediately even though a borrow is alive in the
            // main thread.
            ctx.chain.states_lock.lock();
            ctx.chain.states.put(fake_root, new_rc) catch {
                ctx.chain.states_lock.unlock();
                new_rc.release();
                return;
            };
            ctx.chain.states_lock.unlock();
            ctx.done.store(true, .release);
        }
    };
    var writer_ctx = WriterCtx{
        .chain = &beam_chain,
        .genesis_state = &mock_chain.genesis_state,
    };
    var writer_thread = try std.Thread.spawn(.{}, WriterCtx.run, .{&writer_ctx});

    // Watchdog: spin for at most 1 second waiting for the writer.
    // Under a regression (e.g. a future change re-imposing the
    // shared-held-for-borrow shape) the writer would block on the
    // reader's borrow and this would time out.
    const start_ns = zeam_utils.monotonicTimestampNs();
    const deadline_ns: i128 = start_ns + 1 * std.time.ns_per_s;
    while (zeam_utils.monotonicTimestampNs() < deadline_ns) {
        if (writer_ctx.done.load(.acquire)) break;
        std.Thread.yield() catch {};
    }
    writer_thread.join();
    try std.testing.expect(writer_ctx.done.load(.acquire));

    // The reader's borrow is still valid even after the writer mutated
    // the map: refcount kept the underlying state alive.
    try std.testing.expectEqual(mock_chain.genesis_state.slot, borrow.state.slot);
}
