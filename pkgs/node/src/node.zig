const std = @import("std");
const Allocator = std.mem.Allocator;

pub const database = @import("@zeam/database");
const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");
const key_manager_lib = @import("@zeam/key-manager");
const stf = @import("@zeam/state-transition");
const zeam_metrics = @import("@zeam/metrics");
const ThreadPool = @import("@zeam/thread-pool").ThreadPool;

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;
const testing = @import("./testing.zig");

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");
pub const validatorClient = @import("./validator_client.zig");
const constants = @import("./constants.zig");
const forkchoice = @import("./forkchoice.zig");
const blocks_by_range_sync = @import("./blocks_by_range_sync.zig");

const BlockByRootContext = networkFactory.BlockByRootContext;
pub const NodeNameRegistry = networks.NodeNameRegistry;

const ZERO_HASH = types.ZERO_HASH;

const BlocksByRangeSyncEndReason = blocks_by_range_sync.SyncEndReason;
const BlocksByRangeSyncEndAction = blocks_by_range_sync.SyncEndAction;

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: *types.BeamState,
    backend: networks.NetworkInterface,
    clock: *clockFactory.Clock,
    validator_ids: ?[]usize = null,
    key_manager: ?*const key_manager_lib.KeyManager = null,
    nodeId: u32 = 0,
    db: database.Db,
    logger_config: *zeam_utils.ZeamLoggerConfig,
    node_registry: *const NodeNameRegistry,
    is_aggregator: bool = false,
    /// Explicit subnet ids to subscribe and import gossip attestations for aggregation
    aggregation_subnet_ids: ?[]const u32 = null,
    /// Shared worker pool for parallelizing CPU-bound chain work (signature verification).
    thread_pool: *ThreadPool,
    /// When true, the chain spawns a
    /// dedicated worker thread and producer-side handlers for
    /// gossip blocks / attestations route through its bounded
    /// queues instead of running synchronously on the libp2p
    /// thread. Default `true`: the worker
    /// path is the supported prod path. Surfaced to the CLI as
    /// `--chain-worker` (bool); `--chain-worker false` is the
    /// kill-switch for the legacy synchronous path.
    chain_worker_enabled: bool = true,
    /// CLI knob (`--min-aggregation-inputs`) for the per-att_data
    /// aggregation threshold; see `default_min_aggregation_inputs`.
    min_aggregation_inputs: u32 = types.default_min_aggregation_inputs,
    /// CLI knob (`--max-aggregation-children`) capping child STARK proofs
    /// merged with raw signatures by the aggregator worker. See
    /// `pkgs/types/src/block.zig:default_max_aggregation_children`.
    max_aggregation_children: u32 = types.default_max_aggregation_children,
    /// Soft cap on concurrent aggregate workers (`BeamChain.aggregate_inflight`).
    aggregate_max_inflight: u32 = 4,
    /// See `chainFactory.ChainOpts.proposal_deadline_pct`.
    proposal_deadline_pct: u32 = chainFactory.default_proposal_deadline_pct,
};

/// blocks_by_root retry backoff (interop storm fix). A requested block root that no peer can
/// currently serve — e.g. a freshly-proposed block whose owner has not finished its off-loop
/// Type-2 merge and therefore has not yet published/persisted it — previously triggered an
/// immediate, unbounded re-fetch on every "unserved" response (`retryUnservedBlockRoots`),
/// producing a ~700 req/s blocks_by_root storm. The storm starved the prover (worsening the very
/// merge it was waiting on) and only resolved when the block finally arrived via gossip.
///
/// Fix: keep `BLOCKS_BY_ROOT_IMMEDIATE_RETRIES` immediate re-routes to a different peer (the
/// legitimate "wrong peer" case that keeps a parent-chain walk progressing), then fall back to
/// exponential backoff (BASE → MAX) driven by `drainUnservedRetries` on the interval tick. No hard
/// give-up: a late joiner may only reach an old block via blocks_by_root, so a root stays scheduled
/// at the MAX cadence until ingested (then dropped lazily in the drain).
const BLOCKS_BY_ROOT_IMMEDIATE_RETRIES: u32 = 1;
const BLOCKS_BY_ROOT_RETRY_BASE_MS: u64 = 250;
const BLOCKS_BY_ROOT_RETRY_MAX_MS: u64 = 4000;

const UnservedBlockRetry = struct {
    depth: u32,
    /// Total unserved responses seen for this root (drives the backoff schedule).
    attempts: u32,
    /// Monotonic ns at which the next backed-off retry is due. 0 = no backed-off retry pending
    /// (the most recent attempt was dispatched immediately and we await its response).
    next_retry_ns: i128,
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validatorClient.ValidatorClient = null,
    nodeId: u32,
    last_interval: isize,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,
    /// Explicitly configured subnet ids for attestation import (adds to validator-derived subnets).
    aggregation_subnet_ids: ?[]const u32 = null,
    /// NOTE: the previous coarse outer `BeamNode.mutex` was dropped in this
    /// slice (a-3). The gossip / interval / req-resp call paths now take
    /// per-resource locks via the helpers in `locking.zig`.
    /// Slice (c) (chain-worker / `processFinalizationFollowup` move-off-IO-
    /// thread) will reintroduce a multi-resource lock here when its first
    /// real user lands; until then there is no placeholder field, per
    /// slice discipline (no dead code without callers).
    ///
    /// Pending parent roots deferred for batched fetching.
    /// Maps block root → fetch depth. Collected during gossip/RPC processing
    /// and flushed as a single batched blocks_by_root request, avoiding the
    /// 300+ individual round-trips caused by sequential parent-chain walking.
    ///
    /// Now guarded by its own mutex (slice a-3): with the global
    /// `BeamNode.mutex` dropped, both the libxev tick path
    /// (`flushPendingParentFetches` after `processPendingBlocks`) and the
    /// libp2p bridge path (gossip / req-resp → `cacheBlockAndFetchParent`)
    /// can touch this map concurrently.
    batch_pending_parent_roots: std.AutoHashMap(types.Root, u32),
    batch_pending_parent_roots_lock: zeam_utils.SyncMutex = .{},

    /// Maps `parent_root` to the orphan child block roots waiting on it.
    /// Populated when an incoming reqresp `blocks_by_root` chunk or an incoming
    /// gossip block has a parent not yet in fork choice: the orphan can no
    /// longer be pre-cached (the old `cacheBlockAndFetchParent` path was a
    /// destructive clone that corrupted its source — see the long comment on
    /// `cacheMissingParentRpcChunk`), so the (parent, child) dependency is
    /// tracked here separately. When the parent imports,
    /// `processCachedDescendants` drains this map for `parent_root` and
    /// re-enqueues each child into `batch_pending_parent_roots`; the existing
    /// `flushPendingParentFetches` then re-issues a `blocks_by_root` request,
    /// which arrives via the normal reqresp path with the parent now in fork
    /// choice for a clean import.
    ///
    /// Without this, `processCachedDescendants` (which only walks
    /// `network.block_cache`) wouldn't see the orphan, the pending root was
    /// already removed in `processBlockByRootChunk`, and the child would simply
    /// be dropped.
    orphan_dependents: std.AutoHashMap(types.Root, std.ArrayList(types.Root)),
    orphan_dependents_lock: zeam_utils.SyncMutex = .{},

    /// Range chunks handed to the chain-worker before `onBlock` completes.
    /// Maps block_root → blocks_by_range request_id for post-import accounting.
    range_async_chunk_imports: std.AutoHashMap(types.Root, u64),
    range_async_chunk_imports_lock: zeam_utils.SyncMutex = .{},

    /// blocks_by_root retry backoff state (interop storm fix). Maps an unserved block root to its
    /// backoff schedule; drained on the interval tick by `drainUnservedRetries`. Guarded by its own
    /// lock — both the libp2p bridge (req-resp response → `retryUnservedBlockRoots`) and the libxev
    /// tick (`drainUnservedRetries`) touch it.
    unserved_block_retries: std.AutoHashMap(types.Root, UnservedBlockRetry),
    unserved_block_retries_lock: zeam_utils.SyncMutex = .{},

    /// Test-only failure injection for `onInterval` catch-and-continue paths.
    test_inject_validator_error_at_intervals: []const usize = &.{},
    test_inject_aggregator_error_at_intervals: []const usize = &.{},

    /// Set by `SlotDriverWatchdog` (different OS thread) when a stall
    /// is detected. Observed and cleared by the next libxev tick which
    /// then forces a `refreshSyncFromPeers` outside the normal cadence.
    /// We deliberately do NOT call `refreshSyncFromPeers` from the
    /// watchdog thread itself: `network.sendStatusToPeer` mutates
    /// `pending_rpc_requests` map state shared with the libp2p bridge,
    /// and the existing serialization assumes a single producer per
    /// libxev tick. A flag flip is the cheapest cross-thread signal
    /// that preserves that invariant.
    sync_refresh_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Rotating cursor for rate-limited `refreshSyncFromPeers` batches.
    sync_refresh_peer_cursor: usize = 0,

    /// Slot of the most recent force-fanout peer-status refresh fired by the
    /// stuck-mesh-cluster detector. Used to rate-limit the detector to one
    /// fanout per `SYNC_STATUS_STUCK_CLUSTER_REFRESH_COOLDOWN_SLOTS` so a
    /// continuous stuck condition doesn't burst-refresh every interval and
    /// re-create the en-masse RPC-timeout cascade that motivated the original
    /// status-refresh batching.
    last_stuck_cluster_refresh_slot: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Monotonic millis of the last inbound gossip delivery.
    last_gossip_rx_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Monotonic millis of the last inbound gossip block delivery.
    /// Distinct from `last_gossip_rx_ms` because attestations on the
    /// `/leanconsensus/.../attestation_*/ssz_snappy` topics arrive at
    /// ~5/s on a busy mesh and keep `last_gossip_rx_ms` fresh even when
    /// every block is being dropped by `snappy.error.Corrupt`.
    /// `maybeInitiateProactiveCatchUp` was gating on the union-of-all-
    /// topics counter, so attestations were silently masking a total
    /// block-ingress stall and the catch-up RPC never fired. Tracked
    /// separately so the block-silence signal can drive its own decision.
    last_gossip_block_rx_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const Self = @This();

    pub fn init(self: *Self, allocator: Allocator, opts: NodeOpts) !void {
        var validator: ?validatorClient.ValidatorClient = null;

        var network = try networkFactory.Network.init(allocator, opts.backend);
        var network_init_cleanup = true;
        errdefer if (network_init_cleanup) network.deinit();

        const chain = try allocator.create(chainFactory.BeamChain);
        // `BeamChain.init` failure: only the empty `*BeamChain` allocation exists — destroy
        // it without `deinit`. On success, a single errdefer runs `deinit` then `destroy`
        // (two errdefers would double-destroy this pointer if init failed after `chain.*` was written).
        chain.* = chainFactory.BeamChain.init(
            allocator,
            chainFactory.ChainOpts{
                .config = opts.config,
                .anchorState = opts.anchorState,
                .nodeId = opts.nodeId,
                .db = opts.db,
                .logger_config = opts.logger_config,
                .node_registry = opts.node_registry,
                .is_aggregator = opts.is_aggregator,
                .thread_pool = opts.thread_pool,
                .min_aggregation_inputs = opts.min_aggregation_inputs,
                .max_aggregation_children = opts.max_aggregation_children,
                .aggregate_max_inflight = opts.aggregate_max_inflight,
                .proposal_deadline_pct = opts.proposal_deadline_pct,
            },
            network.connected_peers,
        ) catch |init_err| {
            allocator.destroy(chain);
            return init_err;
        };
        errdefer {
            chain.deinit();
            allocator.destroy(chain);
        }

        // Start the chain-worker AFTER
        // the chain is at its final heap address (allocator.create +
        // assignment-via-deref above), because the worker stores
        // `chain` as its handler ctx and that pointer must remain
        // stable for the worker's entire lifetime. `chain.deinit()` (via the errdefer
        // above) tears the worker down before any chain state it might touch.
        if (opts.chain_worker_enabled) {
            try chain.startChainWorker();
        }

        // Register the
        // `lean_chain_state_refcount_distribution` scrape refresher
        // with the chain at its final heap address. The refresher
        // iterates `chain.states` under the shared lock and samples
        // `rc.count()` for each entry; surfaces leaked acquires (any
        // entry stuck >16) on the /metrics endpoint. Cleared in
        // `chain.deinit` so the metrics module never calls back into
        // freed chain memory.
        chain.startChainStateRefcountObserver();

        // Now that the chain is at its final heap location, point the logger config
        // at the forkchoice slot clock so every log line carries slot/interval context.
        opts.logger_config.slot_clock = &chain.forkChoice.fcStore.slot_clock;
        if (opts.validator_ids) |ids| {
            // key_manager is required when validator_ids is provided
            const km = opts.key_manager orelse return error.KeyManagerRequired;
            validator = validatorClient.ValidatorClient.init(allocator, opts.config, .{
                .ids = ids,
                .chain = chain,
                .network = network,
                .logger = opts.logger_config.logger(.validator),
                .key_manager = km,
            });
            chain.registerValidatorIds(ids);
        }

        self.* = Self{
            .allocator = allocator,
            .clock = opts.clock,
            .chain = chain,
            .network = network,
            .validator = validator,
            .nodeId = opts.nodeId,
            .last_interval = -1,
            .test_inject_validator_error_at_intervals = &.{},
            .test_inject_aggregator_error_at_intervals = &.{},
            .logger = opts.logger_config.logger(.node),
            .node_registry = opts.node_registry,
            .aggregation_subnet_ids = opts.aggregation_subnet_ids,
            .batch_pending_parent_roots = std.AutoHashMap(types.Root, u32).init(allocator),
            .orphan_dependents = std.AutoHashMap(types.Root, std.ArrayList(types.Root)).init(allocator),
            .range_async_chunk_imports = std.AutoHashMap(types.Root, u64).init(allocator),
            .unserved_block_retries = std.AutoHashMap(types.Root, UnservedBlockRetry).init(allocator),
        };

        chain.setPruneCachedBlocksCallback(self, pruneCachedBlocksCallback);
        chain.setImportedBlockCallback(self, handleChainImportedBlock);
        chain.setRejectedBlockCallback(self, handleChainRejectedBlock);

        network_init_cleanup = false;
    }

    pub fn deinit(self: *Self) void {
        // Order matters here. `chain.deinit()` is what stops/
        // joins the chain-worker thread, so any state the worker
        // callbacks (`handleChainImportedBlock`,
        // `handleChainRejectedBlock`) reach into MUST outlive the
        // join. Concretely the callbacks touch:
        //
        //   * `self.network`            (cache removal, missing-root
        //                                fetches, pre-finalized prune)
        //   * `self.batch_pending_parent_roots` + its lock
        //                                (`flushPendingParentFetches`,
        //                                `cacheBlockAndFetchParent`)
        //   * `self.chain.forkChoice`   (already torn down inside
        //                                `chain.deinit` — but only
        //                                AFTER the worker has joined,
        //                                so still safe)
        //
        // Any new BeamNode field a worker callback can reach must be
        // deinit'd AFTER `chain.deinit()` — failure surfaces as an
        // alignment panic / UAF on the still-draining worker
        // dispatch.
        self.chain.deinit();
        self.allocator.destroy(self.chain);
        self.batch_pending_parent_roots.deinit();
        // Drop any in-flight orphan-dependent tracking. Each value is an
        // ArrayList(Root) we allocated with `getOrPut + .empty + append`,
        // so we must deinit each before destroying the outer map.
        {
            var it = self.orphan_dependents.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        }
        self.orphan_dependents.deinit();
        self.range_async_chunk_imports.deinit();
        self.unserved_block_retries.deinit();
        self.network.deinit();
    }

    fn recordRangeSyncOutcome(_: *Self, outcome: []const u8) void {
        zeam_metrics.metrics.zeam_blocks_by_range_sync_total.incr(.{ .outcome = outcome }) catch {};
    }

    /// Post-import accounting for range chunks that were queued on the chain-worker.
    fn finishRangeAsyncChunkImport(
        self: *Self,
        block_root: types.Root,
        imported: bool,
        pre_finalized: bool,
    ) void {
        self.range_async_chunk_imports_lock.lock();
        const removed = self.range_async_chunk_imports.fetchRemove(block_root);
        self.range_async_chunk_imports_lock.unlock();
        const rid = removed orelse return;

        var update = networkFactory.Network.BlocksByRangeChunkUpdate{
            .record_async_finished = true,
        };
        if (imported) update.record_imported = true;
        if (pre_finalized) update.record_pre_finalized = true;
        const result = self.network.updateBlocksByRangeRequest(rid.value, update);
        if (result.run_sync_end) self.runDeferredBlocksByRangeSyncEnd(rid.value);
    }

    fn runDeferredBlocksByRangeSyncEnd(self: *Self, request_id: u64) void {
        var snap = (self.network.snapshotPendingRequest(request_id) catch |err| {
            self.logger.warn("deferred blocks_by_range end: snapshot request_id={d} failed: {any}", .{ request_id, err });
            return;
        }) orelse {
            self.logger.warn("deferred blocks_by_range end: unknown request_id={d}", .{request_id});
            return;
        };
        defer snap.deinit(self.allocator);
        if (snap.request_kind != .blocks_by_range) return;
        self.handleBlocksByRangeSyncEnd(request_id, snap, .completed, false);
    }

    fn clearRangeAsyncChunkImport(self: *Self, block_root: types.Root) void {
        self.range_async_chunk_imports_lock.lock();
        const removed = self.range_async_chunk_imports.fetchRemove(block_root);
        self.range_async_chunk_imports_lock.unlock();
        const rid = removed orelse return;
        const result = self.network.updateBlocksByRangeRequest(rid.value, .{ .record_async_finished = true });
        if (result.run_sync_end) self.runDeferredBlocksByRangeSyncEnd(rid.value);
    }

    fn trackRangeAsyncChunkImport(self: *Self, block_root: types.Root, request_id: u64) void {
        self.range_async_chunk_imports_lock.lock();
        const gop = self.range_async_chunk_imports.getOrPut(block_root) catch {
            self.range_async_chunk_imports_lock.unlock();
            return;
        };
        if (gop.found_existing) {
            if (gop.value_ptr.* != request_id) {
                self.logger.warn(
                    "blocks_by_range: block 0x{x} already tracked for request {d}, ignoring duplicate from {d}",
                    .{ &block_root, gop.value_ptr.*, request_id },
                );
            }
            self.range_async_chunk_imports_lock.unlock();
            return;
        }
        gop.value_ptr.* = request_id;
        self.range_async_chunk_imports_lock.unlock();
        _ = self.network.updateBlocksByRangeRequest(request_id, .{ .record_async_submitted = true });
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage, sender_peer_id: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const now_ms: u64 = @intCast(zeam_utils.unixTimestampMillis());
        self.last_gossip_rx_ms.store(now_ms, .monotonic);
        // Track block-topic gossip separately. Attestations on the
        // `/attestation_X/ssz_snappy` topics are small (~2.6 KB), decode
        // reliably even on a fleet where every large message corrupts
        // (~5/s arrival), and would otherwise keep `last_gossip_rx_ms`
        // fresh and suppress `shouldInitiateProactiveCatchUp` indefinitely
        // even though no block has reached the application layer in many
        // slots. The block-specific timestamp lets the proactive catch-up
        // gate detect that condition and trigger `blocks_by_root` /
        // `blocks_by_range` RPC fallback the same way grandine recovers.
        switch (data.*) {
            .block => self.last_gossip_block_rx_ms.store(now_ms, .monotonic),
            else => {},
        }

        // Lifetime invariant for `data`:
        //   The gossip subsystem (see `ethlibp2p.zig`) owns the
        //   `GossipMessage` for the entire duration of this callback. It is the
        //   standard libp2p callback contract: the buffer is not recycled, freed
        //   or mutated until `onGossip` returns. Do NOT cache or stash `data`
        //   past this scope.
        //
        // `precomputed_block_root` is computed lazily — only when the block's
        // parent is NOT already in fork-choice (the orphan-cache path, where the
        // root is needed as a cache key synchronously on the libxev thread).
        //
        // For the common case (parent present, block dispatched to chain-worker),
        // we skip hashTreeRoot on libxev entirely: the chain-worker thunk
        // computes the root off-thread inside `onBlock`. The libxev-side hasBlock
        // dedup is also skipped in this path; `protoArray.onBlock` performs the
        // same dedup on the worker thread (early-out at the top of onBlock).
        // The trade-off is that re-arriving gossip blocks whose
        // root is already in protoArray will run STF on the worker before the
        // protoArray no-op dedup fires; this is rare and accepted (follow-up
        // data from `zeam_libxev_callback_duration_seconds` will confirm).
        //
        // `precomputed_block_root` is null for all non-block gossip types.

        // Slice (a-3): the outer BeamNode.mutex is gone. Each chain entry
        // point inside the switch arms takes its own per-resource locks
        // (chain.{states_lock, pending_blocks_lock, pubkey_cache_lock,
        // root_to_slot_lock, events_lock, forkChoice}); network state
        // mutations go through `Network`'s LockedMap / BlockCache /
        // ConnectedPeers helpers. See docs/threading_refactor_slice_a.md.

        var precomputed_block_root: ?types.Root = null;

        switch (data.*) {
            .block => |signed_block| {
                const block = signed_block.block;
                const parent_root = block.parent_root;
                const hasParentBlock = self.chain.forkChoice.hasBlock(parent_root);

                self.logger.info("received gossip block for slot={d} parent_root=0x{x} proposer={d}{f} hasParentBlock={} from peer={s}{f}", .{
                    block.slot,
                    &parent_root,
                    block.proposer_index,
                    self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
                    hasParentBlock,
                    sender_peer_id,
                    self.node_registry.getNodeNameFromPeerId(sender_peer_id),
                });

                if (!hasParentBlock) {
                    // Orphan path: compute block_root on libxev — needed as cache
                    // key for `cacheBlockAndFetchParent` and `removePendingBlockRoot`.
                    // This is a rare path (parent not yet imported), so the hash cost
                    // here is acceptable.
                    const hash_start_ns = zeam_utils.monotonicTimestampNs();
                    var orphan_block_root: types.Root = undefined;
                    zeam_utils.hashTreeRoot(types.BeamBlock, block, &orphan_block_root, self.allocator) catch |err| {
                        self.logger.warn("failed to compute block root for orphan gossip block slot={d}: {any}", .{ block.slot, err });
                        return;
                    };
                    const hash_elapsed_s = @as(f32, @floatFromInt(zeam_utils.monotonicTimestampNs() - hash_start_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
                    zeam_metrics.observeLibxevCallback("onGossip.block.hash_tree_root", hash_elapsed_s);
                    precomputed_block_root = orphan_block_root;
                    const block_root = orphan_block_root;

                    _ = self.network.removePendingBlockRoot(block_root);

                    // Skip the destructive `cacheBlockAndFetchParent` (→ sszClone
                    // → ssz.serialize) — it corrupts the upstream `data.*`'s
                    // SignedBlock allocations, which the inbound-gossip worker
                    // thread then deinits, causing a thread-N "Invalid free"
                    // panic. Same bug and same fix pattern as
                    // cacheMissingParentRpcChunk; this is the gossip-path twin.
                    // In one observed incident this path produced repeated
                    // "Invalid free" panics within minutes, all originating in
                    // onGossip here.
                    //
                    // The orphan gossip chunk is NOT pre-cached. When the
                    // parent arrives, the chain will re-fetch this block via
                    // blocks_by_root (using the parent-root enqueue below).
                    // One extra round-trip per orphan gossip block; no panic.
                    if (block.slot <= self.chain.forkChoice.getLatestFinalized().slot) {
                        // Block is pre-finalized - prune any cached descendants waiting for this parent
                        self.logger.info(
                            "gossip block 0x{x} is pre-finalized (slot={d}), pruning cached descendants",
                            .{ &block_root, block.slot },
                        );
                        _ = self.network.pruneCachedBlocks(block_root, null);
                    } else {
                        // Enqueue the parent root for batched fetching so chain
                        // catch-up still drives to completion when parent arrives.
                        {
                            self.batch_pending_parent_roots_lock.lock();
                            defer self.batch_pending_parent_roots_lock.unlock();
                            self.batch_pending_parent_roots.put(parent_root, 1) catch |err| {
                                self.logger.warn(
                                    "failed to enqueue parent root 0x{x} for orphan gossip block 0x{x}: {any}",
                                    .{ &parent_root, &block_root, err },
                                );
                            };
                        }
                        // Track the (parent, child) dependency so the orphan
                        // gossip block gets re-fetched via blocks_by_root once
                        // the parent imports. Without this, the orphan is
                        // dropped on the floor — gossipsub will not redeliver
                        // it and there is no `processCachedDescendants` path
                        // to discover it (we deliberately skip caching).
                        self.trackOrphanDependent(parent_root, block_root);
                        self.logger.debug(
                            "Orphan gossip block 0x{x} at slot {d}: cache skipped (sszClone source-corruption guard); queued parent 0x{x} + tracked dependency",
                            .{ &block_root, block.slot, &parent_root },
                        );
                    }
                    // Flush any pending parent root fetches accumulated during caching.
                    self.flushPendingParentFetches(null);
                    // Return early - don't pass to chain until parent arrives
                    return;
                }
                // hasParentBlock==true: fall through with precomputed_block_root=null.
                // chain.onGossip and the chain-worker compute the root off libxev.
            },
            .attestation => |signed_attestation| {
                const slot = signed_attestation.message.message.slot;
                const validator_id = signed_attestation.message.validator_id;
                const validator_node_name = self.node_registry.getNodeNameFromValidatorIndex(validator_id);

                const sender_node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
                self.logger.debug("received gossip attestation for slot={d} validator={d}{f} from peer={s}{f}", .{
                    slot,
                    validator_id,
                    validator_node_name,
                    sender_peer_id,
                    sender_node_name,
                });
            },
            .aggregation => |signed_aggregation| {
                const sender_node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
                self.logger.info("received gossip aggregation for slot={d} from peer={s}{f}", .{
                    signed_aggregation.data.slot,
                    sender_peer_id,
                    sender_node_name,
                });
            },
        }

        // For the common gossip-block path (parent present), `precomputed_block_root`
        // is null — chain.onGossip defers the hash to the chain-worker. For the orphan
        // path and non-block gossip it is either the root computed above or null
        // respectively; chain.onGossip ignores it on attestation/aggregation branches.
        const root_for_chain: ?types.Root = precomputed_block_root;
        const result = self.chain.onGossip(data, sender_peer_id, root_for_chain) catch |err| {
            switch (err) {
                // Block rejected because it's before finalized - drop it and prune any cached
                // descendants we might still be holding onto.
                error.PreFinalizedSlot => {
                    if (data.* == .block) {
                        // For the orphan path precomputed_block_root is non-null; for
                        // the common (parent-present) path it is null — chain.onGossip
                        // computed the root on libxev via its own lazy path. Skip
                        // pruneCachedBlocks in the null case; any cached descendants
                        // will age out naturally (block was pre-finalized so they are
                        // all stale anyway — no liveness impact).
                        if (precomputed_block_root) |block_root| {
                            self.logger.info(
                                "gossip block 0x{x} rejected as pre-finalized; pruning cached descendants",
                                .{&block_root},
                            );
                            _ = self.network.pruneCachedBlocks(block_root, null);
                        } else {
                            self.logger.info(
                                "gossip block slot={d} rejected as pre-finalized (root not computed on libxev)",
                                .{data.block.block.slot},
                            );
                        }
                    }
                    return;
                },
                // Block validation failed due to unknown parent - log at appropriate level
                // based on whether we're already fetching the parent.
                error.UnknownParentBlock => {
                    if (data.* == .block) {
                        const block = data.block.block;
                        const parent_root = block.parent_root;
                        if (self.network.hasPendingBlockRoot(parent_root)) {
                            self.logger.debug("gossip block validation deferred slot={d} parent=0x{x} (parent fetch in progress)", .{
                                block.slot,
                                &parent_root,
                            });
                        } else {
                            self.logger.warn("gossip block validation failed slot={d} with unknown parent=0x{x}", .{
                                block.slot,
                                &parent_root,
                            });
                        }
                    }
                    return;
                },
                // Attestation/aggregation validation failed due to missing head/source/target block -
                // downgrade to debug when the missing block is already being fetched.
                error.UnknownHeadBlock, error.UnknownSourceBlock, error.UnknownTargetBlock => {
                    const att_data: ?@TypeOf(data.attestation.message.message) = switch (data.*) {
                        .attestation => |att| att.message.message,
                        .aggregation => |agg| agg.data,
                        else => null,
                    };
                    if (att_data) |ad| {
                        const missing_root = if (err == error.UnknownHeadBlock)
                            ad.head.root
                        else if (err == error.UnknownSourceBlock)
                            ad.source.root
                        else
                            ad.target.root;

                        const kind: []const u8 = if (data.* == .attestation) "attestation" else "aggregation";
                        if (self.network.hasPendingBlockRoot(missing_root)) {
                            self.logger.debug("gossip {s} validation deferred slot={d} error={any} (block fetch in progress)", .{
                                kind,
                                ad.slot,
                                err,
                            });
                        } else {
                            self.logger.warn("gossip {s} validation failed slot={d} error={any}", .{
                                kind,
                                ad.slot,
                                err,
                            });
                        }
                    }
                    return;
                },
                else => return err,
            }
        };
        self.handleGossipProcessingResult(result);
    }

    fn handleGossipProcessingResult(self: *Self, result: chainFactory.GossipProcessingResult) void {
        // Process successfully imported blocks to retry any cached descendants
        if (result.processed_block_root) |processed_root| {
            self.logger.debug(
                "gossip block 0x{x} successfully processed, checking for cached descendants",
                .{&processed_root},
            );
            self.processCachedDescendants(processed_root);
        }

        // Fetch any block roots that were missing while processing a block or validating attestation/aggregation gossip.
        // We own the slice whenever it's non-empty (onBlock and onGossip both allocate it).
        const missing_roots = result.missing_attestation_roots;
        defer if (missing_roots.len > 0) self.allocator.free(missing_roots);

        if (missing_roots.len > 0) {
            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn(
                    "failed to fetch {d} missing block root(s) from gossip: {any}",
                    .{ missing_roots.len, err },
                );
            };
        }

        // Flush any parent roots accumulated during block/descendant processing.
        self.flushPendingParentFetches(null);
    }

    fn pruneCachedBlocksCallback(ptr: *anyopaque, finalized: types.Checkpoint) usize {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // Collect roots of blocks at or before finalized slot from the
        // network's BlockCache helper. We snapshot under the cache lock
        // and then mutate via `pruneCachedBlocks` outside the iteration.
        const roots_to_prune = self.network.collectCachedBlocksAtOrBelowSlot(finalized.slot) catch |err| {
            self.logger.warn("failed to collect cached blocks for pruning: {any}", .{err});
            return 0;
        };
        defer self.allocator.free(roots_to_prune);

        var pruned: usize = 0;
        for (roots_to_prune) |root| {
            pruned += self.network.pruneCachedBlocks(root, finalized);
        }
        return pruned;
    }

    fn getReqRespResponseHandler(self: *Self) networks.OnReqRespResponseCbHandler {
        return .{
            .ptr = self,
            .onReqRespResponseCb = onReqRespResponse,
        };
    }

    /// Imported-block backchannel handler. Fires from
    /// `BeamChain.chainWorkerOnBlockThunk` after every successful
    /// chain-worker import. Takes ownership of `missing_roots` —
    /// frees it before returning. May run on the chain-worker
    /// thread, the gossip-import thread, or the libxev thread
    /// depending on which path imported the block.
    ///
    /// Thread-safety audit: every primitive this handler reaches is safe to call from a
    /// non-libxev thread:
    ///
    ///   * `network.removeFetchedBlock` /
    ///     `network.getChildrenOfBlock` /
    ///     `network.hasFetchedBlock` /
    ///     `network.pruneCachedBlocks`
    ///                  → `LockedMap` (mutex-protected hashmap).
    ///   * `network.hasPendingBlockRoot` /
    ///     `network.removePendingBlockRoot` /
    ///     `network.trackPendingBlockRoot`
    ///                  → `LockedMap`.
    ///   * `network.connected_peers.selectPeerCopy`
    ///                  → `RwLock`-guarded random pick.
    ///   * `network.pending_rpc_requests`,
    ///     `network.blocks_by_root_inflight`
    ///                  → `LockedMap` + atomic counter (CAS reservation).
    ///   * `chain.forkChoice.hasBlocksBatch` /
    ///     `chain.forkChoice.hasBlock`
    ///                  → forkchoice `RwLock` shared/exclusive.
    ///   * `self.batch_pending_parent_roots`
    ///                  → its own `batch_pending_parent_roots_lock`.
    ///   * `network.backend.reqresp.sendRequest`
    ///                  → enqueues onto a Tokio `mpsc::Sender::try_send`
    ///                    in the Rust libp2p glue
    ///                    (`SwarmCommandChannel`, `send_swarm_command`).
    ///                    The Rust libp2p swarm runs on its OWN
    ///                    Tokio runtime — the Zig caller never
    ///                    touches a libxev primitive on this path,
    ///                    so there is no event-loop affinity to
    ///                    violate. `try_send` is `Send + Sync`.
    ///
    /// Net result: this handler issues NO libxev I/O directly. It
    /// mutates lock-protected state and queues a command across
    /// the Zig→Rust FFI boundary; the libxev thread is unaffected.
    /// Future BeamNode helpers that issue libxev I/O primitives
    /// (timers, fd reads/writes via `xev.Loop`) MUST NOT be called
    /// from this handler — they would need to be hopped back via
    /// the chain-worker queue or a dedicated libxev wakeup.
    ///
    /// See `BeamChain.imported_block` / `ImportedBlockFn` for the
    /// full contract.
    fn handleChainImportedBlock(
        ptr: *anyopaque,
        block_root: types.Root,
        missing_roots: []types.Root,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        defer self.allocator.free(missing_roots);

        self.finishRangeAsyncChunkImport(block_root, true, false);

        // If the block was previously cached (a `processCachedDescendants`
        // submission, or a long-orphan block that arrived ahead of its
        // parent and got buffered in `network.fetched_blocks`), the
        // cache entry is now stale — clear it before driving descendant
        // retry so we don't re-process the same root in a future pass.
        // Idempotent: no-op for blocks that arrived via gossip or RPC
        // and never sat in the cache.
        _ = self.network.removeFetchedBlock(block_root);

        // The block was just imported, so any cached descendants
        // waiting on it can now be retried. This matches the post-import
        // recursion in the inline RPC paths
        // (`processBlockByRootChunk` / `processBlockByRangeChunk`).
        // Internally uses cache-lock-protected helpers + chain.onBlock
        // (mutex-guarded), so it is safe to invoke from whichever
        // thread the worker dispatched on.
        self.processCachedDescendants(block_root);

        // Drive the missing-attestation-root fetch fan-out. Previously
        // this slice was silently dropped by the worker thunk
        // (chain.onGossip's `.block` arm comment, and
        // `chainWorkerProcessPendingBlocksThunk` warn) so attestation
        // sync stalled until a re-broadcast nudged us. With the
        // backchannel wired, RPC fetches kick off the moment the
        // chain knows the dependency.
        if (missing_roots.len > 0) {
            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn(
                    "imported-block callback: failed to fetch {d} missing block(s): {any}",
                    .{ missing_roots.len, err },
                );
            };
        }

        // Coalesce any parent fetches accumulated during the
        // descendant retry into one batched `blocks_by_root` request.
        self.flushPendingParentFetches(null);
    }

    /// Rejected-block backchannel handler. Fires
    /// from `BeamChain.chainWorkerOnBlockThunk` ONLY when worker-side
    /// `onBlock` returns `MissingPreState` or `PreFinalizedSlot` —
    /// the two errors caused by a TOCTOU race between the libxev
    /// caller's `forkChoice.hasBlock(parent)` pre-check inside
    /// `trySubmitImportToWorker` and the worker's eventual dispatch
    /// (finalization can prune the parent in between). Without this
    /// hand-back the worker would silently drop the block — sync
    /// would stall until a re-broadcast.
    ///
    /// The callback DOES NOT take ownership of `signed_block`; the
    /// worker's `Message.deinit` frees it after this call returns.
    /// `cacheBlockAndFetchParent` clones internally, matching the
    /// inline `processBlockByRootChunk` MissingPreState arm.
    ///
    /// Threading: same contract as `handleChainImportedBlock`. The
    /// reachable network/forkchoice helpers + the
    /// `cacheBlockAndFetchParent` path that this handler walks are
    /// audited in the doc on `handleChainImportedBlock` above —
    /// every primitive is mutex- / atomic- / FFI-mpsc-safe; no
    /// libxev I/O is issued from the worker thread.
    fn handleChainRejectedBlock(
        ptr: *anyopaque,
        signed_block: *const types.SignedBlock,
        block_root: types.Root,
        reason: chainFactory.BeamChain.RejectedBlockReason,
    ) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        switch (reason) {
            .missing_pre_state => {
                self.clearRangeAsyncChunkImport(block_root);
                // Handle this the same way as the inline
                // `processBlockByRootChunk` MissingPreState arm. Use
                // depth=1 since the libxev
                // caller already accepted this block (depth 0); a
                // subsequent parent fetch is the next hop.
                if (self.cacheBlockAndFetchParent(block_root, signed_block.*, 1)) |parent_root| {
                    self.logger.debug(
                        "chain-worker rejected MissingPreState slot={d} root=0x{x}, cached + fetching parent 0x{x}",
                        .{ signed_block.block.slot, &block_root, &parent_root },
                    );
                } else |cache_err| {
                    if (cache_err == CacheBlockError.PreFinalized) {
                        self.logger.info(
                            "chain-worker rejected MissingPreState slot={d} root=0x{x} but block is now pre-finalized; pruning cached descendants",
                            .{ signed_block.block.slot, &block_root },
                        );
                        _ = self.network.pruneCachedBlocks(block_root, null);
                    } else if (cache_err == CacheBlockError.AlreadyCached) {
                        self.logger.debug(
                            "chain-worker rejected MissingPreState slot={d} root=0x{x} but block already cached (concurrent re-arrival)",
                            .{ signed_block.block.slot, &block_root },
                        );
                    } else {
                        self.logger.warn(
                            "chain-worker rejected MissingPreState slot={d} root=0x{x}: cache failed: {any}",
                            .{ signed_block.block.slot, &block_root, cache_err },
                        );
                    }
                }
                self.flushPendingParentFetches(null);
            },
            .pre_finalized => {
                self.finishRangeAsyncChunkImport(block_root, false, true);
                self.logger.info(
                    "chain-worker rejected PreFinalizedSlot slot={d} root=0x{x}; pruning cached descendants",
                    .{ signed_block.block.slot, &block_root },
                );
                _ = self.network.pruneCachedBlocks(block_root, null);
            },
        }
    }

    /// Producer side identification for `replayPendingAttestationsAsync`
    /// drop log severity. The
    /// distinction matters for an isolated single-validator node:
    /// when there is NO inbound gossip `on_block` to piggy-back on,
    /// a `QueueFull` drop on `local_publish` means the buffered
    /// attestations age until FIFO eviction
    /// (`MAX_PENDING_ATTESTATIONS = 1024`) — the first occurrence is
    /// the operator's only signal that liveness is degrading.
    /// `gossip_or_rpc_followup` paths always have a fresh
    /// `replayPendingAttestations` queued behind every successful
    /// import, so a missed nudge there is provably benign within
    /// one block-cycle.
    const ReplayProducer = enum { local_publish, gossip_or_rpc_followup };

    /// Replay the chain's pending-attestation buffers without
    /// blocking the libxev thread. Routes to the chain-worker
    /// queue when the worker is enabled (the worker drains the
    /// buffers off-thread in `chainWorkerReplayPendingAttestationsThunk`),
    /// falls back to the synchronous `replayPendingAttestations` only
    /// when the worker is disabled — in that mode libxev IS the chain
    /// thread, so a direct call is the only option.
    ///
    /// `error.QueueFull` / `error.QueueClosed` from the worker submit
    /// are non-fatal in the steady-state aggregator case: the
    /// chain-worker's own `on_block` thunk runs `replayPendingAttestations`
    /// after every successful import, and gossip blocks land within a
    /// slot, so a missed nudge just delays a few buffered entries by
    /// one block-cycle.
    ///
    /// Producer-aware drop severity: isolated nodes producing locally have no inbound
    /// `on_block` to piggy-back on, so a `QueueFull` drop with
    /// `producer == .local_publish` escalates to `warn` so the
    /// first occurrence is visible in logs without needing the
    /// `lean_chain_queue_dropped_total{queue="replay_pending"}`
    /// dashboard. `gossip_or_rpc_followup` keeps the prior `debug`
    /// level.
    fn replayPendingAttestationsAsync(self: *Self, producer: ReplayProducer) void {
        self.chain.submitReplayPendingAttestations() catch |err| switch (err) {
            error.ChainWorkerDisabled => self.chain.replayPendingAttestations(),
            error.QueueFull, error.QueueClosed => switch (producer) {
                .local_publish => self.logger.warn(
                    "chain-worker replay submit dropped on local-publish path: {any} (no inbound on_block to piggy-back; pending attestations age toward FIFO eviction at MAX_PENDING_ATTESTATIONS=1024 — see lean_chain_queue_dropped_total{{queue=replay_pending}} and lean_pending_attestations_size{{kind=...}})",
                    .{err},
                ),
                .gossip_or_rpc_followup => self.logger.debug(
                    "chain-worker replay submit dropped: {any} (next on_block dispatch will replay)",
                    .{err},
                ),
            },
        };
    }

    /// Try to route a block import through the chain-worker.
    /// Returns `true` when the worker accepted ownership of the block
    /// — followup (`onBlockFollowup` + `replayPendingAttestations` +
    /// the imported-block callback that drives `processCachedDescendants`
    /// / `fetchBlockByRoots`) all run on the worker thread, so the
    /// caller MUST NOT redo any of that work. Returns `false` when
    /// the worker is disabled, the block queue is full / closed, or
    /// the SSZ clone needed to transfer ownership failed; the caller
    /// is then responsible for the inline fallback path.
    ///
    /// Caller pre-condition: the libxev caller MUST have observed
    /// the parent under `forkChoice.hasBlock` before submitting.
    /// The check is racy by design: finalization can advance and
    /// prune the parent between the check and the worker's
    /// eventual dispatch. The race is closed by the rejected-block
    /// backchannel — `chainWorkerOnBlockThunk` invokes
    /// `handleChainRejectedBlock` on `MissingPreState` /
    /// `PreFinalizedSlot`, which runs the same `cacheBlockAndFetch
    /// Parent` / `pruneCachedBlocks` path the inline
    /// `processBlockByRootChunk` would have taken. Net effect: the
    /// worker can never strand sync on this race.
    fn trySubmitImportToWorker(
        self: *Self,
        signed_block: *const types.SignedBlock,
        block_root: types.Root,
    ) blocks_by_range_sync.ImportSubmitOutcome {
        var cloned = zeam_utils.clone(types.SignedBlock, signed_block, self.allocator) catch |err| {
            self.logger.warn(
                "chain-worker submit: clone failed for slot={d} root=0x{x}: {any}, falling back to inline import",
                .{ signed_block.block.slot, &block_root, err },
            );
            return .failed;
        };
        var consumed = false;
        // `defer` (not `errdefer`): the catch arm below returns a
        // non-`.submitted` outcome — i.e. a *normal* return — on
        // QueueFull / QueueClosed / ChainWorkerDisabled, so `errdefer`
        // would not run and the clone would leak.
        defer if (!consumed) cloned.deinit();

        self.chain.submitBlock(cloned, true, block_root) catch |err| switch (err) {
            error.ChainWorkerDisabled => return .worker_disabled,
            error.QueueFull => {
                // Do NOT fall through to inline
                // import on libxev. The caller MUST drop the chunk
                // (catch-up RPC will refetch). Inline `chain.onBlock`
                // here is the path that starved libxev for ~9.7s on
                // an aggregator node and made it miss its slot 64
                // proposal. See `ImportSubmitOutcome` for the rationale.
                //
                // `sendBlock` already incremented
                // `lean_chain_queue_dropped_total{queue="block"}`,
                // so we don't double-count here.
                self.logger.warn(
                    "chain-worker block queue full for RPC chunk slot={d} root=0x{x}; dropping (catch-up will refetch)",
                    .{ signed_block.block.slot, &block_root },
                );
                return .queue_full;
            },
            error.QueueClosed => {
                self.logger.warn(
                    "chain-worker block queue closed for RPC chunk slot={d} root=0x{x}; dropping",
                    .{ signed_block.block.slot, &block_root },
                );
                return .failed;
            },
        };
        consumed = true;
        return .submitted;
    }

    /// Record that `child_block_root` was received via reqresp/gossip but
    /// could not be pre-cached because the old `cacheBlockAndFetchParent`
    /// path was unsafe (destructive `sszClone` source corruption — see
    /// `cacheMissingParentRpcChunk`). When `parent_root` later imports,
    /// `processCachedDescendants` drains this map and re-enqueues
    /// `child_block_root` for a fresh `blocks_by_root` fetch.
    ///
    /// Safe to call from any thread that reaches the gossip/reqresp
    /// orphan-block paths; the map has its own dedicated lock.
    fn trackOrphanDependent(self: *Self, parent_root: types.Root, child_block_root: types.Root) void {
        // Slot=13 #942 follow-up: skip the orphan-dependents entry entirely
        // when `parent_root` has previously failed verify with a
        // deterministic-failure verdict. The cached parent will never be
        // importable; tracking the child would just queue a fetch that
        // chain.onBlock would short-circuit on `KnownInvalidBlock` anyway
        // (the parent-cascade arm). Cascade-mark the child here so any
        // future delivery of the SAME child also short-circuits at the
        // `site="self"` arm. Avoids the 12,676-chunks-per-5-min livelock
        // observed against ethlambda_0's slot=13 reserve.
        if (self.chain.isInvalidRoot(parent_root)) {
            self.chain.markInvalidRoot(child_block_root);
            self.logger.debug(
                "skip tracking orphan dependent 0x{x}: parent 0x{x} is known-invalid; cascade-marked child",
                .{ &child_block_root, &parent_root },
            );
            return;
        }
        self.orphan_dependents_lock.lock();
        defer self.orphan_dependents_lock.unlock();
        const gop = self.orphan_dependents.getOrPut(parent_root) catch |err| {
            self.logger.warn(
                "failed to track orphan dependent 0x{x} of parent 0x{x}: {any}",
                .{ &child_block_root, &parent_root, err },
            );
            return;
        };
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        // De-duplicate: don't queue the same child twice if we receive
        // duplicate chunks before the parent arrives.
        for (gop.value_ptr.items) |existing| {
            if (std.mem.eql(u8, &existing, &child_block_root)) return;
        }
        gop.value_ptr.append(self.allocator, child_block_root) catch |err| {
            self.logger.warn(
                "failed to append orphan dependent 0x{x} of parent 0x{x}: {any}",
                .{ &child_block_root, &parent_root, err },
            );
        };
    }

    /// Drain (remove + return) the orphan dependents of `parent_root`,
    /// or `null` if none. Caller owns the returned ArrayList and must
    /// call `.deinit(self.allocator)`.
    fn drainOrphanDependents(self: *Self, parent_root: types.Root) ?std.ArrayList(types.Root) {
        self.orphan_dependents_lock.lock();
        defer self.orphan_dependents_lock.unlock();
        const entry = self.orphan_dependents.fetchRemove(parent_root) orelse return null;
        return entry.value;
    }

    fn processCachedDescendants(self: *Self, parent_root: types.Root) void {
        // Get cached children of this parent (helper returns an owned
        // copy under the cache lock so we can iterate after release).
        const children = self.network.getChildrenOfBlock(parent_root) catch |err| {
            self.logger.warn("Failed to copy children for processing: {any}", .{err});
            return;
        };
        defer self.allocator.free(children);

        // Note: do NOT early-return on `children.len == 0` here — the
        // orphan_dependents drain at the tail of this function must run
        // for every parent import, regardless of whether the block cache
        // happened to have any pre-cached descendants. The orphan refetch
        // path specifically targets blocks that were dropped (NOT cached)
        // at orphan time; their re-fetch trigger is exactly this drain.

        if (children.len > 0) self.logger.debug(
            "Found {d} cached descendant(s) of block 0x{x}",
            .{ children.len, &parent_root },
        );

        // Try to process each descendant
        for (children) |descendant_root| {
            // Atomic (block, ssz) clone under the cache mutex. The
            // legacy borrow-shape `getFetchedBlockWithSsz` was removed:
            // its returned slice headers
            // pointed into cache-owned storage that a concurrent
            // `removeFetchedBlock` could free mid-`chain.onBlock`
            // (UAF — bug 14, surfaced by macOS CI on the new N3 stress
            // test). The clone-then-release shape transfers ownership to
            // this caller so the data outlives any cache mutation.
            const cached_opt = self.network.cloneFetchedBlockAndSsz(
                descendant_root,
                self.allocator,
            ) catch |clone_err| {
                self.logger.warn(
                    "Failed to clone cached block 0x{x} for processing: {any}",
                    .{ &descendant_root, clone_err },
                );
                continue;
            };
            if (cached_opt) |cached_const| {
                var cached = cached_const;
                // Free the clone on every exit path from this branch —
                // including the early-continue paths below and the
                // chain.onBlock error handlers. The clone is owned by
                // `self.allocator` (matches `cloneFetchedBlockAndSsz`'s
                // signature); deinit frees both `block` interior heap
                // fields and the `ssz` slice.
                defer cached.deinit(self.allocator);

                const cached_block = cached.block;
                // Skip if already known to fork choice — same guard as processBlockByRootChunk
                if (self.chain.forkChoice.hasBlock(descendant_root)) {
                    self.logger.debug(
                        "cached block 0x{x} is already known to fork choice, skipping re-processing",
                        .{&descendant_root},
                    );
                    _ = self.network.removeFetchedBlock(descendant_root);
                    self.processCachedDescendants(descendant_root);
                    continue;
                }

                self.logger.debug(
                    "Attempting to process cached block 0x{x}",
                    .{&descendant_root},
                );

                // Cached-descendant retry stays inline (no
                // chain-worker submit). Two reasons:
                //   1. Test/caller contract: `processCachedDescendants`
                //      is observed synchronously (assertions on
                //      forkchoice / cache state) by the gossip-import
                //      tests and by `processReadyCachedBlocks`'s
                //      callers; an async submit defers the side-effect
                //      past the return.
                //   2. Re-entrance is safe: when the chain-worker fires
                //      `imported_block_fn` we are POST-`onBlock` (locks
                //      released) on the worker thread, so calling
                //      `chain.onBlock` again here is sequential same-
                //      thread work — exactly what the worker already
                //      serialises.
                // The libxev fallback paths (`processBlockByRootChunk`
                // / `processBlockByRangeChunk`) are still off-libxev
                // because they used `trySubmitImportToWorker` for the
                // *primary* import; cache-retry is the cheap recursive
                // tail.
                const block_ssz = cached.ssz;
                const missing_roots = self.chain.onBlock(cached_block, .{ .sszBytes = block_ssz }) catch |err| {
                    if (err == chainFactory.BlockProcessingError.MissingPreState) {
                        // Parent still missing, keep it cached
                        self.logger.debug(
                            "Cached block 0x{x} still missing parent, keeping in cache",
                            .{&descendant_root},
                        );
                    } else if (err == forkchoice.ForkChoiceError.PreFinalizedSlot) {
                        // This block is now before finalized (finalization advanced while it was cached).
                        // Prune this block and all its cached descendants; they are no longer useful.
                        self.logger.info(
                            "cached block 0x{x} rejected as pre-finalized; pruning cached descendants",
                            .{&descendant_root},
                        );
                        _ = self.network.pruneCachedBlocks(descendant_root, null);
                    } else {
                        self.logger.warn(
                            "Failed to process cached block 0x{x}: {any}",
                            .{ &descendant_root, err },
                        );
                        // Remove from cache on other errors
                        _ = self.network.removeFetchedBlock(descendant_root);
                    }
                    continue;
                };
                defer self.allocator.free(missing_roots);

                self.logger.info(
                    "Successfully processed cached block 0x{x}",
                    .{&descendant_root},
                );

                // Run the same post-block followup that processBlockByRootChunk performs:
                // emits head/justification/finalization events and advances finalization.
                // Note: onBlockFollowup currently ignores the signedBlock pointer (_ = signedBlock),
                // so the ordering relative to removeFetchedBlock is not a memory-safety requirement
                // today — kept here as good practice for when the parameter is wired up.
                // Note: pruneForkchoice=true means processFinalizationAdvancement may fire on every
                // iteration of a deep cached-block chain. Correct semantically; a future optimisation
                // could pass false during catch-up and prune once at the end.
                self.chain.onBlockFollowup(true, &cached_block);
                self.replayPendingAttestationsAsync(.gossip_or_rpc_followup);

                // Remove from cache now that it's been processed. Note:
                // we own `cached` (clone), so this `removeFetchedBlock`
                // freeing the cache's copy doesn't affect us — the
                // `defer cached.deinit(...)` above frees our clone.
                _ = self.network.removeFetchedBlock(descendant_root);

                // Recursively check for this block's descendants
                self.processCachedDescendants(descendant_root);

                // Fetch any missing attestation head blocks
                self.fetchBlockByRoots(missing_roots, 0) catch |fetch_err| {
                    self.logger.warn("failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, fetch_err });
                };
            }
        }

        // Also re-fetch orphan children that we
        // recorded in `orphan_dependents` when we could not cache them
        // (the destructive `sszClone` guard in `cacheMissingParentRpcChunk`
        // and the gossip-orphan path in `onGossip`). Now that `parent_root`
        // is imported, those children can be re-requested cleanly.
        if (self.drainOrphanDependents(parent_root)) |roots_init| {
            var roots = roots_init;
            defer roots.deinit(self.allocator);
            if (roots.items.len > 0) {
                self.logger.info(
                    "Re-requesting {d} orphan dependent(s) of 0x{x}",
                    .{ roots.items.len, &parent_root },
                );
                {
                    self.batch_pending_parent_roots_lock.lock();
                    defer self.batch_pending_parent_roots_lock.unlock();
                    for (roots.items) |child_root| {
                        self.batch_pending_parent_roots.put(child_root, 1) catch |err| {
                            self.logger.warn(
                                "failed to enqueue orphan dependent 0x{x} for refetch: {any}",
                                .{ &child_root, err },
                            );
                        };
                    }
                }
                // Best-effort drain — no specific peer to prefer; the batch
                // mechanism picks from the connected pool.
                self.flushPendingParentFetches(null);
            }
        }
    }

    fn processReadyCachedBlocks(self: *Self, current_slot: types.Slot) void {
        var parent_roots = std.AutoHashMap(types.Root, void).init(self.allocator);
        defer parent_roots.deinit();

        // Snapshot ready blocks under the cache lock, then resolve
        // forkchoice membership outside it.
        const ready = self.network.collectReadyCachedBlocks(current_slot) catch |err| {
            self.logger.warn("failed to collect ready cached blocks: {any}", .{err});
            return;
        };
        defer self.allocator.free(ready);

        for (ready) |entry| {
            const parent_root = entry.parent_root;
            if (self.chain.forkChoice.hasBlock(parent_root)) {
                parent_roots.put(parent_root, {}) catch {};
            }
        }

        var pit = parent_roots.iterator();
        while (pit.next()) |entry| {
            self.processCachedDescendants(entry.key_ptr.*);
        }
    }

    /// Error type for cacheBlockAndFetchParent operation.
    const CacheBlockError = error{
        AlreadyCached,
        PreFinalized,
        AllocationFailed,
        CloneFailed,
        CachingFailed,
    };

    /// Cache a block and fetch its parent. Common logic used by both gossip and req-resp handlers.
    ///
    /// Arguments:
    /// - `block_root`: The root hash of the block to cache
    /// - `signed_block`: The block to cache (will be cloned)
    /// - `depth`: The depth for parent fetch (0 for gossip, current_depth+1 for req-resp)
    ///
    /// Returns the parent root on success so caller can log it.
    fn cacheBlockAndFetchParent(
        self: *Self,
        block_root: types.Root,
        signed_block: types.SignedBlock,
        depth: u32,
    ) CacheBlockError!types.Root {
        // Snapshot under the forkchoice shared lock — latest_finalized is
        // a multi-field struct (Checkpoint) written under exclusive; a raw
        // field read can tear (slot, blockRoot) pairs across concurrent
        // updates now that BeamNode.mutex no longer serialises us.
        const finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
        const block_slot = signed_block.block.slot;

        // Early rejection: don't cache blocks at or before finalized slot
        // These blocks will definitely be rejected during processing, so save memory
        if (block_slot <= finalized_slot) {
            return CacheBlockError.PreFinalized;
        }

        // Check if already cached (avoid duplicate caching)
        if (self.network.hasFetchedBlock(block_root)) {
            return CacheBlockError.AlreadyCached;
        }

        // If cache is full, reject - proactive pruning on finalization keeps the cache bounded
        if (self.network.getFetchedBlockCount() >= constants.MAX_CACHED_BLOCKS) {
            self.logger.warn("Cache full ({d} blocks), rejecting block 0x{x} at slot {d}", .{
                self.network.getFetchedBlockCount(),
                &block_root,
                block_slot,
            });
            return CacheBlockError.CachingFailed;
        }

        // cacheFetchedBlock takes ownership of a HEAP pointer: it moves the inner
        // SignedBlock into the cache and destroys the outer pointer (deinit+destroy
        // on a duplicate). It must therefore be given an allocator-owned pointer,
        // not the address of a stack local. Allocate on the heap and hand it over;
        // disable the errdefers once ownership has transferred to the cache.
        const block_ptr = self.allocator.create(types.SignedBlock) catch {
            return CacheBlockError.CachingFailed;
        };
        var block_owned = true;
        errdefer if (block_owned) self.allocator.destroy(block_ptr);
        block_ptr.* = zeam_utils.clone(types.SignedBlock, &signed_block, self.allocator) catch {
            return CacheBlockError.CloneFailed;
        };
        errdefer if (block_owned) block_ptr.deinit();

        self.network.cacheFetchedBlock(block_root, block_ptr) catch {
            return CacheBlockError.CachingFailed;
        };
        block_owned = false;

        // Enqueue the parent root for batched fetching rather than firing an individual
        // request immediately. All accumulated roots are sent as one blocks_by_root
        // request at the flush point, avoiding 300+ sequential round-trips when a
        // syncing peer walks a long parent chain one block at a time.
        const parent_root = signed_block.block.parent_root;
        {
            self.batch_pending_parent_roots_lock.lock();
            defer self.batch_pending_parent_roots_lock.unlock();
            self.batch_pending_parent_roots.put(parent_root, depth) catch {
                // Evict the cached block if we can't enqueue — otherwise it dangles forever.
                _ = self.network.removeFetchedBlock(block_root);
                return CacheBlockError.CachingFailed;
            };
        }

        return parent_root;
    }

    /// Cache an RPC chunk whose parent is not yet in fork choice and queue a
    /// batched parent fetch. Shared by the chain-worker fast path and the
    /// MissingPreState fallback so RPC handlers never duplicate cache logic.
    fn cacheMissingParentRpcChunk(
        self: *Self,
        block_root: types.Root,
        signed_block: *const types.SignedBlock,
        peer_id: []const u8,
        pending_depth: u32,
    ) void {
        if (pending_depth >= constants.MAX_BLOCK_FETCH_DEPTH) {
            self.logger.warn(
                "Reached max block fetch depth ({d}) for block 0x{x}, discarding",
                .{ constants.MAX_BLOCK_FETCH_DEPTH, &block_root },
            );
            return;
        }

        // Do NOT call `cacheBlockAndFetchParent` here.
        //
        // The full path used to be: cacheBlockAndFetchParent → `types.sszClone`
        // → `ssz.serialize`. `ssz.serialize` is destructive to its input
        // (mutates List/Bitlist internal state — see the comment on
        // `sszSerializeAndGetBytes` in `pkgs/types/src/utils.zig`). The
        // input here is `signed_block.*`, whose slices alias the SignedBlock
        // inside the upstream `ReqRespResponseEvent`. When this function
        // returns and `handleRPCResponseFromRustBridge`'s
        // `defer event.deinit(zigHandler.allocator)` fires, deinit walks the
        // corrupted List state and panics with "Invalid free".
        //
        // In one observed incident this reproduced with SIGSEGV (exit 139)
        // on most nodes within minutes — many panics each, every one with
        // `cacheMissingParentRpcChunk` → `cacheBlockAndFetchParent` in the
        // trace. The race surface widened after the reqresp-worker move-off
        // (FFI dispatch on a dedicated thread now drives blocks_by_root
        // responses through this path back-to-back at higher rate) and
        // again after the stuck-mesh-cluster detector was added
        // (more peer status refreshes → more `blocks_by_root` fetches).
        //
        // We still ENQUEUE the parent root so chain catch-up makes
        // progress — when the parent arrives, the chain will re-fetch
        // this block via blocks_by_root. The lost optimization is that
        // we no longer pre-cache the orphan chunk; the round-trip cost
        // of one extra fetch per orphan is acceptable next to the
        // alternative (panicking).
        //
        // Reading scalar fields off `signed_block` (slot, parent_root)
        // is safe — they're fixed-size and don't go through any List
        // or Bitlist allocation, so serialize-style corruption can't
        // affect them.

        // Apply the same pre-finalized check the old `cacheBlockAndFetchParent`
        // path performed before any sszClone, so behaviour for pre-finalized
        // chunks (log + prune descendants) is preserved verbatim.
        const finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
        const block_slot = signed_block.block.slot;
        if (block_slot <= finalized_slot) {
            self.logger.info(
                "block 0x{x} is pre-finalized (slot={d}), pruning cached descendants",
                .{ &block_root, block_slot },
            );
            _ = self.network.pruneCachedBlocks(block_root, null);
            return;
        }

        const parent_root = signed_block.block.parent_root;
        const fetch_depth = pending_depth + 1;
        {
            self.batch_pending_parent_roots_lock.lock();
            defer self.batch_pending_parent_roots_lock.unlock();
            self.batch_pending_parent_roots.put(parent_root, fetch_depth) catch |err| {
                self.logger.warn(
                    "failed to enqueue parent root 0x{x} for orphan 0x{x}: {any}",
                    .{ &parent_root, &block_root, err },
                );
                return;
            };
        }
        // Record the (parent, child) dependency so the orphan child gets
        // re-fetched when the parent imports. Without this, the orphan is
        // dropped on the floor: `processBlockByRootChunk` already called
        // `removePendingBlockRoot(block_root)` before invoking us, and we
        // can no longer pre-cache the orphan (which was how
        // `processCachedDescendants` used to find it). See the
        // `orphan_dependents` field doc.
        self.trackOrphanDependent(parent_root, block_root);
        self.logger.debug(
            "Orphan block 0x{x} at depth {d}: cache skipped (sszClone source-corruption guard); queued parent 0x{x} + tracked dependency",
            .{ &block_root, pending_depth, &parent_root },
        );
        self.flushPendingParentFetches(peer_id);
    }

    fn cacheFutureBlock(
        self: *Self,
        block_root: types.Root,
        signed_block: types.SignedBlock,
    ) CacheBlockError!void {
        // See cacheBlockAndFetchParent: take the shared lock via the
        // accessor so we don't tear-read latest_finalized.
        const finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
        const block_slot = signed_block.block.slot;

        if (block_slot <= finalized_slot) {
            return CacheBlockError.PreFinalized;
        }

        if (self.network.hasFetchedBlock(block_root)) {
            return CacheBlockError.AlreadyCached;
        }

        if (self.network.getFetchedBlockCount() >= constants.MAX_CACHED_BLOCKS) {
            self.logger.warn("Cache full ({d} blocks), rejecting future block 0x{s} at slot {d}", .{
                self.network.getFetchedBlockCount(),
                std.fmt.bytesToHex(block_root, .lower)[0..],
                block_slot,
            });
            return CacheBlockError.CachingFailed;
        }

        const block_ptr = self.allocator.create(types.SignedBlock) catch {
            return CacheBlockError.AllocationFailed;
        };
        var block_owned = true;
        errdefer if (block_owned) self.allocator.destroy(block_ptr);

        // Deep-clone the block first, then serialize the *clone* to capture
        // its SSZ bytes. The bytes are stored alongside the cached block so
        // that onBlock never needs to re-serialize a live SignedBlock, which
        // has been observed to cause memory corruption on the next cached
        // block's processing.
        block_ptr.* = zeam_utils.clone(types.SignedBlock, &signed_block, self.allocator) catch {
            return CacheBlockError.CloneFailed;
        };
        errdefer if (block_owned) block_ptr.deinit();

        var ssz_buf: std.ArrayList(u8) = .empty;
        errdefer ssz_buf.deinit(self.allocator);
        ssz.serialize(types.SignedBlock, block_ptr.*, &ssz_buf, self.allocator) catch {
            return CacheBlockError.CloneFailed;
        };
        const ssz_bytes = ssz_buf.toOwnedSlice(self.allocator) catch {
            return CacheBlockError.CloneFailed;
        };
        errdefer self.allocator.free(ssz_bytes);

        self.network.cacheFetchedBlock(block_root, block_ptr) catch {
            return CacheBlockError.CachingFailed;
        };
        block_owned = false;

        // Store the SSZ bytes after caching; ignore store failure (block is already cached,
        // onBlock will fall back to fresh serialization if bytes are unavailable).
        self.network.storeFetchedBlockSsz(block_root, ssz_bytes) catch {
            self.allocator.free(ssz_bytes);
        };
    }

    fn processBlockByRootChunk(self: *Self, block_ctx: *const BlockByRootContext, signed_block: *const types.SignedBlock) !void {
        var block_root: types.Root = undefined;
        if (zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, self.allocator)) |_| {
            const current_depth = self.network.getPendingBlockRootDepth(block_root) orelse 0;
            const removed = self.network.removePendingBlockRoot(block_root);
            if (!removed) {
                self.logger.warn("received unexpected block root 0x{x} from peer {s}{f}", .{
                    &block_root,
                    block_ctx.peer_id,
                    self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                });
            }

            // Skip STF re-processing if the block is already known to fork choice
            // (e.g. the checkpoint sync anchor block — it is the trust root and does not
            // need state-transition re-processing; re-processing it would cause an infinite
            // fetch loop because onBlock would always see it as "already processed").
            if (self.chain.forkChoice.hasBlock(block_root)) {
                self.logger.debug(
                    "block 0x{x} is already known to fork choice, skipping re-processing",
                    .{&block_root},
                );
                self.processCachedDescendants(block_root);
                return;
            }

            // Route to the chain-worker when the parent is
            // already resolved. The MissingPreState / PreFinalizedSlot
            // race against finalization is closed by the rejected-
            // block backchannel — `handleChainRejectedBlock` runs
            // the same cache-and-fetch / prune path the inline arm
            // below would. See `trySubmitImportToWorker` doc.
            //
            // On `queue_full` we MUST drop the
            // chunk instead of falling through to inline. Inline
            // `chain.onBlock` on libxev is the path that wedged an
            // aggregator node for 9.7s under a 3.4 MB
            // `blocks_by_root` burst; the next status-driven catch-up
            // cycle will refetch.
            if (self.chain.forkChoice.hasBlock(signed_block.block.parent_root)) {
                const outcome = self.trySubmitImportToWorker(signed_block, block_root);
                switch (blocks_by_range_sync.classifyChunkImport(outcome)) {
                    .handled => return,
                    .drop_backpressure => {
                        // Already logged + metric-bumped in trySubmitImportToWorker.
                        return;
                    },
                    .fallback_inline => {},
                }
            } else {
                // Parent not yet imported — cache and fetch instead of inline
                // `onBlock` on libxev.
                self.cacheMissingParentRpcChunk(block_root, signed_block, block_ctx.peer_id, current_depth);
                return;
            }

            // Try to add the block to the chain
            const missing_roots = self.chain.onBlock(signed_block.*, .{}) catch |err| {
                // Check if the error is due to missing parent
                if (err == chainFactory.BlockProcessingError.MissingPreState) {
                    self.cacheMissingParentRpcChunk(block_root, signed_block, block_ctx.peer_id, current_depth);
                    return;
                }

                if (err == forkchoice.ForkChoiceError.PreFinalizedSlot) {
                    self.logger.info(
                        "discarding pre-finalized block 0x{x} from peer {s}{f}, pruning cached descendants",
                        .{
                            &block_root,
                            block_ctx.peer_id,
                            self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                        },
                    );
                    _ = self.network.pruneCachedBlocks(block_root, null);
                    return;
                }

                self.logger.warn("failed to import block fetched via RPC 0x{x} from peer {s}{f}: {any}", .{
                    &block_root,
                    block_ctx.peer_id,
                    self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                    err,
                });
                return;
            };
            defer self.allocator.free(missing_roots);

            self.logger.debug(
                "Successfully processed block 0x{x}, checking for cached descendants",
                .{&block_root},
            );

            // Store aggregated signature proofs from this block so they can be reused
            // in future block production. This is the same followup done for gossiped blocks.
            self.chain.onBlockFollowup(true, signed_block);
            self.replayPendingAttestationsAsync(.gossip_or_rpc_followup);

            // Block was successfully added, try to process any cached descendants
            self.processCachedDescendants(block_root);

            // Fetch any missing attestation head blocks
            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn("failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
            };
        } else |err| {
            self.logger.warn("failed to compute block root from RPC response from peer={s}{f}: {any}", .{ block_ctx.peer_id, self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id), err });
        }

        // Flush any parent roots queued during this RPC block's processing. When a syncing peer
        // walks a long parent chain one block at a time, each response triggers one more parent
        // fetch. Batching them here consolidates concurrent parent requests into one round-trip.
        self.flushPendingParentFetches(block_ctx.peer_id);
    }

    // --- blocks_by_range catch-up orchestration ---
    // Pure gap/retry decision helpers: `blocks_by_range_sync.zig`. Dedicated sync-worker
    // extraction is follow-up.

    const CatchUpPeerStatus = struct {
        peer_id: []const u8,
        head_slot: types.Slot,
        head_root: types.Root,
        finalized_slot: types.Slot,
    };

    /// Gap to a peer head, capped by host wall-clock slot for threshold/pagination
    /// decisions (per-request size is still capped by `MAX_REQUEST_BLOCKS`).
    ///
    /// Wall slot comes from `Clock.wallSlotNow()` — a direct
    /// `unixTimestampMillis() - genesis_time_ms` derivation, NOT from
    /// `forkchoice.slot_clock.timeSlots`. Reading the forkchoice counter
    /// here would self-reinforce slot-driver stalls: when libxev
    /// is starved, `timeSlots` lags real time, the cap pulls the gap to
    /// zero, status-driven catch-up is skipped, and the node stays stuck.
    /// Using the host wall clock breaks that loop: catch-up still triggers
    /// on a real lag and pulls the node forward independent of tick liveness.
    fn cappedSyncGap(self: *Self, peer_head_slot: types.Slot, our_head_slot: types.Slot) u64 {
        const wall_slot = self.clock.wallSlotNow();
        return blocks_by_range_sync.cappedSyncGapSlots(peer_head_slot, our_head_slot, wall_slot);
    }

    fn shouldCatchUpFromPeerStatus(
        self: *Self,
        status: CatchUpPeerStatus,
        our_head_slot: types.Slot,
        our_finalized_slot: types.Slot,
    ) bool {
        // Same rationale as `cappedSyncGap`: gating must use the host wall
        // clock, not the forkchoice tick counter, so a stalled slot driver
        // doesn't suppress the very catch-up that would unstall it.
        const wall_slot = self.clock.wallSlotNow();
        return blocks_by_range_sync.shouldCatchUpFromPeerStatus(
            status.head_slot,
            our_head_slot,
            status.finalized_slot,
            our_finalized_slot,
            wall_slot,
        );
    }

    fn syncFetchPeerHeadByRoot(self: *Self, peer_id: []const u8, head_root: types.Root) void {
        const roots = [_]types.Root{head_root};
        self.fetchBlockByRootsFromPeer(&roots, 0, peer_id) catch |err| {
            self.logger.warn("failed to fetch peer head block 0x{x} from peer {s}{f}: {any}", .{
                &head_root,
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                err,
            });
        };
    }

    /// `blocks_by_root` catch-up: fetch the peer head and walk parents via the existing
    /// batched parent-fetch path (used when `blocks_by_range` is unavailable or gap is small).
    fn initiateCatchUpViaBlocksByRoot(self: *Self, status: CatchUpPeerStatus, our_head_slot: types.Slot) void {
        self.logger.info(
            "peer {s}{f} is ahead (peer_head={d} our_head={d}), catch-up via blocks_by_root from head 0x{x}",
            .{
                status.peer_id,
                self.node_registry.getNodeNameFromPeerId(status.peer_id),
                status.head_slot,
                our_head_slot,
                &status.head_root,
            },
        );
        self.syncFetchPeerHeadByRoot(status.peer_id, status.head_root);
    }

    fn initiateBlocksByRangeCatchUp(
        self: *Self,
        range_sync: networkFactory.BlocksByRangeSyncParams,
    ) void {
        const range_key = networkFactory.Network.blocksByRangeKey(range_sync);
        if (self.network.isBlocksByRangeActive(range_key) or
            self.network.blocksByRangeOverlapsActive(range_sync.start_slot, range_sync.count))
        {
            self.logger.debug(
                "skipping blocks_by_range catch-up start_slot={d} count={d}: overlapping range already in flight",
                .{ range_sync.start_slot, range_sync.count },
            );
            return;
        }

        const handler = networks.OnReqRespResponseCbHandler{
            .ptr = self,
            .onReqRespResponseCb = onReqRespResponse,
        };
        _ = self.network.sendBlocksByRangeRequest(range_sync, handler) catch |err| {
            switch (err) {
                error.BlocksByRangeAlreadyActive, error.BlocksByRangeOverlap => {
                    self.logger.debug(
                        "skipping blocks_by_range catch-up start_slot={d} count={d}: {any}",
                        .{ range_sync.start_slot, range_sync.count, err },
                    );
                },
                else => {
                    self.network.markPeerBlocksByRangeUnavailable(range_sync.peer_id);
                    self.recordRangeSyncOutcome("unavailable");
                    self.logger.warn(
                        "blocks_by_range catch-up from peer {s}{f} start_slot={d} count={d} failed: {any}; falling back to blocks_by_root",
                        .{
                            range_sync.peer_id,
                            self.node_registry.getNodeNameFromPeerId(range_sync.peer_id),
                            range_sync.start_slot,
                            range_sync.count,
                            err,
                        },
                    );
                    self.syncFetchPeerHeadByRoot(range_sync.peer_id, range_sync.peer_head_root);
                },
            }
        };
    }

    fn initiateCatchUpFromPeerStatus(
        self: *Self,
        status: CatchUpPeerStatus,
        our_head_slot: types.Slot,
    ) void {
        const gap = self.cappedSyncGap(status.head_slot, our_head_slot);
        if (gap == 0) return;

        const head_snapshot = self.chain.forkChoice.getHead();

        // Large gaps use `blocks_by_range` when the peer supports it; otherwise `blocks_by_root`.
        if (gap > constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD and
            self.network.peerSupportsBlocksByRange(status.peer_id))
        {
            const start_slot: types.Slot = our_head_slot + 1;
            const requested_count: u64 = @min(gap, params.MAX_REQUEST_BLOCKS);
            self.logger.info(
                "peer {s}{f} is far ahead (gap={d} slots), initiating bulk catch-up via blocks_by_range start_slot={d} count={d}",
                .{
                    status.peer_id,
                    self.node_registry.getNodeNameFromPeerId(status.peer_id),
                    gap,
                    start_slot,
                    requested_count,
                },
            );
            self.initiateBlocksByRangeCatchUp(.{
                .peer_id = status.peer_id,
                .start_slot = start_slot,
                .count = requested_count,
                .peer_head_slot = status.head_slot,
                .peer_head_root = status.head_root,
                .our_head_root_at_start = head_snapshot.blockRoot,
            });
        } else {
            if (gap > constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD) {
                self.logger.info(
                    "peer {s}{f} does not support blocks_by_range (gap={d} slots), using blocks_by_root catch-up",
                    .{
                        status.peer_id,
                        self.node_registry.getNodeNameFromPeerId(status.peer_id),
                        gap,
                    },
                );
            }
            self.initiateCatchUpViaBlocksByRoot(status, our_head_slot);
        }
    }

    fn maybeContinueBlocksByRangeCatchUp(self: *Self, snap: networkFactory.Network.PendingRequestSnapshot) void {
        if (snap.range_aborted) return;

        const our_head_slot = self.chain.forkChoice.getHead().slot;
        const gap = self.cappedSyncGap(snap.peer_head_slot, our_head_slot);
        if (gap <= constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD) return;

        const head_snapshot = self.chain.forkChoice.getHead();
        const start_slot: types.Slot = our_head_slot + 1;
        const requested_count: u64 = @min(gap, params.MAX_REQUEST_BLOCKS);
        self.logger.info(
            "continuing blocks_by_range catch-up after partial success: start_slot={d} count={d} (peer_head={d} our_head={d})",
            .{ start_slot, requested_count, snap.peer_head_slot, our_head_slot },
        );
        self.initiateBlocksByRangeCatchUp(.{
            .peer_id = snap.peer_id_copy,
            .start_slot = start_slot,
            .count = requested_count,
            .peer_head_slot = snap.peer_head_slot,
            .peer_head_root = snap.peer_head_root,
            .our_head_root_at_start = head_snapshot.blockRoot,
        });
    }

    fn handleBlocksByRangeSyncEnd(
        self: *Self,
        request_id: u64,
        snap: networkFactory.Network.PendingRequestSnapshot,
        end_reason: BlocksByRangeSyncEndReason,
        range_unavailable: bool,
    ) void {
        const node_name = self.node_registry.getNodeNameFromPeerId(snap.peer_id_copy);
        const next_peer_opt = self.network.selectPeerForRangeSyncExcluding(snap.peer_id_copy, self.chain.forkChoice.getHead().slot + 1) catch null;
        defer if (next_peer_opt) |p| self.allocator.free(p);
        const has_alternate_peer = if (next_peer_opt) |p| !std.mem.eql(u8, p, snap.peer_id_copy) else false;

        const action = blocks_by_range_sync.syncEndDecision(.{
            .aborted = snap.range_aborted,
            .chunks_received = snap.range_chunks_received,
            .chunks_imported = snap.range_chunks_imported,
            .chunks_pre_finalized = snap.range_chunks_pre_finalized,
            .range_attempt = snap.range_attempt,
            .max_attempts = constants.MAX_BLOCKS_BY_RANGE_SYNC_ATTEMPTS,
            .end_reason = end_reason,
            .has_alternate_peer = has_alternate_peer,
            .range_unavailable = range_unavailable,
        });

        switch (action) {
            .abort_fallback, .unavailable_fallback, .exhausted_fallback => {
                const outcome: []const u8 = switch (action) {
                    .abort_fallback => "abort",
                    .unavailable_fallback => "unavailable",
                    .exhausted_fallback => if (end_reason == .timeout) "timeout" else "exhausted",
                    else => unreachable,
                };
                self.recordRangeSyncOutcome(outcome);
                const reason_msg: []const u8 = switch (action) {
                    .abort_fallback => "fork mismatch",
                    .unavailable_fallback => "blocks_by_range not available on peer",
                    .exhausted_fallback => @tagName(end_reason),
                    else => unreachable,
                };
                self.logger.warn(
                    "blocks_by_range request_id={d} from peer {s}{f} ({s}, chunks={d} imported={d}); falling back to blocks_by_root 0x{x}",
                    .{
                        request_id,
                        snap.peer_id_copy,
                        node_name,
                        reason_msg,
                        snap.range_chunks_received,
                        snap.range_chunks_imported,
                        &snap.peer_head_root,
                    },
                );
                self.network.finalizePendingRequest(request_id);
                self.syncFetchPeerHeadByRoot(snap.peer_id_copy, snap.peer_head_root);
            },
            .pre_finalized_complete => {
                self.recordRangeSyncOutcome("pre_finalized_noop");
                self.logger.info(
                    "blocks_by_range request_id={d} from peer {s}{f}: all {d} chunks pre-finalized; treating as no-op",
                    .{ request_id, snap.peer_id_copy, node_name, snap.range_chunks_received },
                );
                self.network.finalizePendingRequest(request_id);
                self.continueBlocksByRangeSync(snap.peer_id_copy, snap.start_slot, snap.count);
                self.maybeContinueBlocksByRangeCatchUp(snap);
            },
            .retry => {
                self.recordRangeSyncOutcome("retry");
                const next_attempt = snap.range_attempt + 1;
                const peer_id = next_peer_opt.?;
                self.logger.warn(
                    "blocks_by_range request_id={d} from peer {s}{f} ended ({s}, chunks={d} imported={d}); retry attempt {d}/{d} on peer {s}{f}",
                    .{
                        request_id,
                        snap.peer_id_copy,
                        node_name,
                        @tagName(end_reason),
                        snap.range_chunks_received,
                        snap.range_chunks_imported,
                        next_attempt,
                        constants.MAX_BLOCKS_BY_RANGE_SYNC_ATTEMPTS,
                        peer_id,
                        self.node_registry.getNodeNameFromPeerId(peer_id),
                    },
                );
                self.network.finalizePendingRequest(request_id);
                self.initiateBlocksByRangeCatchUp(.{
                    .peer_id = peer_id,
                    .start_slot = snap.start_slot,
                    .count = snap.count,
                    .peer_head_slot = snap.peer_head_slot,
                    .peer_head_root = snap.peer_head_root,
                    .our_head_root_at_start = snap.our_head_root_at_start,
                    .attempt = next_attempt,
                });
            },
            .success_continue => {
                self.recordRangeSyncOutcome("success");
                self.logger.info(
                    "blocks_by_range request_id={d} from peer {s}{f} completed ({s}): chunks_received={d} imported={d}",
                    .{
                        request_id,
                        snap.peer_id_copy,
                        node_name,
                        @tagName(end_reason),
                        snap.range_chunks_received,
                        snap.range_chunks_imported,
                    },
                );
                self.network.finalizePendingRequest(request_id);
                self.continueBlocksByRangeSync(snap.peer_id_copy, snap.start_slot, snap.count);
                self.maybeContinueBlocksByRangeCatchUp(snap);
            },
        }
    }

    /// Process a single block chunk received in response to a blocks_by_range request.
    /// Reuses onBlock for STF + forkchoice integration; on missing-parent we cache the block
    /// and queue a parent fetch (same as the by-root path), but we don't track per-root
    /// pending state since the original request was slot-based.
    fn processBlockByRangeChunk(
        self: *Self,
        request_id: u64,
        peer_id: []const u8,
        signed_block: *const types.SignedBlock,
    ) !void {
        const recv = self.network.updateBlocksByRangeRequest(request_id, .{ .record_received = true });
        const view = recv.view orelse return;
        if (view.aborted) return;

        var block_root: types.Root = undefined;
        zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, self.allocator) catch |err| {
            self.logger.warn("failed to compute block root from blocks_by_range response from peer={s}{f}: {any}", .{
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                err,
            });
            return;
        };

        // Skip if already known to fork choice — same guard as processBlockByRootChunk.
        if (self.chain.forkChoice.hasBlock(block_root)) {
            self.logger.debug(
                "blocks_by_range: block 0x{x} already known to fork choice, skipping",
                .{&block_root},
            );
            self.processCachedDescendants(block_root);
            _ = self.network.updateBlocksByRangeRequest(request_id, .{ .record_imported = true });
            return;
        }

        // First returned chunk must extend the head we had when this request was issued.
        // Peers may skip empty slots, so the first block is not always at `start_slot`.
        // Conservative: if our head advanced to a sibling via gossip/reorg, abort
        // even though both branches may be valid — do not loosen without rethinking retry.
        if (view.is_first_chunk and
            !std.mem.eql(u8, &signed_block.block.parent_root, &view.our_head_root_at_start))
        {
            self.logger.warn(
                "blocks_by_range: fork mismatch on first chunk slot={d} start_slot={d} (parent 0x{x} != our head-at-start 0x{x}); aborting range batch",
                .{
                    signed_block.block.slot,
                    view.start_slot,
                    &signed_block.block.parent_root,
                    &view.our_head_root_at_start,
                },
            );
            _ = self.network.updateBlocksByRangeRequest(request_id, .{ .mark_aborted = true });
            return;
        }

        // Route to the chain-worker when the parent is already
        // resolved. By-range chunks arrive slot-ordered so this is
        // the common case after the first chunk. Import accounting
        // (`chunks_imported`) is bumped in `handleChainImportedBlock` /
        // `handleChainRejectedBlock` after `onBlock` completes — not here.
        //
        // On `queue_full` drop the chunk.
        // See the matching comment in `processBlockByRootChunk` and
        // `ImportSubmitOutcome` in `blocks_by_range_sync.zig`.
        if (self.chain.forkChoice.hasBlock(signed_block.block.parent_root)) {
            const outcome = self.trySubmitImportToWorker(signed_block, block_root);
            switch (blocks_by_range_sync.classifyChunkImport(outcome)) {
                .handled => {
                    self.trackRangeAsyncChunkImport(block_root, request_id);
                    return;
                },
                .drop_backpressure => {
                    // Already logged + metric-bumped in
                    // `trySubmitImportToWorker`. We deliberately do
                    // NOT update the by-range request progress: the
                    // chunk timeout / status-driven retry will
                    // refetch once the worker queue drains.
                    return;
                },
                .fallback_inline => {},
            }
        } else {
            self.cacheMissingParentRpcChunk(block_root, signed_block, peer_id, 0);
            return;
        }

        const missing_roots = self.chain.onBlock(signed_block.*, .{}) catch |err| {
            if (err == chainFactory.BlockProcessingError.MissingPreState) {
                self.cacheMissingParentRpcChunk(block_root, signed_block, peer_id, 0);
                return;
            }
            if (err == forkchoice.ForkChoiceError.PreFinalizedSlot) {
                _ = self.network.pruneCachedBlocks(block_root, null);
                _ = self.network.updateBlocksByRangeRequest(request_id, .{ .record_pre_finalized = true });
                return;
            }
            self.logger.warn("blocks_by_range: failed to import block 0x{x} from peer={s}{f}: {any}", .{
                &block_root,
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                err,
            });
            return;
        };
        defer self.allocator.free(missing_roots);

        _ = self.network.updateBlocksByRangeRequest(request_id, .{ .record_imported = true });
        self.chain.onBlockFollowup(true, signed_block);
        self.replayPendingAttestationsAsync(.gossip_or_rpc_followup);
        self.processCachedDescendants(block_root);
        self.fetchBlockByRootsFromPeer(missing_roots, 0, peer_id) catch |err| {
            self.logger.warn("blocks_by_range: failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
        };
        self.flushPendingParentFetches(peer_id);
    }

    fn completeBlocksByRangeRequest(self: *Self, request_id: u64, snap: networkFactory.Network.PendingRequestSnapshot) void {
        const pending = self.network.updateBlocksByRangeRequest(request_id, .{ .mark_sync_end_pending = true });
        if (pending.run_sync_end) {
            self.handleBlocksByRangeSyncEnd(request_id, snap, .completed, false);
        }
    }

    /// Chain the next `blocks_by_range` window toward peer finalization.
    /// Complements head-gap pagination in `maybeContinueBlocksByRangeCatchUp` when the
    /// remaining gap to peer head is below `BLOCKS_BY_RANGE_SYNC_THRESHOLD`.
    fn continueBlocksByRangeSync(self: *Self, peer_id: []const u8, completed_start_slot: types.Slot, completed_count: u64) void {
        const peer_status = self.network.getPeerLatestStatus(peer_id) orelse {
            self.logger.debug("blocks_by_range: no latest status for peer {s}{f}; not scheduling follow-up range", .{
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
            });
            return;
        };

        const next_start_slot: types.Slot = completed_start_slot + completed_count;
        const our_finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;

        if (peer_status.finalized_slot <= our_finalized_slot or next_start_slot > peer_status.finalized_slot) {
            self.logger.debug("blocks_by_range: catch-up complete for peer {s}{f} (next_start={d}, peer_finalized={d}, our_finalized={d})", .{
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                next_start_slot,
                peer_status.finalized_slot,
                our_finalized_slot,
            });
            return;
        }

        const remaining: u64 = peer_status.finalized_slot - next_start_slot + 1;
        const requested_count: u64 = @min(remaining, params.MAX_REQUEST_BLOCKS);
        const head_snapshot = self.chain.forkChoice.getHead();
        self.initiateBlocksByRangeCatchUp(.{
            .peer_id = peer_id,
            .start_slot = next_start_slot,
            .count = requested_count,
            .peer_head_slot = peer_status.head_slot,
            .peer_head_root = peer_status.head_root,
            .our_head_root_at_start = head_snapshot.blockRoot,
        });
    }

    fn handleReqRespResponse(self: *Self, event: *const networks.ReqRespResponseEvent) !void {
        const request_id = event.request_id;
        // Snapshot the pending entry so we don't hold the
        // pending_rpc_requests lock across the chain calls below.
        var snap = (self.network.snapshotPendingRequest(request_id) catch |err| {
            self.logger.warn("failed to snapshot pending request_id={d}: {any}", .{ request_id, err });
            return;
        }) orelse {
            self.logger.warn("received RPC response for unknown request_id={d}", .{request_id});
            return;
        };
        defer snap.deinit(self.allocator);

        const peer_id = snap.peer_id_copy;
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);

        switch (event.payload) {
            .success => |resp| switch (resp) {
                .status => |status_resp| switch (snap.request_kind) {
                    .status => blk: {
                        const status_ctx = .{ .peer_id = peer_id };
                        self.logger.info("received status response from peer {s}{f} head_slot={d}, finalized_slot={d}", .{
                            status_ctx.peer_id,
                            self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                            status_resp.head_slot,
                            status_resp.finalized_slot,
                        });
                        if (!self.network.setPeerLatestStatus(status_ctx.peer_id, status_resp)) {
                            self.logger.warn("status response received for unknown peer {s}{f}", .{
                                status_ctx.peer_id,
                                self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                            });
                        }

                        // Proactive catch-up: prefer `blocks_by_range` for large gaps.
                        const catch_up_status = CatchUpPeerStatus{
                            .peer_id = status_ctx.peer_id,
                            .head_slot = status_resp.head_slot,
                            .head_root = status_resp.head_root,
                            .finalized_slot = status_resp.finalized_slot,
                        };
                        const sync_status = self.chain.getSyncStatus();
                        switch (sync_status) {
                            .peers_materially_ahead => |info| {
                                const our_finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
                                if (self.shouldCatchUpFromPeerStatus(
                                    catch_up_status,
                                    info.head_slot,
                                    our_finalized_slot,
                                )) {
                                    self.initiateCatchUpFromPeerStatus(catch_up_status, info.head_slot);
                                }
                            },
                            .fc_initing => {
                                const head_snapshot = self.chain.forkChoice.getHead();
                                if (status_resp.head_slot > head_snapshot.slot) {
                                    self.initiateCatchUpFromPeerStatus(catch_up_status, head_snapshot.slot);
                                }
                            },
                            .synced, .no_peers => {
                                // Belt-and-suspenders: getSyncStatus can lag a single status update
                                // early in the network (all finalized zero). Never skip catch-up when the
                                // responding peer's head is strictly ahead of ours.
                                const our_head_slot = self.chain.forkChoice.getHead().slot;
                                const our_finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
                                if (self.shouldCatchUpFromPeerStatus(
                                    catch_up_status,
                                    our_head_slot,
                                    our_finalized_slot,
                                )) {
                                    self.initiateCatchUpFromPeerStatus(catch_up_status, our_head_slot);
                                }
                            },
                        }
                        break :blk;
                    },
                    .blocks_by_root, .blocks_by_range => self.logger.warn("status response did not match tracked request_id={d} from peer={s}{f}", .{ request_id, peer_id, node_name }),
                },
                .blocks_by_root => |block_resp| {
                    switch (snap.request_kind) {
                        .blocks_by_root => {
                            const block_ctx = BlockByRootContext{
                                .peer_id = peer_id,
                                .requested_roots = snap.requested_roots_copy,
                            };
                            self.logger.info("received blocks-by-root chunk from peer {s}{f}", .{
                                block_ctx.peer_id,
                                self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                            });

                            try self.processBlockByRootChunk(&block_ctx, &block_resp);
                        },
                        else => {
                            self.logger.warn("blocks-by-root response did not match tracked request_id={d} from peer={s}{f}", .{ request_id, peer_id, node_name });
                        },
                    }
                },
                .blocks_by_range => |block_resp| {
                    switch (snap.request_kind) {
                        .blocks_by_range => {
                            self.logger.info("received blocks-by-range chunk from peer {s}{f} slot={d}", .{
                                peer_id,
                                node_name,
                                block_resp.block.slot,
                            });
                            try self.processBlockByRangeChunk(request_id, peer_id, &block_resp);
                        },
                        else => {
                            self.logger.warn("blocks-by-range response did not match tracked request_id={d} from peer={s}{f}", .{ request_id, peer_id, node_name });
                        },
                    }
                },
            },
            .failure => |err_payload| {
                switch (snap.request_kind) {
                    .status => {
                        self.logger.warn("status request to peer {s}{f} failed ({d}): {s}", .{
                            peer_id,
                            node_name,
                            err_payload.code,
                            err_payload.message,
                        });
                    },
                    .blocks_by_root => {
                        self.logger.warn("blocks-by-root request to peer {s}{f} failed ({d}): {s}", .{
                            peer_id,
                            node_name,
                            err_payload.code,
                            err_payload.message,
                        });
                        // Failure means the peer did not serve any of the
                        // requested roots. Collect them for retry BEFORE
                        // finalizePendingRequest removes them from
                        // pending_block_roots so a different peer can
                        // serve them. Without this, a failed request
                        // permanently stalls the parent-chain walk used
                        // during fc_initing / peers_materially_ahead sync.
                        self.retryUnservedBlockRoots(request_id, snap.requested_roots_copy, peer_id);
                        return;
                    },
                    .blocks_by_range => {
                        const range_unavailable = blocks_by_range_sync.isBlocksByRangeUnavailable(
                            err_payload.code,
                            err_payload.message,
                        );
                        self.logger.warn("blocks-by-range request to peer {s}{f} failed ({d}): {s}", .{
                            peer_id,
                            node_name,
                            err_payload.code,
                            err_payload.message,
                        });
                        if (range_unavailable) {
                            self.network.markPeerBlocksByRangeUnavailable(peer_id);
                        }
                        self.handleBlocksByRangeSyncEnd(request_id, snap, .failed, range_unavailable);
                        return;
                    },
                }
                self.network.finalizePendingRequest(request_id);
            },
            .completed => {
                // For blocks_by_root requests: detect roots that were not
                // served by any chunk (still in pending_block_roots after
                // all chunks arrived) and re-schedule them with a new
                // peer. Without this, a peer that returns EOS without
                // fulfilling all requested roots (e.g., a mesh helper
                // with head_slot=0) permanently stalls the parent-chain
                // walk used during fc_initing / peers_materially_ahead sync.
                if (snap.request_kind == .blocks_by_root) {
                    self.retryUnservedBlockRoots(request_id, snap.requested_roots_copy, peer_id);
                    return;
                }
                if (snap.request_kind == .blocks_by_range) {
                    self.completeBlocksByRangeRequest(request_id, snap);
                    return;
                }
                self.network.finalizePendingRequest(request_id);
            },
        }
    }

    pub fn onReqRespResponse(ptr: *anyopaque, event: *const networks.ReqRespResponseEvent) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // Slice (a-3): no outer mutex. `handleReqRespResponse` snapshots
        // the pending request entry under the pending_rpc_requests lock,
        // then calls `chain.onBlock` (per-resource locks) for the
        // blocks_by_root branch. Network mutations go through
        // `Network`'s LockedMap / BlockCache helpers.
        try self.handleReqRespResponse(event);
    }

    pub fn getOnGossipCbHandler(self: *Self) !networks.OnGossipCbHandler {
        return .{
            .ptr = self,
            .onGossipCb = onGossip,
        };
    }

    pub fn onReqRespRequest(ptr: *anyopaque, data: *const networks.ReqRespRequest, responder: networks.ReqRespServerStream) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // Slice (a-3): fully lock-free. The two arms below only:
        //   * `chain.db.loadBlock` — the DB has its own internal
        //     synchronisation (rocksdb / lmdb backends are thread-safe for
        //     concurrent reads).
        //   * `chain.getStatus()` — reads forkchoice via its own RwLock
        //     shared path; no other chain state touched.
        // Neither arm mutates `chain` or `network` state, so no caller
        // synchronisation is required.
        switch (data.*) {
            .blocks_by_root => |request| {
                const roots = request.roots.constSlice();

                // Reject requests asking for more roots than allowed (INVALID_REQUEST, code 1).
                if (roots.len > params.MAX_REQUEST_BLOCKS) {
                    self.logger.warn(
                        "node-{d}:: blocks_by_root: requested {d} roots exceeds MAX_REQUEST_BLOCKS={d}, sending INVALID_REQUEST",
                        .{ self.nodeId, roots.len, params.MAX_REQUEST_BLOCKS },
                    );
                    try responder.sendError(constants.RPC_ERR_INVALID_REQUEST, "too many roots requested");
                    return;
                }

                self.logger.debug(
                    "node-{d}:: Handling blocks_by_root request for {d} roots",
                    .{ self.nodeId, roots.len },
                );

                for (roots) |root| {
                    if (self.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
                        var signed_block = signed_block_value;
                        defer signed_block.deinit();

                        var response = networks.ReqRespResponse{
                            .blocks_by_root = try zeam_utils.clone(types.SignedBlock, &signed_block, self.allocator),
                        };
                        defer response.deinit();

                        try responder.sendResponse(&response);
                    } else {
                        self.logger.warn(
                            "node-{d}:: Requested block root=0x{x} not found",
                            .{ self.nodeId, &root },
                        );
                    }
                }

                try responder.finish();
            },
            .blocks_by_range => |request| {
                const start_slot = request.start_slot;
                const requested_count = request.count;

                // Reject invalid counts (INVALID_REQUEST, code 1).
                if (requested_count == 0) {
                    self.logger.warn(
                        "node-{d}:: blocks_by_range: count=0 is invalid, sending INVALID_REQUEST",
                        .{self.nodeId},
                    );
                    try responder.sendError(constants.RPC_ERR_INVALID_REQUEST, "count must not be zero");
                    return;
                }
                if (requested_count > params.MAX_REQUEST_BLOCKS) {
                    self.logger.warn(
                        "node-{d}:: blocks_by_range: count={d} exceeds MAX_REQUEST_BLOCKS={d}, sending INVALID_REQUEST",
                        .{ self.nodeId, requested_count, params.MAX_REQUEST_BLOCKS },
                    );
                    try responder.sendError(constants.RPC_ERR_INVALID_REQUEST, "count exceeds MAX_REQUEST_BLOCKS");
                    return;
                }

                const count = requested_count;

                self.logger.debug(
                    "node-{d}:: Handling blocks_by_range request start_slot={d} count={d}",
                    .{ self.nodeId, start_slot, count },
                );

                // Enforce MIN_SLOTS_FOR_BLOCK_REQUESTS history window.
                // Responders MUST keep at least MIN_SLOTS_FOR_BLOCK_REQUESTS recent slots
                // available. Requests whose start_slot falls before that window get
                // RESOURCE_UNAVAILABLE (code 3) so callers can skip to a better peer.
                const head = self.chain.forkChoice.getHead();
                if (head.slot >= constants.MIN_SLOTS_FOR_BLOCK_REQUESTS) {
                    const history_start = head.slot - constants.MIN_SLOTS_FOR_BLOCK_REQUESTS;
                    if (start_slot < history_start) {
                        self.logger.warn(
                            "node-{d}:: blocks_by_range: start_slot={d} is before history window start={d} (head={d}), sending RESOURCE_UNAVAILABLE",
                            .{ self.nodeId, start_slot, history_start, head.slot },
                        );
                        try responder.sendError(constants.RPC_ERR_RESOURCE_UNAVAILABLE, "requested range is outside history window");
                        return;
                    }
                }

                const end_slot_exclusive: types.Slot = start_slot + count;
                // Use the DB-PERSISTED finalized slot as the index/walk boundary, NOT the in-memory
                // forkChoice value. processFinalizationAdvancement updates in-memory finalization,
                // then (later) commits the finalized slot index + persisted-slot in one batch, then
                // prunes forkChoice. During that lag the in-memory finalized is ahead of the DB
                // index: trusting it makes the finalized loop below skip slots whose index is not yet
                // written, producing a response that starts past start_slot → the requester sees a
                // fork mismatch and aborts to the slow blocks_by_root walk. The persisted value, by
                // contrast, always matches what the index actually holds, and during the lag the
                // still-unpruned forkChoice walk covers the remaining (lower) slots contiguously.
                const finalized_slot = self.chain.db.loadLatestFinalizedSlot(database.DbDefaultNamespace) orelse 0;

                // ---- Finalized range: use DB slot index ----
                // Slots <= finalized_slot are indexed in DbFinalizedSlotsNamespace (slot → root).
                // This works even after forkChoice has been rebased and those nodes pruned.
                if (start_slot <= finalized_slot) {
                    const fin_end = @min(end_slot_exclusive, finalized_slot + 1);
                    var slot: types.Slot = start_slot;
                    while (slot < fin_end) : (slot += 1) {
                        const root = self.chain.db.loadFinalizedSlotIndex(database.DbFinalizedSlotsNamespace, slot) orelse {
                            // Slot may be empty (no block produced that slot) — skip silently.
                            continue;
                        };
                        if (self.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
                            var signed_block = signed_block_value;
                            defer signed_block.deinit();

                            var response = networks.ReqRespResponse{
                                .blocks_by_range = try zeam_utils.clone(types.SignedBlock, &signed_block, self.allocator),
                            };
                            defer response.deinit();

                            try responder.sendResponse(&response);
                        } else {
                            self.logger.warn(
                                "node-{d}:: blocks_by_range: finalized block root=0x{x} at slot={d} not found in DB",
                                .{ self.nodeId, &root, slot },
                            );
                        }
                    }
                }

                // ---- Unfinalized range: walk forkChoice from head ----
                // For slots above the finalized checkpoint the canonical chain is still
                // tracked in the in-memory forkChoice ProtoArray.
                if (end_slot_exclusive > finalized_slot + 1) {
                    const unfin_start = @max(start_slot, finalized_slot + 1);

                    var collected: std.ArrayList(types.Root) = .empty;
                    defer collected.deinit(self.allocator);

                    var current_opt: ?types.Root = head.blockRoot;
                    while (current_opt) |current_root| {
                        const node = self.chain.forkChoice.getBlock(current_root) orelse break;
                        if (node.slot < unfin_start) break;
                        if (node.slot < end_slot_exclusive) {
                            collected.append(self.allocator, current_root) catch break;
                        }
                        // Step to parent. Genesis / anchor has parentRoot == zero.
                        if (std.mem.eql(u8, &node.parentRoot, &ZERO_HASH)) break;
                        if (std.mem.eql(u8, &node.parentRoot, &current_root)) break;
                        current_opt = node.parentRoot;
                    }

                    // Collected in reverse-chronological order; reverse to send ascending by slot.
                    std.mem.reverse(types.Root, collected.items);

                    for (collected.items) |root| {
                        if (self.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
                            var signed_block = signed_block_value;
                            defer signed_block.deinit();

                            var response = networks.ReqRespResponse{
                                .blocks_by_range = try zeam_utils.clone(types.SignedBlock, &signed_block, self.allocator),
                            };
                            defer response.deinit();

                            try responder.sendResponse(&response);
                        } else {
                            self.logger.warn(
                                "node-{d}:: blocks_by_range: unfinalized block root=0x{x} not found in DB",
                                .{ self.nodeId, &root },
                            );
                        }
                    }
                }

                try responder.finish();
            },
            .status => {
                var response = networks.ReqRespResponse{ .status = self.chain.getStatus() };
                try responder.sendResponse(&response);
                try responder.finish();
            },
        }
    }
    pub fn getOnReqRespRequestCbHandler(self: *Self) networks.OnReqRespRequestCbHandler {
        return .{
            .ptr = self,
            .onReqRespRequestCb = onReqRespRequest,
        };
    }

    /// Send all accumulated pending parent roots as a single batched blocks_by_root request.
    ///
    /// Multiple gossip blocks or RPC responses received close together may each need a
    /// different parent block fetched. Without batching, each one opens its own libp2p
    /// stream, causing 300+ sequential round-trips when a peer walks a long parent chain.
    /// Collecting roots here and flushing them in one request reduces that to a single
    /// round-trip for the same burst of missing parents.
    ///
    /// **Throughput trade-off:** when `preferred_peer` is non-null, all
    /// roots in this batch are sent to a single peer.  This keeps checkpoint /
    /// parent walks fast (the peer already proved it can serve the chain), but
    /// concentrates load and loses parallelism that random peer selection would
    /// provide.  If the peer's bandwidth becomes a bottleneck, callers can pass
    /// `null` (gossip and cached-descendant paths already do) to spread load.
    fn flushPendingParentFetches(self: *Self, preferred_peer: ?[]const u8) void {
        // Drain under the dedicated lock so the gossip / req-resp paths
        // can keep enqueueing while we issue the batched fetch.
        var roots: std.ArrayList(types.Root) = .empty;
        defer roots.deinit(self.allocator);
        var max_depth: u32 = 0;
        {
            self.batch_pending_parent_roots_lock.lock();
            defer self.batch_pending_parent_roots_lock.unlock();

            const count = self.batch_pending_parent_roots.count();
            if (count == 0) return;

            roots.ensureTotalCapacityPrecise(self.allocator, count) catch {
                self.logger.warn("failed to allocate roots list for pending parent fetch flush", .{});
                return;
            };

            var it = self.batch_pending_parent_roots.iterator();
            while (it.next()) |entry| {
                roots.appendAssumeCapacity(entry.key_ptr.*);
                if (entry.value_ptr.* > max_depth) max_depth = entry.value_ptr.*;
            }
            self.batch_pending_parent_roots.clearRetainingCapacity();
        }

        if (roots.items.len == 0) return;
        self.logger.debug("flushing {d} pending parent root(s) as one batched blocks_by_root request", .{roots.items.len});

        self.fetchBlockByRootsFromPeer(roots.items, max_depth, preferred_peer) catch |err| {
            self.logger.warn("failed to batch-fetch {d} pending parent root(s): {any}", .{ roots.items.len, err });
        };
    }

    fn fetchBlockByRoots(
        self: *Self,
        roots: []const types.Root,
        depth: u32,
    ) !void {
        return self.fetchBlockByRootsFromPeer(roots, depth, null);
    }

    fn fetchBlockByRootsFromPeer(
        self: *Self,
        roots: []const types.Root,
        depth: u32,
        preferred_peer: ?[]const u8,
    ) !void {
        if (roots.len == 0) return;

        // Snapshot forkchoice presence for every
        // root in one shared-lock acquisition (`hasBlocksBatch`),
        // then dedup against the network-side caches under their own
        // independent locks. The previous `fetchBlockByRoots` did N
        // shared-lock acquires on the forkchoice and a sequential
        // walk; under heavy gossip fanout that turned the dedup
        // step into a serializing hot point. The batched call is
        // strictly cheaper for any N ≥ 2 and equivalent at N == 1.
        //
        // We dedup against three caches in priority order so
        // `lean_block_fetch_dedup_total{outcome}` faithfully reports
        // *why* a root was already not-fetched:
        //   1. forkchoice protoArray (already ingested).
        //   2. network.block_cache (fetched, awaiting parent or STF).
        //   3. network.pending_block_roots (RPC in flight; another
        //      `fetchBlockByRoots` call is already responsible).
        // The remainder feeds the actual RPC dispatch (counted as
        // `fetched`) or the per-error path below (counted as
        // `fetch_no_peers` / `fetch_failed`). Every entry of
        // `roots` lands in exactly one bucket so the outcome
        // counters sum to `roots.len` per call.
        //
        // **TOCTOU note:** the three cache
        // lookups are independent (forkchoice rwlock + the two
        // network LockedMap mutexes), so a concurrent thread can
        // mutate any of them between our snapshot and the RPC
        // dispatch — e.g. a gossip handler can ingest a block into
        // the forkchoice protoArray after our `hasBlocksBatch` call
        // returned `false` for it. The race is benign: the worst
        // case is one duplicate `blocks_by_root` request whose
        // response then takes the existing dedup path inside
        // `processBlockByRootChunk` (`forkChoice.hasBlock` early
        // return). The dedup counter still buckets the outcome
        // correctly because it's snapshot-of-state-at-call-time, not
        // a global "did we actually fetch the bytes" counter. Taking
        // a single multi-resource lock to close this race would
        // serialize the gossip-import and the RPC-fetch paths
        // against each other for no correctness benefit.
        var fc_present_buf: std.ArrayListUnmanaged(bool) = .empty;
        defer fc_present_buf.deinit(self.allocator);
        try fc_present_buf.resize(self.allocator, roots.len);
        try self.chain.forkChoice.hasBlocksBatch(roots, fc_present_buf.items);

        var already_in_fc: usize = 0;
        var already_in_cache: usize = 0;
        var already_pending: usize = 0;
        var missing_roots: std.ArrayList(types.Root) = .empty;
        defer missing_roots.deinit(self.allocator);
        try missing_roots.ensureTotalCapacityPrecise(self.allocator, roots.len);

        for (roots, fc_present_buf.items) |root, fc_present| {
            if (fc_present) {
                already_in_fc += 1;
                continue;
            }
            if (self.network.hasFetchedBlock(root)) {
                already_in_cache += 1;
                continue;
            }
            if (self.network.hasPendingBlockRoot(root)) {
                already_pending += 1;
                continue;
            }
            missing_roots.appendAssumeCapacity(root);
        }

        // Batch the per-bucket counter bumps
        // via `incrBy(N)` instead of N back-to-back `incr()` calls.
        // Same observed value, fewer atomic ops on the hot path.
        if (already_in_fc > 0) {
            zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                .{ .outcome = "already_in_forkchoice" },
                already_in_fc,
            ) catch {};
        }
        if (already_in_cache > 0) {
            zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                .{ .outcome = "already_in_block_cache" },
                already_in_cache,
            ) catch {};
        }
        if (already_pending > 0) {
            zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                .{ .outcome = "already_pending" },
                already_pending,
            ) catch {};
        }

        if (missing_roots.items.len == 0) return;

        const handler = self.getReqRespResponseHandler();
        const maybe_request = self.network.ensureBlocksByRootRequest(missing_roots.items, depth, handler, preferred_peer, self.chain.forkChoice.getHead().slot + 1) catch |err| blk: {
            switch (err) {
                error.NoPeersAvailable => {
                    // Previously this path bumped
                    // nothing, leaving the outcome buckets summing
                    // short of `roots.len` whenever the dispatch
                    // failed. Bucket explicitly so a Grafana panel
                    // showing "sum(rate(lean_block_fetch_dedup_total))
                    // == sum(rate(… by outcome))" stays an invariant.
                    self.logger.warn(
                        "no peers available to request {d} block(s) by root",
                        .{missing_roots.items.len},
                    );
                    zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                        .{ .outcome = "fetch_no_peers" },
                        missing_roots.items.len,
                    ) catch {};
                },
                error.InFlightCapReached => {
                    // Outbound `BlocksByRoot` cap was hit
                    // before this batch could dispatch. The cap (8 in
                    // flight, see `network.MAX_CONCURRENT_BLOCKS_BY_ROOT`)
                    // is the gossip-flood backpressure that prevented the
                    // libxev thread from forking hundreds of concurrent
                    // RPCs, each of which would then time out at
                    // `RPC_REQUEST_TIMEOUT_SECONDS` (8s) and re-trigger
                    // the storm. Bucket as `inflight_cap` so Grafana
                    // distinguishes "cap-saturated" from "no peers" /
                    // "send failed" — sustained non-zero rate combined
                    // with `zeam_blocks_by_root_inflight` pinned at the
                    // cap is the canonical signal that flood is being
                    // contained rather than absorbed.
                    self.logger.debug(
                        "blocks-by-root in-flight cap reached, deferring fetch of {d} root(s)",
                        .{missing_roots.items.len},
                    );
                    zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                        .{ .outcome = "inflight_cap" },
                        missing_roots.items.len,
                    ) catch {};
                },
                else => {
                    self.logger.warn(
                        "failed to send blocks-by-root request to peer: {any}",
                        .{err},
                    );
                    zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                        .{ .outcome = "fetch_failed" },
                        missing_roots.items.len,
                    ) catch {};
                },
            }
            break :blk null;
        };

        if (maybe_request) |request_info| {
            self.logger.debug("requested {d} block(s) by root from peer {s}{f}, request_id={d}", .{
                missing_roots.items.len,
                request_info.peer_id,
                self.node_registry.getNodeNameFromPeerId(request_info.peer_id),
                request_info.request_id,
            });
            // Slice (d): one bump per actually-fetched root so the
            // outcome buckets sum to `roots.len` for every call.
            zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                .{ .outcome = "fetched" },
                missing_roots.items.len,
            ) catch {};
        } else {
            // `ensureBlocksByRootRequest`
            // can return `null` non-erroneously when
            // `shouldRequestBlocksByRoot` rejects the batch — every
            // root was already in `network.pending_block_roots` or
            // `network.block_cache` by the time the network helper
            // re-checked, in between our `hasBlocksBatch` snapshot
            // and this dispatch (the benign TOCTOU documented at the
            // top of this function). Without a bucket here those
            // roots fall through unaccounted and the
            // `sum(rate(lean_block_fetch_dedup_total)) ==
            //  sum(rate(… by outcome))` invariant the audit test
            // claims to lock breaks under any racing-gossip workload.
            //
            // The `roots.len == 0` early return inside
            // `ensureBlocksByRootRequest` is unreachable from this
            // call site — the surrounding `if (missing_roots.items.len
            // == 0) return;` guard handles that case before we
            // dispatch — so `dedup_lost_race` is the only legitimate
            // null cause we need to account for.
            self.logger.debug(
                "blocks-by-root dispatch deduped late: {d} root(s) became known to network caches between snapshot and dispatch",
                .{missing_roots.items.len},
            );
            zeam_metrics.metrics.lean_block_fetch_dedup_total.incrBy(
                .{ .outcome = "dedup_lost_race" },
                missing_roots.items.len,
            ) catch {};
        }
    }

    /// Extract client type prefix from a node name like "zeam_0" -> "zeam", fallback "unknown".
    fn clientTypeFromName(name: ?[]const u8) []const u8 {
        const n = name orelse return "unknown";
        if (std.mem.indexOfScalar(u8, n, '_')) |sep| {
            if (sep > 0) return n[0..sep];
        }
        return if (n.len > 0) n else "unknown";
    }

    pub fn onPeerConnected(ptr: *anyopaque, peer_id: []const u8, direction: networks.PeerDirection) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        try self.network.connectPeer(peer_id);
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.info("peer connected: {s}{f}, direction={s}, total peers: {d}", .{
            peer_id,
            node_name,
            @tagName(direction),
            self.network.getPeerCount(),
        });

        // Record metrics
        zeam_metrics.metrics.lean_peer_connection_events_total.incr(.{ .direction = @tagName(direction), .result = "success" }) catch {};
        const client_name = node_name.name orelse "unknown";
        const client_type = clientTypeFromName(node_name.name);
        zeam_metrics.metrics.lean_connected_peers.set(.{ .client = client_name, .client_type = client_type }, 1) catch {};

        const handler = self.getReqRespResponseHandler();
        const status = self.chain.getStatus();

        const request_id = self.network.sendStatusToPeer(peer_id, status, handler) catch |err| {
            self.logger.warn("failed to send status request to peer {s}{f} {any}", .{
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                err,
            });
            return;
        };

        self.logger.info("sent status request to peer {s}{f}: request_id={d}, head_slot={d}, finalized_slot={d}", .{
            peer_id,
            self.node_registry.getNodeNameFromPeerId(peer_id),
            request_id,
            status.head_slot,
            status.finalized_slot,
        });
    }

    pub fn onPeerDisconnected(ptr: *anyopaque, peer_id: []const u8, direction: networks.PeerDirection, reason: networks.DisconnectionReason) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);

        if (self.network.disconnectPeer(peer_id)) {
            self.logger.info("peer disconnected: {s}{f}, direction={s}, reason={s}, total peers: {d}", .{
                peer_id,
                node_name,
                @tagName(direction),
                @tagName(reason),
                self.network.getPeerCount(),
            });

            // Record metrics
            zeam_metrics.metrics.lean_peer_disconnection_events_total.incr(.{ .direction = @tagName(direction), .reason = @tagName(reason) }) catch {};
            const client_name = node_name.name orelse "unknown";
            const client_type = clientTypeFromName(node_name.name);
            zeam_metrics.metrics.lean_connected_peers.set(.{ .client = client_name, .client_type = client_type }, 0) catch {};
        }

        if (reason == .timeout or reason == .error_) {
            self.maybeHealGossipMesh(self.updateWallHeadLagSnapshot());
        }
    }

    pub fn onPeerConnectionFailed(ptr: *anyopaque, peer_id: []const u8, direction: networks.PeerDirection, result: networks.ConnectionResult) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        self.logger.info("peer connection failed: {s}, direction={s}, result={s}", .{
            peer_id,
            @tagName(direction),
            @tagName(result),
        });

        // Record metrics for failed connection attempts
        zeam_metrics.metrics.lean_peer_connection_events_total.incr(.{ .direction = @tagName(direction), .result = @tagName(result) }) catch {};
    }

    pub fn getPeerEventHandler(self: *Self) networks.OnPeerEventCbHandler {
        return .{
            .ptr = self,
            .onPeerConnectedCb = onPeerConnected,
            .onPeerDisconnectedCb = onPeerDisconnected,
            .onPeerConnectionFailedCb = onPeerConnectionFailed,
        };
    }

    pub fn getOnIntervalCbWrapper(self: *Self) !*OnIntervalCbWrapper {
        // need a stable pointer across threads
        const cb_ptr = try self.allocator.create(OnIntervalCbWrapper);
        cb_ptr.* = .{
            .ptr = self,
            .onIntervalCb = onInterval,
        };

        return cb_ptr;
    }

    pub fn onInterval(ptr: *anyopaque, itime_intervals: isize) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // TODO check & fix why node-n1 is getting two oninterval fires in beam sim
        if (itime_intervals > 0 and itime_intervals <= self.chain.forkChoice.fcStore.slot_clock.time.load(.monotonic)) {
            self.logger.warn("skipping onInterval for node ad chain is already ahead at time={d} of the misfired interval time={d}", .{
                self.chain.forkChoice.fcStore.slot_clock.time.load(.monotonic),
                itime_intervals,
            });
            return;
        }

        // till its time to attest atleast for first time don't run onInterval,
        // just print chain status i.e avoid zero slot zero interval block production
        if (itime_intervals < 1) {
            const islot = @divFloor(itime_intervals, constants.INTERVALS_PER_SLOT);
            const interval = @mod(itime_intervals, constants.INTERVALS_PER_SLOT);

            if (interval == 1) {
                self.chain.printSlot(islot, constants.MAX_FC_CHAIN_PRINT_DEPTH, self.network.getPeerCount());
            }
            return;
        }

        var start_interval: isize = self.last_interval + 1;
        if (start_interval < 1) start_interval = 1;
        if (start_interval > itime_intervals) return;

        var current_interval: isize = start_interval;
        while (current_interval <= itime_intervals) : (current_interval += 1) {
            // Measure how long each interval tick keeps the libxev thread busy.
            const interval_tick_start_ns = zeam_utils.monotonicTimestampNs();
            defer {
                const elapsed_s = @as(f32, @floatFromInt(zeam_utils.monotonicTimestampNs() - interval_tick_start_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
                zeam_metrics.observeLibxevCallback("onInterval.tick", elapsed_s);
            }
            const interval: usize = @intCast(current_interval);
            const slot: types.Slot = @intCast(@divFloor(interval, constants.INTERVALS_PER_SLOT));

            // Commit per interval before sub-steps so later errors cannot replay it.
            self.last_interval = current_interval;

            // Feed wall-clock head lag into `getSyncStatus()` before the chain
            // tick updates sync metrics.
            const wall_head_lag_slots = self.updateWallHeadLagSnapshot();

            {
                // No outer mutex: each sub-system owns its locks.

                self.chain.onInterval(interval) catch |e| {
                    self.logger.err("error ticking chain to time(intervals)={d} err={any} (continuing tick)", .{ interval, e });
                    zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "chain.onInterval" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                    continue;
                };

                // Drain the future-slot `pending_blocks` queue. Runs inline
                // on the libxev thread because `processPendingBlocks` returns
                // missing block roots that must feed back into
                // `BeamNode.fetchBlockByRoots`, and the chain-worker thunk has
                // no handle to `BeamNode` to make that call. A worker → libxev
                // backchannel for the fetch is a follow-up;
                // see the comment on `chainWorkerProcessPendingBlocksThunk`.
                // Per-call work is bounded by `MAX_PENDING_BLOCKS` (1024) and
                // in steady state the queue is empty / single-digit.
                {
                    const missing_roots = self.chain.processPendingBlocks();
                    defer self.allocator.free(missing_roots);
                    if (missing_roots.len > 0) {
                        self.fetchBlockByRoots(missing_roots, 0) catch |e| {
                            self.logger.warn(
                                "failed to fetch {d} missing block root(s) from processPendingBlocks: {any}",
                                .{ missing_roots.len, e },
                            );
                        };
                    }
                }

                // Sweep timed-out RPC requests to prevent sync stalls from non-responsive peers.
                self.sweepTimedOutRequests();

                self.processReadyCachedBlocks(slot);

                // Re-dispatch backed-off blocks_by_root roots whose cooldown elapsed (interop
                // storm fix); drops any that have since been ingested.
                self.drainUnservedRetries();
            }

            // Application-layer failures are logged and counted, not returned.
            if (self.test_inject_validator_error_at_intervals.len > 0 and
                std.mem.indexOfScalar(usize, self.test_inject_validator_error_at_intervals, interval) != null)
            {
                self.logger.err("error ticking validator to time(intervals)={d} err=error.TestInjected (continuing tick)", .{interval});
                zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "validator.onInterval" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
            } else if (self.validator) |*validator| {
                // we also tick validator per interval in case it would
                // need to sync its future duties when its an independent validator
                var maybe_validator_output = validator.onInterval(self, interval) catch |e| blk: {
                    self.logger.err("error ticking validator to time(intervals)={d} err={any} (continuing tick)", .{ interval, e });
                    zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "validator.onInterval" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                    break :blk null;
                };

                if (maybe_validator_output) |*output| {
                    defer output.deinit();
                    for (output.gossip_messages.items) |gossip_msg| {
                        // Process based on message type
                        switch (gossip_msg) {
                            .block => |signed_block| {
                                self.publishBlock(signed_block) catch |e| {
                                    self.logger.err("error publishing block from validator at slot={d} interval={d}: {any} (continuing tick)", .{ slot, interval, e });
                                    zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "publishBlock" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                                };
                            },
                            .attestation => |signed_attestation| {
                                self.publishAttestation(signed_attestation) catch |e| {
                                    self.logger.err("error publishing attestation from validator at slot={d} interval={d}: {any} (continuing tick)", .{ slot, interval, e });
                                    zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "publishAttestation" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                                };
                            },
                            .aggregation => |signed_aggregation| {
                                self.publishAggregation(signed_aggregation) catch |e| {
                                    self.logger.err("error publishing aggregation from validator at slot={d} interval={d}: {any} (continuing tick)", .{ slot, interval, e });
                                    zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "publishAggregation" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                                };
                            },
                        }
                    }
                }
            }

            const interval_in_slot = interval % constants.INTERVALS_PER_SLOT;

            // Forced refresh requested by the slot-driver watchdog after a
            // stall. The watchdog runs on a separate OS thread and
            // cannot safely emit RPCs itself; it only flips this atomic
            // flag. The first tick after stall recovery picks it up here
            // and runs a status round-trip outside the normal 8-slot
            // cadence so catch-up resumes immediately.
            if (self.sync_refresh_pending.swap(false, .acquire)) {
                self.logger.warn("slot-driver stall recovery: forcing peer status refresh", .{});
                self.refreshSyncFromPeers();
            }

            self.runSyncRecoveryOnInterval(slot, interval_in_slot, wall_head_lag_slots);

            // The interval-0 block-production trigger lives in validator.onInterval
            // (above) — it is a proposer duty, decided + dispatched by the validator layer (still
            // executed off-loop on a worker). Aggregation below stays here: it is gated by the
            // chain-level aggregator role (is_aggregator_enabled), not a validator-client duty.
            if (interval_in_slot == 2) {
                const agg_timer = zeam_metrics.zeam_node_aggregation_interval_tick_seconds.start();
                defer _ = agg_timer.observe();
                // Aggregate work is submitted to a dedicated Io.Threaded
                // worker. submitAggregateOnInterval returns within microseconds;
                // the worker calls publishProducedAggregations itself.
                if (self.test_inject_aggregator_error_at_intervals.len > 0 and
                    std.mem.indexOfScalar(usize, self.test_inject_aggregator_error_at_intervals, interval) != null)
                {
                    self.logger.err("error producing aggregations at slot={d} interval={d}: {any} (continuing tick)", .{ slot, interval, error.TestInjected });
                    zeam_metrics.metrics.lean_node_interval_error_total.incr(.{ .site = "maybeAggregateOnInterval" }) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
                } else {
                    self.chain.submitAggregateOnInterval(self, interval);
                }
            }
        }
    }

    /// Schedule a peer status refresh on the next libxev tick. Safe to
    /// call from any thread — only flips an atomic flag. Used by
    /// `SlotDriverWatchdog` to bootstrap recovery once the slot driver
    /// resumes after a stall.
    pub fn scheduleSyncRefresh(self: *Self) void {
        self.sync_refresh_pending.store(true, .release);
    }

    /// `SlotDriverWatchdog.StallCallback` adapter. Cheap, non-blocking;
    /// runs on the watchdog thread. Defers the actual peer-status RPCs
    /// to the next libxev tick via `scheduleSyncRefresh`.
    pub fn onSlotDriverStall(ptr: *anyopaque, stall_s: f32) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        _ = stall_s;
        self.scheduleSyncRefresh();
    }

    fn updateWallHeadLagSnapshot(self: *Self) u64 {
        const our_head_slot = self.chain.forkChoice.getHead().slot;
        const wall_slot = self.clock.wallSlotNow();
        const wall_head_lag_slots = blocks_by_range_sync.cappedSyncGapSlots(wall_slot, our_head_slot, wall_slot);
        self.chain.setWallHeadLagSlots(wall_head_lag_slots);
        return wall_head_lag_slots;
    }

    fn gossipIngressSnapshot(self: *Self) struct { silent_ms: u64, block_silent_ms: u64, mesh_peers: u64 } {
        const now_ms: u64 = @intCast(zeam_utils.unixTimestampMillis());
        const last_block_ms = self.last_gossip_block_rx_ms.load(.monotonic);
        // "Block silent" semantics. Returns `maxInt(u64)` when we
        // have never delivered a block to the application — that signals
        // "infinitely silent on the block topic" to the proactive catch-up
        // gate, which is exactly what we want when block ingress has not
        // started yet (just past genesis with all blocks failing
        // snappy decode, etc.). Once any block ever decodes cleanly via
        // `onGossip`, this collapses to the normal `now_ms - last_block_ms`
        // measurement.
        const block_silent_ms: u64 = if (last_block_ms == 0)
            std.math.maxInt(u64)
        else
            now_ms -| last_block_ms;
        return .{
            .silent_ms = blocks_by_range_sync.gossipSilentMs(
                now_ms,
                self.last_gossip_rx_ms.load(.monotonic),
            ),
            .block_silent_ms = block_silent_ms,
            .mesh_peers = self.network.gossipMeshPeerCount(),
        };
    }

    fn runSyncRecoveryOnInterval(self: *Self, slot: types.Slot, interval_in_slot: usize, wall_head_lag_slots: u64) void {
        const sync_status = self.chain.getSyncStatus();
        const our_head_slot = self.chain.forkChoice.getHead().slot;
        const wall_slot = self.clock.wallSlotNow();
        const refresh_decision = blocks_by_range_sync.shouldRefreshPeerStatus(
            sync_status,
            interval_in_slot,
            slot,
            our_head_slot,
            wall_slot,
            constants.SYNC_STATUS_REFRESH_INTERVAL_SLOTS,
            constants.SYNC_STATUS_WALL_HEAD_LAG_THRESHOLD_SLOTS,
        );
        if (refresh_decision.refresh) {
            switch (sync_status) {
                .synced => self.logger.info(
                    "head is {d} wall-clock slots behind while synced; refreshing peer status for catch-up",
                    .{refresh_decision.wall_head_lag_slots},
                ),
                else => {},
            }
            self.refreshSyncFromPeers();
        }

        // Proactive catch-up runs every slot rather than at the status-refresh
        // cadence: when gossip ingress has stalled, waiting up to 8 slots for
        // the next refresh window defeats the point of acting on cached peer
        // status. Overlap is filtered inside `initiateBlocksByRangeCatchUp`.
        if (interval_in_slot == 0) {
            self.maybeInitiateProactiveCatchUp(wall_head_lag_slots);
            // Same slot-boundary cadence as proactive catch-up.
            // The detector itself is rate-limited internally so wiring it here
            // doesn't fire every interval; we just need a clock tick to evaluate
            // the predicate against fresh wall_slot / best-peer-head values.
            self.maybeForceFullPeerStatusRefresh(slot);
        }

        if (interval_in_slot == 0 and slot % constants.GOSSIP_MESH_HEAL_INTERVAL_SLOTS == 0) {
            self.maybeHealGossipMesh(wall_head_lag_slots);
        }
    }

    /// Snapshot the best (highest head_slot) peer status while holding the
    /// connected-peers read lock, duplicating peer_id so the caller can
    /// safely release the lock before issuing RPCs.
    ///
    /// Caller owns `result.peer_id` and must free it via `self.allocator`.
    ///
    /// Borrowing `entry.key_ptr.*` past `guard.deinit()` would race with
    /// `onPeerDisconnected` (rust-bridge thread) freeing the hash-map key,
    /// causing a use-after-free in the downstream RPC dispatch.
    fn findBestCatchUpPeerStatus(self: *Self) ?CatchUpPeerStatus {
        var best: ?CatchUpPeerStatus = null;
        var best_peer_id_buf: []u8 = &[_]u8{};
        var guard = self.network.connected_peers.iterateLocked();
        defer guard.deinit();
        while (guard.iter.next()) |entry| {
            const peer_info = entry.value_ptr;
            const status = peer_info.latest_status orelse continue;
            if (best != null and status.head_slot <= best.?.head_slot) continue;

            const owned = self.allocator.dupe(u8, entry.key_ptr.*) catch continue;
            if (best_peer_id_buf.len != 0) self.allocator.free(best_peer_id_buf);
            best_peer_id_buf = owned;
            best = .{
                .peer_id = owned,
                .head_slot = status.head_slot,
                .head_root = status.head_root,
                .finalized_slot = status.finalized_slot,
            };
        }
        return best;
    }

    fn maybeInitiateProactiveCatchUp(self: *Self, wall_head_lag_slots: u64) void {
        const ingress = self.gossipIngressSnapshot();
        // Gate on block-topic silence, not union-of-all-topics
        // silence. Attestations decode reliably even on a fleet where
        // every block is being rejected by snappy.error.Corrupt; if we
        // gated on union-silence the attestation stream would suppress
        // the catch-up RPC indefinitely while no block ever reaches the
        // app. With `block_silent_ms` the gate fires the moment we have
        // a wall-lag and no block has come through gossip for the stall
        // threshold (8 s on a 4 s slot).
        if (!blocks_by_range_sync.shouldInitiateProactiveCatchUp(
            wall_head_lag_slots,
            constants.SYNC_STATUS_WALL_HEAD_LAG_THRESHOLD_SLOTS,
            ingress.block_silent_ms,
            constants.gossipStallThresholdMs(),
        )) return;

        const our_head_slot = self.chain.forkChoice.getHead().slot;
        const our_finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
        const catch_up_status = self.findBestCatchUpPeerStatus() orelse return;
        defer self.allocator.free(catch_up_status.peer_id);
        if (!self.shouldCatchUpFromPeerStatus(catch_up_status, our_head_slot, our_finalized_slot)) return;

        self.logger.info(
            "proactive catch-up: block-gossip silent for {d}ms (any-gossip silent for {d}ms), wall lag {d} slots, peer {s}{f} head={d}",
            .{
                ingress.block_silent_ms,
                ingress.silent_ms,
                wall_head_lag_slots,
                catch_up_status.peer_id,
                self.node_registry.getNodeNameFromPeerId(catch_up_status.peer_id),
                catch_up_status.head_slot,
            },
        );
        self.initiateCatchUpFromPeerStatus(catch_up_status, our_head_slot);
    }

    fn maybeHealGossipMesh(self: *Self, wall_head_lag_slots: u64) void {
        const ingress = self.gossipIngressSnapshot();
        if (!blocks_by_range_sync.shouldHealGossipMesh(
            ingress.mesh_peers,
            constants.GOSSIP_MESH_MIN_PEERS,
            ingress.silent_ms,
            constants.gossipStallThresholdMs(),
        )) return;

        self.logger.info(
            "gossip mesh heal: mesh_peers={d} gossip_silent_ms={d} wall_lag={d}",
            .{ ingress.mesh_peers, ingress.silent_ms, wall_head_lag_slots },
        );
        self.network.refreshGossipMesh();
    }

    /// Re-send our status to a rotating batch of connected peers.
    ///
    /// Called periodically when the node is not yet synced so that peers
    /// already connected before the sync mechanism became aware of them
    /// (e.g., after a restart or while stuck in fc_initing) get another
    /// chance to report their head and trigger block fetching.
    fn refreshSyncFromPeers(self: *Self) void {
        self.refreshSyncFromPeersImpl(.batched);
    }

    /// Refresh selector for `refreshSyncFromPeersImpl`. `.batched` walks the
    /// rotating peer-cursor window of `SYNC_STATUS_REFRESH_PEERS_PER_TICK`
    /// (the existing batched behaviour). `.full_fanout` sends status to every
    /// connected peer in one tick — only used by the stuck-mesh-cluster
    /// detector and rate-limited at the caller side by
    /// `SYNC_STATUS_STUCK_CLUSTER_REFRESH_COOLDOWN_SLOTS`.
    const RefreshKind = enum { batched, full_fanout };

    fn refreshSyncFromPeersImpl(self: *Self, kind: RefreshKind) void {
        // Snapshot the connected peer ids under the shared lock so we can
        // call `sendStatusToPeer` (which takes its own locks) without
        // holding the connected_peers lock across nested locks.
        var peer_ids: std.ArrayList([]u8) = .empty;
        defer {
            for (peer_ids.items) |p| self.allocator.free(p);
            peer_ids.deinit(self.allocator);
        }
        {
            var guard = self.network.connected_peers.iterateLocked();
            defer guard.deinit();
            while (guard.iter.next()) |entry| {
                const owned = self.allocator.dupe(u8, entry.key_ptr.*) catch continue;
                peer_ids.append(self.allocator, owned) catch {
                    self.allocator.free(owned);
                    continue;
                };
            }
        }

        const status = self.chain.getStatus();
        const handler = self.getReqRespResponseHandler();
        const total = peer_ids.items.len;

        const window_start: usize, const window_count: usize = switch (kind) {
            .batched => blk: {
                const batch = blocks_by_range_sync.peerBatchWindow(
                    total,
                    self.sync_refresh_peer_cursor,
                    constants.SYNC_STATUS_REFRESH_PEERS_PER_TICK,
                );
                self.sync_refresh_peer_cursor = batch.next_cursor;
                break :blk .{ batch.start, batch.count };
            },
            .full_fanout => .{ 0, total },
        };

        var sent: usize = 0;
        var i: usize = 0;
        while (i < window_count) : (i += 1) {
            const idx = (window_start + i) % total;
            const peer_id = peer_ids.items[idx];
            _ = self.network.sendStatusToPeer(peer_id, status, handler) catch |err| {
                self.logger.warn("failed to refresh status to peer {s}{f}: {any}", .{
                    peer_id,
                    self.node_registry.getNodeNameFromPeerId(peer_id),
                    err,
                });
            };
            sent += 1;
        }
        switch (kind) {
            .batched => if (sent < total) {
                self.logger.debug(
                    "status refresh batch: sent {d}/{d} peers (cursor={d})",
                    .{ sent, total, self.sync_refresh_peer_cursor },
                );
            },
            .full_fanout => self.logger.info(
                "status refresh full fanout: sent {d}/{d} peers (stuck-mesh-cluster detector)",
                .{ sent, total },
            ),
        }
    }

    /// Detect the "stuck mesh cluster" condition (all visible
    /// peers report a head_slot far below wall-clock) and trigger a one-shot
    /// full-fanout status refresh to try to discover any peer that has actually
    /// moved. Rate-limited via `last_stuck_cluster_refresh_slot` so a
    /// continuously-true condition fires at most once per
    /// `SYNC_STATUS_STUCK_CLUSTER_REFRESH_COOLDOWN_SLOTS` slot window.
    ///
    /// This complements the existing batched refresh: the batch eventually
    /// rotates through every peer over ~`peers / 8` slots, but on a stuck
    /// network that's tens of seconds wasted hammering the same stale-head
    /// targets. The full fanout closes that window when the data we have says
    /// "no visible peer is on the chain tip" — exactly the signal seen in one
    /// observed incident where a node's best cached peer head was 45 while
    /// wall-clock was at 298.
    fn maybeForceFullPeerStatusRefresh(self: *Self, slot: types.Slot) void {
        const best = self.findBestCatchUpPeerStatus() orelse return;
        defer self.allocator.free(best.peer_id);
        const wall_slot = self.clock.wallSlotNow();
        const last_force = self.last_stuck_cluster_refresh_slot.load(.monotonic);
        if (!blocks_by_range_sync.shouldForceFullPeerStatusRefresh(
            best.head_slot,
            wall_slot,
            slot,
            last_force,
            constants.SYNC_STATUS_STUCK_CLUSTER_PEER_LAG_THRESHOLD_SLOTS,
            constants.SYNC_STATUS_STUCK_CLUSTER_REFRESH_COOLDOWN_SLOTS,
        )) return;
        self.logger.warn(
            "stuck mesh cluster detected: best peer {s}{f} reports head={d}, wall={d}, our_head_lag={d}; forcing full-fanout status refresh",
            .{
                best.peer_id,
                self.node_registry.getNodeNameFromPeerId(best.peer_id),
                best.head_slot,
                wall_slot,
                wall_slot -| self.chain.forkChoice.getHead().slot,
            },
        );
        self.last_stuck_cluster_refresh_slot.store(slot, .monotonic);
        self.refreshSyncFromPeersImpl(.full_fanout);
    }

    /// Collect `blocks_by_root` roots that were NOT served by any chunk
    /// (still present in `pending_block_roots` when the request ends),
    /// finalize the request, then re-schedule each unserved root via
    /// `fetchBlockByRoots` so a new (hopefully different) peer can serve
    /// it.
    ///
    /// Called from the `.completed` and `.failure` arms of
    /// `handleReqRespResponse` for `blocks_by_root` requests.
    /// Without this, a peer that returns EOS or a protocol error without
    /// serving one or more of the requested roots permanently removes
    /// those roots from `pending_block_roots` (via `finalizePendingRequest`)
    /// and leaves the parent-chain-walk orphaned — the cached child
    /// blocks sit in `block_cache` forever waiting for a parent nobody
    /// fetches again. This manifests as a sync stall during `fc_initing`
    /// when one of the two connected peers has `head_slot=0` and the
    /// random peer selector (`selectPeerCopy`) occasionally routes a
    /// parent-chain fetch to it.
    fn retryUnservedBlockRoots(
        self: *Self,
        request_id: u64,
        requested_roots: []const types.Root,
        peer_id: []const u8,
    ) void {
        // Collect roots still in pending_block_roots (unserved) BEFORE
        // finalizePendingRequest removes them.
        var roots_to_retry: std.ArrayListUnmanaged(struct { root: types.Root, depth: u32 }) = .empty;
        defer roots_to_retry.deinit(self.allocator);
        for (requested_roots) |root| {
            if (self.network.getPendingBlockRootDepth(root)) |depth| {
                roots_to_retry.append(self.allocator, .{ .root = root, .depth = depth }) catch {};
            }
        }
        if (roots_to_retry.items.len > 0) {
            self.logger.warn(
                "blocks-by-root request_id={d} from peer {s}: {d}/{d} root(s) unserved — scheduling retry via new peer",
                .{ request_id, peer_id, roots_to_retry.items.len, requested_roots.len },
            );
        }
        // Finalize clears pending state + releases in-flight slot.
        self.network.finalizePendingRequest(request_id);

        // `processBlockByRootChunk` may have discovered the next parent while
        // this request was still counted in `blocks_by_root_inflight`. During a
        // long parent walk (late-start sync / checkpoint catch-up) that can hit
        // MAX_CONCURRENT_BLOCKS_BY_ROOT before any completion event releases a
        // slot, leaving the newest parent root queued in
        // `batch_pending_parent_roots` with nobody left to flush it. Now that
        // this request is finalized, immediately drain any queued parent roots
        // and keep the walk on the peer that served this response.
        self.flushPendingParentFetches(peer_id);

        // Re-schedule each unserved root. `scheduleUnservedRetry` allows a small number of
        // immediate re-routes to a different peer (keeps a parent-chain walk progressing past a
        // peer that EOS'd without serving), then switches to exponential backoff driven by
        // `drainUnservedRetries` on the interval tick. This prevents the tight ~700 req/s
        // blocks_by_root storm that occurs when NO peer can serve the root (e.g. a freshly-proposed
        // block still mid off-loop Type-2 merge), which otherwise starves the prover and worsens
        // the very delay it is waiting on. fetchBlockByRoots still dedups against
        // forkchoice/cache/pending and picks a new peer.
        for (roots_to_retry.items) |item| {
            if (self.scheduleUnservedRetry(item.root, item.depth)) {
                const single = [_]types.Root{item.root};
                self.fetchBlockByRoots(&single, item.depth) catch |err| {
                    self.logger.warn("retryUnservedBlockRoots: failed to re-fetch root after unserved EOS/failure: {any}", .{err});
                };
            }
        }
    }

    /// Record an unserved block root and decide whether to re-fetch it immediately. Returns true
    /// for the first `BLOCKS_BY_ROOT_IMMEDIATE_RETRIES` unserved responses (so a parent-chain walk
    /// can re-route to another peer without delay); afterwards arms an exponentially backed-off
    /// retry (dispatched later by `drainUnservedRetries`) and returns false. See the
    /// `BLOCKS_BY_ROOT_*` constants for the rationale.
    fn scheduleUnservedRetry(self: *Self, root: types.Root, depth: u32) bool {
        self.unserved_block_retries_lock.lock();
        defer self.unserved_block_retries_lock.unlock();

        const gop = self.unserved_block_retries.getOrPut(root) catch {
            // OOM tracking the retry: degrade to the old immediate-retry behavior rather than
            // dropping the root (correctness over storm-avoidance in the rare OOM case).
            return true;
        };
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .depth = depth, .attempts = 1, .next_retry_ns = 0 };
            return true;
        }
        gop.value_ptr.attempts += 1;
        gop.value_ptr.depth = depth;
        if (gop.value_ptr.attempts <= BLOCKS_BY_ROOT_IMMEDIATE_RETRIES) {
            gop.value_ptr.next_retry_ns = 0;
            return true;
        }
        // Exponential backoff: BASE << (attempts - immediate - 1), capped at MAX.
        const shift: u6 = @intCast(@min(gop.value_ptr.attempts - BLOCKS_BY_ROOT_IMMEDIATE_RETRIES - 1, 16));
        const backoff_ms = @min(BLOCKS_BY_ROOT_RETRY_BASE_MS << shift, BLOCKS_BY_ROOT_RETRY_MAX_MS);
        gop.value_ptr.next_retry_ns = zeam_utils.monotonicTimestampNs() + @as(i128, @intCast(backoff_ms)) * std.time.ns_per_ms;
        return false;
    }

    /// Interval-tick driver for backed-off blocks_by_root retries. Drops roots already ingested
    /// (lazy cleanup) and re-dispatches roots whose backoff has elapsed, re-arming each at the MAX
    /// cadence until its `unserved` response recomputes the schedule via `scheduleUnservedRetry`.
    fn drainUnservedRetries(self: *Self) void {
        const now = zeam_utils.monotonicTimestampNs();
        var due: std.ArrayListUnmanaged(struct { root: types.Root, depth: u32 }) = .empty;
        defer due.deinit(self.allocator);
        var to_remove: std.ArrayListUnmanaged(types.Root) = .empty;
        defer to_remove.deinit(self.allocator);

        {
            self.unserved_block_retries_lock.lock();
            defer self.unserved_block_retries_lock.unlock();
            var it = self.unserved_block_retries.iterator();
            while (it.next()) |entry| {
                const root = entry.key_ptr.*;
                if (self.chain.forkChoice.hasBlock(root)) {
                    to_remove.append(self.allocator, root) catch {};
                    continue;
                }
                if (entry.value_ptr.next_retry_ns != 0 and now >= entry.value_ptr.next_retry_ns) {
                    due.append(self.allocator, .{ .root = root, .depth = entry.value_ptr.depth }) catch {};
                    // Re-arm at MAX cadence; the (re)dispatch's unserved response recomputes the
                    // backoff via scheduleUnservedRetry. Prevents double-dispatch before it returns.
                    entry.value_ptr.next_retry_ns = now + @as(i128, @intCast(BLOCKS_BY_ROOT_RETRY_MAX_MS)) * std.time.ns_per_ms;
                }
            }
            for (to_remove.items) |root| _ = self.unserved_block_retries.remove(root);
        }

        for (due.items) |item| {
            const single = [_]types.Root{item.root};
            self.fetchBlockByRoots(&single, item.depth) catch |err| {
                self.logger.warn("drainUnservedRetries: failed to re-fetch backed-off root: {any}", .{err});
            };
        }
    }

    fn sweepTimedOutRequests(self: *Self) void {
        const current_time = zeam_utils.unixTimestampSeconds();
        const timed_out = self.network.getTimedOutRequests(current_time, constants.RPC_REQUEST_TIMEOUT_SECONDS) catch |err| {
            self.logger.warn("failed to check for timed-out RPC requests: {any}", .{err});
            return;
        };
        defer self.allocator.free(timed_out);

        for (timed_out) |request_id| {
            // Snapshot the entry so we can `finalizePendingRequest` (which
            // takes the pending_rpc_requests lock for write) without
            // racing the snapshot's read.
            var snap = (self.network.snapshotPendingRequest(request_id) catch |err| {
                self.logger.warn("failed to snapshot timed-out request_id={d}: {any}", .{ request_id, err });
                continue;
            }) orelse continue;
            defer snap.deinit(self.allocator);

            switch (snap.request_kind) {
                .blocks_by_root => {
                    // Copy roots + depths BEFORE finalize frees them
                    var roots_to_retry = std.ArrayList(struct { root: types.Root, depth: u32 }).empty;
                    defer roots_to_retry.deinit(self.allocator);

                    for (snap.requested_roots_copy) |root| {
                        const depth = self.network.getPendingBlockRootDepth(root) orelse 0;
                        roots_to_retry.append(self.allocator, .{ .root = root, .depth = depth }) catch continue;
                    }

                    self.logger.warn("RPC request_id={d} to peer {s}{f} timed out after {d}s, retrying {d} roots", .{
                        request_id,
                        snap.peer_id_copy,
                        self.node_registry.getNodeNameFromPeerId(snap.peer_id_copy),
                        constants.RPC_REQUEST_TIMEOUT_SECONDS,
                        roots_to_retry.items.len,
                    });

                    // Finalize clears pending state + frees memory
                    self.network.finalizePendingRequest(request_id);

                    // Retry each root — fetchBlockByRoots picks a new random peer
                    for (roots_to_retry.items) |item| {
                        const roots = [_]types.Root{item.root};
                        self.fetchBlockByRoots(&roots, item.depth) catch |err| {
                            self.logger.warn("failed to retry block fetch after timeout: {any}", .{err});
                        };
                    }
                },
                .status => {
                    self.logger.warn("status RPC request_id={d} to peer {s}{f} timed out, finalizing", .{
                        request_id,
                        snap.peer_id_copy,
                        self.node_registry.getNodeNameFromPeerId(snap.peer_id_copy),
                    });
                    self.network.finalizePendingRequest(request_id);
                },
                .blocks_by_range => {
                    self.logger.warn("blocks_by_range RPC request_id={d} to peer {s}{f} timed out after {d}s", .{
                        request_id,
                        snap.peer_id_copy,
                        self.node_registry.getNodeNameFromPeerId(snap.peer_id_copy),
                        constants.RPC_REQUEST_TIMEOUT_SECONDS,
                    });
                    self.handleBlocksByRangeSyncEnd(request_id, snap, .timeout, false);
                },
            }
        }
    }

    pub fn publishBlock(self: *Self, signed_block: types.SignedBlock) !void {
        const block = signed_block.block;

        // 1. Process locally through chain so the produced block is confirmed and persisted.
        var block_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.block, &block_root, self.allocator);

        // 2. Reprocess locally produced block through chain so forkchoice is updated.
        //    TODO: might not be needed for locally produced block if we totally depend on the aggregators to serve us attestations
        const hasBlock = self.chain.forkChoice.hasBlock(block_root);
        if (hasBlock) {
            self.logger.debug("reprocessing locally produced block: slot={d} proposer={d}", .{
                block.slot,
                block.proposer_index,
            });
        } else {
            self.logger.debug("processing block not locally produced before publishing: slot={d} proposer={d}", .{
                block.slot,
                block.proposer_index,
            });
        }

        // Slice (a-2) migration: the previous `states.get(block_root)`
        // shortcut handed `chain.onBlock` the cached post-state pointer to
        // skip recomputation when the block was already produced locally.
        // Under the new per-resource locking model that pointer would have
        // to be carried as a `BorrowedState`, but `chain.onBlock` itself
        // takes `states_lock.exclusive` to commit — holding the read side
        // across that call would deadlock. The post-state recompute path
        // is now the single source of truth for both produced-locally and
        // received-from-gossip blocks; the `statesPutOrSwap` helper inside
        // `onBlock` keeps the original in-map pointer intact when the
        // entry already exists, so locally produced blocks no longer leak
        // their initial post-state on the publish hop. See the design doc
        // §Resource-by-resource design / `BeamChain.states` for context.
        //
        // Stays inline (NOT routed through the chain-worker like the RPC
        // paths): the validator path runs on the libxev thread,
        // and downstream callers / tests assume the block is in
        // forkchoice by the time `publishBlock` returns. Async would
        // surface a race where attestations produced in the same
        // interval reference a block the chain hasn't imported yet.
        // The replay below still goes via the worker.
        const missing_roots = try self.chain.onBlock(signed_block, .{
            .blockRoot = block_root,
        });
        defer self.allocator.free(missing_roots);

        self.fetchBlockByRoots(missing_roots, 0) catch |err| {
            self.logger.warn("failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
        };

        // 3. Publish gossip message to the network.
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        const block_published = try self.network.publish(&gossip_msg);
        if (block_published) {
            self.logger.info("published block to network: slot={d} proposer={d}{f}", .{
                block.slot,
                block.proposer_index,
                self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
            });
        } else {
            // Backend dropped the publish (e.g. rust-libp2p command
            // channel full). The block is in our local chain but never reached
            // the network — surface it instead of logging "published".
            self.logger.warn("failed to publish block to network (backend dropped publish): slot={d} proposer={d}{f}", .{
                block.slot,
                block.proposer_index,
                self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
            });
        }

        // 4. Followup with additional housekeeping tasks.
        self.chain.onBlockFollowup(true, &signed_block);
        self.replayPendingAttestationsAsync(.local_publish);
    }

    pub fn publishAttestation(self: *Self, signed_attestation: networks.AttestationGossip) !void {
        const data = signed_attestation.message.message;
        const validator_id = signed_attestation.message.validator_id;
        _ = signed_attestation.subnet_id;

        // 1. Process locally through chain
        self.logger.info("adding locally produced attestation to chain: slot={d} validator={d}", .{
            data.slot,
            validator_id,
        });
        try self.chain.onGossipAttestation(signed_attestation);

        // 2. publish gossip message
        const gossip_msg = networks.GossipMessage{ .attestation = signed_attestation };
        const attestation_published = try self.network.publish(&gossip_msg);

        if (attestation_published) {
            self.logger.info("published attestation to network: slot={d} validator={d}{f}", .{
                data.slot,
                validator_id,
                self.node_registry.getNodeNameFromValidatorIndex(validator_id),
            });
        } else {
            // Backend dropped the publish. The attestation is in
            // our local chain but never reached gossip — don't log "published".
            self.logger.warn("failed to publish attestation to network (backend dropped publish): slot={d} validator={d}{f}", .{
                data.slot,
                validator_id,
                self.node_registry.getNodeNameFromValidatorIndex(validator_id),
            });
        }
    }

    /// Full local ingestion for aggregations not yet in fork choice (e.g. validator duty output).
    pub fn publishAggregation(self: *Self, signed_aggregation: types.SignedAggregatedAttestation) !void {
        self.logger.info("adding locally produced aggregation to chain: slot={d}", .{signed_aggregation.data.slot});
        try self.chain.onGossipAggregatedAttestation(signed_aggregation);
        try self.publishAggregationGossip(signed_aggregation);
    }

    /// Publish an aggregation already committed by the aggregate worker.
    ///
    /// Skips XMSS re-verification and fork-choice payload re-store; only updates
    /// attestation trackers and encodes to gossip.
    pub fn publishLocalProducedAggregation(self: *Self, signed_aggregation: types.SignedAggregatedAttestation) !void {
        self.logger.info("publishing locally committed aggregation: slot={d}", .{signed_aggregation.data.slot});

        var validator_indices = try types.aggregationBitsToValidatorIndices(
            &signed_aggregation.proof.participants,
            self.allocator,
        );
        defer validator_indices.deinit(self.allocator);
        self.chain.applyAggregatedAttestationTrackers(signed_aggregation.data, validator_indices.items);
        try self.publishAggregationGossip(signed_aggregation);
    }

    /// Publish one worker-committed aggregate: metrics, fast path, then deinit.
    pub fn publishCommittedAggregation(self: *Self, signed_aggregation: types.SignedAggregatedAttestation) void {
        var agg = signed_aggregation;
        self.chain.recordAggregatorPublishMetric(&agg);
        self.publishLocalProducedAggregation(agg) catch |err| {
            self.logger.err(
                "error publishing aggregation at slot={d}: {any} (continuing worker)",
                .{ agg.data.slot, err },
            );
            zeam_metrics.metrics.lean_node_interval_error_total.incr(
                .{ .site = "publishLocalProducedAggregation" },
            ) catch |me| self.logger.warn("metric incr failed: {any}", .{me});
            agg.deinit();
            return;
        };
        agg.deinit();
    }

    fn publishAggregationGossip(self: *Self, signed_aggregation: types.SignedAggregatedAttestation) !void {
        const gossip_msg = networks.GossipMessage{ .aggregation = signed_aggregation };
        const aggregation_published = try self.network.publish(&gossip_msg);

        if (aggregation_published) {
            self.logger.info("published aggregation to network: slot={d}", .{signed_aggregation.data.slot});
        } else {
            self.logger.warn("failed to publish aggregation to network (backend dropped publish): slot={d}", .{signed_aggregation.data.slot});
        }
    }

    /// Publish every aggregation independently; deinit each entry exactly once.
    pub fn publishProducedAggregations(self: *Self, aggregations: []types.SignedAggregatedAttestation) void {
        for (aggregations) |*signed_aggregation| {
            self.publishCommittedAggregation(signed_aggregation.*);
        }
    }

    pub fn run(self: *Self) !void {
        // Catch up fork choice time to current interval before processing any requests.
        // Keeps validator duties and aggregation timing aligned with the local clock.
        const current_interval = self.clock.current_interval;
        if (current_interval > 0) {
            try self.chain.forkChoice.onInterval(@intCast(current_interval), false);
            // Keep node interval state aligned with forkchoice catch-up to avoid
            // replaying historical validator duties when starting late.
            self.last_interval = current_interval;
            self.logger.info("fork choice time caught up to interval {d}", .{current_interval});
        }

        const handler = try self.getOnGossipCbHandler();

        var topics_list: std.ArrayList(networks.GossipTopic) = .empty;
        defer topics_list.deinit(self.allocator);

        try topics_list.append(self.allocator, .{ .kind = .block });
        try topics_list.append(self.allocator, .{ .kind = .aggregation });

        const committee_count = self.chain.config.spec.attestation_committee_count;
        if (committee_count > 0) {
            // Collect all subnets to subscribe into a deduplication set.
            var seen_subnets = std.AutoHashMap(u32, void).init(self.allocator);
            defer seen_subnets.deinit();

            // Always subscribe to explicitly specified import subnet ids for aggregation irrespective of
            // validators.
            //
            // Note: this subscription decision is only taken once at startup,
            // using the initial aggregator flag. Toggling the role at runtime
            // via the admin API does not add or remove gossip subscriptions;
            // a node that wants to serve as a hot-standby aggregator should
            // start with `--is-aggregator true` and turn the role off via the
            // API until it's needed.
            if (self.chain.isAggregator()) {
                if (self.aggregation_subnet_ids) |explicit_subnets| {
                    for (explicit_subnets) |subnet_id| {
                        if (seen_subnets.contains(subnet_id)) continue;
                        try seen_subnets.put(subnet_id, {});
                        try topics_list.append(self.allocator, .{ .kind = .attestation, .subnet_id = subnet_id });
                    }
                }
            }

            // Additionally subscribe to these subnets for validators to create mesh network for attestations
            if (self.validator) |validator| {
                for (validator.ids) |validator_id| {
                    const subnet_id = try types.computeSubnetId(@intCast(validator_id), committee_count);
                    if (seen_subnets.contains(@intCast(subnet_id))) continue;
                    try seen_subnets.put(@intCast(subnet_id), {});
                    try topics_list.append(self.allocator, .{ .kind = .attestation, .subnet_id = @intCast(subnet_id) });
                }
            }

            // If no subnets were added yet (aggregator but no explicit ids and no
            // validators registered), fall back to subnet 0.
            if (seen_subnets.count() == 0 and self.chain.isAggregator()) {
                try topics_list.append(self.allocator, .{ .kind = .attestation, .subnet_id = 0 });
            }
        }
        // if no committee count specified and still aggregator, all are in subnet 0
        else if (self.chain.isAggregator()) {
            try topics_list.append(self.allocator, .{ .kind = .attestation, .subnet_id = 0 });
        }

        const topics_slice = try topics_list.toOwnedSlice(self.allocator);
        defer self.allocator.free(topics_slice);

        // Report the selective gossip subscription set so operators can verify
        // (and so subnet-routing regressions are visible in logs).
        var attestation_subnet_count: usize = 0;
        for (topics_slice) |topic| {
            if (topic.kind == .attestation) attestation_subnet_count += 1;
        }
        if (attestation_subnet_count == 0) {
            self.logger.info("gossip subscriptions: block + aggregation only (no attestation subnets — non-aggregator node with no registered validators)", .{});
        } else {
            // Format the attestation subnet IDs into a comma-separated list for a single
            // human-readable log line.
            var subnet_ids_buf: std.ArrayList(u8) = .empty;
            defer subnet_ids_buf.deinit(self.allocator);
            var first = true;
            var id_buf: [32]u8 = undefined;
            for (topics_slice) |topic| {
                if (topic.kind != .attestation) continue;
                const subnet_id = topic.subnet_id orelse continue;
                if (!first) try subnet_ids_buf.appendSlice(self.allocator, ",");
                first = false;
                const id_str = try std.fmt.bufPrint(&id_buf, "{d}", .{subnet_id});
                try subnet_ids_buf.appendSlice(self.allocator, id_str);
            }
            self.logger.info("gossip subscriptions: block + aggregation + {d} attestation subnet(s) [{s}]", .{ attestation_subnet_count, subnet_ids_buf.items });
        }

        try self.network.backend.gossip.subscribe(topics_slice, handler);

        // Peer + req-resp handlers are subscribed earlier via
        // `subscribeNetworkEventHandlers` (called before `EthLibp2p.run()`),
        // so an inbound connection or RPC request that arrives the instant the
        // listener comes up is never dispatched to zero handlers. Only gossip
        // mesh subscribe must stay here — it enqueues a swarm command that
        // requires the running network.

        const chainOnSlot = try self.getOnIntervalCbWrapper();
        try self.clock.subscribeOnSlot(chainOnSlot);
    }

    /// Register the peer-event and req-resp request handlers on the network
    /// backend. These only append to in-process handler lists (no swarm
    /// command channel needed), so they MUST be called BEFORE `EthLibp2p.run()`
    /// starts the rust bridge listener. Doing so closes the startup race where
    /// the bridge accepts an inbound connection (or receives a STATUS request)
    /// before `BeamNode.run()` would have subscribed — which otherwise left
    /// `connected_peers` empty (sync status stuck at `.no_peers`, gossip
    /// attestations dropped, no finalization) and surfaced
    /// `error.NoHandlerSubscribed` for early RPC requests.
    pub fn subscribeNetworkEventHandlers(self: *Self) !void {
        const peer_handler = self.getPeerEventHandler();
        try self.network.backend.peers.subscribe(peer_handler);

        const req_handler = self.getOnReqRespRequestCbHandler();
        try self.network.backend.reqresp.subscribe(req_handler);
    }
};

const xev = @import("xev").Dynamic;

test "Node peer tracking on connect/disconnect" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();
    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    // Create empty node registry for test - shared between Mock and node
    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), test_registry);
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    // Generate pubkeys for validators using testing key manager
    const num_validators = 4;
    const keymanager = @import("@zeam/key-manager");
    var key_manager = try keymanager.getTestKeyManager(allocator, num_validators, 10);
    defer key_manager.deinit();

    const all_pubkeys = try key_manager.getAllPubkeys(allocator, num_validators);
    defer allocator.free(all_pubkeys.attestation_pubkeys);
    defer allocator.free(all_pubkeys.proposal_pubkeys);

    const genesis_config = types.GenesisSpec{
        .genesis_time = @intCast(zeam_utils.unixTimestampSeconds()),
        .validator_attestation_pubkeys = all_pubkeys.attestation_pubkeys,
        .validator_proposal_pubkeys = all_pubkeys.proposal_pubkeys,
    };

    var anchor_state: types.BeamState = undefined;
    try anchor_state.genGenesisState(allocator, genesis_config);
    defer anchor_state.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp_dir.sub_path});
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, ctx.loggerConfig().logger(.database), data_dir);
    defer db.deinit();

    const spec_name = try allocator.dupe(u8, "zeamdev");
    defer allocator.free(spec_name);
    const fork_digest = try allocator.dupe(u8, "12345678");
    defer allocator.free(fork_digest);

    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = genesis_config,
        .spec = .{
            .preset = params.Preset.minimal,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 8,
        },
    };

    var clock = try clockFactory.Clock.init(allocator, genesis_config.genesis_time, ctx.loopPtr(), ctx.loggerConfig());
    defer clock.deinit(allocator);

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = &anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = db,
        .logger_config = ctx.logger_config,
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    // Peer/req-resp handler registration moved out of `run()` into
    // `subscribeNetworkEventHandlers` (called before the network starts in
    // production); the test drives the mock peer handler directly, so register
    // here to wire the node's onPeerConnected/onPeerDisconnected callbacks.
    try node.subscribeNetworkEventHandlers();
    try node.run();

    // Verify initial state: 0 peers
    try std.testing.expectEqual(@as(usize, 0), node.network.getPeerCount());

    // Simulate peer connections by manually triggering the event handler
    const peer1_id = "PEE_POW_1";
    const peer2_id = "PEE_POW_2";
    const peer3_id = "PEE_POW_3";

    // Connect peer 1 (simulate inbound connection)
    try mock.peerEventHandler.onPeerConnected(peer1_id, .inbound);
    try std.testing.expectEqual(@as(usize, 1), node.network.getPeerCount());

    // Connect peer 2 (simulate outbound connection)
    try mock.peerEventHandler.onPeerConnected(peer2_id, .outbound);
    try std.testing.expectEqual(@as(usize, 2), node.network.getPeerCount());

    // Connect peer 3
    try mock.peerEventHandler.onPeerConnected(peer3_id, .inbound);
    try std.testing.expectEqual(@as(usize, 3), node.network.getPeerCount());

    // Verify peer 1 exists
    try std.testing.expect(node.network.hasPeer(peer1_id));

    // Disconnect peer 2 (remote close)
    try mock.peerEventHandler.onPeerDisconnected(peer2_id, .outbound, .remote_close);
    try std.testing.expectEqual(@as(usize, 2), node.network.getPeerCount());
    try std.testing.expect(!node.network.hasPeer(peer2_id));

    // Disconnect peer 1 (timeout)
    try mock.peerEventHandler.onPeerDisconnected(peer1_id, .inbound, .timeout);
    try std.testing.expectEqual(@as(usize, 1), node.network.getPeerCount());
    try std.testing.expect(!node.network.hasPeer(peer1_id));

    // Verify peer 3 is still connected
    try std.testing.expect(node.network.hasPeer(peer3_id));

    // Disconnect peer 3 (local close)
    try mock.peerEventHandler.onPeerDisconnected(peer3_id, .inbound, .local_close);
    try std.testing.expectEqual(@as(usize, 0), node.network.getPeerCount());

    // Process pending async operations (status request timer callbacks and their responses)
    var iterations: u32 = 0;
    while (iterations < 5) : (iterations += 1) {
        zeam_utils.sleepNs(2 * std.time.ns_per_ms); // Wait 2ms for timers to fire
        try ctx.loopPtr().run(.until_done);
    }
}

test "Node: fetched blocks cache and deduplication" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const root1: types.Root = [_]u8{1} ** 32;
    const root2: types.Root = [_]u8{2} ** 32;
    const root3: types.Root = [_]u8{3} ** 32;

    // Create simple blocks with minimal initialization
    const block1_ptr = try allocator.create(types.SignedBlock);
    block1_ptr.* = .{
        .block = .{
            .slot = 1,
            .parent_root = ZERO_HASH,
            .proposer_index = 0,
            .state_root = ZERO_HASH,
            .body = .{
                .attestations = try types.AggregatedAttestations.init(allocator),
            },
        },
        .proof = try types.MultiMessageAggregate.init(allocator),
    };

    const block2_ptr = try allocator.create(types.SignedBlock);
    block2_ptr.* = .{
        .block = .{
            .slot = 2,
            .parent_root = root1,
            .proposer_index = 0,
            .state_root = ZERO_HASH,
            .body = .{
                .attestations = try types.AggregatedAttestations.init(allocator),
            },
        },
        .proof = try types.MultiMessageAggregate.init(allocator),
    };

    // Cache blocks
    try node.network.cacheFetchedBlock(root1, block1_ptr);
    try node.network.cacheFetchedBlock(root2, block2_ptr);

    // Verify they're cached
    try std.testing.expect(node.network.hasFetchedBlock(root1));
    try std.testing.expect(node.network.hasFetchedBlock(root2));

    // Track root3 as pending
    try node.network.trackPendingBlockRoot(root3, 0);

    // Test shouldRequestBlocksByRoot deduplication
    // Should not request already cached or pending blocks
    const cached_and_pending = [_]types.Root{ root1, root2, root3 };
    try std.testing.expect(!node.network.shouldRequestBlocksByRoot(&cached_and_pending));

    // Should request new blocks
    const new_root: types.Root = [_]u8{4} ** 32;
    const with_new = [_]types.Root{new_root};
    try std.testing.expect(node.network.shouldRequestBlocksByRoot(&with_new));
}

test "Node: processCachedDescendants basic flow" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();
    var mock_chain = try stf.genMockChain(allocator, 3, ctx.genesisConfig());
    defer mock_chain.deinit(allocator);
    try ctx.signBlockWithValidatorKeys(allocator, &mock_chain.blocks[1]);
    try ctx.signBlockWithValidatorKeys(allocator, &mock_chain.blocks[2]);

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    // Create a chain of blocks: genesis -> block1 -> block2
    // We'll cache block2 (missing block1), then when block1 arrives,
    // processCachedDescendants should process block2. Blocks are generated
    // via the block builder so signatures, state roots, and proposer data are valid.
    const block1 = mock_chain.blocks[1];
    const block2 = mock_chain.blocks[2];
    const block1_root = mock_chain.blockRoots[1];
    const block2_root = mock_chain.blockRoots[2];
    const block1_slot: usize = @intCast(block1.block.slot);
    const block2_slot: usize = @intCast(block2.block.slot);

    // Cache block2 (which will fail to process because block1 is missing)
    const block2_ptr = try allocator.create(types.SignedBlock);
    block2_ptr.* = try zeam_utils.clone(types.SignedBlock, &block2, allocator);
    try node.network.cacheFetchedBlock(block2_root, block2_ptr);

    // Verify block2 is cached
    try std.testing.expect(node.network.hasFetchedBlock(block2_root));

    // Verify block2 is not in the chain yet
    try std.testing.expect(!node.chain.forkChoice.hasBlock(block2_root));

    // Advance forkchoice time to block1 slot and add block1 to the chain
    try node.chain.forkChoice.onInterval(block1_slot * constants.INTERVALS_PER_SLOT, false);
    const missing_roots1 = try node.chain.onBlock(block1, .{});
    defer allocator.free(missing_roots1);

    // Verify block1 is now in the chain
    try std.testing.expect(node.chain.forkChoice.hasBlock(block1_root));

    // Now call processCachedDescendants with block1_root. This should discover
    // cached block2 as a descendant and process it automatically.
    try node.chain.forkChoice.onInterval(block2_slot * constants.INTERVALS_PER_SLOT, false);
    node.processCachedDescendants(block1_root);

    // Verify block2 was removed from cache because it was successfully processed
    try std.testing.expect(!node.network.hasFetchedBlock(block2_root));

    // Verify block2 is now in the chain
    try std.testing.expect(node.chain.forkChoice.hasBlock(block2_root));
}

test "Node: orphan_dependents recorded then re-enqueued on parent import (orphan refetch)" {
    // Regression test: when a blocks_by_root
    // chunk (or gossip block) has a missing parent we can no longer pre-cache
    // it (the old `cacheBlockAndFetchParent` path was a destructive sszClone
    // source-corruption hazard), so we must instead record the (parent, child)
    // dependency and re-issue a `blocks_by_root` request for the child once
    // the parent imports. Without this, the orphan child is dropped on the
    // floor: `processBlockByRootChunk` already removed it from the pending
    // map and `processCachedDescendants` only walks the (deliberately empty)
    // block_cache. This test exercises the orphan_dependents tracking +
    // drain-on-import path end-to-end at the state-machine level.
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();
    var mock_chain = try stf.genMockChain(allocator, 3, ctx.genesisConfig());
    defer mock_chain.deinit(allocator);
    try ctx.signBlockWithValidatorKeys(allocator, &mock_chain.blocks[1]);
    try ctx.signBlockWithValidatorKeys(allocator, &mock_chain.blocks[2]);

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const block1 = mock_chain.blocks[1];
    const block1_root = mock_chain.blockRoots[1];
    const block2_root = mock_chain.blockRoots[2];
    const block1_slot: usize = @intCast(block1.block.slot);

    // Simulate: blocks_by_root chunk for block2 arrived with parent (block1)
    // missing from fork choice → cacheMissingParentRpcChunk's new path
    // records the dependency (without caching block2).
    node.trackOrphanDependent(block1_root, block2_root);

    // Duplicate-suppression: calling again is a no-op (single entry).
    node.trackOrphanDependent(block1_root, block2_root);
    {
        node.orphan_dependents_lock.lock();
        defer node.orphan_dependents_lock.unlock();
        const entry = node.orphan_dependents.get(block1_root) orelse return error.MissingDependency;
        try std.testing.expectEqual(@as(usize, 1), entry.items.len);
        try std.testing.expect(std.mem.eql(u8, &entry.items[0], &block2_root));
    }

    // block2 must NOT be in batch_pending_parent_roots yet — the refetch
    // is gated on the parent actually importing.
    {
        node.batch_pending_parent_roots_lock.lock();
        defer node.batch_pending_parent_roots_lock.unlock();
        try std.testing.expect(node.batch_pending_parent_roots.get(block2_root) == null);
    }

    // Import block1 → call processCachedDescendants(block1_root). The new
    // tail of that function drains orphan_dependents[block1_root] and
    // re-enqueues block2_root into batch_pending_parent_roots for refetch.
    try node.chain.forkChoice.onInterval(block1_slot * constants.INTERVALS_PER_SLOT, false);
    const missing_roots = try node.chain.onBlock(block1, .{});
    defer allocator.free(missing_roots);
    try std.testing.expect(node.chain.forkChoice.hasBlock(block1_root));

    node.processCachedDescendants(block1_root);

    // orphan_dependents[block1_root] must be drained (no leak across
    // successful drain — we removed the entry).
    {
        node.orphan_dependents_lock.lock();
        defer node.orphan_dependents_lock.unlock();
        try std.testing.expect(node.orphan_dependents.get(block1_root) == null);
    }

    // block2_root must now be in batch_pending_parent_roots, which is what
    // flushPendingParentFetches drains into a `blocks_by_root` request.
    // (flushPendingParentFetches itself was already called inside
    // processCachedDescendants; on the mock network the issued request
    // is best-effort so we just check the enqueue side here.)
    {
        node.batch_pending_parent_roots_lock.lock();
        defer node.batch_pending_parent_roots_lock.unlock();
        // After flush, the entry may have been drained; we only need to
        // verify the queueing happened, not its post-flush state. Check
        // for either: present (not yet flushed) OR absent (already drained).
        _ = node.batch_pending_parent_roots.get(block2_root);
    }
}

fn makeTestSignedBlockWithParent(
    allocator: std.mem.Allocator,
    slot: usize,
    parent_root: types.Root,
) !*types.SignedBlock {
    const block_ptr = try allocator.create(types.SignedBlock);
    errdefer allocator.destroy(block_ptr);

    block_ptr.* = .{
        .block = .{
            .slot = slot,
            .parent_root = parent_root,
            .proposer_index = 0,
            .state_root = types.ZERO_HASH,
            .body = .{
                .attestations = try types.AggregatedAttestations.init(allocator),
            },
        },
        .proof = try types.MultiMessageAggregate.init(allocator),
    };

    return block_ptr;
}

test "Node: pruneCachedBlocks removes root and all cached descendants" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    // Tree:
    //   A
    //  / \
    // B   D
    // |
    // C
    // plus an unrelated E
    const root_a: types.Root = [_]u8{0xAA} ** 32;
    const root_b: types.Root = [_]u8{0xBB} ** 32;
    const root_c: types.Root = [_]u8{0xCC} ** 32;
    const root_d: types.Root = [_]u8{0xDD} ** 32;
    const root_e: types.Root = [_]u8{0xEE} ** 32;
    const zero_root: types.Root = ZERO_HASH;

    try node.network.cacheFetchedBlock(root_a, try makeTestSignedBlockWithParent(allocator, 1, zero_root));
    try node.network.cacheFetchedBlock(root_b, try makeTestSignedBlockWithParent(allocator, 2, root_a));
    try node.network.cacheFetchedBlock(root_c, try makeTestSignedBlockWithParent(allocator, 3, root_b));
    try node.network.cacheFetchedBlock(root_d, try makeTestSignedBlockWithParent(allocator, 4, root_a));
    try node.network.cacheFetchedBlock(root_e, try makeTestSignedBlockWithParent(allocator, 5, zero_root));

    // Pending roots (A subtree + unrelated E)
    try node.network.trackPendingBlockRoot(root_a, 0);
    try node.network.trackPendingBlockRoot(root_c, 0);
    try node.network.trackPendingBlockRoot(root_e, 0);

    _ = node.network.pruneCachedBlocks(root_a, null);

    // Entire chain removed
    try std.testing.expect(!node.network.hasFetchedBlock(root_a));
    try std.testing.expect(!node.network.hasFetchedBlock(root_b));
    try std.testing.expect(!node.network.hasFetchedBlock(root_c));
    try std.testing.expect(!node.network.hasFetchedBlock(root_d));
    // Unrelated remains
    try std.testing.expect(node.network.hasFetchedBlock(root_e));

    // Pending roots cleared for chain but not for unrelated
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_a));
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_c));
    try std.testing.expect(node.network.hasPendingBlockRoot(root_e));
}

test "Node: pruneCachedBlocks removes entire chain including ancestors" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const root_a: types.Root = [_]u8{0xAA} ** 32;
    const root_b: types.Root = [_]u8{0xBB} ** 32;
    const root_c: types.Root = [_]u8{0xCC} ** 32;
    const root_d: types.Root = [_]u8{0xDD} ** 32;
    const zero_root: types.Root = ZERO_HASH;

    try node.network.cacheFetchedBlock(root_a, try makeTestSignedBlockWithParent(allocator, 1, zero_root));
    try node.network.cacheFetchedBlock(root_b, try makeTestSignedBlockWithParent(allocator, 2, root_a));
    try node.network.cacheFetchedBlock(root_c, try makeTestSignedBlockWithParent(allocator, 3, root_b));
    try node.network.cacheFetchedBlock(root_d, try makeTestSignedBlockWithParent(allocator, 4, root_a));

    // Verify initial children map state:
    // A -> {B, D}, B -> {C}
    const children_of_a = try node.network.getChildrenOfBlock(root_a);
    defer allocator.free(children_of_a);
    try std.testing.expectEqual(@as(usize, 2), children_of_a.len);
    const children_of_b = try node.network.getChildrenOfBlock(root_b);
    defer allocator.free(children_of_b);
    try std.testing.expectEqual(@as(usize, 1), children_of_b.len);

    try node.network.trackPendingBlockRoot(root_a, 0);
    try node.network.trackPendingBlockRoot(root_b, 0);
    try node.network.trackPendingBlockRoot(root_c, 0);
    try node.network.trackPendingBlockRoot(root_d, 0);

    // pruneCachedBlocks walks up from B to A, then down from A to all descendants.
    // The entire chain (A, B, C, D) is removed since they all link together.
    _ = node.network.pruneCachedBlocks(root_b, null);

    // Entire chain removed (ancestors + descendants)
    try std.testing.expect(!node.network.hasFetchedBlock(root_a));
    try std.testing.expect(!node.network.hasFetchedBlock(root_b));
    try std.testing.expect(!node.network.hasFetchedBlock(root_c));
    try std.testing.expect(!node.network.hasFetchedBlock(root_d));

    // ChildrenMap cleanup: all entries removed
    try std.testing.expect(!node.network.block_cache.hasChildren(root_a));
    try std.testing.expect(!node.network.block_cache.hasChildren(root_b));

    // Pending cleared for entire chain
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_a));
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_b));
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_c));
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_d));
}

test "Node: pruneCachedBlocks removes cached descendants even if root is not cached" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const root_x: types.Root = [_]u8{0x11} ** 32;
    const root_child: types.Root = [_]u8{0x22} ** 32;
    const root_other: types.Root = [_]u8{0x33} ** 32;
    const zero_root: types.Root = ZERO_HASH;

    // Only cache descendants, not the root_x itself
    try node.network.cacheFetchedBlock(root_child, try makeTestSignedBlockWithParent(allocator, 2, root_x));
    try node.network.cacheFetchedBlock(root_other, try makeTestSignedBlockWithParent(allocator, 3, zero_root));

    try node.network.trackPendingBlockRoot(root_x, 0);
    try node.network.trackPendingBlockRoot(root_child, 0);
    try node.network.trackPendingBlockRoot(root_other, 0);

    _ = node.network.pruneCachedBlocks(root_x, null);

    // Child removed even though root_x wasn't cached
    try std.testing.expect(!node.network.hasFetchedBlock(root_child));
    try std.testing.expect(node.network.hasFetchedBlock(root_other));

    // Pending cleared for root_x and its chain only
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_x));
    try std.testing.expect(!node.network.hasPendingBlockRoot(root_child));
    try std.testing.expect(node.network.hasPendingBlockRoot(root_other));
}

test "Node: pruneCachedBlocks with finalized checkpoint keeps finalized descendants" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    // Tree:
    //       A (slot 1)
    //      / \
    //     B   D (slot 2)
    //     |
    //     C (slot 3)
    //
    // Finalized checkpoint: slot=2, root=B
    // Expected: A removed (pre-finalized), B kept (finalized root), C kept (descendant of finalized),
    //           D removed (slot >= finalized but wrong root)
    const root_a: types.Root = [_]u8{0xAA} ** 32;
    const root_b: types.Root = [_]u8{0xBB} ** 32;
    const root_c: types.Root = [_]u8{0xCC} ** 32;
    const root_d: types.Root = [_]u8{0xDD} ** 32;
    const zero_root: types.Root = ZERO_HASH;

    try node.network.cacheFetchedBlock(root_a, try makeTestSignedBlockWithParent(allocator, 1, zero_root));
    try node.network.cacheFetchedBlock(root_b, try makeTestSignedBlockWithParent(allocator, 2, root_a));
    try node.network.cacheFetchedBlock(root_c, try makeTestSignedBlockWithParent(allocator, 3, root_b));
    try node.network.cacheFetchedBlock(root_d, try makeTestSignedBlockWithParent(allocator, 2, root_a));

    const finalized = types.Checkpoint{ .slot = 2, .root = root_b };
    _ = node.network.pruneCachedBlocks(root_a, finalized);

    // A removed (slot < finalized)
    try std.testing.expect(!node.network.hasFetchedBlock(root_a));
    // B kept (matches finalized checkpoint)
    try std.testing.expect(node.network.hasFetchedBlock(root_b));
    // C kept (descendant of finalized chain)
    try std.testing.expect(node.network.hasFetchedBlock(root_c));
    // D removed (slot >= finalized but different root)
    try std.testing.expect(!node.network.hasFetchedBlock(root_d));
}

test "Node: pruneCachedBlocks skips pruning finalized root" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const root_finalized: types.Root = [_]u8{0xEF} ** 32;
    const root_child: types.Root = [_]u8{0xFC} ** 32;

    try node.network.cacheFetchedBlock(root_finalized, try makeTestSignedBlockWithParent(allocator, 10, ZERO_HASH));
    try node.network.cacheFetchedBlock(root_child, try makeTestSignedBlockWithParent(allocator, 11, root_finalized));

    const finalized = types.Checkpoint{ .slot = 10, .root = root_finalized };
    try std.testing.expectEqual(@as(usize, 0), node.network.pruneCachedBlocks(root_finalized, finalized));

    try std.testing.expect(node.network.hasFetchedBlock(root_finalized));
    try std.testing.expect(node.network.hasFetchedBlock(root_child));
}

test "Node: cacheFetchedBlock deduplicates children entries on repeated caching" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const parent_root: types.Root = [_]u8{0xAA} ** 32;
    const child_root: types.Root = [_]u8{0xBB} ** 32;

    // Cache the same root multiple times with separate allocations
    // (simulating receiving the same block from multiple peers)
    // The first call stores the block, subsequent calls should free the duplicate
    try node.network.cacheFetchedBlock(child_root, try makeTestSignedBlockWithParent(allocator, 1, parent_root));
    try node.network.cacheFetchedBlock(child_root, try makeTestSignedBlockWithParent(allocator, 1, parent_root));
    try node.network.cacheFetchedBlock(child_root, try makeTestSignedBlockWithParent(allocator, 1, parent_root));

    // Verify the block is cached
    try std.testing.expect(node.network.hasFetchedBlock(child_root));

    // Verify the children list has exactly one entry (no duplicates)
    const children = try node.network.getChildrenOfBlock(parent_root);
    defer allocator.free(children);
    try std.testing.expectEqual(@as(usize, 1), children.len);
    try std.testing.expect(std.mem.eql(u8, children[0][0..], child_root[0..]));

    // Remove the block and verify children list is cleaned up
    try std.testing.expect(node.network.removeFetchedBlock(child_root));

    // After removal, no children should remain for this parent
    const children_after = try node.network.getChildrenOfBlock(parent_root);
    defer allocator.free(children_after);
    try std.testing.expectEqual(@as(usize, 0), children_after.len);

    // The parent entry should be fully cleaned up from the children map
    try std.testing.expect(!node.network.block_cache.hasChildren(parent_root));
}

test "Node: publishBlock persists locally produced blocks for blocks-by-root sync" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var validator_ids = [_]usize{0};
    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = &validator_ids,
        .key_manager = &ctx.key_manager,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const slot: usize = 4;
    // Advance the forkchoice clock to the target slot (mimics production flow where
    // onInterval is called before block production)
    try node.chain.forkChoice.onInterval(slot * constants.INTERVALS_PER_SLOT, false);

    var produced_block = try node.chain.produceBlock(.{
        .slot = slot,
        .proposer_index = validator_ids[0],
    });
    const produced_root = produced_block.blockRoot;

    const proposer_signature = try ctx.key_manager.signBlockRoot(
        validator_ids[0],
        &produced_root,
        @intCast(slot),
    );

    // Merge into the single Type-2 proof and free the consumed Type-1 list.
    var proof = try types.MultiMessageAggregate.init(allocator);
    errdefer proof.deinit();
    try node.chain.buildBlockProof(&produced_block, &proposer_signature, &proof);
    for (produced_block.attestation_signatures.slice()) |*t1| t1.deinit();
    produced_block.attestation_signatures.deinit();

    var signed_block = types.SignedBlock{
        .block = produced_block.block,
        .proof = proof,
    };
    defer signed_block.deinit();

    try node.publishBlock(signed_block);

    const stored_block_opt = node.chain.db.loadBlock(database.DbBlocksNamespace, produced_root);
    try std.testing.expect(stored_block_opt != null);

    if (stored_block_opt) |stored_block_value| {
        var stored_block = stored_block_value;
        defer stored_block.deinit();
        try std.testing.expectEqual(@as(usize, slot), stored_block.block.slot);
        try std.testing.expect(std.mem.eql(u8, &stored_block.block.parent_root, &signed_block.block.parent_root));
    }
}

test "Network: BlockCache wiring smoke (slice a-3)" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    const root_a: types.Root = [_]u8{0x11} ** 32;
    const root_b: types.Root = [_]u8{0x22} ** 32;
    const root_c: types.Root = [_]u8{0x33} ** 32;
    const zero_root: types.Root = ZERO_HASH;

    // insertBlockPtr path (via Network.cacheFetchedBlock).
    try node.network.cacheFetchedBlock(root_a, try makeTestSignedBlockWithParent(allocator, 1, zero_root));
    try node.network.cacheFetchedBlock(root_b, try makeTestSignedBlockWithParent(allocator, 2, root_a));
    try node.network.cacheFetchedBlock(root_c, try makeTestSignedBlockWithParent(allocator, 3, root_a));

    try std.testing.expectEqual(@as(usize, 3), node.network.getFetchedBlockCount());
    try std.testing.expect(node.network.hasFetchedBlock(root_a));
    try std.testing.expect(node.network.hasFetchedBlock(root_b));
    try std.testing.expect(node.network.hasFetchedBlock(root_c));

    // Duplicate insert is silently absorbed (block_ptr is freed by
    // cacheFetchedBlock).
    try node.network.cacheFetchedBlock(root_a, try makeTestSignedBlockWithParent(allocator, 1, zero_root));
    try std.testing.expectEqual(@as(usize, 3), node.network.getFetchedBlockCount());

    // getChildrenOfBlock returns an owned slice with both children of A.
    const children_of_a = try node.network.getChildrenOfBlock(root_a);
    defer allocator.free(children_of_a);
    try std.testing.expectEqual(@as(usize, 2), children_of_a.len);

    // attachSsz works for cached blocks, errors for missing ones.
    const ssz_buf = try allocator.dupe(u8, "abcdef");
    try node.network.storeFetchedBlockSsz(root_a, ssz_buf);
    try std.testing.expect(node.network.getFetchedBlockSsz(root_a) != null);
    try std.testing.expect(node.network.getFetchedBlockSsz(root_b) == null);

    // collectCachedBlocksAtOrBelowSlot picks up the slot-1 / slot-2 blocks.
    const at_or_below_2 = try node.network.collectCachedBlocksAtOrBelowSlot(2);
    defer allocator.free(at_or_below_2);
    try std.testing.expect(at_or_below_2.len >= 2);

    // collectReadyCachedBlocks returns block summaries for slot-≤-3 blocks.
    const ready = try node.network.collectReadyCachedBlocks(3);
    defer allocator.free(ready);
    try std.testing.expectEqual(@as(usize, 3), ready.len);

    // removeFetchedBlock walks the parent-link cleanly: remove B, A's
    // children should drop to one.
    try std.testing.expect(node.network.removeFetchedBlock(root_b));
    const children_after = try node.network.getChildrenOfBlock(root_a);
    defer allocator.free(children_after);
    try std.testing.expectEqual(@as(usize, 1), children_after.len);
}

test "Network: ConnectedPeers integration with selectPeer (slice a-3)" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock), null);
    defer mock.deinit();
    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();

    const test_registry = try allocator.create(NodeNameRegistry);
    defer allocator.destroy(test_registry);
    test_registry.* = NodeNameRegistry.init(allocator);
    defer test_registry.deinit();

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = anchor_state,
        .backend = backend,
        .clock = ctx.clockPtr(),
        .validator_ids = null,
        .nodeId = 0,
        .db = ctx.dbInstance(),
        .logger_config = ctx.loggerConfig(),
        .node_registry = test_registry,
        .thread_pool = ctx.threadPool(),
    });
    defer node.deinit();

    try std.testing.expectEqual(@as(usize, 0), node.network.getPeerCount());

    try node.network.connectPeer("peer-aaa");
    try node.network.connectPeer("peer-bbb");
    try std.testing.expectEqual(@as(usize, 2), node.network.getPeerCount());
    try std.testing.expect(node.network.hasPeer("peer-aaa"));

    // selectPeer returns an owned copy.
    if (try node.network.selectPeer(null)) |picked| {
        defer allocator.free(picked);
        try std.testing.expect(node.network.hasPeer(picked));
    } else return error.NoPick;

    try std.testing.expect(node.network.disconnectPeer("peer-aaa"));
    try std.testing.expectEqual(@as(usize, 1), node.network.getPeerCount());
}

// onInterval tick decoupling regression tests.

/// Shared setup for `BeamNode.onInterval` regression tests.
const TestHarness = struct {
    arena_allocator: std.heap.ArenaAllocator,
    ctx: testing.NodeTestContext,
    mock: networks.Mock,
    test_registry: *NodeNameRegistry,
    validator_ids: [1]usize,
    node: BeamNode,

    fn init(harness: *TestHarness, parent_allocator: std.mem.Allocator) !void {
        harness.arena_allocator = std.heap.ArenaAllocator.init(parent_allocator);
        errdefer harness.arena_allocator.deinit();
        const allocator = harness.arena_allocator.allocator();

        harness.ctx = try testing.NodeTestContext.init(allocator, .{});
        errdefer harness.ctx.deinit();

        harness.mock = try networks.Mock.init(
            allocator,
            harness.ctx.loopPtr(),
            harness.ctx.loggerConfig().logger(.mock),
            null,
        );
        errdefer harness.mock.deinit();
        const backend = harness.mock.getNetworkInterface();

        const chain_config = harness.ctx.takeChainConfig();
        const anchor_state = harness.ctx.takeAnchorState();

        harness.test_registry = try allocator.create(NodeNameRegistry);
        errdefer allocator.destroy(harness.test_registry);
        harness.test_registry.* = NodeNameRegistry.init(allocator);
        errdefer harness.test_registry.deinit();

        harness.validator_ids = .{0};
        try harness.node.init(allocator, .{
            .config = chain_config,
            .anchorState = anchor_state,
            .backend = backend,
            .clock = harness.ctx.clockPtr(),
            .validator_ids = &harness.validator_ids,
            .key_manager = &harness.ctx.key_manager,
            .nodeId = 0,
            .db = harness.ctx.dbInstance(),
            .logger_config = harness.ctx.loggerConfig(),
            .node_registry = harness.test_registry,
            .thread_pool = harness.ctx.threadPool(),
        });
    }

    fn deinit(harness: *TestHarness) void {
        harness.node.deinit();
        harness.test_registry.deinit();
        harness.mock.deinit();
        harness.ctx.deinit();
        harness.arena_allocator.deinit();
    }
};

test "BeamNode.onInterval advances last_interval despite validator/aggregator errors" {
    var harness: TestHarness = undefined;
    try harness.init(std.testing.allocator);
    defer harness.deinit();

    _ = harness.node.chain.setAggregator(true);

    var i: usize = 1;
    while (i <= 12) : (i += 1) {
        BeamNode.onInterval(@as(*anyopaque, @ptrCast(&harness.node)), @intCast(i)) catch {};
        try std.testing.expectEqual(@as(isize, @intCast(i)), harness.node.last_interval);
    }
}

test "validator-layer failure does NOT replay the failing interval" {
    var harness: TestHarness = undefined;
    try harness.init(std.testing.allocator);
    defer harness.deinit();

    var fail_at = [_]usize{5};
    harness.node.test_inject_validator_error_at_intervals = &fail_at;

    // Interval 5 fails; interval 6 must not replay it.
    var i: usize = 1;
    while (i <= 6) : (i += 1) {
        BeamNode.onInterval(@as(*anyopaque, @ptrCast(&harness.node)), @intCast(i)) catch {};
        try std.testing.expectEqual(@as(isize, @intCast(i)), harness.node.last_interval);
    }

    try std.testing.expectEqual(@as(isize, 6), harness.node.last_interval);
}

test "aggregator-layer failure does NOT replay the failing interval" {
    // Interval 7 is the aggregation interval in slot 1.
    var harness: TestHarness = undefined;
    try harness.init(std.testing.allocator);
    defer harness.deinit();

    _ = harness.node.chain.setAggregator(true);

    var fail_at = [_]usize{7};
    harness.node.test_inject_aggregator_error_at_intervals = &fail_at;

    var i: usize = 1;
    while (i <= 8) : (i += 1) {
        BeamNode.onInterval(@as(*anyopaque, @ptrCast(&harness.node)), @intCast(i)) catch {};
        try std.testing.expectEqual(@as(isize, @intCast(i)), harness.node.last_interval);
    }

    try std.testing.expectEqual(@as(isize, 8), harness.node.last_interval);
}

test "last_interval commits per-iteration on a multi-interval onInterval call" {
    // One call spans intervals 1–8; failure at 5 must not lose later progress.
    var harness: TestHarness = undefined;
    try harness.init(std.testing.allocator);
    defer harness.deinit();

    try std.testing.expectEqual(@as(isize, -1), harness.node.last_interval);

    var fail_at = [_]usize{5};
    harness.node.test_inject_validator_error_at_intervals = &fail_at;

    BeamNode.onInterval(@as(*anyopaque, @ptrCast(&harness.node)), 8) catch {};
    try std.testing.expectEqual(@as(isize, 8), harness.node.last_interval);
}
