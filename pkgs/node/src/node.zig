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

const BlockByRootContext = networkFactory.BlockByRootContext;
pub const NodeNameRegistry = networks.NodeNameRegistry;

const ZERO_HASH = types.ZERO_HASH;

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
    /// Optional worker pool for parallelizing CPU-bound chain work (signature verification).
    /// When non-null it is shared across all nodes in the same process.
    thread_pool: ?*ThreadPool = null,
    /// Slice c-2b commit 3 of #803: when true, the chain spawns a
    /// dedicated worker thread and producer-side handlers for
    /// gossip blocks / attestations route through its bounded
    /// queues instead of running synchronously on the libp2p
    /// thread. Default `true` post devnet-4 burn-in: the worker
    /// path is the supported prod path. Surfaced to the CLI as
    /// `--chain-worker` (bool); `--chain-worker false` is the
    /// kill-switch for the legacy synchronous path.
    chain_worker_enabled: bool = true,
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
    /// per-resource locks via the helpers in `pkgs/node/src/locking.zig`.
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

    const Self = @This();

    pub fn init(self: *Self, allocator: Allocator, opts: NodeOpts) !void {
        var validator: ?validatorClient.ValidatorClient = null;

        var network = try networkFactory.Network.init(allocator, opts.backend);
        var network_init_cleanup = true;
        errdefer if (network_init_cleanup) network.deinit();

        const chain = try allocator.create(chainFactory.BeamChain);
        errdefer allocator.destroy(chain);

        chain.* = try chainFactory.BeamChain.init(
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
            },
            network.connected_peers,
        );
        errdefer {
            chain.deinit();
            allocator.destroy(chain);
        }

        // Slice c-2b commit 3 of #803: start the chain-worker AFTER
        // the chain is at its final heap address (allocator.create +
        // assignment-via-deref above), because the worker stores
        // `chain` as its handler ctx and that pointer must remain
        // stable for the worker's entire lifetime. `chain.deinit()`
        // (above errdefer + the deinit method) tears the worker
        // down before any chain state it might touch.
        if (opts.chain_worker_enabled) {
            try chain.startChainWorker();
        }

        // Slice c-2b commit 5 of #803: register the
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
            .logger = opts.logger_config.logger(.node),
            .node_registry = opts.node_registry,
            .aggregation_subnet_ids = opts.aggregation_subnet_ids,
            .batch_pending_parent_roots = std.AutoHashMap(types.Root, u32).init(allocator),
        };

        chain.setPruneCachedBlocksCallback(self, pruneCachedBlocksCallback);

        network_init_cleanup = false;
    }

    pub fn deinit(self: *Self) void {
        self.batch_pending_parent_roots.deinit();
        self.network.deinit();
        self.chain.deinit();
        self.allocator.destroy(self.chain);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage, sender_peer_id: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // Lifetime invariant for `data`:
        //   The gossip subsystem (see `pkgs/network/src/ethlibp2p.zig`) owns the
        //   `GossipMessage` for the entire duration of this callback. It is the
        //   standard libp2p callback contract: the buffer is not recycled, freed
        //   or mutated until `onGossip` returns. We rely on this twice — once
        //   for the pre-lock `hashTreeRoot` read of `data.block.block` and again
        //   inside the locked section for the same field. If a future refactor
        //   ever changes that contract (e.g. arena-pooled message buffers), the
        //   pre-lock read becomes a use-after-free and this comment must be the
        //   place to revisit. Do NOT cache or stash `data` past this scope.
        //
        // Pre-lock work (issue #786): hashTreeRoot over a BeamBlock is pure CPU
        // work that does not touch any shared state, but it can be expensive on
        // large blocks (up to MAX_ATTESTATIONS_DATA aggregated XMSS proofs ⇒
        // hundreds of KB to MBs of tree-hashing). Computing it before locking
        // shrinks the critical section and lets `onInterval` make progress on
        // the libxev thread in parallel. The computed root is reused in every
        // downstream branch (success path + error paths) so we never recompute
        // under the lock.
        //
        // `precomputed_block_root` stays `undefined` for non-block gossip
        // messages and is read only inside the `.block` arm of the switch
        // below (and its error sub-branches). Any future code path that reads
        // it outside that arm will hit Zig's `undefined` poison in debug
        // builds — intentional defensive behavior.
        var precomputed_block_root: types.Root = undefined;
        if (data.* == .block) {
            zeam_utils.hashTreeRoot(types.BeamBlock, data.block.block, &precomputed_block_root, self.allocator) catch |err| {
                self.logger.warn("failed to compute block root for incoming gossip block: {any}", .{err});
                return;
            };
        }

        // Slice (a-3): the outer BeamNode.mutex is gone. Each chain entry
        // point inside the switch arms takes its own per-resource locks
        // (chain.{states_lock, pending_blocks_lock, pubkey_cache_lock,
        // root_to_slot_lock, events_lock, forkChoice}); network state
        // mutations go through `Network`'s LockedMap / BlockCache /
        // ConnectedPeers helpers. See docs/threading_refactor_slice_a.md.

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

                // Reuse the root we computed before taking the lock.
                const block_root = precomputed_block_root;

                _ = self.network.removePendingBlockRoot(block_root);

                if (!hasParentBlock) {
                    // Cache this block for later processing when parent arrives
                    if (self.cacheBlockAndFetchParent(block_root, signed_block, 0)) |_| {
                        self.logger.debug(
                            "Cached gossip block 0x{x} at slot {d}, fetching parent 0x{x}",
                            .{
                                &block_root,
                                block.slot,
                                &parent_root,
                            },
                        );
                    } else |err| {
                        if (err == CacheBlockError.PreFinalized) {
                            // Block is pre-finalized - prune any cached descendants waiting for this parent
                            self.logger.info(
                                "gossip block 0x{x} is pre-finalized (slot={d}), pruning cached descendants",
                                .{
                                    &block_root,
                                    block.slot,
                                },
                            );
                            _ = self.network.pruneCachedBlocks(block_root, null);
                        } else {
                            self.logger.warn("failed to cache gossip block 0x{x}: {any}", .{
                                &block_root,
                                err,
                            });
                        }
                    }
                    // Flush any pending parent root fetches accumulated during caching.
                    self.flushPendingParentFetches();
                    // Return early - don't pass to chain until parent arrives
                    return;
                }
            },
            .attestation => |signed_attestation| {
                const slot = signed_attestation.message.message.slot;
                const validator_id = signed_attestation.message.validator_id;
                const validator_node_name = self.node_registry.getNodeNameFromValidatorIndex(validator_id);

                const sender_node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
                self.logger.info("received gossip attestation for slot={d} validator={d}{f} from peer={s}{f}", .{
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

        // Slice (e) of #803: thread `precomputed_block_root` through
        // chain.onGossip so the chain layer doesn't recompute the
        // hash-tree root we already have. For non-block gossip
        // (attestation/aggregation) we pass `null`; the chain layer
        // ignores it on those branches.
        const root_for_chain: ?types.Root = if (data.* == .block) precomputed_block_root else null;
        const result = self.chain.onGossip(data, sender_peer_id, root_for_chain) catch |err| {
            switch (err) {
                // Block rejected because it's before finalized - drop it and prune any cached
                // descendants we might still be holding onto.
                error.PreFinalizedSlot => {
                    if (data.* == .block) {
                        // Reuse the root we computed before taking the lock (issue #786).
                        const block_root = precomputed_block_root;
                        self.logger.info(
                            "gossip block 0x{x} rejected as pre-finalized; pruning cached descendants",
                            .{&block_root},
                        );
                        _ = self.network.pruneCachedBlocks(block_root, null);
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
                // Block arrived too early for local clock - cache and retry later.
                error.FutureSlot => {
                    if (data.* == .block) {
                        const signed_block = data.block;
                        // Reuse the root we computed before taking the lock (issue #786).
                        const block_root = precomputed_block_root;
                        if (self.cacheFutureBlock(block_root, signed_block)) |_| {
                            self.logger.debug(
                                "cached future gossip block 0x{s} at slot {d}",
                                .{ std.fmt.bytesToHex(block_root, .lower)[0..], signed_block.block.slot },
                            );
                        } else |cache_err| {
                            if (cache_err == CacheBlockError.PreFinalized) {
                                self.logger.info(
                                    "future gossip block 0x{s} is pre-finalized (slot={d}), pruning cached descendants",
                                    .{ std.fmt.bytesToHex(block_root, .lower)[0..], signed_block.block.slot },
                                );
                                _ = self.network.pruneCachedBlocks(block_root, null);
                            } else {
                                self.logger.warn("failed to cache future gossip block 0x{s}: {any}", .{
                                    std.fmt.bytesToHex(block_root, .lower)[0..],
                                    cache_err,
                                });
                            }
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
        self.flushPendingParentFetches();
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

    fn processCachedDescendants(self: *Self, parent_root: types.Root) void {
        // Get cached children of this parent (helper returns an owned
        // copy under the cache lock so we can iterate after release).
        const children = self.network.getChildrenOfBlock(parent_root) catch |err| {
            self.logger.warn("Failed to copy children for processing: {any}", .{err});
            return;
        };
        defer self.allocator.free(children);

        if (children.len == 0) {
            return;
        }

        self.logger.debug(
            "Found {d} cached descendant(s) of block 0x{x}",
            .{ children.len, &parent_root },
        );

        // Try to process each descendant
        for (children) |descendant_root| {
            // Atomic (block, ssz) clone under the cache mutex. The
            // legacy borrow-shape `getFetchedBlockWithSsz` was removed in
            // PR #820 (slice a-3 follow-up): its returned slice headers
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

                const block_ssz = cached.ssz;
                const missing_roots = self.chain.onBlock(cached_block, .{ .sszBytes = block_ssz }) catch |err| {
                    if (err == chainFactory.BlockProcessingError.MissingPreState) {
                        // Parent still missing, keep it cached
                        self.logger.debug(
                            "Cached block 0x{x} still missing parent, keeping in cache",
                            .{&descendant_root},
                        );
                    } else if (err == error.FutureSlot) {
                        // Block is still in the future, keep it cached
                        self.logger.debug(
                            "Cached block 0x{s} still in future slot, keeping in cache",
                            .{std.fmt.bytesToHex(descendant_root, .lower)[0..]},
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

        // Allocate and clone the block
        const block_ptr = self.allocator.create(types.SignedBlock) catch {
            return CacheBlockError.AllocationFailed;
        };
        var block_owned = true;
        errdefer if (block_owned) self.allocator.destroy(block_ptr);

        types.sszClone(self.allocator, types.SignedBlock, signed_block, block_ptr) catch {
            return CacheBlockError.CloneFailed;
        };
        errdefer if (block_owned) block_ptr.deinit();

        self.network.cacheFetchedBlock(block_root, block_ptr) catch {
            return CacheBlockError.CachingFailed;
        };
        // Ownership transferred to the network cache — disable errdefers
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

        // Clone the block and capture its SSZ bytes in one pass.
        // sszCloneAndGetBytes serializes the original block once (read-only on `signed_block`),
        // then deserializes into the clone. The returned bytes are stored alongside the cached
        // block so that onBlock never needs to re-serialize a live SignedBlock, which has been
        // observed to cause memory corruption on the next cached block's processing.
        const ssz_bytes = types.sszCloneAndGetBytes(self.allocator, types.SignedBlock, signed_block, block_ptr) catch {
            return CacheBlockError.CloneFailed;
        };
        errdefer if (block_owned) block_ptr.deinit();
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

            // Try to add the block to the chain
            const missing_roots = self.chain.onBlock(signed_block.*, .{}) catch |err| {
                // Check if the error is due to missing parent
                if (err == chainFactory.BlockProcessingError.MissingPreState) {
                    // Check if we've hit the max depth
                    if (current_depth >= constants.MAX_BLOCK_FETCH_DEPTH) {
                        self.logger.warn(
                            "Reached max block fetch depth ({d}) for block 0x{x}, discarding",
                            .{ constants.MAX_BLOCK_FETCH_DEPTH, &block_root },
                        );
                        return;
                    }

                    // Cache this block and fetch parent
                    if (self.cacheBlockAndFetchParent(block_root, signed_block.*, current_depth + 1)) |parent_root| {
                        self.logger.debug(
                            "Cached block 0x{x} at depth {d}, fetching parent 0x{x}",
                            .{
                                &block_root,
                                current_depth,
                                &parent_root,
                            },
                        );
                    } else |cache_err| {
                        if (cache_err == CacheBlockError.PreFinalized) {
                            // Block is pre-finalized - prune any cached descendants waiting for this parent
                            self.logger.info(
                                "block 0x{x} is pre-finalized (slot={d}), pruning cached descendants",
                                .{
                                    &block_root,
                                    signed_block.block.slot,
                                },
                            );
                            _ = self.network.pruneCachedBlocks(block_root, null);
                        } else {
                            self.logger.warn("failed to cache block 0x{x}: {any}", .{
                                &block_root,
                                cache_err,
                            });
                        }
                    }
                    self.flushPendingParentFetches();
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
        self.flushPendingParentFetches();
    }

    /// Process a single block chunk received in response to a blocks_by_range request.
    /// Reuses onBlock for STF + forkchoice integration; on missing-parent we cache the block
    /// and queue a parent fetch (same as the by-root path), but we don't track per-root
    /// pending state since the original request was slot-based.
    fn processBlockByRangeChunk(self: *Self, peer_id: []const u8, signed_block: *const types.SignedBlock) !void {
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
            return;
        }

        const missing_roots = self.chain.onBlock(signed_block.*, .{}) catch |err| {
            if (err == chainFactory.BlockProcessingError.MissingPreState) {
                // Cache and try to fetch parent. Range responses arrive ordered by slot,
                // but the first chunk in a batch may still need its parent fetched.
                if (self.cacheBlockAndFetchParent(block_root, signed_block.*, 1)) |parent_root| {
                    self.logger.debug(
                        "blocks_by_range: cached block 0x{x}, fetching parent 0x{x}",
                        .{ &block_root, &parent_root },
                    );
                } else |cache_err| {
                    if (cache_err == CacheBlockError.PreFinalized) {
                        _ = self.network.pruneCachedBlocks(block_root, null);
                    } else {
                        self.logger.warn("blocks_by_range: failed to cache block 0x{x}: {any}", .{ &block_root, cache_err });
                    }
                }
                self.flushPendingParentFetches();
                return;
            }
            if (err == forkchoice.ForkChoiceError.PreFinalizedSlot) {
                _ = self.network.pruneCachedBlocks(block_root, null);
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

        self.chain.onBlockFollowup(true, signed_block);
        self.processCachedDescendants(block_root);
        self.fetchBlockByRoots(missing_roots, 0) catch |err| {
            self.logger.warn("blocks_by_range: failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
        };
        self.flushPendingParentFetches();
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

                        // Proactive initial sync: if peer's finalized slot is ahead of us, request their head block
                        // This triggers parent syncing which will fetch all blocks back to our current state
                        // We compare finalized slots (not head slots) because finalized is more reliable for sync decisions
                        const sync_status = self.chain.getSyncStatus();
                        switch (sync_status) {
                            .behind_peers => |info| {
                                // Only sync from this peer if their finalized slot is ahead of ours
                                const our_finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;
                                if (status_resp.finalized_slot > our_finalized_slot) {
                                    // If the peer is far ahead, prefer a blocks_by_range bulk fetch
                                    // for efficient catch-up. The head-block-by-root path walks parents
                                    // one round-trip at a time which is too slow for large gaps.
                                    const gap: u64 = if (status_resp.head_slot > info.head_slot)
                                        status_resp.head_slot - info.head_slot
                                    else
                                        0;
                                    if (gap > constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD) {
                                        const start_slot: types.Slot = info.head_slot + 1;
                                        const requested_count: u64 = @min(gap, params.MAX_REQUEST_BLOCKS);
                                        self.logger.info("peer {s}{f} is far ahead (gap={d} slots), initiating bulk sync via blocks_by_range start_slot={d} count={d}", .{
                                            status_ctx.peer_id,
                                            self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                            gap,
                                            start_slot,
                                            requested_count,
                                        });
                                        const handler = networks.OnReqRespResponseCbHandler{
                                            .ptr = self,
                                            .onReqRespResponseCb = onReqRespResponse,
                                        };
                                        _ = self.network.sendBlocksByRangeRequest(status_ctx.peer_id, start_slot, requested_count, handler) catch |err| {
                                            self.logger.warn("failed to initiate blocks_by_range sync from peer {s}{f}: {any}; falling back to head-by-root", .{
                                                status_ctx.peer_id,
                                                self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                                err,
                                            });
                                            const roots = [_]types.Root{status_resp.head_root};
                                            self.fetchBlockByRoots(&roots, 0) catch |fetch_err| {
                                                self.logger.warn("fallback head-by-root fetch also failed: {any}", .{fetch_err});
                                            };
                                        };
                                    } else {
                                        self.logger.info("peer {s}{f} is ahead (peer_finalized_slot={d} > our_head_slot={d}), initiating sync by requesting head block 0x{x}", .{
                                            status_ctx.peer_id,
                                            self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                            status_resp.finalized_slot,
                                            info.head_slot,
                                            &status_resp.head_root,
                                        });
                                        const roots = [_]types.Root{status_resp.head_root};
                                        self.fetchBlockByRoots(&roots, 0) catch |err| {
                                            self.logger.warn("failed to initiate sync by fetching head block from peer {s}{f}: {any}", .{
                                                status_ctx.peer_id,
                                                self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                                err,
                                            });
                                        };
                                    }
                                }
                            },
                            .fc_initing => {
                                // Forkchoice is still initializing (checkpoint-sync or DB restore).
                                // We need blocks to reach the first justified checkpoint and exit
                                // fc_initing. Without this branch the node deadlocks: it stays in
                                // fc_initing because no blocks arrive, and no blocks arrive because
                                // the sync code skips fc_initing.
                                // Treat this exactly like behind_peers: if the peer's head is ahead
                                // of our anchor, request their head block to start the parent chain.
                                // Snapshot once: forkChoice.head is a
                                // multi-field ProtoBlock written under
                                // exclusive. A second raw read in the log
                                // call could pair this slot with a
                                // different update's blockRoot.
                                const head_snapshot = self.chain.forkChoice.getHead();
                                if (status_resp.head_slot > head_snapshot.slot) {
                                    self.logger.info("peer {s}{f} is ahead during fc init (peer_head={d} > our_head={d}), requesting head block 0x{x}", .{
                                        status_ctx.peer_id,
                                        self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                        status_resp.head_slot,
                                        head_snapshot.slot,
                                        &status_resp.head_root,
                                    });
                                    const roots = [_]types.Root{status_resp.head_root};
                                    self.fetchBlockByRoots(&roots, 0) catch |err| {
                                        self.logger.warn("failed to initiate sync from peer {s}{f} during fc init: {any}", .{
                                            status_ctx.peer_id,
                                            self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                            err,
                                        });
                                    };
                                }
                            },
                            .synced, .no_peers => {},
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
                            try self.processBlockByRangeChunk(peer_id, &block_resp);
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
                    },
                    .blocks_by_range => {
                        self.logger.warn("blocks-by-range request to peer {s}{f} failed ({d}): {s}", .{
                            peer_id,
                            node_name,
                            err_payload.code,
                            err_payload.message,
                        });
                    },
                }
                self.network.finalizePendingRequest(request_id);
            },
            .completed => {
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

                self.logger.debug(
                    "node-{d}:: Handling blocks_by_root request for {d} roots",
                    .{ self.nodeId, roots.len },
                );

                for (roots) |root| {
                    if (self.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
                        var signed_block = signed_block_value;
                        defer signed_block.deinit();

                        var response = networks.ReqRespResponse{ .blocks_by_root = undefined };
                        try types.sszClone(self.allocator, types.SignedBlock, signed_block, &response.blocks_by_root);
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
                // Cap count at MAX_REQUEST_BLOCKS to bound work per request
                const count = @min(requested_count, params.MAX_REQUEST_BLOCKS);

                self.logger.debug(
                    "node-{d}:: Handling blocks_by_range request start_slot={d} count={d} (capped from {d})",
                    .{ self.nodeId, start_slot, count, requested_count },
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
                const finalized_slot = self.chain.forkChoice.getLatestFinalized().slot;

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

                            var response = networks.ReqRespResponse{ .blocks_by_range = undefined };
                            try types.sszClone(self.allocator, types.SignedBlock, signed_block, &response.blocks_by_range);
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

                            var response = networks.ReqRespResponse{ .blocks_by_range = undefined };
                            try types.sszClone(self.allocator, types.SignedBlock, signed_block, &response.blocks_by_range);
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
    fn flushPendingParentFetches(self: *Self) void {
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

        self.fetchBlockByRoots(roots.items, max_depth) catch |err| {
            self.logger.warn("failed to batch-fetch {d} pending parent root(s): {any}", .{ roots.items.len, err });
        };
    }

    fn fetchBlockByRoots(
        self: *Self,
        roots: []const types.Root,
        depth: u32,
    ) !void {
        if (roots.len == 0) return;

        // Slice (d) of #803: snapshot forkchoice presence for every
        // root in one shared-lock acquisition (`hasBlocksBatch`),
        // then dedup against the network-side caches under their own
        // independent locks. Pre-#803 `fetchBlockByRoots` did N
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
        // counters sum to `roots.len` per call — PR #842 review #1.
        //
        // **TOCTOU note (PR #842 review #3):** the three cache
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

        // PR #842 review (nit): batch the per-bucket counter bumps
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
        const maybe_request = self.network.ensureBlocksByRootRequest(missing_roots.items, depth, handler) catch |err| blk: {
            switch (err) {
                error.NoPeersAvailable => {
                    // PR #842 review #1: previously this path bumped
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
            // PR #842 review followup: `ensureBlocksByRootRequest`
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
            const interval: usize = @intCast(current_interval);
            const slot: types.Slot = @intCast(@divFloor(interval, constants.INTERVALS_PER_SLOT));

            {
                // Slice (a-3): no outer mutex. `chain.onInterval` /
                // `chain.processPendingBlocks` take their own per-resource
                // locks (forkchoice RwLock, pending_blocks_lock,
                // states_lock, events_lock) and `sweepTimedOutRequests` /
                // `processReadyCachedBlocks` go through
                // network/block_cache helpers.

                self.chain.onInterval(interval) catch |e| {
                    self.logger.err("error ticking chain to time(intervals)={d} err={any}", .{ interval, e });
                    // no point going further if chain is not ticked properly
                    return e;
                };

                // Replay blocks that were queued waiting for the forkchoice clock to advance,
                // then fetch any attestation head roots that were missing during replay.
                const pending_missing_roots = self.chain.processPendingBlocks();
                defer self.allocator.free(pending_missing_roots);
                if (pending_missing_roots.len > 0) {
                    self.fetchBlockByRoots(pending_missing_roots, 0) catch |err| {
                        self.logger.warn(
                            "failed to fetch {d} missing block(s) from pending blocks: {any}",
                            .{ pending_missing_roots.len, err },
                        );
                    };
                }

                // Sweep timed-out RPC requests to prevent sync stalls from non-responsive peers.
                self.sweepTimedOutRequests();

                self.processReadyCachedBlocks(slot);
            }

            if (self.validator) |*validator| {
                // we also tick validator per interval in case it would
                // need to sync its future duties when its an independent validator
                var validator_output = validator.onInterval(interval) catch |e| {
                    self.logger.err("error ticking validator to time(intervals)={d} err={any}", .{ interval, e });
                    return e;
                };

                if (validator_output) |*output| {
                    defer output.deinit();
                    for (output.gossip_messages.items) |gossip_msg| {
                        // Process based on message type
                        switch (gossip_msg) {
                            .block => |signed_block| {
                                self.publishBlock(signed_block) catch |e| {
                                    self.logger.err("error publishing block from validator: err={any}", .{e});
                                    return e;
                                };
                            },
                            .attestation => |signed_attestation| {
                                self.publishAttestation(signed_attestation) catch |e| {
                                    self.logger.err("error publishing attestation from validator: err={any}", .{e});
                                    return e;
                                };
                            },
                            .aggregation => |signed_aggregation| {
                                self.publishAggregation(signed_aggregation) catch |e| {
                                    self.logger.err("error publishing aggregation from validator: err={any}", .{e});
                                    return e;
                                };
                            },
                        }
                    }
                }
            }

            const interval_in_slot = interval % constants.INTERVALS_PER_SLOT;

            // Periodically re-send status to all connected peers when not synced.
            // This recovers from the case where peers were already connected when
            // the node was in fc_initing and the status-exchange-triggered sync
            // was skipped (now fixed, but existing connections need a re-probe).
            if (interval_in_slot == 0 and slot % constants.SYNC_STATUS_REFRESH_INTERVAL_SLOTS == 0) {
                switch (self.chain.getSyncStatus()) {
                    .fc_initing, .behind_peers => self.refreshSyncFromPeers(),
                    .synced, .no_peers => {},
                }
            }

            if (interval_in_slot == 2) {
                if (self.chain.maybeAggregateOnInterval(interval) catch |e| {
                    self.logger.err("error producing aggregations at slot={d} interval={d}: {any}", .{ slot, interval, e });
                    return e;
                }) |aggregations| {
                    defer self.allocator.free(aggregations);
                    self.publishProducedAggregations(aggregations) catch |e| {
                        self.logger.err("error producing/publishing aggregations at slot={d} interval={d}: {any}", .{ slot, interval, e });
                        return e;
                    };
                }
            }
        }

        self.last_interval = itime_intervals;
    }

    /// Re-send our status to every connected peer.
    ///
    /// Called periodically when the node is not yet synced so that peers
    /// already connected before the sync mechanism became aware of them
    /// (e.g., after a restart or while stuck in fc_initing) get another
    /// chance to report their head and trigger block fetching.
    fn refreshSyncFromPeers(self: *Self) void {
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
        for (peer_ids.items) |peer_id| {
            _ = self.network.sendStatusToPeer(peer_id, status, handler) catch |err| {
                self.logger.warn("failed to refresh status to peer {s}{f}: {any}", .{
                    peer_id,
                    self.node_registry.getNodeNameFromPeerId(peer_id),
                    err,
                });
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
                    self.logger.warn("blocks_by_range RPC request_id={d} to peer {s}{f} timed out, finalizing", .{
                        request_id,
                        snap.peer_id_copy,
                        self.node_registry.getNodeNameFromPeerId(snap.peer_id_copy),
                    });
                    self.network.finalizePendingRequest(request_id);
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
            // Issue #808: backend dropped the publish (e.g. rust-libp2p command
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
            // Issue #808: backend dropped the publish. The attestation is in
            // our local chain but never reached gossip — don't log "published".
            self.logger.warn("failed to publish attestation to network (backend dropped publish): slot={d} validator={d}{f}", .{
                data.slot,
                validator_id,
                self.node_registry.getNodeNameFromValidatorIndex(validator_id),
            });
        }
    }

    pub fn publishAggregation(self: *Self, signed_aggregation: types.SignedAggregatedAttestation) !void {
        self.logger.info("adding locally produced aggregation to chain: slot={d}", .{signed_aggregation.data.slot});
        try self.chain.onGossipAggregatedAttestation(signed_aggregation);

        const gossip_msg = networks.GossipMessage{ .aggregation = signed_aggregation };
        const aggregation_published = try self.network.publish(&gossip_msg);

        if (aggregation_published) {
            self.logger.info("published aggregation to network: slot={d}", .{signed_aggregation.data.slot});
        } else {
            // Issue #808: backend dropped the publish.
            self.logger.warn("failed to publish aggregation to network (backend dropped publish): slot={d}", .{signed_aggregation.data.slot});
        }
    }

    fn publishProducedAggregations(self: *Self, aggregations: []types.SignedAggregatedAttestation) !void {
        for (aggregations, 0..) |_, i| {
            self.publishAggregation(aggregations[i]) catch |err| {
                for (aggregations[i..]) |*a| a.deinit();
                return err;
            };
            aggregations[i].deinit();
        }
    }

    pub fn run(self: *Self) !void {
        // Catch up fork choice time to current interval before processing any requests.
        // This prevents FutureSlot errors when receiving blocks via RPC immediately after starting.
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
            // validators registered), fall back to subnet 0 to keep parity with leanSpec.
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
        // (and so subnet-routing regressions are visible in logs). Mirrors the
        // leanSpec behaviour at src/lean_spec/__main__.py:541-549.
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

        const peer_handler = self.getPeerEventHandler();
        try self.network.backend.peers.subscribe(peer_handler);

        const req_handler = self.getOnReqRespRequestCbHandler();
        try self.network.backend.reqresp.subscribe(req_handler);

        const chainOnSlot = try self.getOnIntervalCbWrapper();
        try self.clock.subscribeOnSlot(chainOnSlot);
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
            .max_attestations_data = 16,
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
    });
    defer node.deinit();

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
        .signature = try types.createBlockSignatures(allocator, 0),
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
        .signature = try types.createBlockSignatures(allocator, 0),
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
    try types.sszClone(allocator, types.SignedBlock, block2, block2_ptr);
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
        .signature = try types.createBlockSignatures(allocator, 0),
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
    });
    defer node.deinit();

    const slot: usize = 4;
    // Advance the forkchoice clock to the target slot (mimics production flow where
    // onInterval is called before block production)
    try node.chain.forkChoice.onInterval(slot * constants.INTERVALS_PER_SLOT, false);

    const produced_block = try node.chain.produceBlock(.{
        .slot = slot,
        .proposer_index = validator_ids[0],
    });
    const produced_root = produced_block.blockRoot;

    const proposer_signature = try ctx.key_manager.signBlockRoot(
        validator_ids[0],
        &produced_root,
        @intCast(slot),
    );

    var signed_block = types.SignedBlock{
        .block = produced_block.block,
        .signature = .{
            .attestation_signatures = produced_block.attestation_signatures,
            .proposer_signature = proposer_signature,
        },
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
    });
    defer node.deinit();

    try std.testing.expectEqual(@as(usize, 0), node.network.getPeerCount());

    try node.network.connectPeer("peer-aaa");
    try node.network.connectPeer("peer-bbb");
    try std.testing.expectEqual(@as(usize, 2), node.network.getPeerCount());
    try std.testing.expect(node.network.hasPeer("peer-aaa"));

    // selectPeer returns an owned copy.
    if (try node.network.selectPeer()) |picked| {
        defer allocator.free(picked);
        try std.testing.expect(node.network.hasPeer(picked));
    } else return error.NoPick;

    try std.testing.expect(node.network.disconnectPeer("peer-aaa"));
    try std.testing.expectEqual(@as(usize, 1), node.network.getPeerCount());
}
