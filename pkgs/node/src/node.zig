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
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validatorClient.ValidatorClient = null,
    nodeId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

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
            },
            network.connected_peers,
        );
        errdefer {
            chain.deinit();
            allocator.destroy(chain);
        }
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
            .logger = opts.logger_config.logger(.node),
            .node_registry = opts.node_registry,
        };

        chain.setPruneCachedBlocksCallback(self, pruneCachedBlocksCallback);

        network_init_cleanup = false;
    }

    pub fn deinit(self: *Self) void {
        self.network.deinit();
        self.chain.deinit();
        self.allocator.destroy(self.chain);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage, sender_peer_id: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        switch (data.*) {
            .block => |signed_block| {
                const block = signed_block.message.block;
                const parent_root = block.parent_root;
                const hasParentBlock = self.chain.forkChoice.hasBlock(parent_root);

                self.logger.info("received gossip block for slot={d} parent_root=0x{s} proposer={d}{} hasParentBlock={} from peer={s}{}", .{
                    block.slot,
                    std.fmt.fmtSliceHexLower(&parent_root),
                    block.proposer_index,
                    self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
                    hasParentBlock,
                    sender_peer_id,
                    self.node_registry.getNodeNameFromPeerId(sender_peer_id),
                });

                // Compute block root first - needed for both caching and pending tracking
                var block_root: types.Root = undefined;
                zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator) catch |err| {
                    self.logger.warn("failed to compute block root for incoming gossip block: {any}", .{err});
                    return;
                };
                _ = self.network.removePendingBlockRoot(block_root);

                if (!hasParentBlock) {
                    // Cache this block for later processing when parent arrives
                    if (self.cacheBlockAndFetchParent(block_root, signed_block, 0)) |_| {
                        self.logger.debug(
                            "Cached gossip block 0x{s} at slot {d}, fetching parent 0x{s}",
                            .{
                                std.fmt.fmtSliceHexLower(block_root[0..]),
                                block.slot,
                                std.fmt.fmtSliceHexLower(parent_root[0..]),
                            },
                        );
                    } else |err| {
                        if (err == CacheBlockError.PreFinalized) {
                            // Block is pre-finalized - prune any cached descendants waiting for this parent
                            self.logger.info(
                                "gossip block 0x{s} is pre-finalized (slot={d}), pruning cached descendants",
                                .{
                                    std.fmt.fmtSliceHexLower(block_root[0..]),
                                    block.slot,
                                },
                            );
                            _ = self.network.pruneCachedBlocks(block_root, null);
                        } else {
                            self.logger.warn("failed to cache gossip block 0x{s}: {any}", .{
                                std.fmt.fmtSliceHexLower(block_root[0..]),
                                err,
                            });
                        }
                    }
                    // Return early - don't pass to chain until parent arrives
                    return;
                }
            },
            .attestation => |signed_attestation| {
                const slot = signed_attestation.message.slot;
                const validator_id = signed_attestation.validator_id;
                const validator_node_name = self.node_registry.getNodeNameFromValidatorIndex(validator_id);

                const sender_node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
                self.logger.info("received gossip attestation for slot={d} validator={d}{} from peer={s}{}", .{
                    slot,
                    validator_id,
                    validator_node_name,
                    sender_peer_id,
                    sender_node_name,
                });
            },
        }

        const result = self.chain.onGossip(data, sender_peer_id) catch |err| {
            switch (err) {
                // Block rejected because it's before finalized - drop it and prune any cached
                // descendants we might still be holding onto.
                error.PreFinalizedSlot => {
                    if (data.* == .block) {
                        const signed_block = data.block;
                        var block_root: types.Root = undefined;
                        if (zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator)) |_| {
                            self.logger.info(
                                "gossip block 0x{s} rejected as pre-finalized; pruning cached descendants",
                                .{std.fmt.fmtSliceHexLower(block_root[0..])},
                            );
                            _ = self.network.pruneCachedBlocks(block_root, null);
                        } else |_| {}
                    }
                    return;
                },
                // Block validation failed due to unknown parent - log at appropriate level
                // based on whether we're already fetching the parent.
                error.UnknownParentBlock => {
                    if (data.* == .block) {
                        const block = data.block.message.block;
                        const parent_root = block.parent_root;
                        if (self.network.hasPendingBlockRoot(parent_root)) {
                            self.logger.debug("gossip block validation deferred slot={d} parent=0x{s} (parent fetch in progress)", .{
                                block.slot,
                                std.fmt.fmtSliceHexLower(&parent_root),
                            });
                        } else {
                            self.logger.warn("gossip block validation failed slot={d} with unknown parent=0x{s}", .{
                                block.slot,
                                std.fmt.fmtSliceHexLower(&parent_root),
                            });
                        }
                    }
                    return;
                },
                // Attestation validation failed due to missing head/source/target block -
                // downgrade to debug when the missing block is already being fetched.
                error.UnknownHeadBlock, error.UnknownSourceBlock, error.UnknownTargetBlock => {
                    if (data.* == .attestation) {
                        const att = data.attestation;
                        const att_data = att.message;
                        const missing_root = if (err == error.UnknownHeadBlock)
                            att_data.head.root
                        else if (err == error.UnknownSourceBlock)
                            att_data.source.root
                        else
                            att_data.target.root;

                        if (self.network.hasPendingBlockRoot(missing_root)) {
                            self.logger.debug("gossip attestation validation deferred slot={d} validator={d} error={any} (block fetch in progress)", .{
                                att_data.slot,
                                att.validator_id,
                                err,
                            });
                        } else {
                            self.logger.warn("gossip attestation validation failed slot={d} validator={d} error={any}", .{
                                att_data.slot,
                                att.validator_id,
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
                "gossip block 0x{s} successfully processed, checking for cached descendants",
                .{std.fmt.fmtSliceHexLower(processed_root[0..])},
            );
            self.processCachedDescendants(processed_root);
        }

        // Fetch any attestation head roots that were missing while processing the block.
        // We only own the slice when the block was actually processed (onBlock allocates it).
        const missing_roots = result.missing_attestation_roots;
        const owns_missing_roots = result.processed_block_root != null;
        defer if (owns_missing_roots) self.allocator.free(missing_roots);

        if (missing_roots.len > 0 and owns_missing_roots) {
            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn(
                    "failed to fetch {d} missing attestation head block(s) from gossip: {any}",
                    .{ missing_roots.len, err },
                );
            };
        }
    }

    fn pruneCachedBlocksCallback(ptr: *anyopaque, finalized: types.Checkpoint) usize {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // Collect roots of blocks at or before finalized slot
        var roots_to_prune = std.ArrayList(types.Root).init(self.allocator);
        defer roots_to_prune.deinit();

        var it = self.network.fetched_blocks.iterator();
        while (it.next()) |entry| {
            const block_slot = entry.value_ptr.*.message.block.slot;
            if (block_slot <= finalized.slot) {
                roots_to_prune.append(entry.key_ptr.*) catch continue;
            }
        }

        // Remove each root and its full chain (parents + descendants),
        // but preserve the finalized chain's descendants.
        var pruned: usize = 0;
        for (roots_to_prune.items) |root| {
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
        // Get cached children of this parent using O(1) lookup
        const children = self.network.getChildrenOfBlock(parent_root);

        if (children.len == 0) {
            return;
        }

        // Copy the children roots since we'll be modifying the children map during processing
        var descendants_to_process = std.ArrayList(types.Root).init(self.allocator);
        defer descendants_to_process.deinit();
        descendants_to_process.appendSlice(children) catch |err| {
            self.logger.warn("Failed to copy children for processing: {any}", .{err});
            return;
        };

        self.logger.debug(
            "Found {d} cached descendant(s) of block 0x{s}",
            .{ descendants_to_process.items.len, std.fmt.fmtSliceHexLower(parent_root[0..]) },
        );

        // Try to process each descendant
        for (descendants_to_process.items) |descendant_root| {
            if (self.network.getFetchedBlock(descendant_root)) |cached_block| {
                self.logger.debug(
                    "Attempting to process cached block 0x{s}",
                    .{std.fmt.fmtSliceHexLower(descendant_root[0..])},
                );

                const missing_roots = self.chain.onBlock(cached_block.*, .{}) catch |err| {
                    if (err == chainFactory.BlockProcessingError.MissingPreState) {
                        // Parent still missing, keep it cached
                        self.logger.debug(
                            "Cached block 0x{s} still missing parent, keeping in cache",
                            .{std.fmt.fmtSliceHexLower(descendant_root[0..])},
                        );
                    } else if (err == forkchoice.ForkChoiceError.PreFinalizedSlot) {
                        // This block is now before finalized (finalization advanced while it was cached).
                        // Prune this block and all its cached descendants; they are no longer useful.
                        self.logger.info(
                            "cached block 0x{s} rejected as pre-finalized; pruning cached descendants",
                            .{std.fmt.fmtSliceHexLower(descendant_root[0..])},
                        );
                        _ = self.network.pruneCachedBlocks(descendant_root, null);
                    } else {
                        self.logger.warn(
                            "Failed to process cached block 0x{s}: {any}",
                            .{ std.fmt.fmtSliceHexLower(descendant_root[0..]), err },
                        );
                        // Remove from cache on other errors
                        _ = self.network.removeFetchedBlock(descendant_root);
                    }
                    continue;
                };
                defer self.allocator.free(missing_roots);

                self.logger.info(
                    "Successfully processed cached block 0x{s}",
                    .{std.fmt.fmtSliceHexLower(descendant_root[0..])},
                );

                // Remove from cache now that it's been processed
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

    /// Error type for cacheBlockAndFetchParent operation.
    const CacheBlockError = error{
        AlreadyCached,
        PreFinalized,
        AllocationFailed,
        CloneFailed,
        CachingFailed,
        FetchFailed,
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
        signed_block: types.SignedBlockWithAttestation,
        depth: u32,
    ) CacheBlockError!types.Root {
        const finalized_slot = self.chain.forkChoice.fcStore.latest_finalized.slot;
        const block_slot = signed_block.message.block.slot;

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
        if (self.network.fetched_blocks.count() >= constants.MAX_CACHED_BLOCKS) {
            self.logger.warn("Cache full ({d} blocks), rejecting block 0x{s} at slot {d}", .{
                self.network.fetched_blocks.count(),
                std.fmt.fmtSliceHexLower(block_root[0..]),
                block_slot,
            });
            return CacheBlockError.CachingFailed;
        }

        // Allocate and clone the block
        const block_ptr = self.allocator.create(types.SignedBlockWithAttestation) catch {
            return CacheBlockError.AllocationFailed;
        };
        var block_owned = true;
        errdefer if (block_owned) self.allocator.destroy(block_ptr);

        types.sszClone(self.allocator, types.SignedBlockWithAttestation, signed_block, block_ptr) catch {
            return CacheBlockError.CloneFailed;
        };
        errdefer if (block_owned) block_ptr.deinit();

        self.network.cacheFetchedBlock(block_root, block_ptr) catch {
            return CacheBlockError.CachingFailed;
        };
        // Ownership transferred to the network cache — disable errdefers
        block_owned = false;

        // Fetch the parent block
        const parent_root = signed_block.message.block.parent_root;
        const roots = [_]types.Root{parent_root};
        self.fetchBlockByRoots(&roots, depth) catch {
            // Parent fetch failed - drop the cached block so we don't keep dangling entries.
            _ = self.network.removeFetchedBlock(block_root);
            return CacheBlockError.FetchFailed;
        };

        return parent_root;
    }

    fn processBlockByRootChunk(self: *Self, block_ctx: *const BlockByRootContext, signed_block: *const types.SignedBlockWithAttestation) !void {
        var block_root: types.Root = undefined;
        if (zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator)) |_| {
            const current_depth = self.network.getPendingBlockRootDepth(block_root) orelse 0;
            const removed = self.network.removePendingBlockRoot(block_root);
            if (!removed) {
                self.logger.warn("received unexpected block root 0x{s} from peer {s}{}", .{
                    std.fmt.fmtSliceHexLower(block_root[0..]),
                    block_ctx.peer_id,
                    self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                });
            }

            // Try to add the block to the chain
            const missing_roots = self.chain.onBlock(signed_block.*, .{}) catch |err| {
                // Check if the error is due to missing parent
                if (err == chainFactory.BlockProcessingError.MissingPreState) {
                    // Check if we've hit the max depth
                    if (current_depth >= constants.MAX_BLOCK_FETCH_DEPTH) {
                        self.logger.warn(
                            "Reached max block fetch depth ({d}) for block 0x{s}, discarding",
                            .{ constants.MAX_BLOCK_FETCH_DEPTH, std.fmt.fmtSliceHexLower(block_root[0..]) },
                        );
                        return;
                    }

                    // Cache this block and fetch parent
                    if (self.cacheBlockAndFetchParent(block_root, signed_block.*, current_depth + 1)) |parent_root| {
                        self.logger.debug(
                            "Cached block 0x{s} at depth {d}, fetching parent 0x{s}",
                            .{
                                std.fmt.fmtSliceHexLower(block_root[0..]),
                                current_depth,
                                std.fmt.fmtSliceHexLower(parent_root[0..]),
                            },
                        );
                    } else |cache_err| {
                        if (cache_err == CacheBlockError.PreFinalized) {
                            // Block is pre-finalized - prune any cached descendants waiting for this parent
                            self.logger.info(
                                "block 0x{s} is pre-finalized (slot={d}), pruning cached descendants",
                                .{
                                    std.fmt.fmtSliceHexLower(block_root[0..]),
                                    signed_block.message.block.slot,
                                },
                            );
                            _ = self.network.pruneCachedBlocks(block_root, null);
                        } else {
                            self.logger.warn("failed to cache block 0x{s}: {any}", .{
                                std.fmt.fmtSliceHexLower(block_root[0..]),
                                cache_err,
                            });
                        }
                    }
                    return;
                }

                if (err == forkchoice.ForkChoiceError.PreFinalizedSlot) {
                    self.logger.info(
                        "discarding pre-finalized block 0x{s} from peer {s}{}, pruning cached descendants",
                        .{
                            std.fmt.fmtSliceHexLower(block_root[0..]),
                            block_ctx.peer_id,
                            self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                        },
                    );
                    _ = self.network.pruneCachedBlocks(block_root, null);
                    return;
                }

                self.logger.warn("failed to import block fetched via RPC 0x{s} from peer {s}{}: {any}", .{
                    std.fmt.fmtSliceHexLower(block_root[0..]),
                    block_ctx.peer_id,
                    self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                    err,
                });
                return;
            };
            defer self.allocator.free(missing_roots);

            self.logger.debug(
                "Successfully processed block 0x{s}, checking for cached descendants",
                .{std.fmt.fmtSliceHexLower(block_root[0..])},
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
            self.logger.warn("failed to compute block root from RPC response from peer={s}{}: {any}", .{ block_ctx.peer_id, self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id), err });
        }
    }

    fn handleReqRespResponse(self: *Self, event: *const networks.ReqRespResponseEvent) !void {
        const request_id = event.request_id;
        const entry_ptr = self.network.getPendingRequestPtr(request_id) orelse {
            self.logger.warn("received RPC response for unknown request_id={d}", .{request_id});
            return;
        };
        const ctx_ptr = &entry_ptr.request;
        const peer_id = switch (ctx_ptr.*) {
            .status => |*ctx| ctx.peer_id,
            .blocks_by_root => |*ctx| ctx.peer_id,
        };
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);

        switch (event.payload) {
            .success => |resp| switch (resp) {
                .status => |status_resp| {
                    switch (ctx_ptr.*) {
                        .status => |*status_ctx| {
                            self.logger.info("received status response from peer {s}{} head_slot={d}, finalized_slot={d}", .{
                                status_ctx.peer_id,
                                self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                status_resp.head_slot,
                                status_resp.finalized_slot,
                            });
                            if (!self.network.setPeerLatestStatus(status_ctx.peer_id, status_resp)) {
                                self.logger.warn("status response received for unknown peer {s}{}", .{
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
                                    if (status_resp.finalized_slot > self.chain.forkChoice.fcStore.latest_finalized.slot) {
                                        self.logger.info("peer {s}{} is ahead (peer_finalized_slot={d} > our_head_slot={d}), initiating sync by requesting head block 0x{s}", .{
                                            status_ctx.peer_id,
                                            self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                            status_resp.finalized_slot,
                                            info.head_slot,
                                            std.fmt.fmtSliceHexLower(&status_resp.head_root),
                                        });
                                        const roots = [_]types.Root{status_resp.head_root};
                                        self.fetchBlockByRoots(&roots, 0) catch |err| {
                                            self.logger.warn("failed to initiate sync by fetching head block from peer {s}{}: {any}", .{
                                                status_ctx.peer_id,
                                                self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                                                err,
                                            });
                                        };
                                    }
                                },
                                .synced, .no_peers => {},
                            }
                        },
                        else => {
                            self.logger.warn("status response did not match tracked request_id={d} from peer={s}{}", .{ request_id, peer_id, node_name });
                        },
                    }
                },
                .blocks_by_root => |block_resp| {
                    switch (ctx_ptr.*) {
                        .blocks_by_root => |*block_ctx| {
                            self.logger.info("received blocks-by-root chunk from peer {s}{}", .{
                                block_ctx.peer_id,
                                self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
                            });

                            try self.processBlockByRootChunk(block_ctx, &block_resp);
                        },
                        else => {
                            self.logger.warn("blocks-by-root response did not match tracked request_id={d} from peer={s}{}", .{ request_id, peer_id, node_name });
                        },
                    }
                },
            },
            .failure => |err_payload| {
                switch (ctx_ptr.*) {
                    .status => |status_ctx| {
                        self.logger.warn("status request to peer {s}{} failed ({d}): {s}", .{
                            status_ctx.peer_id,
                            self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                            err_payload.code,
                            err_payload.message,
                        });
                    },
                    .blocks_by_root => |block_ctx| {
                        self.logger.warn("blocks-by-root request to peer {s}{} failed ({d}): {s}", .{
                            block_ctx.peer_id,
                            self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
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

        switch (data.*) {
            .blocks_by_root => |request| {
                const roots = request.constSlice();

                self.logger.debug(
                    "node-{d}:: Handling blocks_by_root request for {d} roots",
                    .{ self.nodeId, roots.len },
                );

                for (roots) |root| {
                    if (self.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
                        var signed_block = signed_block_value;
                        defer signed_block.deinit();

                        var response = networks.ReqRespResponse{ .blocks_by_root = undefined };
                        try types.sszClone(self.allocator, types.SignedBlockWithAttestation, signed_block, &response.blocks_by_root);
                        defer response.deinit();

                        try responder.sendResponse(&response);
                    } else {
                        self.logger.warn(
                            "node-{d}:: Requested block root=0x{s} not found",
                            .{ self.nodeId, std.fmt.fmtSliceHexLower(root[0..]) },
                        );
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

    fn fetchBlockByRoots(
        self: *Self,
        roots: []const types.Root,
        depth: u32,
    ) !void {
        if (roots.len == 0) return;

        // Check if any of the requested blocks are missing
        var missing_roots = std.ArrayList(types.Root).init(self.allocator);
        defer missing_roots.deinit();

        for (roots) |root| {
            if (!self.chain.forkChoice.hasBlock(root)) {
                try missing_roots.append(root);
            }
        }

        if (missing_roots.items.len == 0) return;

        const handler = self.getReqRespResponseHandler();
        const maybe_request = self.network.ensureBlocksByRootRequest(missing_roots.items, depth, handler) catch |err| blk: {
            switch (err) {
                error.NoPeersAvailable => {
                    self.logger.warn(
                        "no peers available to request {d} block(s) by root",
                        .{missing_roots.items.len},
                    );
                },
                else => {
                    self.logger.warn(
                        "failed to send blocks-by-root request to peer: {any}",
                        .{err},
                    );
                },
            }
            break :blk null;
        };

        if (maybe_request) |request_info| {
            self.logger.debug("requested {d} block(s) by root from peer {s}{}, request_id={d}", .{
                missing_roots.items.len,
                request_info.peer_id,
                self.node_registry.getNodeNameFromPeerId(request_info.peer_id),
                request_info.request_id,
            });
        }
    }

    pub fn onPeerConnected(ptr: *anyopaque, peer_id: []const u8, direction: networks.PeerDirection) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        try self.network.connectPeer(peer_id);
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.info("peer connected: {s}{}, direction={s}, total peers: {d}", .{
            peer_id,
            node_name,
            @tagName(direction),
            self.network.getPeerCount(),
        });

        // Record metrics
        zeam_metrics.metrics.lean_peer_connection_events_total.incr(.{ .direction = @tagName(direction), .result = "success" }) catch {};
        zeam_metrics.metrics.lean_connected_peers.set(@intCast(self.network.getPeerCount()));

        const handler = self.getReqRespResponseHandler();
        const status = self.chain.getStatus();

        const request_id = self.network.sendStatusToPeer(peer_id, status, handler) catch |err| {
            self.logger.warn("failed to send status request to peer {s}{} {any}", .{
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                err,
            });
            return;
        };

        self.logger.info("sent status request to peer {s}{}: request_id={d}, head_slot={d}, finalized_slot={d}", .{
            peer_id,
            self.node_registry.getNodeNameFromPeerId(peer_id),
            request_id,
            status.head_slot,
            status.finalized_slot,
        });
    }

    pub fn onPeerDisconnected(ptr: *anyopaque, peer_id: []const u8, direction: networks.PeerDirection, reason: networks.DisconnectionReason) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (self.network.disconnectPeer(peer_id)) {
            self.logger.info("peer disconnected: {s}{}, direction={s}, reason={s}, total peers: {d}", .{
                peer_id,
                self.node_registry.getNodeNameFromPeerId(peer_id),
                @tagName(direction),
                @tagName(reason),
                self.network.getPeerCount(),
            });

            // Record metrics
            zeam_metrics.metrics.lean_peer_disconnection_events_total.incr(.{ .direction = @tagName(direction), .reason = @tagName(reason) }) catch {};
            zeam_metrics.metrics.lean_connected_peers.set(@intCast(self.network.getPeerCount()));
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
        if (itime_intervals > 0 and itime_intervals <= self.chain.forkChoice.fcStore.time) {
            self.logger.warn("skipping onInterval for node ad chain is already ahead at time={d} of the misfired interval time={d}", .{
                self.chain.forkChoice.fcStore.time,
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
        const interval: usize = @intCast(itime_intervals);

        self.chain.onInterval(interval) catch |e| {
            self.logger.err("error ticking chain to time(intervals)={d} err={any}", .{ interval, e });
            // no point going further if chain is not ticked properly
            return e;
        };

        // Sweep timed-out RPC requests to prevent sync stalls from non-responsive peers
        self.sweepTimedOutRequests();

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
                    }
                }
            }
        }
    }

    fn sweepTimedOutRequests(self: *Self) void {
        const current_time = std.time.timestamp();
        const timed_out = self.network.getTimedOutRequests(current_time, constants.RPC_REQUEST_TIMEOUT_SECONDS) catch |err| {
            self.logger.warn("failed to check for timed-out RPC requests: {any}", .{err});
            return;
        };

        for (timed_out) |request_id| {
            const entry_ptr = self.network.getPendingRequestPtr(request_id) orelse continue;

            switch (entry_ptr.request) {
                .blocks_by_root => |block_ctx| {
                    // Copy roots + depths BEFORE finalize frees them
                    var roots_to_retry = std.ArrayList(struct { root: types.Root, depth: u32 }).init(self.allocator);
                    defer roots_to_retry.deinit();

                    for (block_ctx.requested_roots) |root| {
                        const depth = self.network.getPendingBlockRootDepth(root) orelse 0;
                        roots_to_retry.append(.{ .root = root, .depth = depth }) catch continue;
                    }

                    self.logger.warn("RPC request_id={d} to peer {s}{} timed out after {d}s, retrying {d} roots", .{
                        request_id,
                        block_ctx.peer_id,
                        self.node_registry.getNodeNameFromPeerId(block_ctx.peer_id),
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
                .status => |status_ctx| {
                    self.logger.warn("status RPC request_id={d} to peer {s}{} timed out, finalizing", .{
                        request_id,
                        status_ctx.peer_id,
                        self.node_registry.getNodeNameFromPeerId(status_ctx.peer_id),
                    });
                    self.network.finalizePendingRequest(request_id);
                },
            }
        }
    }

    pub fn publishBlock(self: *Self, signed_block: types.SignedBlockWithAttestation) !void {
        const block = signed_block.message.block;

        // 1. Process locally through chain so that produced block first can be confirmed
        var block_root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator);

        // check if the block has not already been received through the network
        const hasBlock = self.chain.forkChoice.hasBlock(block_root);
        if (!hasBlock) {
            self.logger.info("adding produced signed block to the chain: slot={d} proposer={d}", .{
                block.slot,
                block.proposer_index,
            });

            const missing_roots = try self.chain.onBlock(signed_block, .{
                .postState = self.chain.states.get(block_root),
                .blockRoot = block_root,
            });
            defer self.allocator.free(missing_roots);

            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn("failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
            };
        } else {
            self.logger.debug("skip adding produced signed block to chain as already present: slot={d} proposer={d}", .{
                block.slot,
                block.proposer_index,
            });
        }

        // 2. publish gossip message
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.network.publish(&gossip_msg);
        self.logger.info("published block to network: slot={d} proposer={d}{}", .{
            block.slot,
            block.proposer_index,
            self.node_registry.getNodeNameFromValidatorIndex(block.proposer_index),
        });

        // 3. followup with additional housekeeping tasks
        self.chain.onBlockFollowup(true, &signed_block);
    }

    pub fn publishAttestation(self: *Self, signed_attestation: types.SignedAttestation) !void {
        const data = signed_attestation.message;
        const validator_id = signed_attestation.validator_id;

        // 1. Process locally through chain
        self.logger.info("adding locally produced attestation to chain: slot={d} validator={d}", .{
            data.slot,
            validator_id,
        });
        try self.chain.onGossipAttestation(signed_attestation);

        // 2. publish gossip message
        const gossip_msg = networks.GossipMessage{ .attestation = signed_attestation };
        try self.network.publish(&gossip_msg);

        self.logger.info("published attestation to network: slot={d} validator={d}{}", .{
            data.slot,
            validator_id,
            self.node_registry.getNodeNameFromValidatorIndex(validator_id),
        });
    }

    pub fn run(self: *Self) !void {
        // Catch up fork choice time to current interval before processing any requests.
        // This prevents FutureSlot errors when receiving blocks via RPC immediately after starting.
        const current_interval = self.clock.current_interval;
        if (current_interval > 0) {
            try self.chain.forkChoice.onInterval(@intCast(current_interval), false);
            self.logger.info("fork choice time caught up to interval {d}", .{current_interval});
        }

        const handler = try self.getOnGossipCbHandler();
        var topics = [_]networks.GossipTopic{ .block, .attestation };
        try self.network.backend.gossip.subscribe(&topics, handler);

        const peer_handler = self.getPeerEventHandler();
        try self.network.backend.peers.subscribe(peer_handler);

        const req_handler = self.getOnReqRespRequestCbHandler();
        try self.network.backend.reqresp.subscribe(req_handler);

        const chainOnSlot = try self.getOnIntervalCbWrapper();
        try self.clock.subscribeOnSlot(chainOnSlot);
    }
};

const xev = @import("xev");

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

    const pubkeys = try key_manager.getAllPubkeys(allocator, num_validators);
    defer allocator.free(pubkeys);

    const genesis_config = types.GenesisSpec{
        .genesis_time = @intCast(std.time.timestamp()),
        .validator_pubkeys = pubkeys,
    };

    var anchor_state: types.BeamState = undefined;
    try anchor_state.genGenesisState(allocator, genesis_config);
    defer anchor_state.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, ctx.loggerConfig().logger(.database), data_dir);
    defer db.deinit();

    const spec_name = try allocator.dupe(u8, "zeamdev");
    defer allocator.free(spec_name);

    const chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = genesis_config,
        .spec = .{
            .preset = params.Preset.minimal,
            .name = spec_name,
        },
    };

    var clock = try clockFactory.Clock.init(allocator, genesis_config.genesis_time, ctx.loopPtr());
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
        std.time.sleep(2 * std.time.ns_per_ms); // Wait 2ms for timers to fire
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
    const block1_ptr = try allocator.create(types.SignedBlockWithAttestation);
    block1_ptr.* = .{
        .message = .{
            .block = .{
                .slot = 1,
                .parent_root = ZERO_HASH,
                .proposer_index = 0,
                .state_root = ZERO_HASH,
                .body = .{
                    .attestations = try types.AggregatedAttestations.init(allocator),
                },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 1,
                    .head = .{ .root = ZERO_HASH, .slot = 0 },
                    .target = .{ .root = ZERO_HASH, .slot = 0 },
                    .source = .{ .root = ZERO_HASH, .slot = 0 },
                },
            },
        },
        .signature = try types.createBlockSignatures(allocator, 0),
    };

    const block2_ptr = try allocator.create(types.SignedBlockWithAttestation);
    block2_ptr.* = .{
        .message = .{
            .block = .{
                .slot = 2,
                .parent_root = root1,
                .proposer_index = 0,
                .state_root = ZERO_HASH,
                .body = .{
                    .attestations = try types.AggregatedAttestations.init(allocator),
                },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 2,
                    .head = .{ .root = ZERO_HASH, .slot = 0 },
                    .target = .{ .root = ZERO_HASH, .slot = 0 },
                    .source = .{ .root = ZERO_HASH, .slot = 0 },
                },
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
    const block1_slot: usize = @intCast(block1.message.block.slot);
    const block2_slot: usize = @intCast(block2.message.block.slot);

    // Cache block2 (which will fail to process because block1 is missing)
    const block2_ptr = try allocator.create(types.SignedBlockWithAttestation);
    try types.sszClone(allocator, types.SignedBlockWithAttestation, block2, block2_ptr);
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
) !*types.SignedBlockWithAttestation {
    const block_ptr = try allocator.create(types.SignedBlockWithAttestation);
    errdefer allocator.destroy(block_ptr);

    block_ptr.* = .{
        .message = .{
            .block = .{
                .slot = slot,
                .parent_root = parent_root,
                .proposer_index = 0,
                .state_root = types.ZERO_HASH,
                .body = .{
                    .attestations = try types.AggregatedAttestations.init(allocator),
                },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = slot,
                    .head = .{ .root = ZERO_HASH, .slot = 0 },
                    .target = .{ .root = ZERO_HASH, .slot = 0 },
                    .source = .{ .root = ZERO_HASH, .slot = 0 },
                },
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
    const children_of_a = node.network.getChildrenOfBlock(root_a);
    try std.testing.expectEqual(@as(usize, 2), children_of_a.len);
    const children_of_b = node.network.getChildrenOfBlock(root_b);
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
    try std.testing.expect(node.network.fetched_block_children.get(root_a) == null);
    try std.testing.expect(node.network.fetched_block_children.get(root_b) == null);

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
    const children = node.network.getChildrenOfBlock(parent_root);
    try std.testing.expectEqual(@as(usize, 1), children.len);
    try std.testing.expect(std.mem.eql(u8, children[0][0..], child_root[0..]));

    // Remove the block and verify children list is cleaned up
    try std.testing.expect(node.network.removeFetchedBlock(child_root));

    // After removal, no children should remain for this parent
    const children_after = node.network.getChildrenOfBlock(parent_root);
    try std.testing.expectEqual(@as(usize, 0), children_after.len);

    // The parent entry should be fully cleaned up from the children map
    try std.testing.expect(node.network.fetched_block_children.get(parent_root) == null);
}
