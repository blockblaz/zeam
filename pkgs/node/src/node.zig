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

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;
const testing = @import("./testing.zig");

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");
pub const validatorClient = @import("./validator_client.zig");
const constants = @import("./constants.zig");

const BlockByRootContext = networkFactory.BlockByRootContext;

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
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validatorClient.ValidatorClient = null,
    nodeId: u32,
    logger: zeam_utils.ModuleLogger,

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
        };

        network_init_cleanup = false;
    }

    pub fn deinit(self: *Self) void {
        self.network.deinit();
        self.chain.deinit();
        self.allocator.destroy(self.chain);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        switch (data.*) {
            .block => |signed_block| {
                const parent_root = signed_block.message.block.parent_root;
                if (!self.chain.forkChoice.hasBlock(parent_root)) {
                    const roots = [_]types.Root{parent_root};
                    self.fetchBlockByRoots(&roots, 0) catch |err| {
                        self.logger.warn("Failed to fetch block by root: {any}", .{err});
                    };
                }

                var block_root: types.Root = undefined;
                if (ssz.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator)) |_| {
                    _ = self.network.removePendingBlockRoot(block_root);
                } else |err| {
                    self.logger.warn("Failed to compute block root for incoming gossip block: {any}", .{err});
                }
            },
            .attestation => {},
        }

        const result = try self.chain.onGossip(data);
        self.handleGossipProcessingResult(result);
    }

    fn handleGossipProcessingResult(self: *Self, result: chainFactory.GossipProcessingResult) void {
        // Process successfully imported blocks to retry any cached descendants
        if (result.processed_block_root) |processed_root| {
            self.logger.debug(
                "Gossip block 0x{s} successfully processed, checking for cached descendants",
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
                    "Failed to fetch {d} missing attestation head block(s) from gossip: {any}",
                    .{ missing_roots.len, err },
                );
            };
        }
    }

    fn getReqRespResponseHandler(self: *Self) networks.OnReqRespResponseCbHandler {
        return .{
            .ptr = self,
            .onReqRespResponseCb = onReqRespResponse,
        };
    }

    fn processCachedDescendants(self: *Self, parent_root: types.Root) void {
        // Find all cached blocks that have this parent
        var descendants_to_process = std.ArrayList(types.Root).init(self.allocator);
        defer descendants_to_process.deinit();

        var it = self.network.fetched_blocks.iterator();
        while (it.next()) |entry| {
            const cached_block = entry.value_ptr.*;
            if (std.mem.eql(u8, &cached_block.message.block.parent_root, &parent_root)) {
                descendants_to_process.append(entry.key_ptr.*) catch |err| {
                    self.logger.warn("Failed to track descendant for processing: {any}", .{err});
                    continue;
                };
            }
        }

        if (descendants_to_process.items.len == 0) {
            return;
        }

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
                    self.logger.warn("Failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, fetch_err });
                };
            }
        }
    }

    fn processBlockByRootChunk(self: *Self, block_ctx: *const BlockByRootContext, signed_block: *const types.SignedBlockWithAttestation) !void {
        var block_root: types.Root = undefined;
        if (ssz.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator)) |_| {
            const current_depth = self.network.getPendingBlockRootDepth(block_root) orelse 0;
            const removed = self.network.removePendingBlockRoot(block_root);
            if (!removed) {
                self.logger.warn(
                    "Received unexpected block root 0x{s} from peer {s}",
                    .{ std.fmt.fmtSliceHexLower(block_root[0..]), block_ctx.peer_id },
                );
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

                    // Check if cache is full to prevent unbounded growth
                    if (self.network.fetched_blocks.count() >= constants.MAX_CACHED_BLOCKS) {
                        self.logger.warn(
                            "Block cache full ({d} blocks), discarding block 0x{s}",
                            .{ constants.MAX_CACHED_BLOCKS, std.fmt.fmtSliceHexLower(block_root[0..]) },
                        );
                        return;
                    }

                    // Cache this block for later processing
                    const block_ptr = try self.allocator.create(types.SignedBlockWithAttestation);
                    errdefer self.allocator.destroy(block_ptr);

                    try types.sszClone(self.allocator, types.SignedBlockWithAttestation, signed_block.*, block_ptr);
                    errdefer block_ptr.deinit();

                    try self.network.cacheFetchedBlock(block_root, block_ptr);

                    self.logger.debug(
                        "Cached block 0x{s} at depth {d}, fetching parent 0x{s}",
                        .{
                            std.fmt.fmtSliceHexLower(block_root[0..]),
                            current_depth,
                            std.fmt.fmtSliceHexLower(signed_block.message.block.parent_root[0..]),
                        },
                    );

                    // Fetch the parent block with increased depth
                    const parent_root = signed_block.message.block.parent_root;
                    const roots = [_]types.Root{parent_root};
                    try self.fetchBlockByRoots(&roots, current_depth + 1);
                    return;
                }

                self.logger.warn(
                    "Failed to import block fetched via RPC 0x{s} from peer {s}: {any}",
                    .{ std.fmt.fmtSliceHexLower(block_root[0..]), block_ctx.peer_id, err },
                );
                return;
            };
            defer self.allocator.free(missing_roots);

            self.logger.debug(
                "Successfully processed block 0x{s}, checking for cached descendants",
                .{std.fmt.fmtSliceHexLower(block_root[0..])},
            );

            // Block was successfully added, try to process any cached descendants
            self.processCachedDescendants(block_root);

            // Fetch any missing attestation head blocks
            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn("Failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
            };
        } else |err| {
            self.logger.warn("Failed to compute block root from RPC response: {any}", .{err});
        }
    }

    fn handleReqRespResponse(self: *Self, event: *const networks.ReqRespResponseEvent) !void {
        const request_id = event.request_id;
        const ctx_ptr = self.network.getPendingRequestPtr(request_id) orelse {
            self.logger.warn("Received RPC response for unknown request_id={d}", .{request_id});
            return;
        };

        switch (event.payload) {
            .success => |resp| switch (resp) {
                .status => |status_resp| {
                    switch (ctx_ptr.*) {
                        .status => |*status_ctx| {
                            self.logger.info(
                                "Received status response from peer {s}: head_slot={d}, finalized_slot={d}",
                                .{ status_ctx.peer_id, status_resp.head_slot, status_resp.finalized_slot },
                            );
                            if (!self.network.setPeerLatestStatus(status_ctx.peer_id, status_resp)) {
                                self.logger.warn(
                                    "Status response received for unknown peer {s}",
                                    .{status_ctx.peer_id},
                                );
                            }
                        },
                        else => {
                            self.logger.warn("Status response did not match tracked request_id={d}", .{request_id});
                        },
                    }
                },
                .blocks_by_root => |block_resp| {
                    switch (ctx_ptr.*) {
                        .blocks_by_root => |*block_ctx| {
                            self.logger.info(
                                "Received blocks-by-root chunk from peer {s}",
                                .{block_ctx.peer_id},
                            );

                            try self.processBlockByRootChunk(block_ctx, &block_resp);
                        },
                        else => {
                            self.logger.warn("Blocks-by-root response did not match tracked request_id={d}", .{request_id});
                        },
                    }
                },
            },
            .failure => |err_payload| {
                switch (ctx_ptr.*) {
                    .status => |status_ctx| {
                        self.logger.warn(
                            "Status request to peer {s} failed ({d}): {s}",
                            .{ status_ctx.peer_id, err_payload.code, err_payload.message },
                        );
                    },
                    .blocks_by_root => |block_ctx| {
                        self.logger.warn(
                            "Blocks-by-root request to peer {s} failed ({d}): {s}",
                            .{ block_ctx.peer_id, err_payload.code, err_payload.message },
                        );
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
                        "No peers available to request {d} block(s) by root",
                        .{missing_roots.items.len},
                    );
                },
                else => {
                    self.logger.warn(
                        "Failed to send blocks-by-root request to peer: {any}",
                        .{err},
                    );
                },
            }
            break :blk null;
        };

        if (maybe_request) |request_info| {
            self.logger.debug(
                "Requested {d} block(s) by root from peer {s}, request_id={d}",
                .{ missing_roots.items.len, request_info.peer_id, request_info.request_id },
            );
        }
    }

    pub fn onPeerConnected(ptr: *anyopaque, peer_id: []const u8) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        try self.network.connectPeer(peer_id);
        self.logger.info("Peer connected: {s}, total peers: {d}", .{ peer_id, self.network.getPeerCount() });

        const handler = self.getReqRespResponseHandler();
        const status = self.chain.getStatus();

        const request_id = self.network.sendStatusToPeer(peer_id, status, handler) catch |err| {
            self.logger.warn("Failed to send status request to peer {s}: {any}", .{ peer_id, err });
            return;
        };

        self.logger.info(
            "Sent status request to peer {s}: request_id={d}, head_slot={d}, finalized_slot={d}",
            .{ peer_id, request_id, status.head_slot, status.finalized_slot },
        );
    }

    pub fn onPeerDisconnected(ptr: *anyopaque, peer_id: []const u8) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (self.network.disconnectPeer(peer_id)) {
            self.logger.info("Peer disconnected: {s}, total peers: {d}", .{ peer_id, self.network.getPeerCount() });
        }
    }

    pub fn getPeerEventHandler(self: *Self) networks.OnPeerEventCbHandler {
        return .{
            .ptr = self,
            .onPeerConnectedCb = onPeerConnected,
            .onPeerDisconnectedCb = onPeerDisconnected,
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
        if (itime_intervals <= self.chain.forkChoice.fcStore.time) {
            self.logger.warn("Skipping onInterval for node ad chain is already ahead at time={d} of the misfired interval time={d}", .{
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
                self.chain.printSlot(islot, self.network.getPeerCount());
            }
            return;
        }
        const interval: usize = @intCast(itime_intervals);

        self.chain.onInterval(interval) catch |e| {
            self.logger.err("Error ticking chain to time(intervals)={d} err={any}", .{ interval, e });
            // no point going further if chain is not ticked properly
            return e;
        };
        if (self.validator) |*validator| {
            // we also tick validator per interval in case it would
            // need to sync its future duties when its an independent validator
            var validator_output = validator.onInterval(interval) catch |e| {
                self.logger.err("Error ticking validator to time(intervals)={d} err={any}", .{ interval, e });
                return e;
            };

            if (validator_output) |*output| {
                defer output.deinit();
                for (output.gossip_messages.items) |gossip_msg| {

                    // Process based on message type
                    switch (gossip_msg) {
                        .block => |signed_block| {
                            self.publishBlock(signed_block) catch |e| {
                                self.logger.err("Error publishing block from validator: err={any}", .{e});
                                return e;
                            };
                        },
                        .attestation => |signed_attestation| {
                            self.publishAttestation(signed_attestation) catch |e| {
                                self.logger.err("Error publishing attestation from validator: err={any}", .{e});
                                return e;
                            };
                        },
                    }
                }
            }
        }
    }

    pub fn publishBlock(self: *Self, signed_block: types.SignedBlockWithAttestation) !void {
        // 1. publish gossip message
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.network.publish(&gossip_msg);

        const block = signed_block.message.block;

        self.logger.info("Published block to network: slot={d} proposer={d}", .{
            block.slot,
            block.proposer_index,
        });

        // 2. Process locally through chain
        var block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator);

        // check if the block has not already been received through the network
        const hasBlock = self.chain.forkChoice.hasBlock(block_root);
        if (!hasBlock) {
            self.logger.info("Seems like block was not locally produced, adding to the chain: slot={d} proposer={d}", .{
                block.slot,
                block.proposer_index,
            });

            const missing_roots = try self.chain.onBlock(signed_block, .{
                .postState = self.chain.states.get(block_root),
                .blockRoot = block_root,
            });
            defer self.allocator.free(missing_roots);

            self.fetchBlockByRoots(missing_roots, 0) catch |err| {
                self.logger.warn("Failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
            };
        } else {
            self.logger.debug("Skip adding produced block to chain as already present: slot={d} proposer={d}", .{
                block.slot,
                block.proposer_index,
            });
        }
    }

    pub fn publishAttestation(self: *Self, signed_attestation: types.SignedAttestation) !void {
        // 1. publish gossip message
        const gossip_msg = networks.GossipMessage{ .attestation = signed_attestation };
        try self.network.publish(&gossip_msg);

        const message = signed_attestation.message;
        const data = message.data;
        self.logger.info("Published attestation to network: slot={d} validator={d}", .{
            data.slot,
            message.validator_id,
        });

        // 2. Process locally through chain
        return self.chain.onAttestation(signed_attestation);
    }

    pub fn run(self: *Self) !void {
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

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock));
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();
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
    });
    defer node.deinit();

    try node.run();

    // Verify initial state: 0 peers
    try std.testing.expectEqual(@as(usize, 0), node.network.getPeerCount());

    // Simulate peer connections by manually triggering the event handler
    const peer1_id = "PEE_POW_1";
    const peer2_id = "PEE_POW_2";
    const peer3_id = "PEE_POW_3";

    // Connect peer 1
    try mock.peerEventHandler.onPeerConnected(peer1_id);
    try std.testing.expectEqual(@as(usize, 1), node.network.getPeerCount());

    // Connect peer 2
    try mock.peerEventHandler.onPeerConnected(peer2_id);
    try std.testing.expectEqual(@as(usize, 2), node.network.getPeerCount());

    // Connect peer 3
    try mock.peerEventHandler.onPeerConnected(peer3_id);
    try std.testing.expectEqual(@as(usize, 3), node.network.getPeerCount());

    // Verify peer 1 exists
    try std.testing.expect(node.network.hasPeer(peer1_id));

    // Disconnect peer 2
    try mock.peerEventHandler.onPeerDisconnected(peer2_id);
    try std.testing.expectEqual(@as(usize, 2), node.network.getPeerCount());
    try std.testing.expect(!node.network.hasPeer(peer2_id));

    // Disconnect peer 1
    try mock.peerEventHandler.onPeerDisconnected(peer1_id);
    try std.testing.expectEqual(@as(usize, 1), node.network.getPeerCount());
    try std.testing.expect(!node.network.hasPeer(peer1_id));

    // Verify peer 3 is still connected
    try std.testing.expect(node.network.hasPeer(peer3_id));

    // Disconnect peer 3
    try mock.peerEventHandler.onPeerDisconnected(peer3_id);
    try std.testing.expectEqual(@as(usize, 0), node.network.getPeerCount());
}

test "Node: fetched blocks cache and deduplication" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var ctx = try testing.NodeTestContext.init(allocator, .{});
    defer ctx.deinit();

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock));
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();
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
                .parent_root = [_]u8{0} ** 32,
                .proposer_index = 0,
                .state_root = [_]u8{0} ** 32,
                .body = .{
                    .attestations = try ssz.utils.List(types.Attestation, params.VALIDATOR_REGISTRY_LIMIT).init(allocator),
                },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 1,
                    .head = .{ .root = [_]u8{0} ** 32, .slot = 0 },
                    .target = .{ .root = [_]u8{0} ** 32, .slot = 0 },
                    .source = .{ .root = [_]u8{0} ** 32, .slot = 0 },
                },
            },
        },
        .signature = try types.BlockSignatures.init(allocator),
    };

    const block2_ptr = try allocator.create(types.SignedBlockWithAttestation);
    block2_ptr.* = .{
        .message = .{
            .block = .{
                .slot = 2,
                .parent_root = root1,
                .proposer_index = 0,
                .state_root = [_]u8{0} ** 32,
                .body = .{
                    .attestations = try ssz.utils.List(types.Attestation, params.VALIDATOR_REGISTRY_LIMIT).init(allocator),
                },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 2,
                    .head = .{ .root = [_]u8{0} ** 32, .slot = 0 },
                    .target = .{ .root = [_]u8{0} ** 32, .slot = 0 },
                    .source = .{ .root = [_]u8{0} ** 32, .slot = 0 },
                },
            },
        },
        .signature = try types.BlockSignatures.init(allocator),
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

    var mock = try networks.Mock.init(allocator, ctx.loopPtr(), ctx.loggerConfig().logger(.mock));
    defer mock.deinit();

    const backend = mock.getNetworkInterface();

    const chain_config = ctx.takeChainConfig();
    const anchor_state = ctx.takeAnchorState();
    var mock_chain = try stf.genMockChain(allocator, 3, ctx.genesisConfig());
    defer mock_chain.deinit(allocator);
    try ctx.signBlockWithValidatorKeys(allocator, &mock_chain.blocks[1]);
    try ctx.signBlockWithValidatorKeys(allocator, &mock_chain.blocks[2]);
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
