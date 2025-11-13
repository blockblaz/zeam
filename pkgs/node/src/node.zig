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

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;

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
                    self.fetchBlockByRoots(&roots) catch |err| {
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

        try self.chain.onGossip(data);
    }

    fn getReqRespResponseHandler(self: *Self) networks.OnReqRespResponseCbHandler {
        return .{
            .ptr = self,
            .onReqRespResponseCb = onReqRespResponse,
        };
    }

    fn processBlockByRootChunk(self: *Self, block_ctx: *const BlockByRootContext, signed_block: *const types.SignedBlockWithAttestation) void {
        var block_root: types.Root = undefined;
        if (ssz.hashTreeRoot(types.BeamBlock, signed_block.message.block, &block_root, self.allocator)) |_| {
            const removed = self.network.removePendingBlockRoot(block_root);
            if (!removed) {
                self.logger.warn(
                    "Received unexpected block root 0x{s} from peer {s}",
                    .{ std.fmt.fmtSliceHexLower(block_root[0..]), block_ctx.peer_id },
                );
            }

            const missing_roots = self.chain.onBlock(signed_block.*, .{}) catch |err| {
                self.logger.warn(
                    "Failed to import block fetched via RPC 0x{s} from peer {s}: {any}",
                    .{ std.fmt.fmtSliceHexLower(block_root[0..]), block_ctx.peer_id, err },
                );
                return;
            };
            defer self.allocator.free(missing_roots);

            self.fetchBlockByRoots(missing_roots) catch |err| {
                self.logger.warn("Failed to fetch {d} missing block(s): {any}", .{ missing_roots.len, err });
            };
        } else |err| {
            self.logger.warn("Failed to compute block root from RPC response: {any}", .{err});
        }
    }

    fn handleReqRespResponse(self: *Self, event: *const networks.ReqRespResponseEvent) void {
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

                            self.processBlockByRootChunk(block_ctx, &block_resp);
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
        self.handleReqRespResponse(event);
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
        const maybe_request = self.network.ensureBlocksByRootRequest(missing_roots.items, handler) catch |err| blk: {
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

            self.fetchBlockByRoots(missing_roots) catch |err| {
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

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    var mock = try networks.Mock.init(allocator, &loop, logger_config.logger(.mock));
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
        .genesis_time = 0,
        .validator_pubkeys = pubkeys,
    };

    var anchor_state: types.BeamState = undefined;
    try anchor_state.genGenesisState(allocator, genesis_config);
    defer anchor_state.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_dir);

    var db = try database.Db.open(allocator, logger_config.logger(.database), data_dir);
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

    var clock = try clockFactory.Clock.init(allocator, genesis_config.genesis_time, &loop);
    defer clock.deinit(allocator);

    var node: BeamNode = undefined;
    try node.init(allocator, .{
        .config = chain_config,
        .anchorState = &anchor_state,
        .backend = backend,
        .clock = &clock,
        .validator_ids = null,
        .nodeId = 0,
        .db = db,
        .logger_config = &logger_config,
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
