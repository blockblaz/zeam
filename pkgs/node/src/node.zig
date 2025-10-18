const std = @import("std");
const Allocator = std.mem.Allocator;

pub const database = @import("@zeam/database");
const params = @import("@zeam/params");
const types = @import("@zeam/types");
const configs = @import("@zeam/configs");
const networks = @import("@zeam/network");
const zeam_utils = @import("@zeam/utils");
const ssz = @import("ssz");

const utils = @import("./utils.zig");
const OnIntervalCbWrapper = utils.OnIntervalCbWrapper;

pub const chainFactory = @import("./chain.zig");
pub const clockFactory = @import("./clock.zig");
pub const networkFactory = @import("./network.zig");
pub const validators = @import("./validator.zig");
const constants = @import("./constants.zig");

const NodeOpts = struct {
    config: configs.ChainConfig,
    anchorState: *types.BeamState,
    backend: networks.NetworkInterface,
    clock: *clockFactory.Clock,
    validator_ids: ?[]usize = null,
    nodeId: u32 = 0,
    db: database.Db,
    logger_config: *zeam_utils.ZeamLoggerConfig,
};

pub const PeerInfo = struct {
    peer_id: []const u8,
    connected_at: i64, // timestamp in seconds
    latest_status: ?types.Status = null,
};

const StatusRequestContext = struct {
    peer_id: []const u8,

    fn deinit(self: *StatusRequestContext, allocator: Allocator) void {
        allocator.free(self.peer_id);
    }
};

const BlockByRootContext = struct {
    peer_id: []const u8,
    requested_roots: []types.Root,

    fn deinit(self: *BlockByRootContext, allocator: Allocator) void {
        allocator.free(self.peer_id);
        allocator.free(self.requested_roots);
    }
};

const PendingRPC = union(enum) {
    status: StatusRequestContext,
    block_by_root: BlockByRootContext,

    fn deinit(self: *PendingRPC, allocator: Allocator) void {
        switch (self.*) {
            .status => |*ctx| ctx.deinit(allocator),
            .block_by_root => |*ctx| ctx.deinit(allocator),
        }
    }
};

pub const BeamNode = struct {
    allocator: Allocator,
    clock: *clockFactory.Clock,
    chain: *chainFactory.BeamChain,
    network: networkFactory.Network,
    validator: ?validators.BeamValidator = null,
    nodeId: u32,
    logger: zeam_utils.ModuleLogger,
    connected_peers: *std.StringHashMap(PeerInfo),
    pending_rpc_requests: std.AutoHashMap(u64, PendingRPC),
    pending_block_roots: std.AutoHashMap(types.Root, void),

    const Self = @This();
    pub fn init(self: *Self, allocator: Allocator, opts: NodeOpts) !void {
        var validator: ?validators.BeamValidator = null;

        // Allocate connected_peers on the heap
        const connected_peers = try allocator.create(std.StringHashMap(PeerInfo));
        connected_peers.* = std.StringHashMap(PeerInfo).init(allocator);

        const chain = try allocator.create(chainFactory.BeamChain);
        const network = networkFactory.Network.init(opts.backend);

        chain.* = try chainFactory.BeamChain.init(
            allocator,
            chainFactory.ChainOpts{
                .config = opts.config,
                .anchorState = opts.anchorState,
                .nodeId = opts.nodeId,
                .db = opts.db,
                .logger_config = opts.logger_config,
            },
            connected_peers,
        );
        if (opts.validator_ids) |ids| {
            validator = validators.BeamValidator.init(allocator, opts.config, .{ .ids = ids, .chain = chain, .network = network, .logger = opts.logger_config.logger(.validator) });
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
            .connected_peers = connected_peers,
            .pending_rpc_requests = std.AutoHashMap(u64, PendingRPC).init(allocator),
            .pending_block_roots = std.AutoHashMap(types.Root, void).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self.chain);

        var rpc_it = self.pending_rpc_requests.iterator();
        while (rpc_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_rpc_requests.deinit();

        self.pending_block_roots.deinit();

        // Clean up peer info
        var iter = self.connected_peers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.peer_id);
        }
        self.connected_peers.deinit();
        self.allocator.destroy(self.connected_peers);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const networks.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        switch (data.*) {
            .block => |signed_block| {
                const parent_root = signed_block.message.parent_root;
                if (!self.chain.forkChoice.hasBlock(parent_root)) {
                    self.requestBlocksByRoot(&[_]types.Root{parent_root});
                }

                var block_root: types.Root = undefined;
                if (ssz.hashTreeRoot(types.BeamBlock, signed_block.message, &block_root, self.allocator)) |_| {
                    _ = self.pending_block_roots.remove(block_root);
                } else |err| {
                    self.logger.warn("Failed to compute block root for incoming gossip block: {any}", .{err});
                }
            },
            else => {},
        }

        try self.chain.onGossip(data);
    }

    fn getReqRespResponseHandler(self: *Self) networks.OnReqRespResponseCbHandler {
        return .{
            .ptr = self,
            .onReqRespResponseCb = onReqRespResponse,
        };
    }

    fn sendStatusToPeer(self: *Self, peer_id: []const u8) void {
        const peer_copy = self.allocator.dupe(u8, peer_id) catch |err| {
            self.logger.warn("Failed to duplicate peer id for status request: {any}", .{err});
            return;
        };

        var pending = PendingRPC{ .status = .{ .peer_id = peer_copy } };
        const handler = self.getReqRespResponseHandler();
        const status = self.chain.getStatus();

        const request_id = self.network.sendStatus(peer_id, status, handler) catch |err| {
            self.logger.warn("Failed to send status request to peer {s}: {any}", .{ peer_id, err });
            pending.deinit(self.allocator);
            return;
        };

        self.pending_rpc_requests.put(request_id, pending) catch |err| {
            self.logger.warn("Failed to track status request {d} for peer {s}: {any}", .{ request_id, peer_id, err });
            pending.deinit(self.allocator);
            return;
        };

        self.logger.info(
            "Sent status request to peer {s}: request_id={d}, head_slot={d}, finalized_slot={d}",
            .{ peer_id, request_id, status.head_slot, status.finalized_slot },
        );
    }

    fn selectPeerForRequest(self: *Self) ?[]const u8 {
        var it = self.connected_peers.iterator();
        if (it.next()) |entry| {
            return entry.value_ptr.peer_id;
        }
        return null;
    }

    fn requestBlocksByRoot(self: *Self, roots: []const types.Root) void {
        if (roots.len == 0) return;

        var requires_request = false;
        for (roots) |root| {
            if (self.pending_block_roots.get(root) == null) {
                requires_request = true;
                break;
            }
        }
        if (!requires_request) return;

        const peer = self.selectPeerForRequest() orelse {
            self.logger.warn("No peers available to request {d} block(s) by root", .{roots.len});
            return;
        };

        const peer_copy = self.allocator.dupe(u8, peer) catch |err| {
            self.logger.warn("Failed to duplicate peer id for blocks-by-root request: {any}", .{err});
            return;
        };

        const roots_copy = self.allocator.alloc(types.Root, roots.len) catch |err| {
            self.logger.warn("Failed to allocate root buffer for RPC request: {any}", .{err});
            self.allocator.free(peer_copy);
            return;
        };
        std.mem.copyForwards(types.Root, roots_copy, roots);

        const handler = self.getReqRespResponseHandler();
        const request_id = self.network.requestBlocksByRoot(self.allocator, peer, roots, handler) catch |err| {
            self.logger.warn("Failed to send blocks-by-root request to peer {s}: {any}", .{ peer, err });
            self.allocator.free(roots_copy);
            self.allocator.free(peer_copy);
            return;
        };

        var pending = PendingRPC{ .block_by_root = .{
            .peer_id = peer_copy,
            .requested_roots = roots_copy,
        } };

        self.pending_rpc_requests.put(request_id, pending) catch |err| {
            self.logger.warn(
                "Failed to track blocks-by-root request {d} for peer {s}: {any}",
                .{ request_id, peer, err },
            );
            pending.deinit(self.allocator);
            return;
        };

        for (roots) |root| {
            if (self.pending_block_roots.get(root) != null) continue;
            self.pending_block_roots.put(root, {}) catch |err| {
                self.logger.warn(
                    "Failed to track pending block root 0x{s}: {any}",
                    .{ std.fmt.fmtSliceHexLower(root[0..]), err },
                );
                self.finalizePendingRequest(request_id);
                return;
            };
        }

        self.logger.debug(
            "Requested {d} block(s) by root from peer {s}, request_id={d}",
            .{ roots.len, peer, request_id },
        );
    }

    fn processBlockByRootChunk(self: *Self, block_ctx: *const BlockByRootContext, block: *const types.SignedBeamBlock) void {
        var block_root: types.Root = undefined;
        if (ssz.hashTreeRoot(types.BeamBlock, block.message, &block_root, self.allocator)) |_| {
            const removed = self.pending_block_roots.remove(block_root);
            if (!removed) {
                self.logger.warn(
                    "Received unexpected block root 0x{s} from peer {s}",
                    .{ std.fmt.fmtSliceHexLower(block_root[0..]), block_ctx.peer_id },
                );
            }

            self.chain.onBlock(block.*, .{}) catch |err| {
                self.logger.warn(
                    "Failed to import block fetched via RPC 0x{s} from peer {s}: {any}",
                    .{ std.fmt.fmtSliceHexLower(block_root[0..]), block_ctx.peer_id, err },
                );
            };
        } else |err| {
            self.logger.warn("Failed to compute block root from RPC response: {any}", .{err});
        }
    }

    fn handleReqRespResponse(self: *Self, event: *const networks.ReqRespResponseEvent) void {
        const request_id = event.request_id;
        const ctx_ptr = self.pending_rpc_requests.getPtr(request_id) orelse {
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
                            if (self.connected_peers.getPtr(status_ctx.peer_id)) |peer_info| {
                                peer_info.latest_status = status_resp;
                            }
                        },
                        else => {
                            self.logger.warn("Status response did not match tracked request_id={d}", .{request_id});
                        },
                    }
                },
                .block_by_root => |block_resp| {
                    switch (ctx_ptr.*) {
                        .block_by_root => |*block_ctx| {
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
                    .block_by_root => |block_ctx| {
                        self.logger.warn(
                            "Blocks-by-root request to peer {s} failed ({d}): {s}",
                            .{ block_ctx.peer_id, err_payload.code, err_payload.message },
                        );
                    },
                }
                self.finalizePendingRequest(request_id);
            },
            .completed => {
                self.finalizePendingRequest(request_id);
            },
        }
    }

    fn finalizePendingRequest(self: *Self, request_id: u64) void {
        if (self.pending_rpc_requests.fetchRemove(request_id)) |entry| {
            var ctx = entry.value;
            switch (ctx) {
                .block_by_root => |block_ctx| {
                    for (block_ctx.requested_roots) |root| {
                        _ = self.pending_block_roots.remove(root);
                    }
                },
                .status => {},
            }
            ctx.deinit(self.allocator);
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
            .block_by_root => |request| {
                const roots = request.roots.constSlice();

                self.logger.debug(
                    "node-{d}:: Handling block_by_root request for {d} roots",
                    .{ self.nodeId, roots.len },
                );

                for (roots) |root| {
                    if (self.chain.db.loadBlock(database.DbBlocksNamespace, root)) |signed_block_value| {
                        var signed_block = signed_block_value;
                        defer signed_block.deinit();

                        var response = networks.ReqRespResponse{ .block_by_root = undefined };
                        try types.sszClone(self.allocator, types.SignedBeamBlock, signed_block, &response.block_by_root);
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

    pub fn onPeerConnected(ptr: *anyopaque, peer_id: []const u8) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const owned_key = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_key);

        const owned_peer_id = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned_peer_id);

        const peer_info = PeerInfo{
            .peer_id = owned_peer_id,
            .connected_at = std.time.timestamp(),
        };

        try self.connected_peers.put(owned_key, peer_info);
        self.logger.info("Peer connected: {s}, total peers: {d}", .{ peer_id, self.connected_peers.count() });

        self.sendStatusToPeer(peer_id);
    }

    pub fn onPeerDisconnected(ptr: *anyopaque, peer_id: []const u8) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (self.connected_peers.fetchRemove(peer_id)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value.peer_id);
            self.logger.info("Peer disconnected: {s}, total peers: {d}", .{ peer_id, self.connected_peers.count() });
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

        // till its time to attest atleast for first time don't run onInterval,
        // just print chain status i.e avoid zero slot zero interval block production
        if (itime_intervals < 1) {
            const islot = @divFloor(itime_intervals, constants.INTERVALS_PER_SLOT);
            const interval = @mod(itime_intervals, constants.INTERVALS_PER_SLOT);

            if (interval == 1) {
                self.chain.printSlot(islot, self.connected_peers.count());
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
            const validator_output = validator.onInterval(interval) catch |e| {
                self.logger.err("Error ticking validator to time(intervals)={d} err={any}", .{ interval, e });
                return e;
            };

            if (validator_output) |output| {
                var mutable_output = output;
                defer mutable_output.deinit();
                for (mutable_output.gossip_messages.items) |gossip_msg| {

                    // Process based on message type
                    switch (gossip_msg) {
                        .block => |signed_block| {
                            self.publishBlock(signed_block) catch |e| {
                                self.logger.err("Error publishing block from validator: err={any}", .{e});
                                return e;
                            };
                        },
                        .vote => |signed_vote| {
                            self.publishVote(signed_vote) catch |e| {
                                self.logger.err("Error publishing vote from validator: err={any}", .{e});
                                return e;
                            };
                        },
                    }
                }
            }
        }
    }

    pub fn publishBlock(self: *Self, signed_block: types.SignedBeamBlock) !void {
        // 1. publish gossip message
        const gossip_msg = networks.GossipMessage{ .block = signed_block };
        try self.network.publish(&gossip_msg);

        self.logger.info("Published block to network: slot={d} proposer={d}", .{
            signed_block.message.slot,
            signed_block.message.proposer_index,
        });

        // 2. Process locally through chain
        var block_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, signed_block.message, &block_root, self.allocator);

        // check if the block has not already been received through the network
        const hasBlock = self.chain.forkChoice.hasBlock(block_root);
        if (!hasBlock) {
            try self.chain.onBlock(signed_block, .{
                .postState = self.chain.states.get(block_root),
                .blockRoot = block_root,
            });
        } else {
            self.logger.debug("Skip adding produced block to chain as already present: slot={d} proposer={d}", .{
                signed_block.message.slot,
                signed_block.message.proposer_index,
            });
        }
    }

    pub fn publishVote(self: *Self, signed_vote: types.SignedVote) !void {
        // 1. publish gossip message
        const gossip_msg = networks.GossipMessage{ .vote = signed_vote };
        try self.network.publish(&gossip_msg);

        self.logger.info("Published vote to network: slot={d} validator={d}", .{
            signed_vote.message.slot,
            signed_vote.validator_id,
        });

        // 2. Process locally through chain
        // no need to see if we produced this vote as everything is trusted in-process lifecycle
        // validate when validator is separated out
        return self.chain.onAttestation(signed_vote);
    }

    pub fn run(self: *Self) !void {
        const handler = try self.getOnGossipCbHandler();
        var topics = [_]networks.GossipTopic{ .block, .vote };
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

    const genesis_config = types.GenesisSpec{
        .genesis_time = 0,
        .num_validators = 4,
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
    try std.testing.expectEqual(@as(usize, 0), node.connected_peers.count());

    // Simulate peer connections by manually triggering the event handler
    const peer1_id = "PEE_POW_1";
    const peer2_id = "PEE_POW_2";
    const peer3_id = "PEE_POW_3";

    // Connect peer 1
    try mock.peerEventHandler.onPeerConnected(peer1_id);
    try std.testing.expectEqual(@as(usize, 1), node.connected_peers.count());

    // Connect peer 2
    try mock.peerEventHandler.onPeerConnected(peer2_id);
    try std.testing.expectEqual(@as(usize, 2), node.connected_peers.count());

    // Connect peer 3
    try mock.peerEventHandler.onPeerConnected(peer3_id);
    try std.testing.expectEqual(@as(usize, 3), node.connected_peers.count());

    // Verify peer 1 exists
    try std.testing.expect(node.connected_peers.contains(peer1_id));

    // Disconnect peer 2
    try mock.peerEventHandler.onPeerDisconnected(peer2_id);
    try std.testing.expectEqual(@as(usize, 2), node.connected_peers.count());
    try std.testing.expect(!node.connected_peers.contains(peer2_id));

    // Disconnect peer 1
    try mock.peerEventHandler.onPeerDisconnected(peer1_id);
    try std.testing.expectEqual(@as(usize, 1), node.connected_peers.count());
    try std.testing.expect(!node.connected_peers.contains(peer1_id));

    // Verify peer 3 is still connected
    try std.testing.expect(node.connected_peers.contains(peer3_id));

    // Disconnect peer 3
    try mock.peerEventHandler.onPeerDisconnected(peer3_id);
    try std.testing.expectEqual(@as(usize, 0), node.connected_peers.count());
}
