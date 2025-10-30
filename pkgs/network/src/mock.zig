const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("@zeam/types");
const xev = @import("xev");
const zeam_utils = @import("@zeam/utils");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;

pub const Mock = struct {
    allocator: Allocator,
    logger: zeam_utils.ModuleLogger,
    gossipHandler: interface.GenericGossipHandler,
    peerEventHandler: interface.PeerEventHandler,

    rpcCallbacks: std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback),
    peerLookup: std.StringHashMapUnmanaged(usize),
    ownerToPeer: std.AutoHashMapUnmanaged(usize, usize),
    peers: std.ArrayListUnmanaged(Peer),
    connectedPairs: std.AutoHashMapUnmanaged(PairKey, void),
    activeStreams: std.AutoHashMapUnmanaged(u64, *MockServerStream),
    timer: xev.Timer,
    nextPeerIndex: usize,
    nextRequestId: u64,

    const Self = @This();

    const PairKey = struct {
        a: usize,
        b: usize,

        fn from(a: usize, b: usize) PairKey {
            return if (a <= b) PairKey{ .a = a, .b = b } else PairKey{ .a = b, .b = a };
        }
    };

    const Peer = struct {
        owner_key: usize,
        peer_id: ?[]u8 = null,
        req_handler: ?interface.OnReqRespRequestCbHandler = null,
        event_handler: ?interface.OnPeerEventCbHandler = null,

        fn isReady(self: *const Peer) bool {
            return self.req_handler != null and self.event_handler != null and self.peer_id != null;
        }
    };

    const StreamError = error{StreamAlreadyFinished};

    const MockServerStream = struct {
        mock: *Mock,
        request_id: u64,
        method: interface.LeanSupportedProtocol,
        finished: bool = false,
    };

    const SyntheticResponseTask = struct {
        mock: *Mock,
        request_id: u64,
        method: interface.LeanSupportedProtocol,
        payload: union(enum) {
            success: interface.ReqRespResponse,
            failure: struct {
                code: u32,
                message: []const u8,
            },
        },

        fn init(mock: *Mock, request_id: u64, method: interface.LeanSupportedProtocol, request: *const interface.ReqRespRequest) !*SyntheticResponseTask {
            const task = try mock.allocator.create(SyntheticResponseTask);
            task.mock = mock;
            task.request_id = request_id;
            task.method = method;
            switch (request.*) {
                .status => |status_req| {
                    task.payload = .{ .success = interface.ReqRespResponse{ .status = status_req } };
                },
                .blocks_by_root => {
                    task.payload = .{ .failure = .{ .code = 1, .message = "mock peer has no block data" } };
                },
            }
            return task;
        }

        fn release(self: *SyntheticResponseTask) void {
            switch (self.payload) {
                .success => |*resp| resp.deinit(),
                .failure => {},
            }
            self.mock.allocator.destroy(self);
        }

        fn dispatch(self: *SyntheticResponseTask) void {
            switch (self.payload) {
                .success => |*resp| {
                    const mock = self.mock;
                    mock.notifySuccess(self.request_id, self.method, resp.*);
                    resp.deinit();
                    mock.notifyCompleted(self.request_id, self.method);
                },
                .failure => |err_payload| {
                    self.mock.notifyError(self.request_id, self.method, err_payload.code, err_payload.message);
                },
            }
            self.mock.allocator.destroy(self);
        }
    };

    fn syntheticResponseCallback(ud: ?*SyntheticResponseTask, _: *xev.Loop, completion: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch |err| {
            if (ud) |task| {
                const mock = task.mock;
                mock.logger.err("mock:: Synthetic response scheduling failed: {any}", .{err});
                task.release();
                mock.allocator.destroy(completion);
            }
            return .disarm;
        };

        if (ud) |task| {
            const allocator = task.mock.allocator;
            defer allocator.destroy(completion);
            task.dispatch();
        }

        return .disarm;
    }

    pub fn init(allocator: Allocator, loop: *xev.Loop, logger: zeam_utils.ModuleLogger) !Self {
        const gossip_handler = try interface.GenericGossipHandler.init(allocator, loop, 0, logger);
        errdefer gossip_handler.deinit();

        const peer_event_handler = try interface.PeerEventHandler.init(allocator, 0, logger);
        errdefer peer_event_handler.deinit();

        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        return Self{
            .allocator = allocator,
            .logger = logger,
            .gossipHandler = gossip_handler,
            .peerEventHandler = peer_event_handler,
            .rpcCallbacks = .empty,
            .peerLookup = .empty,
            .ownerToPeer = .empty,
            .peers = .empty,
            .connectedPairs = .empty,
            .activeStreams = .empty,
            .timer = timer,
            .nextPeerIndex = 0,
            .nextRequestId = 1,
        };
    }

    pub fn deinit(self: *Self) void {
        var rpc_it = self.rpcCallbacks.iterator();
        while (rpc_it.next()) |entry| {
            var callback = entry.value_ptr.*;
            callback.deinit();
        }
        self.rpcCallbacks.deinit(self.allocator);

        self.peerLookup.deinit(self.allocator);
        self.ownerToPeer.deinit(self.allocator);
        self.connectedPairs.deinit(self.allocator);
        var stream_it = self.activeStreams.iterator();
        while (stream_it.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.activeStreams.deinit(self.allocator);

        self.timer.deinit();

        for (self.peers.items) |peer| {
            if (peer.peer_id) |pid| {
                self.allocator.free(pid);
            }
        }
        self.peers.deinit(self.allocator);

        self.gossipHandler.deinit();
        self.peerEventHandler.deinit();
    }

    fn allocateRequestId(self: *Self) u64 {
        const id = self.nextRequestId;
        self.nextRequestId +%= 1;
        if (self.nextRequestId == 0) {
            self.nextRequestId = 1;
        }
        return if (id == 0) self.allocateRequestId() else id;
    }

    fn getOrCreatePeerEntry(self: *Self, owner_ptr: *anyopaque) !struct { idx: usize, peer: *Peer } {
        const owner_key = @intFromPtr(owner_ptr);
        if (self.ownerToPeer.get(owner_key)) |idx| {
            return .{ .idx = idx, .peer = &self.peers.items[idx] };
        }

        const peer = Peer{ .owner_key = owner_key };
        try self.peers.append(self.allocator, peer);
        const idx = self.peers.items.len - 1;
        try self.ownerToPeer.put(self.allocator, owner_key, idx);
        return .{ .idx = idx, .peer = &self.peers.items[idx] };
    }

    fn assignPeerId(self: *Self, idx: usize) !void {
        var peer = &self.peers.items[idx];
        if (peer.peer_id != null) return;

        const peer_id = try std.fmt.allocPrint(self.allocator, "mock-peer-{d}", .{self.nextPeerIndex});
        self.nextPeerIndex += 1;
        peer.peer_id = peer_id;
        try self.peerLookup.put(self.allocator, peer_id, idx);
    }

    fn ensurePeerEntry(self: *Self, peer_id: []const u8) !usize {
        if (self.peerLookup.get(peer_id)) |idx| {
            return idx;
        }

        const owned = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(owned);

        const peer = Peer{
            .owner_key = 0,
            .peer_id = owned,
            .req_handler = null,
            .event_handler = null,
        };

        try self.peers.append(self.allocator, peer);
        const idx = self.peers.items.len - 1;
        errdefer {
            const new_len = self.peers.items.len - 1;
            const removed = self.peers.items[new_len];
            self.peers.shrinkRetainingCapacity(new_len);
            if (removed.peer_id) |pid| {
                self.allocator.free(pid);
            }
        }

        try self.peerLookup.put(self.allocator, owned, idx);
        return idx;
    }

    fn handleSyntheticRequest(self: *Self, request_id: u64, method: interface.LeanSupportedProtocol, request: *const interface.ReqRespRequest) void {
        const task = SyntheticResponseTask.init(self, request_id, method, request) catch |err| {
            self.logger.err("mock:: Failed to prepare synthetic response request_id={d}: {any}", .{ request_id, err });
            self.notifyError(request_id, method, 1, "mock peer has no block data");
            return;
        };

        const completion = self.allocator.create(xev.Completion) catch |err| {
            self.logger.err("mock:: Failed to allocate completion for synthetic response request_id={d}: {any}", .{ request_id, err });
            task.dispatch();
            return;
        };

        self.timer.run(
            self.gossipHandler.loop,
            completion,
            1,
            SyntheticResponseTask,
            task,
            syntheticResponseCallback,
        );
    }

    fn peerIsReady(self: *Self, idx: usize) bool {
        return self.peers.items[idx].isReady();
    }

    fn connectPair(self: *Self, idx_a: usize, idx_b: usize) void {
        if (idx_a == idx_b) return;

        const key = PairKey.from(idx_a, idx_b);
        if (self.connectedPairs.contains(key)) {
            return;
        }

        self.connectedPairs.put(self.allocator, key, {}) catch |err| {
            self.logger.err("mock:: Failed to track connected pair ({d}, {d}): {any}", .{ idx_a, idx_b, err });
            return;
        };

        const peer_a = &self.peers.items[idx_a];
        const peer_b = &self.peers.items[idx_b];

        const peer_a_id = peer_a.peer_id.?;
        const peer_b_id = peer_b.peer_id.?;

        peer_a.event_handler.?.onPeerConnected(peer_b_id) catch |e| {
            self.logger.err("mock:: Failed delivering onPeerConnected to peer {s}: {any}", .{ peer_b_id, e });
        };

        peer_b.event_handler.?.onPeerConnected(peer_a_id) catch |e| {
            self.logger.err("mock:: Failed delivering onPeerConnected to peer {s}: {any}", .{ peer_a_id, e });
        };
    }

    fn maybeConnectPeers(self: *Self, idx: usize) void {
        if (!self.peerIsReady(idx)) return;

        const peers_len = self.peers.items.len;
        var other_idx: usize = 0;
        while (other_idx < peers_len) : (other_idx += 1) {
            if (other_idx == idx) continue;
            if (!self.peerIsReady(other_idx)) continue;
            self.connectPair(idx, other_idx);
        }
    }

    fn cloneResponse(self: *Self, response: *const interface.ReqRespResponse) !interface.ReqRespResponse {
        return switch (response.*) {
            .status => |status_resp| interface.ReqRespResponse{ .status = status_resp },
            .blocks_by_root => |block_resp| blk: {
                var cloned_block: types.SignedBlockWithAttestation = undefined;
                try types.sszClone(self.allocator, types.SignedBlockWithAttestation, block_resp, &cloned_block);
                break :blk interface.ReqRespResponse{ .blocks_by_root = cloned_block };
            },
        };
    }

    fn cloneRequest(self: *Self, request: *const interface.ReqRespRequest) !interface.ReqRespRequest {
        return switch (request.*) {
            .status => |status_req| interface.ReqRespRequest{ .status = status_req },
            .blocks_by_root => |block_req| blk: {
                var cloned_request: types.BlockByRootRequest = undefined;
                try types.sszClone(self.allocator, types.BlockByRootRequest, block_req, &cloned_request);
                break :blk interface.ReqRespRequest{ .blocks_by_root = cloned_request };
            },
        };
    }

    fn notifySuccess(self: *Self, request_id: u64, method: interface.LeanSupportedProtocol, response: interface.ReqRespResponse) void {
        var event = interface.ReqRespResponseEvent.initSuccess(request_id, method, response);
        defer event.deinit(self.allocator);

        if (self.rpcCallbacks.getPtr(request_id)) |callback| {
            callback.*.notify(&event) catch |notify_err| {
                self.logger.err("mock:: Failed delivering RPC success callback request_id={d}: {any}", .{ request_id, notify_err });
            };
        }
    }

    fn notifyError(self: *Self, request_id: u64, method: interface.LeanSupportedProtocol, code: u32, message: []const u8) void {
        const owned = self.allocator.dupe(u8, message) catch |alloc_err| {
            self.logger.err("mock:: Failed to allocate RPC error message for request_id={d}: {any}", .{ request_id, alloc_err });
            return;
        };

        var event = interface.ReqRespResponseEvent.initError(request_id, method, .{
            .code = code,
            .message = owned,
        });
        defer event.deinit(self.allocator);

        if (self.rpcCallbacks.fetchRemove(request_id)) |entry| {
            var callback = entry.value;
            callback.notify(&event) catch |notify_err| {
                self.logger.err("mock:: Failed delivering RPC error callback request_id={d}: {any}", .{ request_id, notify_err });
            };
            callback.deinit();
        } else {
            self.logger.warn("mock:: Dropping RPC error for unknown request_id={d}", .{request_id});
        }
    }

    fn notifyCompleted(self: *Self, request_id: u64, method: interface.LeanSupportedProtocol) void {
        var event = interface.ReqRespResponseEvent.initCompleted(request_id, method);
        defer event.deinit(self.allocator);

        if (self.rpcCallbacks.fetchRemove(request_id)) |entry| {
            var callback = entry.value;
            callback.notify(&event) catch |notify_err| {
                self.logger.err("mock:: Failed delivering RPC completion callback request_id={d}: {any}", .{ request_id, notify_err });
            };
            callback.deinit();
        }
    }

    fn serverStreamSendResponse(ptr: *anyopaque, response: *const interface.ReqRespResponse) anyerror!void {
        const ctx: *MockServerStream = @ptrCast(@alignCast(ptr));
        if (ctx.finished) {
            return StreamError.StreamAlreadyFinished;
        }

        const cloned = try ctx.mock.cloneResponse(response);
        ctx.mock.notifySuccess(ctx.request_id, ctx.method, cloned);
    }

    fn serverStreamSendError(ptr: *anyopaque, code: u32, message: []const u8) anyerror!void {
        const ctx: *MockServerStream = @ptrCast(@alignCast(ptr));
        if (ctx.finished) {
            return StreamError.StreamAlreadyFinished;
        }
        ctx.finished = true;
        ctx.mock.finalizeServerStream(ctx);
        ctx.mock.notifyError(ctx.request_id, ctx.method, code, message);
    }

    fn serverStreamFinish(ptr: *anyopaque) anyerror!void {
        const ctx: *MockServerStream = @ptrCast(@alignCast(ptr));
        if (ctx.finished) return;
        ctx.finished = true;
        ctx.mock.finalizeServerStream(ctx);
        ctx.mock.notifyCompleted(ctx.request_id, ctx.method);
    }

    fn serverStreamIsFinished(ptr: *anyopaque) bool {
        const ctx: *MockServerStream = @ptrCast(@alignCast(ptr));
        return ctx.finished;
    }

    fn removeActiveStream(self: *Self, request_id: u64) void {
        if (self.activeStreams.fetchRemove(request_id)) |entry| {
            self.allocator.destroy(entry.value);
        }
    }

    fn finalizeServerStream(self: *Self, ctx: *MockServerStream) void {
        self.removeActiveStream(ctx.request_id);
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        // TODO: prevent from publishing to self handler
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, true);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.subscribe(topics, handler);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, true);
    }

    pub fn sendRequest(ptr: *anyopaque, peer_id: []const u8, req: *const interface.ReqRespRequest, callback: ?interface.OnReqRespResponseCbHandler) anyerror!u64 {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const target_idx = try self.ensurePeerEntry(peer_id);
        const target_peer = &self.peers.items[target_idx];

        var request_copy = try self.cloneRequest(req);
        defer request_copy.deinit();

        const method = std.meta.activeTag(request_copy);
        const request_id = self.allocateRequestId();

        errdefer {
            if (self.rpcCallbacks.fetchRemove(request_id)) |entry| {
                var cb = entry.value;
                cb.deinit();
            }
        }

        const callback_entry = interface.ReqRespRequestCallback.init(method, self.allocator, callback);
        try self.rpcCallbacks.put(self.allocator, request_id, callback_entry);

        if (target_peer.req_handler) |handler| {
            const stream_ctx = try self.allocator.create(MockServerStream);
            stream_ctx.* = .{
                .mock = self,
                .request_id = request_id,
                .method = method,
            };

            var stream_registered = false;
            errdefer if (!stream_registered) self.allocator.destroy(stream_ctx);

            try self.activeStreams.put(self.allocator, request_id, stream_ctx);
            stream_registered = true;

            const stream_iface = interface.ReqRespServerStream{
                .ptr = stream_ctx,
                .sendResponseFn = serverStreamSendResponse,
                .sendErrorFn = serverStreamSendError,
                .finishFn = serverStreamFinish,
                .isFinishedFn = serverStreamIsFinished,
            };

            handler.onReqRespRequest(&request_copy, stream_iface) catch |err| {
                self.removeActiveStream(request_id);
                if (self.rpcCallbacks.fetchRemove(request_id)) |entry| {
                    var cb = entry.value;
                    cb.deinit();
                }
                return err;
            };
        } else {
            self.handleSyntheticRequest(request_id, method, &request_copy);
        }

        return request_id;
    }

    pub fn onReqRespRequest(ptr: *anyopaque, data: *interface.ReqRespRequest, stream: interface.ReqRespServerStream) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        for (self.peers.items) |peer| {
            if (peer.req_handler) |handler| {
                try handler.onReqRespRequest(data, stream);
                return;
            }
        }

        return error.NoHandlerSubscribed;
    }

    pub fn subscribeReqResp(ptr: *anyopaque, handler: interface.OnReqRespRequestCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const entry = try self.getOrCreatePeerEntry(handler.ptr);
        try self.assignPeerId(entry.idx);
        entry.peer.req_handler = handler;
        self.maybeConnectPeers(entry.idx);
    }

    pub fn subscribePeerEvents(ptr: *anyopaque, handler: interface.OnPeerEventCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        try self.peerEventHandler.subscribe(handler);

        const entry = try self.getOrCreatePeerEntry(handler.ptr);
        try self.assignPeerId(entry.idx);
        entry.peer.event_handler = handler;
        self.maybeConnectPeers(entry.idx);
    }

    pub fn getNetworkInterface(self: *Self) NetworkInterface {
        return .{
            .gossip = .{
                .ptr = self,
                .publishFn = publish,
                .subscribeFn = subscribe,
                .onGossipFn = onGossip,
            },
            .reqresp = .{
                .ptr = self,
                .sendRequestFn = sendRequest,
                .onReqRespRequestFn = onReqRespRequest,
                .subscribeFn = subscribeReqResp,
            },
            .peers = .{
                .ptr = self,
                .subscribeFn = subscribePeerEvents,
            },
        };
    }
};

test "Mock messaging across two subscribers" {
    const TestSubscriber = struct {
        calls: u32 = 0,
        received_message: ?interface.GossipMessage = null,

        fn onGossip(ptr: *anyopaque, message: *const interface.GossipMessage) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            self.received_message = message.*;
        }

        fn getCallbackHandler(self: *@This()) interface.OnGossipCbHandler {
            return .{
                .ptr = self,
                .onGossipCb = onGossip,
            };
        }
    };
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.mock);
    var mock = try Mock.init(allocator, &loop, logger);

    // Create test subscribers with embedded data
    var subscriber1 = TestSubscriber{};
    var subscriber2 = TestSubscriber{};

    // Both subscribers subscribe to the same block topic using the complete network interface
    var topics = [_]interface.GossipTopic{.block};
    const network = mock.getNetworkInterface();
    try network.gossip.subscribe(&topics, subscriber1.getCallbackHandler());
    try network.gossip.subscribe(&topics, subscriber2.getCallbackHandler());

    // Create a simple block message
    var attestations = try types.Attestations.init(allocator);

    const block_message = try allocator.create(interface.GossipMessage);
    defer allocator.destroy(block_message);
    block_message.* = .{ .block = .{
        .message = .{
            .block = .{
                .slot = 1,
                .proposer_index = 0,
                .parent_root = [_]u8{1} ** 32,
                .state_root = [_]u8{2} ** 32,
                .body = .{
                    .attestations = attestations,
                },
            },
            .proposer_attestation = .{
                .validator_id = 0,
                .data = .{
                    .slot = 1,
                    .head = .{
                        .slot = 1,
                        .root = [_]u8{1} ** 32,
                    },
                    .source = .{
                        .slot = 0,
                        .root = [_]u8{0} ** 32,
                    },
                    .target = .{
                        .slot = 1,
                        .root = [_]u8{1} ** 32,
                    },
                },
            },
        },
        .signature = try types.createBlockSignatures(allocator, attestations.len()),
    } };

    // Publish the message using the network interface - both subscribers should receive it
    try network.gossip.publish(block_message);

    // Run the event loop to process scheduled callbacks
    try loop.run(.until_done);

    // Verify both subscribers received the message
    try std.testing.expect(subscriber1.calls == 1);
    try std.testing.expect(subscriber2.calls == 1);

    // Verify both subscribers received the same message content
    try std.testing.expect(subscriber1.received_message != null);
    try std.testing.expect(subscriber2.received_message != null);

    const received1 = subscriber1.received_message.?;
    const received2 = subscriber2.received_message.?;

    // Verify both received block messages
    try std.testing.expect(received1 == .block);
    try std.testing.expect(received2 == .block);

    // Verify the block content is identical
    try std.testing.expect(std.mem.eql(u8, &received1.block.message.block.parent_root, &received2.block.message.block.parent_root));
    try std.testing.expect(std.mem.eql(u8, &received1.block.message.block.state_root, &received2.block.message.block.state_root));
    try std.testing.expect(received1.block.message.block.slot == received2.block.message.block.slot);
    try std.testing.expect(received1.block.message.block.proposer_index == received2.block.message.block.proposer_index);
}

test "Mock status RPC between peers" {
    const TestPeer = struct {
        const Self = @This();
        allocator: Allocator,
        status: types.Status,
        connections: std.ArrayListUnmanaged([]u8) = .empty,
        received_status: ?types.Status = null,
        completed: bool = false,
        failures: u32 = 0,

        fn init(allocator: Allocator, status: types.Status) Self {
            return Self{ .allocator = allocator, .status = status };
        }

        fn deinit(self: *Self) void {
            for (self.connections.items) |conn| {
                self.allocator.free(conn);
            }
            self.connections.deinit(self.allocator);
        }

        fn onPeerConnected(ptr: *anyopaque, peer_id: []const u8) !void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            const owned = try self.allocator.dupe(u8, peer_id);
            try self.connections.append(self.allocator, owned);
        }

        fn onPeerDisconnected(ptr: *anyopaque, peer_id: []const u8) !void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            var idx: usize = 0;
            while (idx < self.connections.items.len) : (idx += 1) {
                if (std.mem.eql(u8, self.connections.items[idx], peer_id)) {
                    const removed = self.connections.swapRemove(idx);
                    self.allocator.free(removed);
                    break;
                }
            }
        }

        fn onReqRespRequest(ptr: *anyopaque, request: *const interface.ReqRespRequest, stream: interface.ReqRespServerStream) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            switch (request.*) {
                .status => {
                    var response = interface.ReqRespResponse{ .status = self.status };
                    try stream.sendResponse(&response);
                    try stream.finish();
                },
                .blocks_by_root => {
                    try stream.sendError(1, "unsupported");
                },
            }
        }

        fn onReqRespResponse(ptr: *anyopaque, event: *const interface.ReqRespResponseEvent) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            switch (event.payload) {
                .success => |resp| switch (resp) {
                    .status => |status_resp| self.received_status = status_resp,
                    .blocks_by_root => {
                        self.failures += 1;
                    },
                },
                .failure => {
                    self.failures += 1;
                },
                .completed => {
                    self.completed = true;
                },
            }
        }

        fn getEventHandler(self: *Self) interface.OnPeerEventCbHandler {
            return .{
                .ptr = self,
                .onPeerConnectedCb = onPeerConnected,
                .onPeerDisconnectedCb = onPeerDisconnected,
            };
        }

        fn getReqHandler(self: *Self) interface.OnReqRespRequestCbHandler {
            return .{
                .ptr = self,
                .onReqRespRequestCb = onReqRespRequest,
            };
        }

        fn getResponseHandler(self: *Self) interface.OnReqRespResponseCbHandler {
            return .{
                .ptr = self,
                .onReqRespResponseCb = onReqRespResponse,
            };
        }
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var logger_config = zeam_utils.getTestLoggerConfig();
    const logger = logger_config.logger(.mock);

    var mock = try Mock.init(allocator, &loop, logger);
    defer mock.deinit();

    const backend_a = mock.getNetworkInterface();
    const backend_b = mock.getNetworkInterface();

    const status_a = types.Status{
        .finalized_root = [_]u8{0x01} ** 32,
        .finalized_slot = 10,
        .head_root = [_]u8{0x02} ** 32,
        .head_slot = 20,
    };
    const status_b = types.Status{
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_slot = 30,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 40,
    };

    var peer_a = TestPeer.init(allocator, status_a);
    defer peer_a.deinit();
    var peer_b = TestPeer.init(allocator, status_b);
    defer peer_b.deinit();

    try backend_a.peers.subscribe(peer_a.getEventHandler());
    try backend_b.peers.subscribe(peer_b.getEventHandler());

    try backend_a.reqresp.subscribe(peer_a.getReqHandler());
    try backend_b.reqresp.subscribe(peer_b.getReqHandler());

    try std.testing.expectEqual(@as(usize, 1), peer_a.connections.items.len);
    try std.testing.expectEqual(@as(usize, 1), peer_b.connections.items.len);

    const remote_id_a = peer_a.connections.items[0];
    const response_handler_a = peer_a.getResponseHandler();
    var request = interface.ReqRespRequest{ .status = status_a };
    const request_id = try backend_a.reqresp.sendRequest(remote_id_a, &request, response_handler_a);
    request.deinit();

    try std.testing.expect(request_id != 0);
    try std.testing.expect(peer_a.received_status != null);
    const received = peer_a.received_status.?;
    try std.testing.expect(std.mem.eql(u8, &received.finalized_root, &status_b.finalized_root));
    try std.testing.expectEqual(status_b.finalized_slot, received.finalized_slot);
    try std.testing.expect(std.mem.eql(u8, &received.head_root, &status_b.head_root));
    try std.testing.expectEqual(status_b.head_slot, received.head_slot);
    try std.testing.expect(peer_a.completed);
    try std.testing.expectEqual(@as(u32, 0), peer_a.failures);
}
