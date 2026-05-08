const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

const types = @import("@zeam/types");
const ssz = @import("ssz");
const xev = @import("xev").Dynamic;
const zeam_utils = @import("@zeam/utils");
const consensus_params = @import("@zeam/params");

const node_registry = @import("./node_registry.zig");
const NodeNameRegistry = node_registry.NodeNameRegistry;

// Connection direction for peer events
pub const PeerDirection = enum(u32) {
    inbound = 0,
    outbound = 1,
    unknown = 2,
};

// Connection result for connection events
pub const ConnectionResult = enum(u32) {
    success = 0,
    timeout = 1,
    error_ = 2, // 'error' is reserved in Zig
};

// Disconnection reason for disconnection events
pub const DisconnectionReason = enum(u32) {
    timeout = 0,
    remote_close = 1,
    local_close = 2,
    error_ = 3,
};

const topic_prefix = "leanconsensus";
const lean_blocks_by_root_protocol = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
const lean_blocks_by_range_protocol = "/leanconsensus/req/blocks_by_range/1/ssz_snappy";
const lean_status_protocol = "/leanconsensus/req/status/1/ssz_snappy";

fn unionPayloadType(comptime UnionType: type, comptime tag: anytype) type {
    return @FieldType(UnionType, @tagName(tag));
}

fn freeJsonValue(val: *json.Value, allocator: Allocator) void {
    switch (val.*) {
        .object => |*o| {
            var it = o.iterator();
            while (it.next()) |entry| {
                freeJsonValue(&entry.value_ptr.*, allocator);
            }
            o.deinit(allocator);
        },
        .array => |*a| {
            for (a.items) |*item| {
                freeJsonValue(item, allocator);
            }
            a.deinit();
        },
        .string => |s| allocator.free(s),
        else => {},
    }
}

pub const GossipSub = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    publishFn: *const fn (ptr: *anyopaque, obj: *const GossipMessage) anyerror!bool,
    subscribeFn: *const fn (ptr: *anyopaque, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void,
    onGossipFn: *const fn (ptr: *anyopaque, data: *GossipMessage, sender_peer_id: []const u8) anyerror!void,

    pub fn format(self: GossipSub, writer: anytype) !void {
        _ = self;
        try writer.writeAll("GossipSub");
    }

    pub fn subscribe(self: GossipSub, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, topics, handler);
    }

    /// Publish a gossip message. Returns `true` if the message was successfully
    /// handed off to the underlying transport (and is therefore expected to
    /// reach the network), `false` if the publish was dropped (e.g. backend
    /// command channel full, see issue #808). Callers should not log the
    /// publish as successful when this returns `false`.
    pub fn publish(self: GossipSub, obj: *const GossipMessage) anyerror!bool {
        return self.publishFn(self.ptr, obj);
    }
};

pub const ReqResp = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    sendRequestFn: *const fn (ptr: *anyopaque, peer_id: []const u8, req: *const ReqRespRequest, callback: ?OnReqRespResponseCbHandler) anyerror!u64,
    onReqRespRequestFn: *const fn (ptr: *anyopaque, data: *ReqRespRequest, stream: ReqRespServerStream) anyerror!void,
    subscribeFn: *const fn (ptr: *anyopaque, handler: OnReqRespRequestCbHandler) anyerror!void,

    pub fn subscribe(self: ReqResp, handler: OnReqRespRequestCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, handler);
    }

    pub fn sendRequest(self: ReqResp, peer_id: []const u8, req: *const ReqRespRequest, callback: ?OnReqRespResponseCbHandler) anyerror!u64 {
        return self.sendRequestFn(self.ptr, peer_id, req, callback);
    }
};

pub const PeerEvents = struct {
    // ptr to the implementation
    ptr: *anyopaque,
    subscribeFn: *const fn (ptr: *anyopaque, handler: OnPeerEventCbHandler) anyerror!void,

    pub fn subscribe(self: PeerEvents, handler: OnPeerEventCbHandler) anyerror!void {
        return self.subscribeFn(self.ptr, handler);
    }
};

pub const NetworkInterface = struct {
    gossip: GossipSub,
    reqresp: ReqResp,
    peers: PeerEvents,
};

const OnGossipCbType = *const fn (*anyopaque, *const GossipMessage, sender_peer_id: []const u8) anyerror!void;
pub const OnGossipCbHandler = struct {
    ptr: *anyopaque,
    onGossipCb: OnGossipCbType,
    // c: xev.Completion = undefined,

    pub fn format(self: OnGossipCbHandler, writer: anytype) !void {
        _ = self;
        try writer.writeAll("OnGossipCbHandler");
    }

    pub fn onGossip(self: OnGossipCbHandler, data: *const GossipMessage, sender_peer_id: []const u8) anyerror!void {
        return self.onGossipCb(self.ptr, data, sender_peer_id);
    }
};

pub const GossipEncoding = enum {
    ssz_snappy,

    pub fn encode(self: GossipEncoding) []const u8 {
        return std.enums.tagName(GossipEncoding, self).?;
    }

    pub fn decode(encoded: []const u8) !GossipEncoding {
        return std.meta.stringToEnum(GossipEncoding, encoded) orelse error.InvalidDecoding;
    }
};

pub const LeanNetworkTopic = struct {
    gossip_topic: GossipTopic,
    encoding: GossipEncoding,
    fork_digest: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, gossip_topic: GossipTopic, encoding: GossipEncoding, fork_digest: []const u8) !LeanNetworkTopic {
        return LeanNetworkTopic{
            .allocator = allocator,
            .gossip_topic = gossip_topic,
            .encoding = encoding,
            .fork_digest = try allocator.dupe(u8, fork_digest),
        };
    }

    pub fn encodeZ(self: *const LeanNetworkTopic) ![:0]u8 {
        const gossip_part = try self.gossip_topic.encode(self.allocator);
        defer self.allocator.free(gossip_part);
        return try std.fmt.allocPrintSentinel(self.allocator, "/{s}/{s}/{s}/{s}", .{ topic_prefix, self.fork_digest, gossip_part, self.encoding.encode() }, 0);
    }

    pub fn encode(self: *const LeanNetworkTopic) ![]u8 {
        const topic_name = try self.gossip_topic.encode(self.allocator);
        defer self.allocator.free(topic_name);
        return try std.fmt.allocPrint(self.allocator, "/{s}/{s}/{s}/{s}", .{ topic_prefix, self.fork_digest, topic_name, self.encoding.encode() });
    }

    // topic format: /leanconsensus/<fork_digest>/<name>/<encoding>
    pub fn decode(allocator: Allocator, topic_str: [*:0]const u8) !LeanNetworkTopic {
        const topic = std.mem.span(topic_str);
        var iter = std.mem.splitSequence(u8, topic, "/");
        _ = iter.next() orelse return error.InvalidTopic; // skip empty
        const prefix = iter.next() orelse return error.InvalidTopic;
        if (!std.mem.eql(u8, prefix, topic_prefix)) {
            return error.InvalidTopic;
        }
        const fork_digest_slice = iter.next() orelse return error.InvalidTopic;
        const gossip_topic_slice = iter.next() orelse return error.InvalidTopic;
        const encoding_slice = iter.next() orelse return error.InvalidTopic;

        const gossip_topic = try GossipTopic.decode(gossip_topic_slice);
        const encoding = try GossipEncoding.decode(encoding_slice);

        return LeanNetworkTopic{
            .allocator = allocator,
            .gossip_topic = gossip_topic,
            .encoding = encoding,
            .fork_digest = try allocator.dupe(u8, fork_digest_slice),
        };
    }

    pub fn deinit(self: *LeanNetworkTopic) void {
        self.allocator.free(self.fork_digest);
    }
};

pub const GossipTopicKind = enum {
    block,
    attestation,
    aggregation,
};

pub const GossipTopic = struct {
    kind: GossipTopicKind,
    subnet_id: ?types.SubnetId = null,

    pub fn encode(self: GossipTopic, allocator: Allocator) ![]u8 {
        if (self.kind == .attestation) {
            const subnet_id = self.subnet_id orelse return error.MissingSubnetId;
            return std.fmt.allocPrint(allocator, "attestation_{d}", .{subnet_id});
        }
        return allocator.dupe(u8, @tagName(self.kind));
    }

    pub fn decode(encoded: []const u8) !GossipTopic {
        if (std.mem.startsWith(u8, encoded, "attestation_")) {
            const subnet_slice = encoded["attestation_".len..];
            const subnet_id = std.fmt.parseInt(types.SubnetId, subnet_slice, 10) catch return error.InvalidDecoding;
            return GossipTopic{ .kind = .attestation, .subnet_id = subnet_id };
        }
        const kind = std.meta.stringToEnum(GossipTopicKind, encoded) orelse return error.InvalidDecoding;
        return GossipTopic{ .kind = kind };
    }

    pub fn format(self: GossipTopic, writer: anytype) !void {
        switch (self.kind) {
            .block, .aggregation => try writer.writeAll(@tagName(self.kind)),
            .attestation => {
                if (self.subnet_id) |subnet_id| {
                    try writer.print("attestation_{d}", .{subnet_id});
                } else {
                    try writer.writeAll(@tagName(self.kind));
                }
            },
        }
    }
};

pub const AttestationGossip = struct {
    subnet_id: types.SubnetId,
    message: types.SignedAttestation,
};

pub const GossipMessage = union(GossipTopicKind) {
    block: types.SignedBlock,
    attestation: AttestationGossip,
    aggregation: types.SignedAggregatedAttestation,

    const Self = @This();

    pub fn getLeanNetworkTopic(self: *const Self, allocator: Allocator, fork_digest: []const u8) !LeanNetworkTopic {
        const gossip_kind = std.meta.activeTag(self.*);
        const gossip_topic = switch (gossip_kind) {
            .block => GossipTopic{ .kind = .block },
            .aggregation => GossipTopic{ .kind = .aggregation },
            .attestation => GossipTopic{ .kind = .attestation, .subnet_id = self.attestation.subnet_id },
        };
        return try LeanNetworkTopic.init(allocator, gossip_topic, .ssz_snappy, fork_digest);
    }

    pub fn getGossipTopic(self: *const Self) GossipTopic {
        return switch (std.meta.activeTag(self.*)) {
            .block => GossipTopic{ .kind = .block },
            .aggregation => GossipTopic{ .kind = .aggregation },
            .attestation => GossipTopic{ .kind = .attestation, .subnet_id = self.attestation.subnet_id },
        };
    }

    pub fn format(self: Self, writer: anytype) !void {
        switch (self) {
            .block => |blk| try writer.print("GossipMessage{{ block: slot={d}, proposer={d} }}", .{
                blk.block.slot,
                blk.block.proposer_index,
            }),
            .attestation => |att| try writer.print("GossipMessage{{ attestation: subnet={d} validator={d}, slot={d} }}", .{
                att.subnet_id,
                att.message.validator_id,
                att.message.message.slot,
            }),
            .aggregation => |agg| try writer.print("GossipMessage{{ aggregation: slot={d} }}", .{
                agg.data.slot,
            }),
        }
    }

    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var serialized: std.ArrayList(u8) = .empty;
        errdefer serialized.deinit(allocator);

        switch (self.*) {
            inline else => |payload, tag| {
                const PayloadType = unionPayloadType(Self, tag);
                switch (tag) {
                    .attestation => try ssz.serialize(types.SignedAttestation, payload.message, &serialized, allocator),
                    else => try ssz.serialize(PayloadType, payload, &serialized, allocator),
                }
            },
        }

        return serialized.toOwnedSlice(allocator);
    }

    pub fn clone(self: *const Self, allocator: Allocator) !*Self {
        const cloned_data = try allocator.create(Self);

        switch (self.*) {
            .block => {
                cloned_data.* = .{ .block = undefined };
                try types.sszClone(allocator, types.SignedBlock, self.block, &cloned_data.block);
            },
            .attestation => {
                cloned_data.* = .{ .attestation = undefined };
                cloned_data.attestation.subnet_id = self.attestation.subnet_id;
                try types.sszClone(allocator, types.SignedAttestation, self.attestation.message, &cloned_data.attestation.message);
            },
            .aggregation => {
                cloned_data.* = .{ .aggregation = undefined };
                try types.sszClone(allocator, types.SignedAggregatedAttestation, self.aggregation, &cloned_data.aggregation);
            },
        }

        return cloned_data;
    }

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            .block => |*block| block.deinit(),
            .attestation => {},
            .aggregation => |*aggregation| aggregation.deinit(),
        }
    }

    pub fn toJson(self: *const Self, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .block => |block| block.toJson(allocator) catch |e| {
                std.log.err("Failed to convert block to JSON: {any}", .{e});
                return e;
            },
            .attestation => |attestation| attestation.message.toJson(allocator) catch |e| {
                std.log.err("Failed to convert attestation to JSON: {any}", .{e});
                return e;
            },
            .aggregation => |aggregation| aggregation.toJson(allocator) catch |e| {
                std.log.err("Failed to convert aggregation to JSON: {any}", .{e});
                return e;
            },
        };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var message_json = try self.toJson(allocator);
        defer freeJsonValue(&message_json, allocator);
        return zeam_utils.jsonToString(allocator, message_json);
    }
};

pub const LeanSupportedProtocol = enum(u32) {
    // Ordinals must match the Rust side's `#[repr(u32)]` discriminants
    // AND `TryFrom<u32>` mapping in
    // `rust/libp2p-glue/src/req_resp/protocol_id.rs::LeanSupportedProtocol`.
    // The cross-FFI invariant runs in BOTH directions: Zig u32 → Rust
    // try_from (incoming RPC tag) AND Rust enum → u32 (outgoing tag).
    // The Rust side pins both via `#[repr(u32)]` + explicit discriminants;
    // a unit test (`try_from_round_trip_matches_repr` in the Rust file)
    // guards against future drift. Reported by @ch4r10t33r on PR #824.
    blocks_by_root = 0,
    status = 1,
    blocks_by_range = 2,

    pub fn protocolId(self: LeanSupportedProtocol) []const u8 {
        return switch (self) {
            .blocks_by_root => lean_blocks_by_root_protocol,
            .blocks_by_range => lean_blocks_by_range_protocol,
            .status => lean_status_protocol,
        };
    }

    pub fn name(self: LeanSupportedProtocol) []const u8 {
        return @tagName(self);
    }

    pub fn fromSlice(slice: []const u8) ?LeanSupportedProtocol {
        const protocols = comptime std.enums.values(LeanSupportedProtocol);
        inline for (protocols) |value| {
            if (std.mem.eql(u8, slice, value.protocolId())) return value;
        }
        return null;
    }

    pub fn fromProtocolId(protocol_id: []const u8) !LeanSupportedProtocol {
        if (std.mem.eql(u8, protocol_id, lean_status_protocol)) {
            return .status;
        }

        if (std.mem.eql(u8, protocol_id, lean_blocks_by_root_protocol)) {
            return .blocks_by_root;
        }

        if (std.mem.eql(u8, protocol_id, lean_blocks_by_range_protocol)) {
            return .blocks_by_range;
        }

        return error.UnsupportedProtocol;
    }
};

/// Validate the wire shape of a `BlocksByRootV1` request payload.
///
/// `BlockByRootRequest = struct { roots: List<Root, MAX_REQUEST_BLOCKS> }`
/// serialises as a 4-byte little-endian offset prefix followed by the packed
/// list body of `N × 32` bytes. The struct has only one variable-length field,
/// so the offset must point exactly at the end of the offset section, i.e.
/// must equal `4`.
///
/// Anything else is malformed: a peer-supplied garbage offset would otherwise
/// trigger a slice-bounds panic deep inside the SSZ decoder, which aborts the
/// FFI thread and brings down the whole zeam process. We return an error
/// instead so the request handler's existing catch path can send an RPC
/// error back and keep the node alive.
///
/// Intentionally module-private: this is a wire-shape shim for
/// `ReqRespRequest.deserialize` only and exists purely to dodge an upstream
/// SSZ panic surface (see #843). Once the bounds checks land in `ssz.zig`
/// itself this whole helper goes away. If a future caller in `pkgs/network/`
/// needs the same validation, lift it then — don't widen the API now and
/// invite reuse of a fix that is meant to be temporary.
fn validateBlocksByRootRequestBytes(bytes: []const u8) !void {
    // The body-length checks below assume the SSZ wire size of `Root` is 32
    // bytes (i.e. `Root` is `[32]u8` with no padding). If anyone ever wraps
    // `Root` in a struct with padding or otherwise drifts the in-memory size,
    // `@sizeOf(types.Root)` and the SSZ wire size diverge silently and these
    // checks misclassify well-formed payloads as malformed (or vice versa).
    // Catch that at compile time rather than waiting for it to reach Hive.
    comptime std.debug.assert(@sizeOf(types.Root) == 32);

    if (bytes.len < 4) return error.MalformedReqRespRequest;
    const offset = std.mem.readInt(u32, bytes[0..4], .little);
    if (offset != 4) return error.MalformedReqRespRequest;
    const body = bytes[offset..];
    if (body.len % @sizeOf(types.Root) != 0) return error.MalformedReqRespRequest;
    if (body.len / @sizeOf(types.Root) > consensus_params.MAX_REQUEST_BLOCKS) {
        return error.MalformedReqRespRequest;
    }
}

pub const ReqRespRequest = union(LeanSupportedProtocol) {
    blocks_by_root: types.BlockByRootRequest,
    status: types.Status,
    blocks_by_range: types.BlocksByRangeRequest,

    const Self = @This();

    pub fn format(self: Self, writer: anytype) !void {
        switch (self) {
            .blocks_by_root => try writer.writeAll("ReqRespRequest{ blocks_by_root }"),
            .blocks_by_range => try writer.writeAll("ReqRespRequest{ blocks_by_range }"),
            .status => try writer.writeAll("ReqRespRequest{ status }"),
        }
    }

    pub fn toJson(self: *const ReqRespRequest, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .status => |status| status.toJson(allocator),
            .blocks_by_root => |request| request.toJson(allocator),
            .blocks_by_range => |request| request.toJson(allocator),
        };
    }

    pub fn toJsonString(self: *const ReqRespRequest, allocator: Allocator) ![]const u8 {
        var message_json = try self.toJson(allocator);
        defer freeJsonValue(&message_json, allocator);
        return zeam_utils.jsonToString(allocator, message_json);
    }

    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var serialized: std.ArrayList(u8) = .empty;
        errdefer serialized.deinit(allocator);

        switch (self.*) {
            inline else => |payload, tag| {
                const PayloadType = unionPayloadType(Self, tag);
                try ssz.serialize(PayloadType, payload, &serialized, allocator);
            },
        }

        return serialized.toOwnedSlice(allocator);
    }

    fn initPayload(comptime tag: LeanSupportedProtocol, allocator: Allocator) !unionPayloadType(Self, tag) {
        const PayloadType = unionPayloadType(Self, tag);
        return switch (tag) {
            .blocks_by_root => PayloadType{
                .roots = try ssz.utils.List(types.Root, consensus_params.MAX_REQUEST_BLOCKS).init(allocator),
            },
            inline else => @as(PayloadType, undefined),
        };
    }

    fn deinitPayload(comptime tag: LeanSupportedProtocol, payload: *unionPayloadType(Self, tag)) void {
        switch (tag) {
            .blocks_by_root => payload.roots.deinit(),
            .blocks_by_range => {},
            inline else => {},
        }
    }

    pub fn deserialize(allocator: Allocator, method: LeanSupportedProtocol, bytes: []const u8) !Self {
        // Pre-validate the wire shape before handing it to the SSZ codec.
        //
        // The vendored ssz.zig has bounds checks on its array/list deserializer
        // (out-of-range offsets surface as `error.OffsetExceedsSize`) but not yet
        // on the variable-field offsets inside its container/struct deserializer.
        // A malformed `BlocksByRootV1` request that puts garbage in the offset
        // prefix slips past the upfront `minInLength`/`maxInLength` check
        // (24 bytes is comfortably inside `[4, 4 + 32 * MAX_REQUEST_BLOCKS]`)
        // and slice-overruns inside the wrapping struct's deserializer, which
        // panics the FFI thread and aborts the whole zeam process — any peer
        // can DoS the node by sending one bad RPC. Reject malformed input
        // here so the callsite's existing error path can send an RPC error
        // back without crashing.
        //
        // `Status` and `BlocksByRange` are fixed-size containers; ssz.zig's
        // upfront length check already rejects malformed input for those, so
        // no extra pre-validation is needed for them.
        switch (method) {
            .status, .blocks_by_range => {},
            .blocks_by_root => try validateBlocksByRootRequestBytes(bytes),
        }

        return switch (method) {
            inline else => |tag| {
                const PayloadType = unionPayloadType(Self, tag);
                var payload = try initPayload(tag, allocator);
                var succeeded = false;
                defer if (!succeeded) deinitPayload(tag, &payload);
                try ssz.deserialize(PayloadType, bytes, &payload, allocator);
                succeeded = true;
                return @unionInit(Self, @tagName(tag), payload);
            },
        };
    }

    pub fn deinit(self: *ReqRespRequest) void {
        switch (self.*) {
            inline else => |*payload, tag| deinitPayload(tag, payload),
        }
    }
};
pub const ReqRespResponse = union(LeanSupportedProtocol) {
    blocks_by_root: types.SignedBlock,
    status: types.Status,
    blocks_by_range: types.SignedBlock,

    const Self = @This();

    pub fn toJson(self: *const ReqRespResponse, allocator: Allocator) !json.Value {
        return switch (self.*) {
            .status => |status| status.toJson(allocator),
            .blocks_by_root => |block| block.toJson(allocator),
            .blocks_by_range => |block| block.toJson(allocator),
        };
    }

    pub fn toJsonString(self: *const ReqRespResponse, allocator: Allocator) ![]const u8 {
        var message_json = try self.toJson(allocator);
        defer freeJsonValue(&message_json, allocator);
        return zeam_utils.jsonToString(allocator, message_json);
    }

    pub fn serialize(self: *const ReqRespResponse, allocator: Allocator) ![]u8 {
        var serialized: std.ArrayList(u8) = .empty;
        errdefer serialized.deinit(allocator);

        switch (self.*) {
            inline else => |payload, tag| {
                const PayloadType = unionPayloadType(Self, tag);
                try ssz.serialize(PayloadType, payload, &serialized, allocator);
            },
        }

        return serialized.toOwnedSlice(allocator);
    }

    pub fn deserialize(allocator: Allocator, method: LeanSupportedProtocol, bytes: []const u8) !ReqRespResponse {
        return switch (method) {
            inline else => |tag| {
                const PayloadType = unionPayloadType(Self, tag);
                var payload: PayloadType = undefined;
                try ssz.deserialize(PayloadType, bytes, &payload, allocator);
                return @unionInit(Self, @tagName(tag), payload);
            },
        };
    }

    pub fn deinit(self: *ReqRespResponse) void {
        switch (self.*) {
            .status => {},
            .blocks_by_root => |*block| block.deinit(),
            .blocks_by_range => |*block| block.deinit(),
        }
    }
};

pub const ReqRespServerStream = struct {
    ptr: *anyopaque,
    sendResponseFn: *const fn (ptr: *anyopaque, response: *const ReqRespResponse) anyerror!void,
    sendErrorFn: *const fn (ptr: *anyopaque, code: u32, message: []const u8) anyerror!void,
    finishFn: *const fn (ptr: *anyopaque) anyerror!void,
    isFinishedFn: *const fn (ptr: *anyopaque) bool,
    getPeerIdFn: ?*const fn (ptr: *anyopaque) ?[]const u8 = null,

    const Self = @This();

    pub const Error = error{ServerStreamUnsupported};

    pub fn sendResponse(self: Self, response: *const ReqRespResponse) anyerror!void {
        return self.sendResponseFn(self.ptr, response);
    }

    pub fn sendError(self: Self, code: u32, message: []const u8) anyerror!void {
        return self.sendErrorFn(self.ptr, code, message);
    }

    pub fn finish(self: Self) anyerror!void {
        return self.finishFn(self.ptr);
    }

    pub fn isFinished(self: Self) bool {
        return self.isFinishedFn(self.ptr);
    }

    pub fn getPeerId(self: Self) ?[]const u8 {
        if (self.getPeerIdFn) |fn_ptr| {
            return fn_ptr(self.ptr);
        }
        return null;
    }
};
pub const ReqRespResponseError = struct {
    code: u32,
    message: []const u8,

    pub fn deinit(self: *ReqRespResponseError, allocator: Allocator) void {
        allocator.free(self.message);
    }
};

pub const ReqRespResponseEvent = struct {
    method: LeanSupportedProtocol,
    request_id: u64,
    payload: Payload,

    const Payload = union(enum) {
        success: ReqRespResponse,
        failure: ReqRespResponseError,
        completed,
    };

    pub fn initSuccess(request_id: u64, method: LeanSupportedProtocol, response: ReqRespResponse) ReqRespResponseEvent {
        return ReqRespResponseEvent{
            .method = method,
            .request_id = request_id,
            .payload = .{ .success = response },
        };
    }

    pub fn initError(request_id: u64, method: LeanSupportedProtocol, err: ReqRespResponseError) ReqRespResponseEvent {
        return ReqRespResponseEvent{
            .method = method,
            .request_id = request_id,
            .payload = .{ .failure = err },
        };
    }

    pub fn initCompleted(request_id: u64, method: LeanSupportedProtocol) ReqRespResponseEvent {
        return ReqRespResponseEvent{
            .method = method,
            .request_id = request_id,
            .payload = .completed,
        };
    }

    pub fn deinit(self: *ReqRespResponseEvent, allocator: Allocator) void {
        switch (self.payload) {
            .success => |*resp| resp.deinit(),
            .failure => |*err| err.deinit(allocator),
            .completed => {},
        }
    }
};

pub const ReqRespRequestCallback = struct {
    method: LeanSupportedProtocol,
    allocator: Allocator,
    handler: ?OnReqRespResponseCbHandler,
    peer_id: []const u8,

    pub fn init(method: LeanSupportedProtocol, allocator: Allocator, handler: ?OnReqRespResponseCbHandler, peer_id: []const u8) ReqRespRequestCallback {
        return ReqRespRequestCallback{
            .method = method,
            .allocator = allocator,
            .handler = handler,
            .peer_id = peer_id,
        };
    }

    pub fn deinit(self: *ReqRespRequestCallback) void {
        // peer_id is owned by the callback, free it
        self.allocator.free(self.peer_id);
    }

    pub fn notify(self: *ReqRespRequestCallback, event: *const ReqRespResponseEvent) anyerror!void {
        if (self.handler) |handler| {
            try handler.onReqRespResponse(event);
        }
    }
};

const OnReqRespResponseCbType = *const fn (*anyopaque, *const ReqRespResponseEvent) anyerror!void;
pub const OnReqRespResponseCbHandler = struct {
    ptr: *anyopaque,
    onReqRespResponseCb: OnReqRespResponseCbType,

    pub fn onReqRespResponse(self: OnReqRespResponseCbHandler, data: *const ReqRespResponseEvent) anyerror!void {
        return self.onReqRespResponseCb(self.ptr, data);
    }
};

const OnReqRespRequestCbType = *const fn (*anyopaque, *const ReqRespRequest, ReqRespServerStream) anyerror!void;
pub const OnReqRespRequestCbHandler = struct {
    ptr: *anyopaque,
    onReqRespRequestCb: OnReqRespRequestCbType,
    // c: xev.Completion = undefined,

    pub fn onReqRespRequest(self: OnReqRespRequestCbHandler, data: *const ReqRespRequest, stream: ReqRespServerStream) anyerror!void {
        return self.onReqRespRequestCb(self.ptr, data, stream);
    }
};
pub const ReqRespRequestHandler = struct {
    allocator: Allocator,
    handlers: std.ArrayList(OnReqRespRequestCbHandler),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();

    pub fn init(allocator: Allocator, networkId: u32, logger: zeam_utils.ModuleLogger, registry: *const NodeNameRegistry) !Self {
        return Self{
            .allocator = allocator,
            .handlers = .empty,
            .networkId = networkId,
            .logger = logger,
            .node_registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    pub fn subscribe(self: *Self, handler: OnReqRespRequestCbHandler) !void {
        try self.handlers.append(self.allocator, handler);
    }

    pub fn onReqRespRequest(self: *Self, req: *const ReqRespRequest, stream: ReqRespServerStream) anyerror!void {
        const peer_id_opt = stream.getPeerId();
        const peer_id = peer_id_opt orelse "unknown";
        const node_name = if (peer_id_opt) |pid| self.node_registry.getNodeNameFromPeerId(pid) else zeam_utils.OptionalNode.init(null);
        self.logger.debug("network-{d}:: onReqRespRequest={f} handlers={d} from peer={s}{f}", .{ self.networkId, req.*, self.handlers.items.len, peer_id, node_name });
        if (self.handlers.items.len == 0) {
            return error.NoHandlerSubscribed;
        }

        var handled = false;
        var last_err: ?anyerror = null;

        for (self.handlers.items) |handler| {
            handler.onReqRespRequest(req, stream) catch |err| {
                self.logger.err("network-{d}:: onReqRespRequest handler error={any} from peer={s}{f}", .{ self.networkId, err, peer_id, node_name });
                last_err = err;
                continue;
            };

            handled = true;

            if (stream.isFinished()) {
                break;
            }
        }

        if (!handled) {
            return last_err orelse error.NoHandlerSubscribed;
        }
    }
};

const MessagePublishWrapper = struct {
    allocator: Allocator,
    handler: OnGossipCbHandler,
    data: *GossipMessage,
    sender_peer_id: []const u8,
    networkId: u32,
    logger: zeam_utils.ModuleLogger,

    const Self = @This();

    pub fn format(self: Self, writer: anytype) !void {
        try writer.print("MessagePublishWrapper{{ networkId={d}, topic={f}, sender={s} }}", .{
            self.networkId,
            self.data.getGossipTopic(),
            self.sender_peer_id,
        });
    }

    fn init(allocator: Allocator, handler: OnGossipCbHandler, data: *const GossipMessage, sender_peer_id: []const u8, networkId: u32, logger: zeam_utils.ModuleLogger) !*Self {
        const cloned_data = try data.clone(allocator);
        const sender_peer_id_copy = try allocator.dupe(u8, sender_peer_id);

        const self = try allocator.create(Self);
        self.* = MessagePublishWrapper{
            .allocator = allocator,
            .handler = handler,
            .data = cloned_data,
            .sender_peer_id = sender_peer_id_copy,
            .networkId = networkId,
            .logger = logger,
        };
        return self;
    }

    fn deinit(self: *Self) void {
        self.allocator.free(self.sender_peer_id);
        self.data.deinit();
        self.allocator.destroy(self.data);
        self.allocator.destroy(self);
    }
};

pub const OnPeerConnectedCbType = *const fn (*anyopaque, peer_id: []const u8, direction: PeerDirection) anyerror!void;
pub const OnPeerDisconnectedCbType = *const fn (*anyopaque, peer_id: []const u8, direction: PeerDirection, reason: DisconnectionReason) anyerror!void;
pub const OnPeerConnectionFailedCbType = *const fn (*anyopaque, peer_id: []const u8, direction: PeerDirection, result: ConnectionResult) anyerror!void;

pub const OnPeerEventCbHandler = struct {
    ptr: *anyopaque,
    onPeerConnectedCb: OnPeerConnectedCbType,
    onPeerDisconnectedCb: OnPeerDisconnectedCbType,
    onPeerConnectionFailedCb: ?OnPeerConnectionFailedCbType = null,

    pub fn onPeerConnected(self: OnPeerEventCbHandler, peer_id: []const u8, direction: PeerDirection) anyerror!void {
        return self.onPeerConnectedCb(self.ptr, peer_id, direction);
    }

    pub fn onPeerDisconnected(self: OnPeerEventCbHandler, peer_id: []const u8, direction: PeerDirection, reason: DisconnectionReason) anyerror!void {
        return self.onPeerDisconnectedCb(self.ptr, peer_id, direction, reason);
    }

    pub fn onPeerConnectionFailed(self: OnPeerEventCbHandler, peer_id: []const u8, direction: PeerDirection, result: ConnectionResult) anyerror!void {
        if (self.onPeerConnectionFailedCb) |cb| {
            return cb(self.ptr, peer_id, direction, result);
        }
    }
};

pub const PeerEventHandler = struct {
    allocator: Allocator,
    handlers: std.ArrayList(OnPeerEventCbHandler),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();

    pub fn init(allocator: Allocator, networkId: u32, logger: zeam_utils.ModuleLogger, registry: *const NodeNameRegistry) !Self {
        return Self{
            .allocator = allocator,
            .handlers = .empty,
            .networkId = networkId,
            .logger = logger,
            .node_registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
    }

    pub fn subscribe(self: *Self, handler: OnPeerEventCbHandler) !void {
        try self.handlers.append(self.allocator, handler);
    }

    pub fn onPeerConnected(self: *Self, peer_id: []const u8, direction: PeerDirection) anyerror!void {
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerConnected peer_id={s}{f} direction={s}, handlers={d}", .{ self.networkId, peer_id, node_name, @tagName(direction), self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerConnected(peer_id, direction) catch |e| {
                self.logger.err("network-{d}:: onPeerConnected handler error={any}", .{ self.networkId, e });
            };
        }
    }

    pub fn onPeerDisconnected(self: *Self, peer_id: []const u8, direction: PeerDirection, reason: DisconnectionReason) anyerror!void {
        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerDisconnected peer_id={s}{f} direction={s} reason={s}, handlers={d}", .{ self.networkId, peer_id, node_name, @tagName(direction), @tagName(reason), self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerDisconnected(peer_id, direction, reason) catch |e| {
                self.logger.err("network-{d}:: onPeerDisconnected handler error={any}", .{ self.networkId, e });
            };
        }
    }

    pub fn onPeerConnectionFailed(self: *Self, peer_id: []const u8, direction: PeerDirection, result: ConnectionResult) anyerror!void {
        self.logger.debug("network-{d}:: PeerEventHandler.onPeerConnectionFailed peer_id={s} direction={s} result={s}, handlers={d}", .{ self.networkId, peer_id, @tagName(direction), @tagName(result), self.handlers.items.len });
        for (self.handlers.items) |handler| {
            handler.onPeerConnectionFailed(peer_id, direction, result) catch |e| {
                self.logger.err("network-{d}:: onPeerConnectionFailed handler error={any}", .{ self.networkId, e });
            };
        }
    }
};

pub const GenericGossipHandler = struct {
    loop: *xev.Loop,
    timer: xev.Timer,
    allocator: Allocator,
    onGossipHandlers: std.AutoHashMapUnmanaged(GossipTopic, std.ArrayList(OnGossipCbHandler)),
    networkId: u32,
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();
    pub fn init(allocator: Allocator, loop: *xev.Loop, networkId: u32, logger: zeam_utils.ModuleLogger, registry: *const NodeNameRegistry) !Self {
        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        var onGossipHandlers: std.AutoHashMapUnmanaged(GossipTopic, std.ArrayList(OnGossipCbHandler)) = .empty;
        errdefer {
            var it = onGossipHandlers.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit(allocator);
            }
            onGossipHandlers.deinit(allocator);
        }

        return Self{
            .allocator = allocator,
            .loop = loop,
            .timer = timer,
            .onGossipHandlers = onGossipHandlers,
            .networkId = networkId,
            .logger = logger,
            .node_registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        self.timer.deinit();
        var it = self.onGossipHandlers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.onGossipHandlers.deinit(self.allocator);
    }

    pub fn onGossip(self: *Self, data: *const GossipMessage, sender_peer_id: []const u8, scheduleOnLoop: bool) anyerror!void {
        const gossip_topic = data.getGossipTopic();
        const handlerArr = self.onGossipHandlers.get(gossip_topic) orelse {
            const node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
            self.logger.debug("network-{d}:: ongossip no handlers for topic={f} from peer={s}{f}", .{ self.networkId, gossip_topic, sender_peer_id, node_name });
            return;
        };
        const node_name = self.node_registry.getNodeNameFromPeerId(sender_peer_id);
        self.logger.debug("network-{d}:: ongossip handlers={d} topic={f} from peer={s}{f}", .{ self.networkId, handlerArr.items.len, gossip_topic, sender_peer_id, node_name });
        for (handlerArr.items) |handler| {

            // TODO: figure out why scheduling on the loop is not working for libp2p separate net instance
            // remove this option once resolved
            if (scheduleOnLoop) {
                const publishWrapper = try MessagePublishWrapper.init(self.allocator, handler, data, sender_peer_id, self.networkId, self.logger);

                self.logger.debug("network-{d}:: scheduling ongossip publishWrapper={f} for topic={f}", .{ self.networkId, publishWrapper, gossip_topic });

                // Create a separate completion object for each handler to avoid conflicts
                const completion = try self.allocator.create(xev.Completion);
                completion.* = undefined;

                self.timer.run(
                    self.loop,
                    completion,
                    1,
                    MessagePublishWrapper,
                    publishWrapper,
                    (struct {
                        fn callback(
                            ud: ?*MessagePublishWrapper,
                            _: *xev.Loop,
                            c: *xev.Completion,
                            r: xev.Timer.RunError!void,
                        ) xev.CallbackAction {
                            _ = r catch unreachable;
                            if (ud) |pwrap| {
                                pwrap.logger.debug("network-{d}:: ONGOSSIP PUBLISH callback executed", .{pwrap.networkId});
                                _ = pwrap.handler.onGossip(pwrap.data, pwrap.sender_peer_id) catch void;
                                defer pwrap.deinit();
                                // Clean up the completion object
                                pwrap.allocator.destroy(c);
                            }
                            return .disarm;
                        }
                    }).callback,
                );
            } else {
                handler.onGossip(data, sender_peer_id) catch |e| {
                    self.logger.err("network-{d}:: onGossip handler error={any}", .{ self.networkId, e });
                };
            }
        }
        // we don't need to run the loop as this is a shared loop and is already being run by the clock
    }

    pub fn subscribe(self: *Self, topics: []GossipTopic, handler: OnGossipCbHandler) anyerror!void {
        for (topics) |topic| {
            const gop = try self.onGossipHandlers.getOrPut(self.allocator, topic);
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
            }
            var handlerArr = gop.value_ptr.*;
            try handlerArr.append(self.allocator, handler);
            gop.value_ptr.* = handlerArr;
        }
    }
};

test GossipEncoding {
    const enc = GossipEncoding.ssz_snappy;
    try std.testing.expect(std.mem.eql(u8, enc.encode(), "ssz_snappy"));
    try std.testing.expectEqual(enc, try GossipEncoding.decode("ssz_snappy"));

    try std.testing.expectError(error.InvalidDecoding, GossipEncoding.decode("invalid"));
}

test GossipTopic {
    const allocator = std.testing.allocator;

    const block_topic = GossipTopic{ .kind = .block };
    const block_encoded = try block_topic.encode(allocator);
    defer allocator.free(block_encoded);
    try std.testing.expect(std.mem.eql(u8, block_encoded, "block"));
    try std.testing.expectEqual(block_topic, try GossipTopic.decode("block"));

    const att_topic = GossipTopic{ .kind = .attestation, .subnet_id = 0 };
    const att_encoded = try att_topic.encode(allocator);
    defer allocator.free(att_encoded);
    try std.testing.expect(std.mem.eql(u8, att_encoded, "attestation_0"));
    try std.testing.expectEqual(att_topic, try GossipTopic.decode("attestation_0"));

    try std.testing.expectError(error.InvalidDecoding, GossipTopic.decode("invalid"));
}

test LeanNetworkTopic {
    const allocator = std.testing.allocator;

    var topic = try LeanNetworkTopic.init(allocator, .{ .kind = .block }, .ssz_snappy, "12345678");
    defer topic.deinit();

    const topic_str = try topic.encodeZ();
    defer allocator.free(topic_str);

    try std.testing.expect(std.mem.eql(u8, topic_str, "/leanconsensus/12345678/block/ssz_snappy"));

    var decoded_topic = try LeanNetworkTopic.decode(allocator, topic_str.ptr);
    defer decoded_topic.deinit();

    try std.testing.expectEqual(topic.gossip_topic, decoded_topic.gossip_topic);
    try std.testing.expectEqual(topic.encoding, decoded_topic.encoding);
    try std.testing.expect(std.mem.eql(u8, topic.fork_digest, decoded_topic.fork_digest));
}

test "ReqRespRequest.deserialize rejects malformed BlocksByRoot without panicking" {
    // Regression test for the Hive `reqresp/blocks_by_root/malformed_request`
    // failures. The regression test merged with #845 used a hand-crafted
    // 24-byte approximation; this test pins the real simulator input.
    //
    // The Hive simulator sends `encode_request_raw(&[0xab; 64])`:
    //   - Wire:  25 bytes = varint(64) || snappy_frame_compress([0xab; 64])
    //   - After zeam's snappy frame decode: 64 bytes all `0xAB`
    //   - SSZ offset field (bytes 0..4 LE): 0xABABABAB = 2880154539
    //
    // Without the guard added in #845, the ssz.zig container deserializer at
    // lib.zig:604 sliced `bytes[2880154539..]` on a 64-byte buffer and
    // panicked, killing the FFI thread and aborting zeam.
    //
    // Scope: this test exercises the post-decompression validation path only.
    // The snappy framing layer and the varint length pre-checks are not
    // covered here; a full end-to-end harness (not yet in this project)
    // would be needed to lock those against regression too.
    //
    // Incidents: image 993f193 (v0.4.15, May 7 2026)
    //            image 14222bc (v0.4.16, May 7 2026, Hive test-506)
    //
    // The `@sizeOf(types.Root) == 32` compile-time assert inside
    // `validateBlocksByRootRequestBytes` ensures the 32-byte step assumption
    // used in cases 3, 6, and 7 holds. If `Root` ever gets padding the build
    // will fail at compile time rather than silently misclassifying payloads.
    //
    // All rejection cases also call `ReqRespRequest.deserialize` end-to-end.
    // Without the end-to-end call, a future contributor who mis-wires the
    // pre-validation switch (e.g. only `.status`, not `.blocks_by_root`)
    // would leave the production SSZ panic path reachable while the
    // per-shape validator checks still pass. The end-to-end calls lock that
    // wiring. The `errdefer req.deinit()` inside `deserialize` means any
    // allocation made before the validator fires is cleaned up on error;
    // `std.testing.allocator` enforces this by detecting leaks at test exit.
    const allocator = std.testing.allocator;

    {
        // Case 1: exact decompressed bytes from the Hive malformed_request test.
        // 64 bytes all 0xAB → offset 0xABABABAB (2880154539), way past the end.
        var malformed = [_]u8{0xAB} ** 64;
        try std.testing.expectError(error.MalformedReqRespRequest, validateBlocksByRootRequestBytes(&malformed));
        try std.testing.expectError(
            error.MalformedReqRespRequest,
            ReqRespRequest.deserialize(allocator, .blocks_by_root, &malformed),
        );
    }

    {
        // Case 2: non-uniform garbage — offset 0xDEADBEEF, mixed body bytes.
        // Guards against an (unlikely) optimisation that only rejects
        // homogeneous byte patterns.
        var mixed: [36]u8 = undefined;
        std.mem.writeInt(u32, mixed[0..4], 0xDEADBEEF, .little);
        @memset(mixed[4..], 0x5A);
        try std.testing.expectError(error.MalformedReqRespRequest, validateBlocksByRootRequestBytes(&mixed));
        try std.testing.expectError(
            error.MalformedReqRespRequest,
            ReqRespRequest.deserialize(allocator, .blocks_by_root, &mixed),
        );
    }

    {
        // Case 3: offset = 0 (null-prefix / classic adversarial first try).
        var zero_offset: [36]u8 = undefined;
        std.mem.writeInt(u32, zero_offset[0..4], 0, .little);
        @memset(zero_offset[4..], 0);
        try std.testing.expectError(error.MalformedReqRespRequest, validateBlocksByRootRequestBytes(&zero_offset));
        try std.testing.expectError(
            error.MalformedReqRespRequest,
            ReqRespRequest.deserialize(allocator, .blocks_by_root, &zero_offset),
        );
    }

    {
        // Case 4: offset = 8 (close to legal but wrong — "near-legal" family).
        var bad_offset: [36]u8 = undefined;
        std.mem.writeInt(u32, bad_offset[0..4], 8, .little);
        @memset(bad_offset[4..], 0);
        try std.testing.expectError(error.MalformedReqRespRequest, validateBlocksByRootRequestBytes(&bad_offset));
        try std.testing.expectError(
            error.MalformedReqRespRequest,
            ReqRespRequest.deserialize(allocator, .blocks_by_root, &bad_offset),
        );
    }

    {
        // Case 5: body length not a multiple of 32 (ragged root list).
        var ragged: [37]u8 = undefined;
        std.mem.writeInt(u32, ragged[0..4], 4, .little);
        @memset(ragged[4..], 0);
        try std.testing.expectError(error.MalformedReqRespRequest, validateBlocksByRootRequestBytes(&ragged));
        try std.testing.expectError(
            error.MalformedReqRespRequest,
            ReqRespRequest.deserialize(allocator, .blocks_by_root, &ragged),
        );
    }

    {
        // Case 6: root count exceeds MAX_REQUEST_BLOCKS.
        const oversize_count = consensus_params.MAX_REQUEST_BLOCKS + 1;
        const oversize_len = 4 + oversize_count * @sizeOf(types.Root);
        const oversize = try allocator.alloc(u8, oversize_len);
        defer allocator.free(oversize);
        std.mem.writeInt(u32, oversize[0..4], 4, .little);
        @memset(oversize[4..], 0);
        try std.testing.expectError(error.MalformedReqRespRequest, validateBlocksByRootRequestBytes(oversize));
        try std.testing.expectError(
            error.MalformedReqRespRequest,
            ReqRespRequest.deserialize(allocator, .blocks_by_root, oversize),
        );
    }

    // Sanity cases: the validator must not over-reject well-formed payloads.
    {
        // Case 7: empty root list (offset=4, body empty). Valid.
        var empty: [4]u8 = undefined;
        std.mem.writeInt(u32, empty[0..4], 4, .little);
        try validateBlocksByRootRequestBytes(&empty);
        var req = try ReqRespRequest.deserialize(allocator, .blocks_by_root, &empty);
        defer req.deinit();
        try std.testing.expectEqual(@as(usize, 0), req.blocks_by_root.roots.constSlice().len);
    }

    {
        // Case 8: exactly one root (offset=4, body=32 bytes). Valid.
        // Ensures the rejection path doesn't drift to over-rejecting
        // legitimate non-empty requests.
        var one_root: [4 + 32]u8 = undefined;
        std.mem.writeInt(u32, one_root[0..4], 4, .little);
        @memset(one_root[4..], 0); // zero root hash is a valid hash value
        try validateBlocksByRootRequestBytes(&one_root);
        var req = try ReqRespRequest.deserialize(allocator, .blocks_by_root, &one_root);
        defer req.deinit();
        try std.testing.expectEqual(@as(usize, 1), req.blocks_by_root.roots.constSlice().len);
    }
}
