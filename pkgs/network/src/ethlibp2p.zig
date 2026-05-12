const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const xev = @import("xev").Dynamic;
const multiformats = @import("multiformats");
const multiaddr_mod = @import("multiaddr");
const Multiaddr = multiaddr_mod.Multiaddr;
const uvarint = multiformats.uvarint;
const zeam_utils = @import("@zeam/utils");
const zeam_metrics = @import("@zeam/metrics");

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;
const snappyz = @import("snappyz");
const snappyframesz = @import("snappyframesz");
const node_registry = @import("./node_registry.zig");
const NodeNameRegistry = node_registry.NodeNameRegistry;

const ServerStreamError = error{
    StreamAlreadyFinished,
    InvalidResponseVariant,
};

/// General RPC message size limit (4 MB). Used for req/resp protocol messages
/// (BlocksByRoot, Status, etc.) and as a baseline gossip limit for small messages
/// such as attestations and aggregations.
const MAX_RPC_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Gossip block message size limit.
///
/// XMSS/post-quantum signatures are substantially larger than BLS: a single
/// AggregatedSignatureProof can be hundreds of KB, and blocks carry up to
/// MAX_ATTESTATIONS_DATA (16) attestations each with such a proof.  On devnet4
/// a legitimate block reached ~9.37 MB, exceeding the 4 MB RPC limit and
/// triggering error.TooLarge (issue #723).
///
/// Set to 50 MB to accommodate current devnet block sizes with room to grow.
/// Revisit once the leanSpec formalises a MAX_GOSSIP_BLOCK_SIZE constant.
///
/// TODO(#855 review #14): 50 MB × N peers is a real memory-pressure surface.
/// Track in a follow-up issue once the spec lands and we can lower this.
const MAX_GOSSIP_BLOCK_SIZE: usize = 50 * 1024 * 1024;
const MAX_VARINT_BYTES: usize = uvarint.bufferSize(usize);

const FrameDecodeError = error{
    EmptyFrame,
    MalformedVarint,
    PayloadTooLarge,
    Incomplete,
};

/// Failure modes returned by the snappy block-format header validators.
/// Each variant maps to a distinct ops/attacker shape; callers should keep
/// them distinct in logs and (eventually) metrics.
const SnappyHeaderValidationError = error{
    /// Empty buffer — nothing to decode.
    EmptyMessage,
    /// Leading varint is corrupt (truncated, oversized, or u64-overflow).
    InvalidVarint,
    /// Varint decoded cleanly but declares a payload larger than the limit
    /// allowed for this protocol/topic. Strict `>` to match the upstream
    /// `snappyz.decodeWithMax` contract (`if (block.blockLen > max_size)`).
    /// Pinning that comparison here so a future upstream change to `>=`
    /// flips the boundary and is caught loudly via this comment plus tests,
    /// rather than silently disagreeing across a 1-byte gap.
    DeclaredPayloadTooLarge,
    /// Header parsed cleanly and declared a non-zero payload, but the
    /// buffer contains only the header bytes (no body). Distinct from
    /// `InvalidVarint` because the header itself is well-formed; this is a
    /// truncated message, not a malformed one.
    HeaderWithoutBody,
};

/// Successful decode of a snappy block-format header: the declared
/// uncompressed length and the number of bytes occupied by the varint
/// header itself.
const SnappyHeader = struct {
    value: usize,
    length: usize,
};

const LeanSupportedProtocol = interface.LeanSupportedProtocol;

fn encodeVarint(buffer: *std.ArrayList(u8), allocator: Allocator, value: usize) !void {
    var scratch: [MAX_VARINT_BYTES]u8 = undefined;
    const encoded = uvarint.encode(usize, value, &scratch);
    try buffer.appendSlice(allocator, encoded);
}

fn decodeVarint(bytes: []const u8) uvarint.VarintParseError!struct { value: usize, length: usize } {
    const result = try uvarint.decode(usize, bytes);
    return .{
        .value = result.value,
        .length = bytes.len - result.remaining.len,
    };
}

/// Validate a snappy block-format header against an arbitrary size limit.
/// Used by both the gossip path (`validateGossipSnappyHeader`) and the RPC
/// frame parsers (`validateRpcSnappyHeader`); each caller passes its own
/// per-protocol/per-topic limit.
///
/// On success, returns the decoded length and the header byte count. On
/// failure, returns one of the `SnappyHeaderValidationError` variants so
/// callers can attribute different attacker shapes (corrupt varint vs.
/// oversized claim vs. missing body) in logs and metrics.
///
/// Header-only validation: this is *not* a full body integrity check. A
/// well-formed header followed by a body shorter than `decoded.value`
/// (but at least one byte) is accepted here — the actual decoder is
/// authoritative for body checks. We only reject the degenerate case
/// where the buffer is exactly the header and nothing else, because that
/// can never compress to a non-zero declared size.
fn validateSnappyHeader(
    message_bytes: []const u8,
    max_size: usize,
) SnappyHeaderValidationError!SnappyHeader {
    if (message_bytes.len == 0) return error.EmptyMessage;
    const decoded = decodeVarint(message_bytes) catch return error.InvalidVarint;
    if (decoded.value > max_size) return error.DeclaredPayloadTooLarge;
    // A valid snappy block must have at least the header byte(s) and may have
    // zero compressed bytes only when the declared uncompressed size is zero.
    if (decoded.value > 0 and decoded.length == message_bytes.len) {
        return error.HeaderWithoutBody;
    }
    return .{
        .value = decoded.value,
        .length = decoded.length,
    };
}

/// RPC frame snappy-header validator. Used by `parseRequestFrame` and
/// `parseResponseFrame` to bound declared sizes before snappy-frame decode.
/// (Renamed from `validateGossipSnappyHeader` in PR #855: the original
/// name was inverted — it was always RPC, never gossip.)
fn validateRpcSnappyHeader(message_bytes: []const u8) FrameDecodeError!SnappyHeader {
    return validateSnappyHeader(message_bytes, MAX_RPC_MESSAGE_SIZE) catch |e| switch (e) {
        error.EmptyMessage => return error.EmptyFrame,
        error.InvalidVarint => return error.MalformedVarint,
        error.DeclaredPayloadTooLarge => return error.PayloadTooLarge,
        // Header-only is not a fatal RPC frame condition: the body bytes
        // may simply not have arrived yet on this read. Treat as Incomplete.
        error.HeaderWithoutBody => return error.Incomplete,
    };
}

/// Gossip block-format snappy-header validator. Called from
/// `handleMsgFromRustBridge` before invoking `snappyz.decodeWithMax` so
/// malformed varint headers and oversized declared sizes are rejected
/// before any heap allocation. Per-topic `max_size` lets the caller
/// pass `MAX_GOSSIP_BLOCK_SIZE` for blocks vs. `MAX_RPC_MESSAGE_SIZE`
/// for attestations/aggregations.
///
/// This guard rejects malformed varint headers and oversized declared
/// sizes; it does not (and cannot) verify body integrity — that's the
/// decoder's job.
///
/// Two-layer defense exit criteria (PR #855 review #6): keep this guard
/// permanently. It serves three purposes the upstream zig-snappy library
/// can't: (a) rejects oversized declared sizes pre-allocation using zeam's
/// per-topic limits, (b) gives callers a typed error so we can attribute
/// attacker shapes in logs/metrics, (c) acts as a safety net if a future
/// upstream version regresses on malformed-input handling. The varint
/// decode is the only piece that overlaps with the upstream decoder; that
/// overlap is documented in `handleMsgFromRustBridge`'s call site.
fn validateGossipSnappyHeader(
    message_bytes: []const u8,
    max_size: usize,
) SnappyHeaderValidationError!SnappyHeader {
    return validateSnappyHeader(message_bytes, max_size);
}

/// Build a request frame with varint-encoded uncompressed size followed by snappy-framed payload.
fn buildRequestFrame(allocator: Allocator, uncompressed_size: usize, snappy_payload: []const u8) ![]u8 {
    if (uncompressed_size > MAX_RPC_MESSAGE_SIZE) {
        return error.PayloadTooLarge;
    }

    var frame = std.ArrayList(u8).empty;
    errdefer frame.deinit(allocator);

    try encodeVarint(&frame, allocator, uncompressed_size);
    try frame.appendSlice(allocator, snappy_payload);

    return frame.toOwnedSlice(allocator);
}

/// Build a response frame with response code, varint-encoded uncompressed size, and snappy-framed payload.
fn buildResponseFrame(allocator: Allocator, code: u8, uncompressed_size: usize, snappy_payload: []const u8) ![]u8 {
    if (uncompressed_size > MAX_RPC_MESSAGE_SIZE) {
        return error.PayloadTooLarge;
    }

    var frame = std.ArrayList(u8).empty;
    errdefer frame.deinit(allocator);

    try frame.append(allocator, code);
    try encodeVarint(&frame, allocator, uncompressed_size);
    try frame.appendSlice(allocator, snappy_payload);

    return frame.toOwnedSlice(allocator);
}

fn parseRequestFrame(bytes: []const u8) FrameDecodeError!struct {
    declared_len: usize,
    payload: []const u8,
} {
    if (bytes.len == 0) {
        return error.EmptyFrame;
    }

    const decoded = try validateRpcSnappyHeader(bytes);

    return .{
        .declared_len = decoded.value,
        .payload = bytes[decoded.length..],
    };
}

fn parseResponseFrame(bytes: []const u8) FrameDecodeError!struct {
    code: u8,
    declared_len: usize,
    payload: []const u8,
} {
    if (bytes.len == 0) {
        return error.EmptyFrame;
    }
    if (bytes.len == 1) {
        return error.Incomplete;
    }

    const decoded = try validateRpcSnappyHeader(bytes[1..]);

    return .{
        .code = bytes[0],
        .declared_len = decoded.value,
        .payload = bytes[1 + decoded.length ..],
    };
}

const ServerStreamContext = struct {
    zigHandler: *EthLibp2p,
    channel_id: u64,
    peer_id: []const u8,
    method: interface.LeanSupportedProtocol,
    finished: bool = false,
};

fn serverStreamGetPeerId(ptr: *anyopaque) ?[]const u8 {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    return ctx.peer_id;
}

fn serverStreamSendResponse(ptr: *anyopaque, response: *const interface.ReqRespResponse) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) {
        return ServerStreamError.StreamAlreadyFinished;
    }

    const allocator = ctx.zigHandler.allocator;
    const response_method = std.meta.activeTag(response.*);
    const response_method_name = @tagName(response_method);
    const node_name = ctx.zigHandler.node_registry.getNodeNameFromPeerId(ctx.peer_id);
    ctx.zigHandler.logger.debug(
        "network-{d}:: serverStreamSendResponse ctx.method={s} response.tag={s} peer={s}{f}",
        .{ ctx.zigHandler.params.networkId, @tagName(ctx.method), @tagName(response_method), ctx.peer_id, node_name },
    );

    if (ctx.method != response_method) {
        ctx.zigHandler.logger.err(
            "network-{d}:: serverStreamSendResponse method mismatch: ctx.method={s} response.tag={s}",
            .{ ctx.zigHandler.params.networkId, @tagName(ctx.method), response_method_name },
        );
        return ServerStreamError.InvalidResponseVariant;
    }
    const encoded = response.serialize(allocator) catch |err| {
        ctx.zigHandler.logger.err(
            "network-{d}:: Failed to serialize {s} response for peer={s}{f} channel={d}: {any}",
            .{ ctx.zigHandler.params.networkId, response_method_name, ctx.peer_id, node_name, ctx.channel_id, err },
        );
        return err;
    };
    defer allocator.free(encoded);

    const framed = snappyframesz.encode(allocator, encoded) catch |err| {
        ctx.zigHandler.logger.err(
            "network-{d}:: Failed to snappy-frame {s} response for peer={s}{f} channel={d}: {any}",
            .{ ctx.zigHandler.params.networkId, response_method_name, ctx.peer_id, node_name, ctx.channel_id, err },
        );
        return err;
    };
    defer allocator.free(framed);

    const frame = try buildResponseFrame(allocator, 0, encoded.len, framed);
    defer allocator.free(frame);

    ctx.zigHandler.logger.debug(
        "network-{d}:: Streaming {s} response to peer={s}{f} channel={d}",
        .{ ctx.zigHandler.params.networkId, response_method_name, ctx.peer_id, node_name, ctx.channel_id },
    );

    send_rpc_response_chunk(
        ctx.zigHandler.params.networkId,
        ctx.channel_id,
        frame.ptr,
        frame.len,
    );
}

fn serverStreamSendError(ptr: *anyopaque, code: u32, message: []const u8) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) {
        return ServerStreamError.StreamAlreadyFinished;
    }

    const allocator = ctx.zigHandler.allocator;
    const owned_message = try allocator.dupeZ(u8, message);
    defer allocator.free(owned_message);

    const node_name = ctx.zigHandler.node_registry.getNodeNameFromPeerId(ctx.peer_id);
    ctx.zigHandler.logger.warn(
        "network-{d}:: Streaming RPC error to peer={s}{f} channel={d} code={d}: {s}",
        .{ ctx.zigHandler.params.networkId, ctx.peer_id, node_name, ctx.channel_id, code, message },
    );

    send_rpc_error_response(
        ctx.zigHandler.params.networkId,
        ctx.channel_id,
        owned_message.ptr,
    );

    ctx.finished = true;
}

fn serverStreamFinish(ptr: *anyopaque) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) {
        return;
    }

    send_rpc_end_of_stream(ctx.zigHandler.params.networkId, ctx.channel_id);
    ctx.finished = true;
}

fn serverStreamIsFinished(ptr: *anyopaque) bool {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    return ctx.finished;
}

/// 1-of-N sample counter for malformed-message debug dumps. Without this gate,
/// a peer spamming garbage gossip (e.g. sustained 1k msg/s) would fill the
/// disk with one debug file per message (PR #855 review #5). We only persist
/// `1` of every `MALFORMED_DUMP_SAMPLE_RATE` rejections; the rest are logged
/// inline. The counter is process-local and racy across threads, which is
/// fine — the goal is *not* exact 1:1024 sampling, just bounded disk pressure.
const MALFORMED_DUMP_SAMPLE_RATE: usize = 1024;
var malformed_dump_counter: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

/// Returns true iff the caller should persist this malformed message to disk.
/// Always persists the very first malformed message of a process so a single
/// reproducible failure during testing isn't lost behind the sampler.
fn shouldPersistMalformedDump() bool {
    const n = malformed_dump_counter.fetchAdd(1, .monotonic);
    return n == 0 or (n % MALFORMED_DUMP_SAMPLE_RATE) == 0;
}

/// Writes failed deserialization bytes to disk for debugging purposes.
/// Logs the outcome (success or failure) itself; returns true on success.
///
/// Previously returned `?[]const u8` (the allocated filename) while also doing
/// `defer allocator.free(filename)` — so callers received a dangling pointer and
/// segfaulted when logging it.  The fix: log from inside this function and return
/// a plain bool; callers no longer touch the filename string at all (#725).
fn writeFailedBytes(message_bytes: []const u8, message_type: []const u8, allocator: Allocator, timestamp: ?i64, logger: zeam_utils.ModuleLogger) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    // Create dumps directory if it doesn't exist
    std.Io.Dir.cwd().createDirPath(io, "deserialization_dumps") catch |e| {
        logger.err("Failed to create deserialization dumps directory: {any}", .{e});
        return false;
    };

    // Generate timestamp-based filename
    const actual_timestamp = timestamp orelse zeam_utils.unixTimestampSeconds();
    const filename = std.fmt.allocPrint(allocator, "deserialization_dumps/failed_{s}_{d}.bin", .{ message_type, actual_timestamp }) catch |e| {
        logger.err("Failed to allocate filename for {s} deserialization dump: {any}", .{ message_type, e });
        return false;
    };
    defer allocator.free(filename);

    // Write bytes to file
    const file = std.Io.Dir.cwd().createFile(io, filename, .{ .truncate = true }) catch |e| {
        logger.err("Failed to create file {s} for {s} deserialization dump: {any}", .{ filename, message_type, e });
        return false;
    };
    defer file.close(io);

    var write_buf: [4096]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    writer.interface.writeAll(message_bytes) catch |e| {
        logger.err("Failed to write {d} bytes to file {s} for {s} deserialization dump: {any}", .{ message_bytes.len, filename, message_type, e });
        return false;
    };
    writer.interface.flush() catch |e| {
        logger.err("Failed to flush file {s} for {s} deserialization dump: {any}", .{ filename, message_type, e });
        return false;
    };

    // Log while filename is still live (before defer free runs).
    logger.warn("SSZ deserialization failed for {s} message - written {d} bytes to debug file: {s}", .{ message_type, message_bytes.len, filename });
    return true;
}

/// Generic SSZ deserializer for gossip messages. Returns null on failure (with
/// error logging and debug-file creation), so callers can simply `orelse return`.
fn deserializeGossipMessage(
    comptime T: type,
    comptime label: []const u8,
    data: []const u8,
    allocator: Allocator,
    logger: zeam_utils.ModuleLogger,
) ?T {
    var message_data: T = undefined;
    ssz.deserialize(T, data, &message_data, allocator) catch |e| {
        logger.err("Error in deserializing the signed {s} message: {any}", .{ label, e });
        if (!writeFailedBytes(data, label, allocator, null, logger)) {
            logger.err("{s} deserialization failed - could not create debug file", .{label});
        }
        return null;
    };
    return message_data;
}

/// Log + sample-dump a gossip rejection from the snappy-header guard. Each
/// `SnappyHeaderValidationError` variant maps to a distinct attacker shape:
/// corrupt varint = malformed bytes, declared-too-large = oversized claim,
/// header-without-body = truncated stream, empty = degenerate. Keeping these
/// separate in the log line preserves attribution; collapsing into a single
/// "malformed snappy header" line (as the original PR did) loses the signal.
fn rejectMalformedGossip(
    zigHandler: *EthLibp2p,
    err: SnappyHeaderValidationError,
    topic_slice: []const u8,
    sender_peer_id_slice: []const u8,
    message_bytes: []const u8,
) void {
    const reason: []const u8 = switch (err) {
        error.EmptyMessage => "empty gossip payload",
        error.InvalidVarint => "corrupt snappy varint header",
        error.DeclaredPayloadTooLarge => "declared snappy payload exceeds per-topic limit",
        error.HeaderWithoutBody => "snappy header parsed but body bytes are missing",
    };
    const dump_label: []const u8 = switch (err) {
        error.EmptyMessage => "snappy_empty",
        error.InvalidVarint => "snappy_varint",
        error.DeclaredPayloadTooLarge => "snappy_oversized",
        error.HeaderWithoutBody => "snappy_truncated",
    };
    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(sender_peer_id_slice);
    zigHandler.logger.err(
        "Rejecting gossip message: {s} (topic={s}, len={d}, peer={s}{f})",
        .{ reason, topic_slice, message_bytes.len, sender_peer_id_slice, node_name },
    );
    if (shouldPersistMalformedDump()) {
        if (!writeFailedBytes(message_bytes, dump_label, zigHandler.allocator, null, zigHandler.logger)) {
            zigHandler.logger.err("Failed to persist malformed gossip dump ({s})", .{dump_label});
        }
    }
}

export fn handleMsgFromRustBridge(zigHandler: *EthLibp2p, topic_str: [*:0]const u8, message_ptr: [*]const u8, message_len: usize, sender_peer_id: [*:0]const u8) void {
    const topic = interface.LeanNetworkTopic.decode(zigHandler.allocator, topic_str) catch |err| {
        zigHandler.logger.err("Ignoring Invalid topic_id={s} sent in handleMsgFromRustBridge: {any}", .{ std.mem.span(topic_str), err });
        return;
    };

    const message_bytes: []const u8 = message_ptr[0..message_len];
    const sender_peer_id_slice = std.mem.span(sender_peer_id);
    const topic_slice = std.mem.span(topic_str);

    // Block gossip messages carry XMSS/post-quantum aggregated signatures and can be
    // substantially larger than the 4 MB RPC limit (devnet4 saw ~9.37 MB — issue #723).
    // Use the larger MAX_GOSSIP_BLOCK_SIZE for block topics; keep the tighter limit for
    // small messages (attestations, aggregations) to bound memory use.
    //
    // TODO(#855 review #9): attestations/aggregations rarely approach
    // MAX_RPC_MESSAGE_SIZE (4 MB). Tighter per-kind ceilings would let us
    // reject earlier and reduce attacker amplification. Track separately.
    const decode_limit: usize = switch (topic.gossip_topic.kind) {
        .block => MAX_GOSSIP_BLOCK_SIZE,
        else => MAX_RPC_MESSAGE_SIZE,
    };

    // Defense-in-depth gate before the third-party decoder. Rejects malformed
    // varint headers and oversized declared sizes so the gossip thread can't
    // panic on adversarial input regardless of upstream decoder state. Returns
    // typed errors so we can attribute attacker shapes (corrupt varint vs.
    // oversized claim vs. truncated body) in logs and — eventually — metrics.
    //
    // Note (PR #855 review #8): this decodes the leading varint, and so does
    // `snappyz.decodeWithMax` further down. The duplication is intentional and
    // worth O(10ns) per gossip message; both decoders MUST agree on the same
    // size-limit comparison (strict `>`, see `SnappyHeaderValidationError`).
    // If the upstream contract ever changes (e.g. to `>=`), the boundary tests
    // pinned in the test block below will go red.
    _ = validateGossipSnappyHeader(message_bytes, decode_limit) catch |e| {
        rejectMalformedGossip(zigHandler, e, topic_slice, sender_peer_id_slice, message_bytes);
        // TODO(#855 review #4): apply a libp2p gossipsub score penalty here
        // so a peer spamming malformed gossip is ejected by the protocol
        // instead of getting unlimited free retries. Out of scope for the
        // panic fix; tracked separately.
        return;
    };

    const uncompressed_message = snappyz.decodeWithMax(zigHandler.allocator, message_bytes, decode_limit) catch |e| {
        zigHandler.logger.err(
            "Error in snappyz decoding the message for topic={s} from peer={s}: {any}",
            .{ topic_slice, sender_peer_id_slice, e },
        );
        if (shouldPersistMalformedDump()) {
            if (!writeFailedBytes(message_bytes, "snappyz_decode", zigHandler.allocator, null, zigHandler.logger)) {
                zigHandler.logger.err("Snappyz decode failed - could not create debug file", .{});
            }
        }
        return;
    };
    defer zigHandler.allocator.free(uncompressed_message);

    // Record gossip message size metrics — observed on uncompressed bytes
    switch (topic.gossip_topic.kind) {
        .block => zeam_metrics.lean_gossip_block_size_bytes.record(@floatFromInt(uncompressed_message.len)),
        .attestation => zeam_metrics.lean_gossip_attestation_size_bytes.record(@floatFromInt(uncompressed_message.len)),
        .aggregation => zeam_metrics.lean_gossip_aggregation_size_bytes.record(@floatFromInt(uncompressed_message.len)),
    }

    var message: interface.GossipMessage = switch (topic.gossip_topic.kind) {
        .block => .{ .block = deserializeGossipMessage(
            types.SignedBlock,
            "block",
            uncompressed_message,
            zigHandler.allocator,
            zigHandler.logger,
        ) orelse return },
        .attestation => blk: {
            const subnet_id = topic.gossip_topic.subnet_id orelse {
                zigHandler.logger.err("attestation topic missing subnet id: {s}", .{std.mem.span(topic_str)});
                return;
            };
            const msg = deserializeGossipMessage(
                types.SignedAttestation,
                "attestation",
                uncompressed_message,
                zigHandler.allocator,
                zigHandler.logger,
            ) orelse return;
            break :blk .{ .attestation = .{ .subnet_id = subnet_id, .message = msg } };
        },
        .aggregation => .{ .aggregation = deserializeGossipMessage(
            types.SignedAggregatedAttestation,
            "aggregation",
            uncompressed_message,
            zigHandler.allocator,
            zigHandler.logger,
        ) orelse return },
    };
    defer message.deinit();

    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(sender_peer_id_slice);
    switch (message) {
        .block => |signed_block| {
            const block = signed_block.block;
            zigHandler.logger.debug(
                "network-{d}:: received gossip block slot={d} proposer={d} (compressed={d}B, raw={d}B) from peer={s}{f}",
                .{
                    zigHandler.params.networkId,
                    block.slot,
                    block.proposer_index,
                    message_bytes.len,
                    uncompressed_message.len,
                    sender_peer_id_slice,
                    node_name,
                },
            );
        },
        .attestation => |signed_attestation| {
            const slot = signed_attestation.message.message.slot;
            const validator_id = signed_attestation.message.validator_id;
            zigHandler.logger.debug(
                "network-{d}:: received gossip attestation subnet={d} slot={d} validator={d} (compressed={d}B, raw={d}B) from peer={s}{f}",
                .{
                    zigHandler.params.networkId,
                    signed_attestation.subnet_id,
                    slot,
                    validator_id,
                    message_bytes.len,
                    uncompressed_message.len,
                    sender_peer_id_slice,
                    node_name,
                },
            );
        },
        .aggregation => |signed_aggregation| {
            zigHandler.logger.debug(
                "network-{d}:: received gossip aggregation slot={d} (compressed={d}B, raw={d}B) from peer={s}{f}",
                .{
                    zigHandler.params.networkId,
                    signed_aggregation.data.slot,
                    message_bytes.len,
                    uncompressed_message.len,
                    sender_peer_id_slice,
                    node_name,
                },
            );
        },
    }

    // Debug-only JSON dump (conversion happens only if debug is actually emitted).
    zigHandler.logger.debug(
        "network-{d}:: gossip payload json topic={s} from peer={s}{f}: {f}",
        .{
            zigHandler.params.networkId,
            topic_slice,
            sender_peer_id_slice,
            node_name,
            zeam_utils.LazyJson(interface.GossipMessage).init(zigHandler.allocator, &message),
        },
    );

    // TODO: figure out why scheduling on the loop is not working
    zigHandler.gossipHandler.onGossip(&message, sender_peer_id_slice, false) catch |e| {
        zigHandler.logger.err("onGossip handling of message failed with error e={any} from sender_peer_id={s}{f}", .{ e, sender_peer_id_slice, node_name });
    };
}

export fn handleRPCRequestFromRustBridge(
    zigHandler: *EthLibp2p,
    channel_id: u64,
    peer_id: [*:0]const u8,
    protocol_id: [*:0]const u8,
    request_ptr: [*]const u8,
    request_len: usize,
) void {
    const peer_id_slice = std.mem.span(peer_id);
    const protocol_slice = std.mem.span(protocol_id);

    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(peer_id_slice);
    const rpc_protocol = LeanSupportedProtocol.fromSlice(protocol_slice) orelse {
        zigHandler.logger.warn(
            "network-{d}:: Unsupported RPC protocol from peer={s}{f} on channel={d}: {s}",
            .{ zigHandler.params.networkId, peer_id_slice, node_name, channel_id, protocol_slice },
        );
        send_rpc_error_response(zigHandler.params.networkId, channel_id, "Unsupported RPC protocol");
        return;
    };

    const request_frame: []const u8 = request_ptr[0..request_len];

    const request_frame_info = parseRequestFrame(request_frame) catch |err| {
        zigHandler.logger.err(
            "network-{d}:: Invalid RPC request frame from peer={s}{f} protocol={s}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, node_name, protocol_slice, err },
        );
        send_rpc_error_response(zigHandler.params.networkId, channel_id, "Invalid RPC request frame");
        return;
    };

    const request_bytes = snappyframesz.decode(zigHandler.allocator, request_frame_info.payload) catch |err| {
        zigHandler.logger.err(
            "network-{d}:: Failed to decode snappy-framed RPC request from peer={s}{f} protocol={s}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, node_name, protocol_slice, err },
        );
        send_rpc_error_response(zigHandler.params.networkId, channel_id, "Failed to decode RPC request");
        return;
    };
    defer zigHandler.allocator.free(request_bytes);
    if (request_bytes.len != request_frame_info.declared_len) {
        zigHandler.logger.err(
            "network-{d}:: Invalid RPC request length from peer={s}{f} protocol={s}: declared={d} decoded={d}",
            .{
                zigHandler.params.networkId,
                peer_id_slice,
                node_name,
                protocol_slice,
                request_frame_info.declared_len,
                request_bytes.len,
            },
        );
        send_rpc_error_response(zigHandler.params.networkId, channel_id, "Invalid RPC request length");
        return;
    }

    const method = rpc_protocol;
    var request = interface.ReqRespRequest.deserialize(zigHandler.allocator, method, request_bytes) catch |err| {
        const label = method.name();
        zigHandler.logger.err(
            "Error in deserializing the {s} RPC request from peer={s}{f}: {any}",
            .{ label, peer_id_slice, node_name, err },
        );
        if (!writeFailedBytes(request_bytes, label, zigHandler.allocator, null, zigHandler.logger)) {
            zigHandler.logger.err("RPC {s} deserialization failed - could not create debug file from peer={s}{f}", .{ label, peer_id_slice, node_name });
        }
        send_rpc_error_response(zigHandler.params.networkId, channel_id, "Failed to deserialize RPC request");
        return;
    };
    defer request.deinit();

    zigHandler.logger.debug(
        "network-{d}:: received RPC request peer={s}{f} protocol={s} channel={d} size={d}",
        .{ zigHandler.params.networkId, peer_id_slice, node_name, rpc_protocol.protocolId(), channel_id, request_bytes.len },
    );

    // Debug-only JSON dump (conversion happens only if debug is actually emitted).
    zigHandler.logger.debug(
        "network-{d}:: rpc request json peer={s}{f} protocol={s} channel={d}: {any}",
        .{
            zigHandler.params.networkId,
            peer_id_slice,
            node_name,
            rpc_protocol.protocolId(),
            channel_id,
            zeam_utils.LazyJson(interface.ReqRespRequest).init(zigHandler.allocator, &request),
        },
    );

    const request_method = std.meta.activeTag(request);

    // Heap-allocate the stream context so its address remains valid even if
    // a handler (now or in the future) retains the stream for work that
    // outlives this function call. A stack-allocated context would leave
    // stream.ptr dangling the moment handleRPCRequestFromRustBridge returns.
    const stream_context = zigHandler.allocator.create(ServerStreamContext) catch |err| {
        zigHandler.logger.err(
            "network-{d}:: Failed to allocate RPC stream context for peer={s}{f} channel={d}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, node_name, channel_id, err },
        );
        send_rpc_error_response(zigHandler.params.networkId, channel_id, "Internal error allocating stream context");
        return;
    };
    defer zigHandler.allocator.destroy(stream_context);
    stream_context.* = ServerStreamContext{
        .zigHandler = zigHandler,
        .channel_id = channel_id,
        .peer_id = peer_id_slice,
        .method = request_method,
    };

    var stream = interface.ReqRespServerStream{
        .ptr = stream_context,
        .sendResponseFn = serverStreamSendResponse,
        .sendErrorFn = serverStreamSendError,
        .finishFn = serverStreamFinish,
        .isFinishedFn = serverStreamIsFinished,
        .getPeerIdFn = serverStreamGetPeerId,
    };

    zigHandler.reqrespHandler.onReqRespRequest(&request, stream) catch |e| {
        zigHandler.logger.err(
            "network-{d}:: Error while handling RPC request from peer={s}{f} on channel={d}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, node_name, channel_id, e },
        );

        if (!stream.isFinished()) {
            const msg = std.fmt.allocPrint(zigHandler.allocator, "Handler error: {any}", .{e}) catch null;
            if (msg) |owned| {
                defer zigHandler.allocator.free(owned);
                stream.sendError(1, owned) catch |send_err| {
                    zigHandler.logger.err(
                        "network-{d}:: Failed to send RPC error response for peer={s}{f} channel={d}: {any}",
                        .{ zigHandler.params.networkId, peer_id_slice, node_name, channel_id, send_err },
                    );
                };
            } else {
                stream.finish() catch |finish_err| {
                    zigHandler.logger.err(
                        "network-{d}:: Failed to finalize errored RPC stream for peer={s}{f} channel={d}: {any}",
                        .{ zigHandler.params.networkId, peer_id_slice, node_name, channel_id, finish_err },
                    );
                };
            }
        }
        return;
    };

    if (!stream.isFinished()) {
        stream.finish() catch |finish_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to finalize RPC stream for peer={s}{f} channel={d}: {any}",
                .{ zigHandler.params.networkId, peer_id_slice, node_name, channel_id, finish_err },
            );
        };
    }
}

export fn handleRPCResponseFromRustBridge(
    zigHandler: *EthLibp2p,
    request_id: u64,
    peer_id: [*:0]const u8,
    protocol_id: [*:0]const u8,
    response_ptr: [*]const u8,
    response_len: usize,
) void {
    const protocol_slice = std.mem.span(protocol_id);
    const peer_id_slice = std.mem.span(peer_id);
    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(peer_id_slice);

    const callback_ptr = zigHandler.rpcCallbacks.getPtr(request_id) orelse {
        zigHandler.logger.warn(
            "network-{d}:: Received RPC response for unknown request_id={d} protocol={s} from peer={s}{f}",
            .{ zigHandler.params.networkId, request_id, protocol_slice, peer_id_slice, node_name },
        );
        return;
    };
    // Use peer_id from callback if available, otherwise use the one passed from Rust
    // (They should match, but callback takes precedence for consistency)
    const callback_peer_id = callback_ptr.peer_id;
    const callback_node_name = zigHandler.node_registry.getNodeNameFromPeerId(callback_peer_id);
    const protocol = LeanSupportedProtocol.fromSlice(protocol_slice) orelse {
        zigHandler.notifyRpcErrorFmt(
            request_id,
            callback_ptr.method,
            2,
            "Unsupported RPC protocol in response: {s}",
            .{protocol_slice},
        );
        return;
    };
    const method = callback_ptr.method;
    if (protocol != method) {
        zigHandler.logger.warn(
            "network-{d}:: RPC protocol/method mismatch for request_id={d}: protocol={s} method={s} from peer={s}{f}",
            .{ zigHandler.params.networkId, request_id, protocol.protocolId(), @tagName(method), callback_peer_id, callback_node_name },
        );
    }

    const response_frame = response_ptr[0..response_len];

    const parsed_frame = parseResponseFrame(response_frame) catch |err| {
        zigHandler.notifyRpcErrorFmt(
            request_id,
            method,
            2,
            "Invalid response frame (protocol={s}): {any}",
            .{ protocol.protocolId(), err },
        );
        return;
    };

    if (parsed_frame.code != 0) {
        zigHandler.logger.warn(
            "network-{d}:: RPC error response for request_id={d} protocol={s} code={d} from peer={s}{f}",
            .{ zigHandler.params.networkId, request_id, protocol.protocolId(), parsed_frame.code, callback_peer_id, callback_node_name },
        );

        const owned_message = zigHandler.allocator.dupe(u8, parsed_frame.payload) catch |dup_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to duplicate RPC error payload for request_id={d} from peer={s}{f}: {any}",
                .{ zigHandler.params.networkId, request_id, callback_peer_id, callback_node_name, dup_err },
            );
            zigHandler.notifyRpcErrorFmt(
                request_id,
                method,
                @intCast(parsed_frame.code),
                "Failed to duplicate RPC error payload (protocol={s})",
                .{protocol_slice},
            );
            return;
        };

        zigHandler.notifyRpcErrorWithOwnedMessage(
            request_id,
            method,
            @intCast(parsed_frame.code),
            owned_message,
        );
        return;
    }

    const response_bytes = snappyframesz.decode(zigHandler.allocator, parsed_frame.payload) catch |err| {
        zigHandler.notifyRpcErrorFmt(
            request_id,
            method,
            2,
            "Failed to decode snappy-framed response (protocol={s}): {any}",
            .{ protocol.protocolId(), err },
        );
        return;
    };
    defer zigHandler.allocator.free(response_bytes);
    if (response_bytes.len != parsed_frame.declared_len) {
        zigHandler.notifyRpcErrorFmt(
            request_id,
            method,
            2,
            "Response length mismatch (protocol={s}): declared {d} decoded {d}",
            .{ protocol.protocolId(), parsed_frame.declared_len, response_bytes.len },
        );
        return;
    }

    const response_union = interface.ReqRespResponse.deserialize(zigHandler.allocator, method, response_bytes) catch |err| {
        zigHandler.notifyRpcErrorFmt(
            request_id,
            method,
            2,
            "Failed to deserialize RPC response (protocol={s}): {any}",
            .{ protocol.protocolId(), err },
        );
        return;
    };

    var event = interface.ReqRespResponseEvent.initSuccess(request_id, method, response_union);
    defer event.deinit(zigHandler.allocator);

    zigHandler.logger.debug(
        "network-{d}:: Received RPC response for request_id={d} protocol={s} size={d} from peer={s}{f}",
        .{ zigHandler.params.networkId, request_id, protocol.protocolId(), response_bytes.len, callback_peer_id, callback_node_name },
    );

    callback_ptr.notify(&event) catch |notify_err| {
        zigHandler.logger.err(
            "network-{d}:: Failed to notify RPC success callback for request_id={d} from peer={s}{f}: {any}",
            .{ zigHandler.params.networkId, request_id, callback_peer_id, callback_node_name, notify_err },
        );
    };
}

export fn handleRPCEndOfStreamFromRustBridge(
    zigHandler: *EthLibp2p,
    request_id: u64,
    peer_id: [*:0]const u8,
    protocol_id: [*:0]const u8,
) void {
    const protocol_slice = std.mem.span(protocol_id);
    const peer_id_slice = std.mem.span(peer_id);
    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(peer_id_slice);
    const protocol_str = if (LeanSupportedProtocol.fromSlice(protocol_slice)) |proto| proto.protocolId() else protocol_slice;

    if (zigHandler.rpcCallbacks.fetchRemove(request_id)) |entry| {
        var callback = entry.value;
        const method = callback.method;
        const callback_peer_id = callback.peer_id;
        const callback_node_name = zigHandler.node_registry.getNodeNameFromPeerId(callback_peer_id);

        var event = interface.ReqRespResponseEvent.initCompleted(request_id, method);
        defer event.deinit(zigHandler.allocator);

        zigHandler.logger.debug(
            "network-{d}:: Received RPC end-of-stream for request_id={d} protocol={s} from peer={s}{f}",
            .{ zigHandler.params.networkId, request_id, protocol_str, callback_peer_id, callback_node_name },
        );

        callback.notify(&event) catch |notify_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to notify RPC completion for request_id={d}: {any}",
                .{ zigHandler.params.networkId, request_id, notify_err },
            );
        };
        callback.deinit();
    } else {
        zigHandler.logger.warn(
            "network-{d}:: Received RPC end-of-stream for unknown request_id={d} protocol={s} from peer={s}{f}",
            .{ zigHandler.params.networkId, request_id, protocol_str, peer_id_slice, node_name },
        );
    }
}

export fn handleRPCErrorFromRustBridge(
    zigHandler: *EthLibp2p,
    request_id: u64,
    protocol_id: [*:0]const u8,
    code: u32,
    message_ptr: [*:0]const u8,
) void {
    const protocol_slice = std.mem.span(protocol_id);
    const protocol_str = if (LeanSupportedProtocol.fromSlice(protocol_slice)) |proto| proto.protocolId() else protocol_slice;
    const message_slice = std.mem.span(message_ptr);

    if (zigHandler.rpcCallbacks.fetchRemove(request_id)) |entry| {
        var callback = entry.value;
        const method = callback.method;
        const peer_id = callback.peer_id;
        const node_name = zigHandler.node_registry.getNodeNameFromPeerId(peer_id);

        const owned_message = zigHandler.allocator.dupe(u8, message_slice) catch |alloc_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to duplicate RPC error message for request_id={d} from peer={s}{f}: {any}",
                .{ zigHandler.params.networkId, request_id, peer_id, node_name, alloc_err },
            );
            callback.deinit();
            return;
        };

        var event = interface.ReqRespResponseEvent.initError(request_id, method, .{
            .code = code,
            .message = owned_message,
        });
        defer event.deinit(zigHandler.allocator);

        zigHandler.logger.warn(
            "network-{d}:: Received RPC error for request_id={d} protocol={s} code={d} from peer={s}{f}",
            .{ zigHandler.params.networkId, request_id, protocol_str, code, peer_id, node_name },
        );

        callback.notify(&event) catch |notify_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to notify RPC error for request_id={d} from peer={s}{f}: {any}",
                .{ zigHandler.params.networkId, request_id, peer_id, node_name, notify_err },
            );
        };
        callback.deinit();
    } else {
        zigHandler.logger.warn(
            "network-{d}:: Dropping RPC error for unknown request_id={d} protocol={s} code={d}",
            .{ zigHandler.params.networkId, request_id, protocol_str, code },
        );
    }
}

export fn handlePeerConnectedFromRustBridge(
    zigHandler: *EthLibp2p,
    peer_id: [*:0]const u8,
    direction: u32,
) void {
    const peer_id_slice = std.mem.span(peer_id);
    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(peer_id_slice);
    const dir = @as(interface.PeerDirection, @enumFromInt(direction));
    zigHandler.logger.info("network-{d}:: Peer connected: {s}{f} direction={s}", .{
        zigHandler.params.networkId,
        peer_id_slice,
        node_name,
        @tagName(dir),
    });

    zigHandler.peerEventHandler.onPeerConnected(peer_id_slice, dir) catch |e| {
        zigHandler.logger.err("network-{d}:: Error handling peer connected event: {any}", .{ zigHandler.params.networkId, e });
    };
}

export fn handlePeerDisconnectedFromRustBridge(
    zigHandler: *EthLibp2p,
    peer_id: [*:0]const u8,
    direction: u32,
    reason: u32,
) void {
    const peer_id_slice = std.mem.span(peer_id);
    const node_name = zigHandler.node_registry.getNodeNameFromPeerId(peer_id_slice);
    const dir = @as(interface.PeerDirection, @enumFromInt(direction));
    const rsn = @as(interface.DisconnectionReason, @enumFromInt(reason));
    zigHandler.logger.info("network-{d}:: Peer disconnected: {s}{f} direction={s} reason={s}", .{
        zigHandler.params.networkId,
        peer_id_slice,
        node_name,
        @tagName(dir),
        @tagName(rsn),
    });

    zigHandler.failInflightRpcsForPeer(peer_id_slice) catch |e| {
        zigHandler.logger.err(
            "network-{d}:: Error failing in-flight RPCs for disconnected peer={s}{f}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, node_name, e },
        );
    };

    zigHandler.peerEventHandler.onPeerDisconnected(peer_id_slice, dir, rsn) catch |e| {
        zigHandler.logger.err("network-{d}:: Error handling peer disconnected event: {any}", .{ zigHandler.params.networkId, e });
    };
}

export fn handlePeerConnectionFailedFromRustBridge(
    zigHandler: *EthLibp2p,
    peer_id: ?[*:0]const u8,
    direction: u32,
    result: u32,
) void {
    const peer_id_slice = if (peer_id) |p| std.mem.span(p) else "unknown";
    const dir = @as(interface.PeerDirection, @enumFromInt(direction));
    const res = @as(interface.ConnectionResult, @enumFromInt(result));
    zigHandler.logger.info("network-{d}:: Peer connection failed: {s} direction={s} result={s}", .{
        zigHandler.params.networkId,
        peer_id_slice,
        @tagName(dir),
        @tagName(res),
    });

    zigHandler.peerEventHandler.onPeerConnectionFailed(peer_id_slice, dir, res) catch |e| {
        zigHandler.logger.err("network-{d}:: Error handling peer connection failed event: {any}", .{ zigHandler.params.networkId, e });
    };
}

// Receive plain log lines from the Rust bridge and emit using Zeam logger with proper node scope
export fn handleLogFromRustBridge(
    zigHandler: *EthLibp2p,
    level: u32,
    message_ptr: [*]const u8,
    message_len: usize,
) void {
    const message_slice: []const u8 = message_ptr[0..message_len];
    const trimmed: []const u8 = std.mem.trim(u8, message_slice, " \t\r\n");
    switch (level) {
        0 => zigHandler.logger.debug("rust-bridge: {s}", .{trimmed}),
        1 => zigHandler.logger.info("rust-bridge: {s}", .{trimmed}),
        2 => zigHandler.logger.warn("rust-bridge: {s}", .{trimmed}),
        3 => zigHandler.logger.err("rust-bridge: {s}", .{trimmed}),
        else => zigHandler.logger.debug("rust-bridge:{s}", .{trimmed}),
    }
}

export fn releaseStartNetworkParams(zig_handler: *EthLibp2p, local_private_key: [*:0]const u8, listen_addresses: [*:0]const u8, connect_addresses: [*:0]const u8) void {
    const listen_slice = std.mem.span(listen_addresses);
    zig_handler.allocator.free(listen_slice);

    const connect_slice = std.mem.span(connect_addresses);
    zig_handler.allocator.free(connect_slice);

    const private_key_slice = std.mem.span(local_private_key);
    zig_handler.allocator.free(private_key_slice);
}

/// Must match `CreateNetworkParams` in `rust/libp2p-glue/src/lib.rs` (repr(C)).
pub const CreateNetworkParams = extern struct {
    network_id: u32,
    padding: u32,
    zig_handler: u64,
    local_private_key: [*:0]const u8,
    listen_addresses: [*:0]const u8,
    connect_addresses: [*:0]const u8,
};

pub extern fn create_and_run_network(params: *const CreateNetworkParams) callconv(.c) void;
pub extern fn wait_for_network_ready(
    network_id: u32,
    timeout_ms: u64,
) callconv(.c) bool;
/// Signal the Rust-side libp2p event loop to exit. After returning, the hosting
/// bridge thread is guaranteed to unwind soon and can be `join`ed. Safe to call
/// on a network that was never started or is already stopped (no-op).
pub extern fn stop_network(network_id: u32) callconv(.c) void;
/// Returns `true` when the publish was successfully enqueued onto the Rust-side
/// swarm command channel, `false` when the command was dropped (network not
/// initialized, channel full / closed, or null topic). See issue #808 — under
/// load the bounded command channel can drop our own attestations and the
/// caller needs to know rather than logging "published" unconditionally.
pub extern fn publish_msg_to_rust_bridge(
    networkId: u32,
    topic_str: [*:0]const u8,
    message_ptr: [*]const u8,
    message_len: usize,
) callconv(.c) bool;
/// Enqueue a gossipsub mesh subscription on the Rust-side swarm command channel.
/// Returns `true` if the command was enqueued, `false` if dropped (network not
/// initialized, channel full / closed, or null `topic_str`). Driven from
/// `EthLibp2p.subscribe`, which keeps `gossip.subscribe` on the Zig side as
/// the single source of truth for which subnets a node joins.
pub extern fn subscribe_gossip_topic_to_rust_bridge(
    networkId: u32,
    topic_str: [*:0]const u8,
) callconv(.c) bool;
pub extern fn send_rpc_request(
    networkId: u32,
    peer_id: [*:0]const u8,
    protocol_tag: u32,
    request_ptr: [*]const u8,
    request_len: usize,
) callconv(.c) u64;
pub extern fn send_rpc_response_chunk(
    networkId: u32,
    channel_id: u64,
    response_ptr: [*]const u8,
    response_len: usize,
) callconv(.c) void;
pub extern fn send_rpc_end_of_stream(networkId: u32, channel_id: u64) callconv(.c) void;
pub extern fn send_rpc_error_response(
    networkId: u32,
    channel_id: u64,
    message_ptr: [*:0]const u8,
) callconv(.c) void;

/// Issue #808: tag space for `get_swarm_command_dropped_total`. Mirrors the
/// `SwarmCommandDropReason` enum on the Rust side. **Stable wire contract** —
/// these tags are passed by value across FFI; do not renumber. Adding a new
/// reason is fine; existing reasons must keep their tag.
pub const SwarmCommandDropReason = enum(u32) {
    full = 0,
    closed = 1,
    uninitialized = 2,
};

/// Returns the cumulative count of swarm commands dropped before reaching the
/// Rust event loop, for the given reason tag. Counts are global across all
/// networks; the metrics layer scrapes once per Prometheus hit and turns the
/// monotonic count into a labeled `zeam_libp2p_swarm_command_dropped_total`
/// counter via deltas (see `pkgs/metrics`).
pub extern fn get_swarm_command_dropped_total(reason_tag: u32) callconv(.c) u64;

/// Last cumulative drop count we observed from the Rust side, per reason
/// (matching `SwarmCommandDropReason`). The scrape refresher computes
/// `current - last_seen`, calls `incrBy` with the delta, and updates this.
var swarm_command_drop_last_seen: [3]u64 = .{ 0, 0, 0 };

fn refreshSwarmCommandDropMetric() void {
    inline for (.{ SwarmCommandDropReason.full, SwarmCommandDropReason.closed, SwarmCommandDropReason.uninitialized }) |reason| {
        const idx: usize = @intFromEnum(reason);
        const current = get_swarm_command_dropped_total(@intFromEnum(reason));
        const last = swarm_command_drop_last_seen[idx];
        if (current > last) {
            const delta = current - last;
            zeam_metrics.metrics.zeam_libp2p_swarm_command_dropped_total.incrBy(
                .{ .reason = @tagName(reason) },
                delta,
            ) catch {};
            swarm_command_drop_last_seen[idx] = current;
        }
    }
}

/// leanMetrics PR #35: current number of remote peers in this node's
/// gossipsub mesh, across all subscribed topics. Kept fresh from inside the
/// rust-libp2p swarm task (gossipsub events, connection closes, 1s tick) and
/// read here on every Prometheus scrape — "on scrape" semantics.
pub extern fn get_mesh_peers_total(network_id: u32) callconv(.c) u64;

/// leanMetrics PR #35 — `lean_gossip_mesh_peers`.
///
/// The Rust glue keeps `MESH_PEERS_TOTAL` as a fixed-size
/// `[AtomicU64; MAX_NETWORKS]` (slots for `network_id` 0…MAX_NETWORKS-1,
/// matching the hardcoded slot table in `rust/libp2p-glue/src/lib.rs`).
/// Sum across every slot rather than tracking a single "active"
/// network_id in a Zig-side global — the previous design silently
/// reported only the most recently `init`-ed network's count if more
/// than one `EthLibp2p` was created in-process (multi-network tests,
/// future multi-network deployments). Inactive slots are 0 (reset by
/// `stop_network` and never written for unused ids), so summing is the
/// correct single-gauge answer for every current usage.
///
/// A future per-network label scheme (`client=<name>_<N>`) would emit
/// one labelled gauge per non-zero slot rather than summing. The
/// fixed-size atomic shape on the Rust side is what makes that change a
/// localised follow-up rather than a re-architecture.
const MESH_PEERS_MAX_NETWORKS: u32 = 3;

fn refreshMeshPeersMetric() void {
    var total: u64 = 0;
    var network_id: u32 = 0;
    while (network_id < MESH_PEERS_MAX_NETWORKS) : (network_id += 1) {
        total += get_mesh_peers_total(network_id);
    }
    zeam_metrics.metrics.lean_gossip_mesh_peers.set(total);
}

/// Combined scrape refresher for all network-layer metrics. Historically
/// `registerScrapeRefresher` stored a single callback, so this fan-out
/// existed because registering each refresher individually would silently
/// overwrite the previous one. The metrics module now keeps an append-only
/// list of refreshers (see `pkgs/metrics/src/lib.zig`), so individual
/// registration would also be safe — but we keep the fan-out for two
/// reasons:
///   * one callback per module makes the registration site (below) easier
///     to audit;
///   * adding a new network-layer refresher is a one-liner here without
///     touching the metrics-module registry capacity.
/// Add new network-layer refreshers here.
fn refreshNetworkMetrics() void {
    refreshSwarmCommandDropMetric();
    refreshMeshPeersMetric();
}

/// Arguments for the libp2p Rust runtime thread. Kept in a Zig function so `std.Thread.spawn`
/// uses a normal Zig entry point; passing `create_and_run_network` (a C symbol) as the spawn
/// target has been observed to fault on Linux x86_64 (GPF in `Thread.callFn`).
const CreateNetworkThreadArgs = struct {
    network_id: u32,
    handle: *EthLibp2p,
    local_private_key: [*:0]const u8,
    listen_addresses: [*:0]const u8,
    connect_addresses: [*:0]const u8,
};

fn createAndRunNetworkThread(args: CreateNetworkThreadArgs) void {
    var c_params: CreateNetworkParams = .{
        .network_id = args.network_id,
        .padding = 0,
        .zig_handler = @intFromPtr(args.handle),
        .local_private_key = args.local_private_key,
        .listen_addresses = args.listen_addresses,
        .connect_addresses = args.connect_addresses,
    };
    create_and_run_network(&c_params);
}

pub const EthLibp2pParams = struct {
    networkId: u32,
    fork_digest: []const u8,
    local_private_key: []const u8,
    listen_addresses: []const Multiaddr,
    connect_peers: ?[]const Multiaddr,
    node_registry: *const NodeNameRegistry,
};

pub const EthLibp2p = struct {
    allocator: Allocator,
    gossipHandler: interface.GenericGossipHandler,
    peerEventHandler: interface.PeerEventHandler,
    reqrespHandler: interface.ReqRespRequestHandler,
    params: EthLibp2pParams,
    rustBridgeThread: ?Thread = null,
    rpcCallbacks: std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback),
    logger: zeam_utils.ModuleLogger,
    node_registry: *const NodeNameRegistry,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthLibp2pParams,
        logger: zeam_utils.ModuleLogger,
    ) !Self {
        const owned_fork_digest = try allocator.dupe(u8, params.fork_digest);
        errdefer allocator.free(owned_fork_digest);

        // Issue #808: hand the metrics layer a callback so every Prometheus
        // scrape pulls the latest cumulative drop counts from the Rust side
        // and turns them into deltas on `zeam_libp2p_swarm_command_dropped_total`.
        // Counts are global; registering once is enough even with multiple
        // EthLibp2p instances (the call is idempotent).
        // leanMetrics PR #35: register the network-layer scrape
        // refresher. `registerScrapeRefresher` is now append-only (the
        // metrics module keeps a bounded list); we still register a
        // single network-layer fan-out (`refreshNetworkMetrics`) for
        // the reasons documented at its definition above. The mesh-peers
        // refresher inside the fan-out sums across all `network_id`
        // slots on the Rust side, so we do not need to stash this
        // instance's `params.networkId` in a Zig-side global.
        zeam_metrics.registerScrapeRefresher(refreshNetworkMetrics);

        const gossip_handler = try interface.GenericGossipHandler.init(allocator, loop, params.networkId, logger, params.node_registry);
        errdefer gossip_handler.deinit();

        const peer_event_handler = try interface.PeerEventHandler.init(allocator, params.networkId, logger, params.node_registry);
        errdefer peer_event_handler.deinit();

        const reqresp_handler = try interface.ReqRespRequestHandler.init(allocator, params.networkId, logger, params.node_registry);
        errdefer reqresp_handler.deinit();

        return Self{
            .allocator = allocator,
            .params = .{
                .networkId = params.networkId,
                .fork_digest = owned_fork_digest,
                .local_private_key = params.local_private_key,
                .listen_addresses = params.listen_addresses,
                .connect_peers = params.connect_peers,
                .node_registry = params.node_registry,
            },
            .gossipHandler = gossip_handler,
            .peerEventHandler = peer_event_handler,
            .reqrespHandler = reqresp_handler,
            .rpcCallbacks = std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback).empty,
            .logger = logger,
            .node_registry = params.node_registry,
        };
    }

    pub fn deinit(self: *Self) void {
        // Signal the Rust libp2p event loop to exit and then wait for the OS
        // thread to actually unwind before we start tearing down the fields it
        // might still touch. After `stop_network` the event loop takes its
        // shutdown arm, drops the swarm, clears the per-network handler
        // pointer, and returns from `run_eventloop`, which lets the hosting
        // thread exit; `thread.join` then completes deterministically.
        //
        // Ordering matters: we must join before freeing anything reachable
        // from `zigHandler` (gossip/peer-event/reqresp handlers, param
        // strings, rpcCallbacks), otherwise an in-flight callback could
        // dereference already-freed memory.
        if (self.rustBridgeThread) |thread| {
            stop_network(self.params.networkId);
            thread.join();
            self.rustBridgeThread = null;
        }

        self.gossipHandler.deinit();
        self.peerEventHandler.deinit();

        for (self.params.listen_addresses) |addr| addr.deinit();
        self.allocator.free(self.params.listen_addresses);

        if (self.params.connect_peers) |peers| {
            for (peers) |addr| addr.deinit();
            self.allocator.free(peers);
        }

        self.allocator.free(self.params.fork_digest);

        var it = self.rpcCallbacks.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.rpcCallbacks.deinit(self.allocator);
    }

    pub fn run(self: *Self) !void {
        const listen_addresses_str = try multiaddrsToString(self.allocator, self.params.listen_addresses);
        const connect_peers_str = if (self.params.connect_peers) |peers|
            try multiaddrsToString(self.allocator, peers)
        else
            try self.allocator.dupeZ(u8, "");
        const local_private_key = try self.allocator.dupeZ(u8, self.params.local_private_key);

        // Topic subscriptions are not passed to the Rust bridge at startup.
        // `EthLibp2p.subscribe` drives them via
        // `subscribe_gossip_topic_to_rust_bridge` once the swarm command
        // channel is up, keeping `gossip.subscribe` (called from `BeamNode`)
        // as the single source of truth for joined subnets. The previous
        // approach (enumerate every attestation subnet at startup) joined the
        // mesh to every subnet on every node and defeated the bandwidth
        // savings of attestation subnets; the intermediate fix (read the
        // handler map after BeamNode.run()) required a strict startup order
        // and did not surface late changes to the subscription set. See
        // https://github.com/leanEthereum/leanSpec/blob/main/src/lean_spec/__main__.py
        // for the spec-conformant selective subscribe.
        self.rustBridgeThread = try Thread.spawn(.{}, createAndRunNetworkThread, .{CreateNetworkThreadArgs{
            .network_id = self.params.networkId,
            .handle = self,
            .local_private_key = local_private_key.ptr,
            .listen_addresses = listen_addresses_str.ptr,
            .connect_addresses = connect_peers_str.ptr,
        }});

        // Wait for the network to be fully initialized before returning
        // Use a 10 second timeout to avoid hanging indefinitely
        const timeout_ms: u64 = 10000;
        self.logger.debug("network-{d}:: Waiting for network initialization to complete...", .{self.params.networkId});

        if (!wait_for_network_ready(self.params.networkId, timeout_ms)) {
            self.logger.err("network-{d}:: Network failed to initialize within {d}ms timeout", .{ self.params.networkId, timeout_ms });
            return error.NetworkInitializationTimeout;
        }

        self.logger.info("network-{d}:: Network initialization complete, ready to send/receive messages", .{self.params.networkId});
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // publish
        var topic = try data.getLeanNetworkTopic(self.allocator, self.params.fork_digest);
        defer topic.deinit();
        const topic_str = try topic.encodeZ();
        defer self.allocator.free(topic_str);

        // TODO: deinit the message later ob once done
        const message = try data.serialize(self.allocator);
        defer self.allocator.free(message);

        const compressed_message = try snappyz.encode(self.allocator, message);
        defer self.allocator.free(compressed_message);
        self.logger.debug("network-{d}:: publishing to rust bridge data={f} size={d}", .{ self.params.networkId, data.*, compressed_message.len });
        return publish_msg_to_rust_bridge(self.params.networkId, topic_str.ptr, compressed_message.ptr, compressed_message.len);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // Drive the Rust gossipsub mesh subscriptions from the same call site
        // that registers the in-process Zig handlers. After this, the subnet
        // set the node joins on the wire is exactly the set whose handlers
        // are wired up in `gossipHandler.onGossipHandlers`. Caller (BeamNode)
        // must invoke this AFTER `EthLibp2p.run()` has spawned the rust
        // bridge thread; `run()`'s `wait_for_network_ready` ensures the swarm
        // command channel exists by the time `run()` returns.
        for (topics) |gossip_topic| {
            var topic = try interface.LeanNetworkTopic.init(self.allocator, gossip_topic, .ssz_snappy, self.params.fork_digest);
            defer topic.deinit();
            const topic_str = try topic.encodeZ();
            defer self.allocator.free(topic_str);
            if (!subscribe_gossip_topic_to_rust_bridge(self.params.networkId, topic_str.ptr)) {
                self.logger.err(
                    "network-{d}:: gossip mesh subscribe dropped for topic={f} (network not ready or swarm command channel full — see rust-bridge logs)",
                    .{ self.params.networkId, gossip_topic },
                );
                return error.GossipMeshSubscribeFailed;
            }
        }
        try self.gossipHandler.subscribe(topics, handler);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage, sender_peer_id: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, sender_peer_id, false);
    }

    pub fn sendRPCRequest(
        ptr: *anyopaque,
        peer_id: []const u8,
        req: *const interface.ReqRespRequest,
        callback: ?interface.OnReqRespResponseCbHandler,
    ) !u64 {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const peer_id_cstr = try self.allocator.dupeZ(u8, peer_id);
        defer self.allocator.free(peer_id_cstr);

        const method = std.meta.activeTag(req.*);
        const protocol_tag: u32 = @as(u32, @intFromEnum(method));

        const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
        const encoded_message = req.serialize(self.allocator) catch |err| {
            self.logger.err(
                "network-{d}:: Failed to serialize RPC request for peer={s}{f} method={s}: {any}",
                .{ self.params.networkId, peer_id, node_name, @tagName(method), err },
            );
            return err;
        };

        defer self.allocator.free(encoded_message);

        const framed_payload = snappyframesz.encode(self.allocator, encoded_message) catch |err| {
            self.logger.err(
                "network-{d}:: Failed to snappy-frame RPC request payload for peer={s}{f} protocol_tag={d}: {any}",
                .{ self.params.networkId, peer_id, node_name, protocol_tag, err },
            );
            return err;
        };
        defer self.allocator.free(framed_payload);

        const frame = buildRequestFrame(self.allocator, encoded_message.len, framed_payload) catch |err| {
            self.logger.err(
                "network-{d}:: Failed to build RPC request frame for peer={s}{f} protocol_tag={d}: {any}",
                .{ self.params.networkId, peer_id, node_name, protocol_tag, err },
            );
            return err;
        };
        defer self.allocator.free(frame);

        const request_id = send_rpc_request(
            self.params.networkId,
            peer_id_cstr.ptr,
            protocol_tag,
            frame.ptr,
            frame.len,
        );

        if (request_id == 0) {
            // Issue #808: send_rpc_request returns 0 when the Rust-side swarm
            // command channel is uninitialized / full / closed, i.e. the
            // request never reached the wire. The Rust layer already logs
            // the specific reason and bumps `get_swarm_command_dropped_total`,
            // but surface a Zig-side warn so operators correlating req-resp
            // timeouts have the dispatch-failure event in the same log stream.
            self.logger.warn(
                "network-{d}:: dropping RPC request to peer={s}{f} protocol_tag={d}: rust-bridge swarm command channel rejected enqueue (see preceding rust-bridge error for reason)",
                .{ self.params.networkId, peer_id, node_name, protocol_tag },
            );
            return error.RequestDispatchFailed;
        }

        if (callback) |handler| {
            const peer_id_copy = try self.allocator.dupe(u8, peer_id);
            errdefer self.allocator.free(peer_id_copy);
            var callback_entry = interface.ReqRespRequestCallback.init(method, self.allocator, handler, peer_id_copy);
            errdefer callback_entry.deinit();

            self.rpcCallbacks.put(self.allocator, request_id, callback_entry) catch |err| {
                self.allocator.free(peer_id_copy);
                self.logger.err(
                    "network-{d}:: Failed to register RPC callback for request_id={d} peer={s}{f}: {any}",
                    .{ self.params.networkId, request_id, peer_id, node_name, err },
                );
                return err;
            };
        }

        return request_id;
    }

    fn notifyRpcErrorWithOwnedMessage(
        self: *Self,
        request_id: u64,
        method: interface.LeanSupportedProtocol,
        code: u32,
        message: []u8,
    ) void {
        var event = interface.ReqRespResponseEvent.initError(request_id, method, .{
            .code = code,
            .message = message,
        });
        defer event.deinit(self.allocator);

        if (self.rpcCallbacks.fetchRemove(request_id)) |entry| {
            var callback = entry.value;
            const peer_id = callback.peer_id;
            const node_name = self.node_registry.getNodeNameFromPeerId(peer_id);
            callback.notify(&event) catch |notify_err| {
                self.logger.err(
                    "network-{d}:: Failed to deliver RPC error callback for request_id={d} from peer={s}{f}: {any}",
                    .{ self.params.networkId, request_id, peer_id, node_name, notify_err },
                );
            };
            callback.deinit();
        } else {
            self.logger.warn(
                "network-{d}:: Dropping RPC error for unknown request_id={d}",
                .{ self.params.networkId, request_id },
            );
        }
    }

    fn notifyRpcErrorFmt(
        self: *Self,
        request_id: u64,
        method: interface.LeanSupportedProtocol,
        code: u32,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        const callback_ptr = self.rpcCallbacks.getPtr(request_id);
        const peer_id = if (callback_ptr) |cb| cb.peer_id else "unknown";
        const node_name = if (callback_ptr) |cb| self.node_registry.getNodeNameFromPeerId(cb.peer_id) else zeam_utils.OptionalNode.init(null);
        const owned_message = std.fmt.allocPrint(self.allocator, fmt, args) catch |alloc_err| {
            self.logger.err(
                "network-{d}:: Failed to allocate RPC error message for request_id={d} from peer={s}{f}: {any}",
                .{ self.params.networkId, request_id, peer_id, node_name, alloc_err },
            );
            return;
        };

        self.notifyRpcErrorWithOwnedMessage(request_id, method, code, owned_message);
    }

    /// Fail every in-flight RPC whose callback is waiting on the given peer.
    ///
    /// The Rust bridge already times requests out via REQUEST_TIMEOUT, but that
    /// window is seconds-to-minutes. When a peer disconnects we know the
    /// response will never arrive, so notify all matching callbacks with a
    /// PeerDisconnected failure and drop them from the map immediately. This
    /// gives callers fast feedback and prevents the callback entries (plus
    /// their owned peer_id strings) from sitting around until the Rust-side
    /// timeout fires. `ReqRespRequestCallback.deinit` frees the peer_id buffer.
    fn failInflightRpcsForPeer(self: *Self, peer_id: []const u8) !void {
        // Collect request_ids first so we can mutate the map without iterator
        // invalidation while also holding a reference to each callback's peer_id.
        var matching: std.ArrayList(u64) = .empty;
        defer matching.deinit(self.allocator);

        var it = self.rpcCallbacks.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.peer_id, peer_id)) {
                try matching.append(self.allocator, entry.key_ptr.*);
            }
        }

        // 499 = "Client Closed Request" (nginx-style); closest well-known code
        // for "peer went away before responding". Distinct from 408 used by the
        // Rust-side REQUEST_TIMEOUT so callers can tell them apart.
        const PEER_DISCONNECTED_CODE: u32 = 499;

        for (matching.items) |request_id| {
            const callback_ptr = self.rpcCallbacks.getPtr(request_id) orelse continue;
            const method = callback_ptr.method;
            self.notifyRpcErrorFmt(
                request_id,
                method,
                PEER_DISCONNECTED_CODE,
                "peer disconnected before responding (peer={s})",
                .{peer_id},
            );
        }
    }

    pub fn onRPCRequest(ptr: *anyopaque, data: *interface.ReqRespRequest, stream: interface.ReqRespServerStream) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.reqrespHandler.onReqRespRequest(data, stream);
    }

    pub fn subscribeReqResp(ptr: *anyopaque, handler: interface.OnReqRespRequestCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.reqrespHandler.subscribe(handler);
    }

    pub fn subscribePeerEvents(ptr: *anyopaque, handler: interface.OnPeerEventCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.peerEventHandler.subscribe(handler);
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
                .sendRequestFn = sendRPCRequest,
                .onReqRespRequestFn = onRPCRequest,
                .subscribeFn = subscribeReqResp,
            },
            .peers = .{
                .ptr = self,
                .subscribeFn = subscribePeerEvents,
            },
        };
    }

    fn multiaddrsToString(allocator: Allocator, addrs: []const Multiaddr) ![:0]u8 {
        if (addrs.len == 0) {
            return try allocator.dupeZ(u8, "");
        }

        var addr_strings = std.ArrayList([]const u8).empty;
        defer {
            for (addr_strings.items) |addr_str| {
                allocator.free(addr_str);
            }
            addr_strings.deinit(allocator);
        }

        for (addrs) |addr| {
            const addr_str = try addr.toString(allocator);
            try addr_strings.append(allocator, addr_str);
        }

        const joined = try std.mem.join(allocator, ",", addr_strings.items);
        defer allocator.free(joined);

        const result = try allocator.dupeZ(u8, joined);

        return result;
    }
};

test "validateRpcSnappyHeader rejects oversized declared size" {
    var scratch: [MAX_VARINT_BYTES]u8 = undefined;
    const encoded = uvarint.encode(usize, MAX_RPC_MESSAGE_SIZE + 1, &scratch);
    try std.testing.expectError(error.PayloadTooLarge, validateRpcSnappyHeader(encoded));
}

test "validateGossipSnappyHeader returns typed errors for each rejection class" {
    // Regression for Hive `gossip: ignores malformed ssz` (test 390 on
    // hive.leanroadmap.org / suite 1778305924-...). The simulator publishes
    // 1024 bytes of 0xef on a valid block topic; an unguarded decoder hit an
    // `integer overflow` panic in the third-party snappy uvarint and crashed
    // the network thread, cascading into ~26 follow-up failures as the second
    // node became unreachable.
    //
    // Each sub-case asserts both the rejection AND its specific error variant
    // so log/metric attribution stays distinct (PR #855 review #2).

    // 1024 bytes of 0xef: the original Hive panic payload. Rejected as
    // InvalidVarint (every byte is a continuation byte; no terminator).
    const garbage = [_]u8{0xef} ** 1024;
    try std.testing.expectError(
        error.InvalidVarint,
        validateGossipSnappyHeader(&garbage, MAX_GOSSIP_BLOCK_SIZE),
    );

    // 11 continuation bytes then a terminator: varint > u64.
    var long_varint: [12]u8 = undefined;
    @memset(long_varint[0..11], 0xff);
    long_varint[11] = 0x01;
    try std.testing.expectError(
        error.InvalidVarint,
        validateGossipSnappyHeader(&long_varint, MAX_GOSSIP_BLOCK_SIZE),
    );

    // Empty payload.
    const empty = [_]u8{};
    try std.testing.expectError(
        error.EmptyMessage,
        validateGossipSnappyHeader(&empty, MAX_GOSSIP_BLOCK_SIZE),
    );

    // Declared size exceeds the per-topic limit (oversized claim).
    var oversize_buf: [MAX_VARINT_BYTES + 1]u8 = undefined;
    const oversize_header = uvarint.encode(usize, MAX_GOSSIP_BLOCK_SIZE + 1, oversize_buf[0..MAX_VARINT_BYTES]);
    oversize_buf[oversize_header.len] = 0x00; // payload byte so it isn't header-only
    try std.testing.expectError(
        error.DeclaredPayloadTooLarge,
        validateGossipSnappyHeader(oversize_buf[0 .. oversize_header.len + 1], MAX_GOSSIP_BLOCK_SIZE),
    );

    // Header-only buffer for a non-zero declared size: header is valid, body
    // is missing. Distinct error so callers can attribute truncated streams
    // separately from corrupt headers (PR #855 review #7).
    var header_only_buf: [MAX_VARINT_BYTES]u8 = undefined;
    const header_only = uvarint.encode(usize, 32, &header_only_buf);
    try std.testing.expectError(
        error.HeaderWithoutBody,
        validateGossipSnappyHeader(header_only, MAX_GOSSIP_BLOCK_SIZE),
    );

    // Well-formed header followed by at least one payload byte: accepted.
    // The validator does *not* check that the body length matches the
    // declared uncompressed size — that's the decoder's job. See doc comment
    // on `validateSnappyHeader` (PR #855 review #12).
    var ok_buf: [MAX_VARINT_BYTES + 1]u8 = undefined;
    const ok_header = uvarint.encode(usize, 32, ok_buf[0..MAX_VARINT_BYTES]);
    ok_buf[ok_header.len] = 0x00;
    const ok = try validateGossipSnappyHeader(ok_buf[0 .. ok_header.len + 1], MAX_GOSSIP_BLOCK_SIZE);
    try std.testing.expectEqual(@as(usize, 32), ok.value);

    // Zero-length declared payload with no body is accepted (snappy can
    // legitimately describe an empty uncompressed block as just the varint 0).
    const zero_header = [_]u8{0x00};
    const zero_ok = try validateGossipSnappyHeader(&zero_header, MAX_GOSSIP_BLOCK_SIZE);
    try std.testing.expectEqual(@as(usize, 0), zero_ok.value);

    // Body shorter than declared but well-formed header: validator accepts
    // by design. The decoder is authoritative for body integrity. Pinning
    // current behaviour so a future change to also enforce body length here
    // is a deliberate breaking change rather than a silent drift.
    var short_body_buf: [MAX_VARINT_BYTES + 4]u8 = undefined;
    const short_body_header = uvarint.encode(usize, 1024, short_body_buf[0..MAX_VARINT_BYTES]);
    @memset(short_body_buf[short_body_header.len .. short_body_header.len + 4], 0x00);
    const short_body_ok = try validateGossipSnappyHeader(
        short_body_buf[0 .. short_body_header.len + 4],
        MAX_GOSSIP_BLOCK_SIZE,
    );
    try std.testing.expectEqual(@as(usize, 1024), short_body_ok.value);

    // Boundary: declared == max_size is accepted (strict `>`); declared ==
    // max_size + 1 is rejected. Pinned to match upstream
    // `snappyz.decodeWithMax`'s `if (block.blockLen > max_size)` contract
    // (PR #855 review #13). If upstream ever flips to `>=` this test will
    // fail loudly instead of the validator silently disagreeing across a
    // 1-byte gap.
    var boundary_buf: [MAX_VARINT_BYTES + 1]u8 = undefined;
    const at_limit_header = uvarint.encode(usize, MAX_GOSSIP_BLOCK_SIZE, boundary_buf[0..MAX_VARINT_BYTES]);
    boundary_buf[at_limit_header.len] = 0x00;
    const at_limit_ok = try validateGossipSnappyHeader(
        boundary_buf[0 .. at_limit_header.len + 1],
        MAX_GOSSIP_BLOCK_SIZE,
    );
    try std.testing.expectEqual(@as(usize, MAX_GOSSIP_BLOCK_SIZE), at_limit_ok.value);
}

test "snappyz.decodeWithMax regression canary: 1024 bytes of 0xef must not panic" {
    // REGRESSION CANARY (PR #855 review #11): if this test ever panics the
    // whole test binary instead of returning `error.Corrupt`, the upstream
    // `zig-snappy` dependency has been downgraded below v0.0.5 and the
    // uvarint integer-overflow fix is gone. Restore the pin in `build.zig.zon`
    // before doing anything else — the gossip thread will crash on the next
    // malformed payload.
    //
    // Belt-and-suspenders: even if the dep is rolled back, the
    // `validateGossipSnappyHeader` test above still ensures the gossip
    // handler short-circuits before reaching the decoder.
    const garbage = [_]u8{0xef} ** 1024;
    const result = snappyz.decodeWithMax(std.testing.allocator, &garbage, MAX_GOSSIP_BLOCK_SIZE);
    try std.testing.expectError(error.Corrupt, result);
}
