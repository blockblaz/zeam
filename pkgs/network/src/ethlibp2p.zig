const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const ssz = @import("ssz");
const types = @import("@zeam/types");
const xev = @import("xev");
const multiformats = @import("multiformats");
const Multiaddr = multiformats.multiaddr.Multiaddr;
const uvarint = multiformats.uvarint;
const zeam_utils = @import("@zeam/utils");
const jsonToString = zeam_utils.jsonToString;

const interface = @import("./interface.zig");
const NetworkInterface = interface.NetworkInterface;
const snappyz = @import("snappyz");
const snappyframesz = @import("snappyframesz");

const ServerStreamError = error{
    StreamAlreadyFinished,
    InvalidResponseVariant,
};

const MAX_RPC_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const MAX_VARINT_BYTES: usize = uvarint.bufferSize(usize);

const FrameDecodeError = error{
    EmptyFrame,
    PayloadTooLarge,
    LengthMismatch,
    Incomplete,
} || uvarint.VarintParseError;

const LeanSupportedProtocol = interface.LeanSupportedProtocol;

fn encodeVarint(buffer: *std.ArrayListUnmanaged(u8), allocator: Allocator, value: usize) !void {
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

fn buildRequestFrame(allocator: Allocator, payload: []const u8) ![]u8 {
    if (payload.len > MAX_RPC_MESSAGE_SIZE) {
        return error.PayloadTooLarge;
    }

    var frame = std.ArrayListUnmanaged(u8).empty;
    errdefer frame.deinit(allocator);

    try encodeVarint(&frame, allocator, payload.len);
    try frame.appendSlice(allocator, payload);

    return frame.toOwnedSlice(allocator);
}

fn buildResponseFrame(allocator: Allocator, code: u8, payload: []const u8) ![]u8 {
    if (payload.len > MAX_RPC_MESSAGE_SIZE) {
        return error.PayloadTooLarge;
    }

    var frame = std.ArrayListUnmanaged(u8).empty;
    errdefer frame.deinit(allocator);

    try frame.append(allocator, code);
    try encodeVarint(&frame, allocator, payload.len);
    try frame.appendSlice(allocator, payload);

    return frame.toOwnedSlice(allocator);
}

fn parseRequestFrame(bytes: []const u8) FrameDecodeError![]const u8 {
    if (bytes.len == 0) {
        return error.EmptyFrame;
    }

    const decoded = try decodeVarint(bytes);
    if (decoded.value > MAX_RPC_MESSAGE_SIZE) {
        return error.PayloadTooLarge;
    }

    const total = decoded.length + decoded.value;
    if (total != bytes.len) {
        return error.LengthMismatch;
    }

    return bytes[decoded.length..total];
}

fn parseResponseFrame(bytes: []const u8) FrameDecodeError!struct {
    code: u8,
    payload: []const u8,
} {
    if (bytes.len == 0) {
        return error.EmptyFrame;
    }
    if (bytes.len == 1) {
        return error.Incomplete;
    }

    const decoded = try decodeVarint(bytes[1..]);
    if (decoded.value > MAX_RPC_MESSAGE_SIZE) {
        return error.PayloadTooLarge;
    }

    const total = 1 + decoded.length + decoded.value;
    if (total != bytes.len) {
        return error.LengthMismatch;
    }

    return .{
        .code = bytes[0],
        .payload = bytes[1 + decoded.length .. total],
    };
}

const ServerStreamContext = struct {
    zigHandler: *EthLibp2p,
    channel_id: u64,
    peer_id: []const u8,
    method: interface.LeanSupportedProtocol,
    finished: bool = false,
};

fn serverStreamSendResponse(ptr: *anyopaque, response: *const interface.ReqRespResponse) anyerror!void {
    const ctx: *ServerStreamContext = @ptrCast(@alignCast(ptr));
    if (ctx.finished) {
        return ServerStreamError.StreamAlreadyFinished;
    }

    const allocator = ctx.zigHandler.allocator;
    const response_method = std.meta.activeTag(response.*);
    const response_method_name = @tagName(response_method);
    ctx.zigHandler.logger.debug(
        "network-{d}:: serverStreamSendResponse ctx.method={s} response.tag={s}",
        .{ ctx.zigHandler.params.networkId, @tagName(ctx.method), @tagName(response_method) },
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
            "network-{d}:: Failed to serialize {s} response for peer={s} channel={d}: {any}",
            .{ ctx.zigHandler.params.networkId, response_method_name, ctx.peer_id, ctx.channel_id, err },
        );
        return err;
    };
    defer allocator.free(encoded);

    const framed = snappyframesz.encode(allocator, encoded) catch |err| {
        ctx.zigHandler.logger.err(
            "network-{d}:: Failed to snappy-frame {s} response for peer={s} channel={d}: {any}",
            .{ ctx.zigHandler.params.networkId, response_method_name, ctx.peer_id, ctx.channel_id, err },
        );
        return err;
    };
    defer allocator.free(framed);

    const frame = try buildResponseFrame(allocator, 0, framed);
    defer allocator.free(frame);

    ctx.zigHandler.logger.debug(
        "network-{d}:: Streaming {s} response to peer={s} channel={d}",
        .{ ctx.zigHandler.params.networkId, response_method_name, ctx.peer_id, ctx.channel_id },
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

    ctx.zigHandler.logger.warn(
        "network-{d}:: Streaming RPC error to peer={s} channel={d} code={d}: {s}",
        .{ ctx.zigHandler.params.networkId, ctx.peer_id, ctx.channel_id, code, message },
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

/// Writes failed deserialization bytes to disk for debugging purposes
/// Returns the filename if the file was successfully created, null otherwise
/// If timestamp is null, generates a new timestamp automatically
fn writeFailedBytes(message_bytes: []const u8, message_type: []const u8, allocator: Allocator, timestamp: ?i64, logger: zeam_utils.ModuleLogger) ?[]const u8 {
    // Create dumps directory if it doesn't exist
    std.fs.cwd().makeDir("deserialization_dumps") catch |e| switch (e) {
        error.PathAlreadyExists => {}, // Directory already exists, continue
        else => {
            logger.err("Failed to create deserialization dumps directory: {any}", .{e});
            return null;
        },
    };

    // Generate timestamp-based filename
    const actual_timestamp = timestamp orelse std.time.timestamp();
    const filename = std.fmt.allocPrint(allocator, "deserialization_dumps/failed_{s}_{d}.bin", .{ message_type, actual_timestamp }) catch |e| {
        logger.err("Failed to allocate filename for {s} deserialization dump: {any}", .{ message_type, e });
        return null;
    };
    defer allocator.free(filename);

    // Write bytes to file
    const file = std.fs.cwd().createFile(filename, .{ .truncate = true }) catch |e| {
        logger.err("Failed to create file {s} for {s} deserialization dump: {any}", .{ filename, message_type, e });
        return null;
    };
    defer file.close();

    file.writeAll(message_bytes) catch |e| {
        logger.err("Failed to write {d} bytes to file {s} for {s} deserialization dump: {any}", .{ message_bytes.len, filename, message_type, e });
        return null;
    };

    logger.warn("SSZ deserialization failed for {s} message - written {d} bytes to debug file: {s}", .{ message_type, message_bytes.len, filename });
    return filename;
}

export fn handleMsgFromRustBridge(zigHandler: *EthLibp2p, topic_str: [*:0]const u8, message_ptr: [*]const u8, message_len: usize) void {
    const topic = interface.LeanNetworkTopic.decode(zigHandler.allocator, topic_str) catch |err| {
        zigHandler.logger.err("Ignoring Invalid topic_id={d} sent in handleMsgFromRustBridge: {any}", .{ std.mem.span(topic_str), err });
        return;
    };

    const message_bytes: []const u8 = message_ptr[0..message_len];

    const uncompressed_message = snappyz.decode(zigHandler.allocator, message_bytes) catch |e| {
        zigHandler.logger.err("Error in snappyz decoding the message for topic={s}: {any}", .{ std.mem.span(topic_str), e });
        if (writeFailedBytes(message_bytes, "snappyz_decode", zigHandler.allocator, null, zigHandler.logger)) |filename| {
            zigHandler.logger.err("Snappyz decode failed - debug file created: {s}", .{filename});
        } else {
            zigHandler.logger.err("Snappyz decode failed - could not create debug file", .{});
        }
        return;
    };
    defer zigHandler.allocator.free(uncompressed_message);
    const message: interface.GossipMessage = switch (topic.gossip_topic) {
        .block => blockmessage: {
            var message_data: types.SignedBeamBlock = undefined;
            ssz.deserialize(types.SignedBeamBlock, uncompressed_message, &message_data, zigHandler.allocator) catch |e| {
                zigHandler.logger.err("Error in deserializing the signed block message: {any}", .{e});
                if (writeFailedBytes(uncompressed_message, "block", zigHandler.allocator, null, zigHandler.logger)) |filename| {
                    zigHandler.logger.err("Block deserialization failed - debug file created: {s}", .{filename});
                } else {
                    zigHandler.logger.err("Block deserialization failed - could not create debug file", .{});
                }
                return;
            };

            break :blockmessage .{ .block = message_data };
        },
        .vote => votemessage: {
            var message_data: types.SignedVote = undefined;
            ssz.deserialize(types.SignedVote, uncompressed_message, &message_data, zigHandler.allocator) catch |e| {
                zigHandler.logger.err("Error in deserializing the signed vote message: {any}", .{e});
                if (writeFailedBytes(uncompressed_message, "vote", zigHandler.allocator, null, zigHandler.logger)) |filename| {
                    zigHandler.logger.err("Vote deserialization failed - debug file created: {s}", .{filename});
                } else {
                    zigHandler.logger.err("Vote deserialization failed - could not create debug file", .{});
                }
                return;
            };
            break :votemessage .{ .vote = message_data };
        },
    };

    const message_str = message.toJsonString(zigHandler.allocator) catch |e| {
        zigHandler.logger.err("Failed to convert message to JSON string: {any}", .{e});
        return;
    };
    defer zigHandler.allocator.free(message_str);

    zigHandler.logger.debug("\network-{d}:: !!!handleMsgFromRustBridge topic={s}:: message={s} from bytes={any} \n", .{ zigHandler.params.networkId, std.mem.span(topic_str), message_str, message_bytes });

    // TODO: figure out why scheduling on the loop is not working
    zigHandler.gossipHandler.onGossip(&message, false) catch |e| {
        zigHandler.logger.err("onGossip handling of message failed with error e={any}", .{e});
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

    const rpc_protocol = LeanSupportedProtocol.fromSlice(protocol_slice) orelse {
        zigHandler.logger.warn(
            "network-{d}:: Unsupported RPC protocol from peer={s} on channel={d}: {s}",
            .{ zigHandler.params.networkId, peer_id_slice, channel_id, protocol_slice },
        );
        return;
    };

    const request_frame: []const u8 = request_ptr[0..request_len];
    const request_payload = parseRequestFrame(request_frame) catch |err| {
        zigHandler.logger.err(
            "network-{d}:: Invalid RPC request frame from peer={s} protocol={s}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, protocol_slice, err },
        );
        return;
    };

    const request_bytes = snappyframesz.decode(zigHandler.allocator, request_payload) catch |err| {
        zigHandler.logger.err(
            "network-{d}:: Failed to decode snappy-framed RPC request from peer={s} protocol={s}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, protocol_slice, err },
        );
        return;
    };
    defer zigHandler.allocator.free(request_bytes);

    const method = rpc_protocol;
    var request = interface.ReqRespRequest.deserialize(zigHandler.allocator, method, request_bytes) catch |err| {
        const label = method.name();
        zigHandler.logger.err(
            "Error in deserializing the {s} RPC request from peer={s}: {any}",
            .{ label, peer_id_slice, err },
        );
        if (writeFailedBytes(request_bytes, label, zigHandler.allocator, null, zigHandler.logger)) |filename| {
            zigHandler.logger.err("RPC {s} deserialization failed - debug file created: {s}", .{ label, filename });
        } else {
            zigHandler.logger.err("RPC {s} deserialization failed - could not create debug file", .{label});
        }
        return;
    };
    defer request.deinit();

    const request_str = request.toJsonString(zigHandler.allocator) catch |e| {
        zigHandler.logger.err("Failed to convert RPC request to JSON string: {any}", .{e});
        return;
    };
    defer zigHandler.allocator.free(request_str);

    zigHandler.logger.debug(
        "network-{d}:: !!!handleRPCRequestFromRustBridge peer={s} protocol={s} channel={d}:: request={s}",
        .{ zigHandler.params.networkId, peer_id_slice, rpc_protocol.protocolId(), channel_id, request_str },
    );

    const request_method = std.meta.activeTag(request);

    var stream_context = ServerStreamContext{
        .zigHandler = zigHandler,
        .channel_id = channel_id,
        .peer_id = peer_id_slice,
        .method = request_method,
    };

    var stream = interface.ReqRespServerStream{
        .ptr = &stream_context,
        .sendResponseFn = serverStreamSendResponse,
        .sendErrorFn = serverStreamSendError,
        .finishFn = serverStreamFinish,
        .isFinishedFn = serverStreamIsFinished,
    };

    zigHandler.reqrespHandler.onReqRespRequest(&request, stream) catch |e| {
        zigHandler.logger.err(
            "network-{d}:: Error while handling RPC request from peer={s} on channel={d}: {any}",
            .{ zigHandler.params.networkId, peer_id_slice, channel_id, e },
        );

        if (!stream.isFinished()) {
            const msg = std.fmt.allocPrint(zigHandler.allocator, "Handler error: {any}", .{e}) catch null;
            if (msg) |owned| {
                defer zigHandler.allocator.free(owned);
                stream.sendError(1, owned) catch |send_err| {
                    zigHandler.logger.err(
                        "network-{d}:: Failed to send RPC error response for peer={s} channel={d}: {any}",
                        .{ zigHandler.params.networkId, peer_id_slice, channel_id, send_err },
                    );
                };
            } else {
                stream.finish() catch |finish_err| {
                    zigHandler.logger.err(
                        "network-{d}:: Failed to finalize errored RPC stream for peer={s} channel={d}: {any}",
                        .{ zigHandler.params.networkId, peer_id_slice, channel_id, finish_err },
                    );
                };
            }
        }
        return;
    };

    if (!stream.isFinished()) {
        stream.finish() catch |finish_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to finalize RPC stream for peer={s} channel={d}: {any}",
                .{ zigHandler.params.networkId, peer_id_slice, channel_id, finish_err },
            );
        };
    }
}

export fn handleRPCResponseFromRustBridge(
    zigHandler: *EthLibp2p,
    request_id: u64,
    protocol_id: [*:0]const u8,
    response_ptr: [*]const u8,
    response_len: usize,
) void {
    const protocol_slice = std.mem.span(protocol_id);

    const callback_ptr = zigHandler.rpcCallbacks.getPtr(request_id) orelse {
        zigHandler.logger.warn(
            "network-{d}:: Received RPC response for unknown request_id={d} protocol={s}",
            .{ zigHandler.params.networkId, request_id, protocol_slice },
        );
        return;
    };
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
            "network-{d}:: RPC protocol/method mismatch for request_id={d}: protocol={s} method={s}",
            .{ zigHandler.params.networkId, request_id, protocol.protocolId(), @tagName(method) },
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
            "network-{d}:: RPC error response for request_id={d} protocol={s} code={d}",
            .{ zigHandler.params.networkId, request_id, protocol.protocolId(), parsed_frame.code },
        );

        const owned_message = zigHandler.allocator.dupe(u8, parsed_frame.payload) catch |dup_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to duplicate RPC error payload for request_id={d}: {any}",
                .{ zigHandler.params.networkId, request_id, dup_err },
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
        "network-{d}:: Received RPC response for request_id={d} protocol={s} size={d}",
        .{ zigHandler.params.networkId, request_id, protocol.protocolId(), response_bytes.len },
    );

    callback_ptr.notify(&event) catch |notify_err| {
        zigHandler.logger.err(
            "network-{d}:: Failed to notify RPC success callback for request_id={d}: {any}",
            .{ zigHandler.params.networkId, request_id, notify_err },
        );
    };
}

export fn handleRPCEndOfStreamFromRustBridge(
    zigHandler: *EthLibp2p,
    request_id: u64,
    protocol_id: [*:0]const u8,
) void {
    const protocol_slice = std.mem.span(protocol_id);
    const protocol_str = if (LeanSupportedProtocol.fromSlice(protocol_slice)) |proto| proto.protocolId() else protocol_slice;

    if (zigHandler.rpcCallbacks.fetchRemove(request_id)) |entry| {
        var callback = entry.value;
        const method = callback.method;

        var event = interface.ReqRespResponseEvent.initCompleted(request_id, method);
        defer event.deinit(zigHandler.allocator);

        zigHandler.logger.debug(
            "network-{d}:: Received RPC end-of-stream for request_id={d} protocol={s}",
            .{ zigHandler.params.networkId, request_id, protocol_str },
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
            "network-{d}:: Received RPC end-of-stream for unknown request_id={d} protocol={s}",
            .{ zigHandler.params.networkId, request_id, protocol_str },
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

        const owned_message = zigHandler.allocator.dupe(u8, message_slice) catch |alloc_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to duplicate RPC error message for request_id={d}: {any}",
                .{ zigHandler.params.networkId, request_id, alloc_err },
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
            "network-{d}:: Received RPC error for request_id={d} protocol={s} code={d}",
            .{ zigHandler.params.networkId, request_id, protocol_str, code },
        );

        callback.notify(&event) catch |notify_err| {
            zigHandler.logger.err(
                "network-{d}:: Failed to notify RPC error for request_id={d}: {any}",
                .{ zigHandler.params.networkId, request_id, notify_err },
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

export fn handlePeerConnectedFromRustBridge(zigHandler: *EthLibp2p, peer_id: [*:0]const u8) void {
    const peer_id_slice = std.mem.span(peer_id);
    zigHandler.logger.info("network-{d}:: Peer connected: {s}", .{ zigHandler.params.networkId, peer_id_slice });

    zigHandler.peerEventHandler.onPeerConnected(peer_id_slice) catch |e| {
        zigHandler.logger.err("network-{d}:: Error handling peer connected event: {any}", .{ zigHandler.params.networkId, e });
    };
}

export fn handlePeerDisconnectedFromRustBridge(zigHandler: *EthLibp2p, peer_id: [*:0]const u8) void {
    const peer_id_slice = std.mem.span(peer_id);
    zigHandler.logger.info("network-{d}:: Peer disconnected: {s}", .{ zigHandler.params.networkId, peer_id_slice });

    zigHandler.peerEventHandler.onPeerDisconnected(peer_id_slice) catch |e| {
        zigHandler.logger.err("network-{d}:: Error handling peer disconnected event: {any}", .{ zigHandler.params.networkId, e });
    };
}

export fn releaseStartNetworkParams(zig_handler: *EthLibp2p, local_private_key: [*:0]const u8, listen_addresses: [*:0]const u8, connect_addresses: [*:0]const u8, topics: [*:0]const u8) void {
    const listen_slice = std.mem.span(listen_addresses);
    zig_handler.allocator.free(listen_slice);

    const connect_slice = std.mem.span(connect_addresses);
    zig_handler.allocator.free(connect_slice);

    const topics_slice = std.mem.span(topics);
    zig_handler.allocator.free(topics_slice);

    const private_key_slice = std.mem.span(local_private_key);
    zig_handler.allocator.free(private_key_slice);
}

pub extern fn create_and_run_network(
    network_id: u32,
    handle: *EthLibp2p,
    local_private_key: [*:0]const u8,
    listen_addresses: [*:0]const u8,
    connect_addresses: [*:0]const u8,
    topics: [*:0]const u8,
) void;
pub extern fn publish_msg_to_rust_bridge(
    networkId: u32,
    topic_str: [*:0]const u8,
    message_ptr: [*]const u8,
    message_len: usize,
) void;
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

pub const EthLibp2pParams = struct {
    networkId: u32,
    network_name: []const u8,
    local_private_key: []const u8,
    listen_addresses: []const Multiaddr,
    connect_peers: ?[]const Multiaddr,
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

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *xev.Loop,
        params: EthLibp2pParams,
        logger: zeam_utils.ModuleLogger,
    ) !Self {
        const owned_network_name = try allocator.dupe(u8, params.network_name);
        errdefer allocator.free(owned_network_name);

        const gossip_handler = try interface.GenericGossipHandler.init(allocator, loop, params.networkId, logger);
        errdefer gossip_handler.deinit();

        const peer_event_handler = try interface.PeerEventHandler.init(allocator, params.networkId, logger);
        errdefer peer_event_handler.deinit();

        const reqresp_handler = try interface.ReqRespRequestHandler.init(allocator, params.networkId, logger);
        errdefer reqresp_handler.deinit();

        return Self{
            .allocator = allocator,
            .params = .{
                .networkId = params.networkId,
                .network_name = owned_network_name,
                .local_private_key = params.local_private_key,
                .listen_addresses = params.listen_addresses,
                .connect_peers = params.connect_peers,
            },
            .gossipHandler = gossip_handler,
            .peerEventHandler = peer_event_handler,
            .reqrespHandler = reqresp_handler,
            .rpcCallbacks = std.AutoHashMapUnmanaged(u64, interface.ReqRespRequestCallback).empty,
            .logger = logger,
        };
    }

    pub fn deinit(self: *Self) void {
        self.gossipHandler.deinit();
        self.peerEventHandler.deinit();

        for (self.params.listen_addresses) |addr| addr.deinit();
        self.allocator.free(self.params.listen_addresses);

        if (self.params.connect_peers) |peers| {
            for (peers) |addr| addr.deinit();
            self.allocator.free(peers);
        }

        self.allocator.free(self.params.network_name);

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

        var topics_list: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (topics_list.items) |topic_str| {
                self.allocator.free(topic_str);
            }
            topics_list.deinit(self.allocator);
        }

        for (std.enums.values(interface.GossipTopic)) |gossip_topic| {
            var topic = try interface.LeanNetworkTopic.init(self.allocator, gossip_topic, .ssz_snappy, self.params.network_name);
            defer topic.deinit();
            const topic_str = try topic.encode();
            try topics_list.append(self.allocator, topic_str);
        }
        const topics_str = try std.mem.joinZ(self.allocator, ",", topics_list.items);

        self.rustBridgeThread = try Thread.spawn(.{}, create_and_run_network, .{ self.params.networkId, self, local_private_key.ptr, listen_addresses_str.ptr, connect_peers_str.ptr, topics_str.ptr });
    }

    pub fn publish(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // publish
        var topic = try data.getLeanNetworkTopic(self.allocator, self.params.network_name);
        defer topic.deinit();
        const topic_str = try topic.encodeZ();
        defer self.allocator.free(topic_str);

        // TODO: deinit the message later ob once done
        const message = try data.serialize(self.allocator);
        defer self.allocator.free(message);

        const compressed_message = try snappyz.encode(self.allocator, message);
        defer self.allocator.free(compressed_message);
        self.logger.debug("network-{d}:: calling publish_msg_to_rust_bridge with message={any} for data={any}", .{ self.params.networkId, compressed_message, data });
        publish_msg_to_rust_bridge(self.params.networkId, topic_str.ptr, compressed_message.ptr, compressed_message.len);
    }

    pub fn subscribe(ptr: *anyopaque, topics: []interface.GossipTopic, handler: interface.OnGossipCbHandler) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.subscribe(topics, handler);
    }

    pub fn onGossip(ptr: *anyopaque, data: *const interface.GossipMessage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.gossipHandler.onGossip(data, false);
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

        const encoded_message = req.serialize(self.allocator) catch |err| {
            self.logger.err(
                "network-{d}:: Failed to serialize RPC request for peer={s} method={s}: {any}",
                .{ self.params.networkId, peer_id, @tagName(method), err },
            );
            return err;
        };

        defer self.allocator.free(encoded_message);

        const framed_payload = snappyframesz.encode(self.allocator, encoded_message) catch |err| {
            self.logger.err(
                "network-{d}:: Failed to snappy-frame RPC request payload for peer={s} protocol_tag={d}: {any}",
                .{ self.params.networkId, peer_id, protocol_tag, err },
            );
            return err;
        };
        defer self.allocator.free(framed_payload);

        const frame = buildRequestFrame(self.allocator, framed_payload) catch |err| {
            self.logger.err(
                "network-{d}:: Failed to build RPC request frame for peer={s} protocol_tag={d}: {any}",
                .{ self.params.networkId, peer_id, protocol_tag, err },
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
            return error.RequestDispatchFailed;
        }

        if (callback) |handler| {
            var callback_entry = interface.ReqRespRequestCallback.init(method, self.allocator, handler);
            errdefer callback_entry.deinit();

            self.rpcCallbacks.put(self.allocator, request_id, callback_entry) catch |err| {
                self.logger.err(
                    "network-{d}:: Failed to register RPC callback for request_id={d} peer={s}: {any}",
                    .{ self.params.networkId, request_id, peer_id, err },
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
            callback.notify(&event) catch |notify_err| {
                self.logger.err(
                    "network-{d}:: Failed to deliver RPC error callback for request_id={d}: {any}",
                    .{ self.params.networkId, request_id, notify_err },
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
        const owned_message = std.fmt.allocPrint(self.allocator, fmt, args) catch |alloc_err| {
            self.logger.err(
                "network-{d}:: Failed to allocate RPC error message for request_id={d}: {any}",
                .{ self.params.networkId, request_id, alloc_err },
            );
            return;
        };

        self.notifyRpcErrorWithOwnedMessage(request_id, method, code, owned_message);
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

        var addr_strings = std.ArrayListUnmanaged([]const u8).empty;
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
