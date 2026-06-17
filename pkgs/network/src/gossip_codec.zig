//! Pure-Zig snappy-block + SSZ codec helpers for the gossipsub path,
//! reused by `ethlibp2p_v2.zig` and the related #942 regression fixtures.
//!
//! Lifted out of the legacy `ethlibp2p.zig` (which the Rust-FFI consumer
//! used) so the codec stays around after that file + the `rust/libp2p-glue/`
//! crate are deleted. Behaviour is byte-identical to the legacy
//! implementations; the helpers are intentionally allocator- + logger-
//! agnostic so they're cheap to call from any transport layer.
//!
//! Surface (consumed by `ethlibp2p_v2.zig`):
//!   - `MESSAGE_DOMAIN_VALID_SNAPPY`
//!   - `MAX_GOSSIP_BLOCK_SIZE` / `MAX_RPC_MESSAGE_SIZE` / `GOSSIP_PREVIEW_MAX_BYTES`
//!   - `BytePreview` + `byteHexPreview`
//!   - `SnappyHeader` + `SnappyHeaderValidationError` + `validateGossipSnappyHeader`
//!   - `deserializeGossipMessage`

const std = @import("std");
const Allocator = std.mem.Allocator;
const ssz = @import("ssz");
const multiformats = @import("multiformats");
const uvarint = multiformats.uvarint;
const zeam_utils = @import("@zeam/utils");

/// gossipsub `message_id` domain prefix per the libp2p spec, used by the
/// validator hook side; kept here so the v2 path imports a single source.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [4]u8 = .{ 0x01, 0x00, 0x00, 0x00 };

/// Worst-case post-snappy block size for the gossip path (zeam's spec
/// caps this at 50 MB; same number as the legacy Rust glue). The per-topic
/// caller passes the appropriate `max_size` into `validateGossipSnappyHeader`.
pub const MAX_GOSSIP_BLOCK_SIZE: usize = 50 * 1024 * 1024;

/// Same 50 MB cap for the req/resp wire protocol.
pub const MAX_RPC_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

/// Maximum leading bytes inlined into gossip-decode-failure log lines for
/// the #942 diagnostic preview. 32 bytes is enough to cover any reasonable
/// framing-magic prefix (snappy-frames magic is 10 bytes; snappy-block
/// varint headers are 1–3 bytes plus body tags) while keeping the log
/// readable and bounded.
pub const GOSSIP_PREVIEW_MAX_BYTES: usize = 32;

const MAX_VARINT_BYTES: usize = uvarint.bufferSize(usize);

/// Fixed-capacity hex preview buffer returned by `byteHexPreview`.
/// `2 × GOSSIP_PREVIEW_MAX_BYTES` for the hex pair + (N − 1) single-space
/// separators between pairs. Lives on the caller's stack; `.slice()`
/// returns the populated prefix.
pub const BytePreview = struct {
    buf: [GOSSIP_PREVIEW_MAX_BYTES * 3]u8 = undefined,
    len: usize = 0,
    pub fn slice(self: *const BytePreview) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Build a `"aa bb cc ..."` hex preview of the first `max_bytes` of `data`
/// for #942 gossip-decode-failure logs. Returns an empty slice when `data`
/// is empty. Pure / stack-only; safe to call from FFI gossip ingress
/// without heap allocation.
pub fn byteHexPreview(data: []const u8, max_bytes: usize) BytePreview {
    var out = BytePreview{};
    const n = @min(@min(data.len, max_bytes), GOSSIP_PREVIEW_MAX_BYTES);
    const hex_digits = "0123456789abcdef";
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (i != 0) {
            out.buf[out.len] = ' ';
            out.len += 1;
        }
        const b = data[i];
        out.buf[out.len] = hex_digits[(b >> 4) & 0x0f];
        out.buf[out.len + 1] = hex_digits[b & 0x0f];
        out.len += 2;
    }
    return out;
}

/// Failure modes returned by the snappy block-format header validator.
/// Each variant maps to a distinct ops/attacker shape; callers should keep
/// them distinct in logs and (eventually) metrics.
pub const SnappyHeaderValidationError = error{
    /// Empty buffer — nothing to decode.
    EmptyMessage,
    /// Leading varint is corrupt (truncated, oversized, or u64-overflow).
    InvalidVarint,
    /// Varint decoded cleanly but declares a payload larger than the limit
    /// allowed for this protocol/topic. Strict `>` to match the upstream
    /// `snappyz.decodeWithMax` contract.
    DeclaredPayloadTooLarge,
    /// Header parsed cleanly and declared a non-zero payload, but the
    /// buffer contains only the header bytes (no body). Distinct from
    /// `InvalidVarint` because the header itself is well-formed; this is a
    /// truncated message, not a malformed one.
    HeaderWithoutBody,
};

/// Successful decode of a snappy block-format header: the declared
/// uncompressed length and the number of bytes the varint header occupies.
pub const SnappyHeader = struct {
    value: usize,
    length: usize,
};

fn decodeVarint(bytes: []const u8) uvarint.VarintParseError!struct { value: usize, length: usize } {
    const result = try uvarint.decode(usize, bytes);
    return .{
        .value = result.value,
        .length = bytes.len - result.remaining.len,
    };
}

/// Validate a snappy block-format header against a caller-supplied limit.
/// Header-only validation: a well-formed header followed by a body shorter
/// than `decoded.value` (but at least one byte) is accepted here — the
/// actual decoder is authoritative for body checks. We only reject the
/// degenerate case where the buffer is exactly the header and nothing
/// else, because that can never compress to a non-zero declared size.
pub fn validateGossipSnappyHeader(
    message_bytes: []const u8,
    max_size: usize,
) SnappyHeaderValidationError!SnappyHeader {
    if (message_bytes.len == 0) return error.EmptyMessage;
    const decoded = decodeVarint(message_bytes) catch return error.InvalidVarint;
    if (decoded.value > max_size) return error.DeclaredPayloadTooLarge;
    if (decoded.value > 0 and decoded.length == message_bytes.len) {
        return error.HeaderWithoutBody;
    }
    return .{ .value = decoded.value, .length = decoded.length };
}

/// On SSZ-decode failure, dump the raw bytes to
/// `deserialization_dumps/failed_<label>_<unixsec>.bin` and log the path.
/// Returns `true` on a successful write, `false` otherwise (the SSZ failure
/// itself is already surfaced by the caller — this is post-mortem
/// forensics, not a control-flow signal).
fn writeFailedBytes(
    message_bytes: []const u8,
    message_type: []const u8,
    allocator: Allocator,
    timestamp: ?i64,
    logger: zeam_utils.ModuleLogger,
) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().createDirPath(io, "deserialization_dumps") catch |e| {
        logger.err("Failed to create deserialization dumps directory: {any}", .{e});
        return false;
    };

    const actual_timestamp = timestamp orelse zeam_utils.unixTimestampSeconds();
    const filename = std.fmt.allocPrint(
        allocator,
        "deserialization_dumps/failed_{s}_{d}.bin",
        .{ message_type, actual_timestamp },
    ) catch |e| {
        logger.err("Failed to allocate filename for {s} deserialization dump: {any}", .{ message_type, e });
        return false;
    };
    defer allocator.free(filename);

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

    logger.warn(
        "SSZ deserialization failed for {s} message - written {d} bytes to debug file: {s}",
        .{ message_type, message_bytes.len, filename },
    );
    return true;
}

/// Generic SSZ deserializer for gossip messages. Returns `null` on failure
/// (with error logging and a forensic byte dump) so callers can simply
/// `orelse return` without separate error branches.
pub fn deserializeGossipMessage(
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
