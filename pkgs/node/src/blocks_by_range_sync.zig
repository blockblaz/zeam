//! `blocks_by_range` catch-up helpers (issue #893).
//!
//! Pure gap/decision logic and unit tests live here. `BeamNode` orchestration
//! (RPC handlers, chunk import, retry/fallback) remains in `node.zig` until a
//! dedicated sync-worker module is split out (review on PR #894).

const std = @import("std");

const types = @import("@zeam/types");

const constants = @import("./constants.zig");

/// Pure gap helper for status-driven `blocks_by_range` catch-up (issue #893).
/// Caps the peer-reported gap used for sync thresholding and pagination; per-request
/// size is still bounded separately by `MAX_REQUEST_BLOCKS`.
/// Conservative overlap test for concurrent `blocks_by_range` windows.
/// Treats `count` as an upper bound on the slot span `[start_slot, start_slot + count)`.
pub fn rangesOverlap(
    a_start: types.Slot,
    a_count: u64,
    b_start: types.Slot,
    b_count: u64,
) bool {
    if (a_count == 0 or b_count == 0) return false;
    const a_end = a_start +% a_count;
    const b_end = b_start +% b_count;
    return a_start < b_end and b_start < a_end;
}

pub fn cappedSyncGapSlots(peer_head_slot: types.Slot, our_head_slot: types.Slot, wall_slot: types.Slot) u64 {
    if (peer_head_slot <= our_head_slot) return 0;
    const peer_gap: u64 = peer_head_slot - our_head_slot;
    const wall_gap: u64 = if (wall_slot > our_head_slot) wall_slot - our_head_slot else 0;
    return @min(peer_gap, wall_gap);
}

/// Whether a peer status should trigger proactive catch-up (issue #893 / PR #894).
/// `BLOCKS_BY_RANGE_SYNC_THRESHOLD` only selects range vs by-root inside `initiateCatchUpFromPeerStatus`.
pub fn shouldCatchUpFromPeerStatus(
    peer_head_slot: types.Slot,
    our_head_slot: types.Slot,
    peer_finalized_slot: types.Slot,
    our_finalized_slot: types.Slot,
    wall_slot: types.Slot,
) bool {
    if (peer_finalized_slot > our_finalized_slot) return true;
    return cappedSyncGapSlots(peer_head_slot, our_head_slot, wall_slot) > 0;
}

pub const SyncEndReason = enum { completed, failed, timeout };

pub const SyncEndInput = struct {
    aborted: bool,
    chunks_received: u32,
    chunks_imported: u32,
    chunks_pre_finalized: u32,
    range_attempt: u8,
    max_attempts: u8,
    end_reason: SyncEndReason,
    has_alternate_peer: bool,
    /// Peer does not implement `blocks_by_range` — fall back to `blocks_by_root` immediately.
    range_unavailable: bool = false,
};

pub const SyncEndAction = enum {
    abort_fallback,
    pre_finalized_complete,
    retry,
    exhausted_fallback,
    unavailable_fallback,
    success_continue,
};

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

/// True when the peer's `blocks_by_range` handler is missing or explicitly unsupported.
pub fn isBlocksByRangeUnavailable(code: u32, message: []const u8) bool {
    if (code == constants.RPC_ERR_INVALID_REQUEST) return true;
    const needles = [_][]const u8{ "unsupported", "not available", "not supported", "unknown protocol" };
    for (needles) |needle| {
        if (containsIgnoreCase(message, needle)) return true;
    }
    return false;
}

pub fn syncEndDecision(input: SyncEndInput) SyncEndAction {
    if (input.range_unavailable) return .unavailable_fallback;
    if (input.aborted) return .abort_fallback;
    if (input.chunks_received > 0 and input.chunks_pre_finalized == input.chunks_received) {
        return .pre_finalized_complete;
    }
    const no_progress = input.chunks_imported == 0;
    const should_retry = (input.end_reason == .failed or input.end_reason == .timeout or no_progress) and
        input.range_attempt < input.max_attempts and input.has_alternate_peer;
    if (should_retry) return .retry;
    if (input.end_reason == .failed or input.end_reason == .timeout or no_progress) return .exhausted_fallback;
    return .success_continue;
}

test "rangesOverlap detects overlapping slot windows" {
    try std.testing.expect(rangesOverlap(100, 64, 100, 32));
    try std.testing.expect(rangesOverlap(100, 64, 150, 64));
    try std.testing.expect(!rangesOverlap(100, 64, 164, 32));
    try std.testing.expect(!rangesOverlap(100, 0, 100, 32));
}

test "cappedSyncGapSlots limits range catch-up to wall-clock head" {
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(100, 100, 200));
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(50, 100, 200));
    try std.testing.expectEqual(@as(u64, 50), cappedSyncGapSlots(200, 100, 150));
    try std.testing.expectEqual(@as(u64, 100), cappedSyncGapSlots(200, 100, 250));
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(200, 150, 100));
}

test "shouldCatchUpFromPeerStatus triggers on head gap before finalization" {
    // Early devnet: both finalized at 0, peer head ahead — must catch up via blocks_by_root.
    try std.testing.expect(shouldCatchUpFromPeerStatus(31, 0, 0, 0, 40));
    try std.testing.expect(!shouldCatchUpFromPeerStatus(0, 0, 0, 0, 40));
    try std.testing.expect(shouldCatchUpFromPeerStatus(31, 0, 0, 0, 10)); // wall caps gap but still > 0
    try std.testing.expect(!shouldCatchUpFromPeerStatus(5, 0, 0, 0, 0)); // wall not ahead of us
    // Finalized ahead still triggers even when head gap is zero.
    try std.testing.expect(shouldCatchUpFromPeerStatus(100, 100, 10, 0, 200));
}

test "shouldCatchUpFromPeerStatus small gaps use by-root not threshold gate" {
    const gap = cappedSyncGapSlots(50, 0, 100);
    try std.testing.expect(gap < constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD);
    try std.testing.expect(shouldCatchUpFromPeerStatus(50, 0, 0, 0, 100));
}

test "syncEndDecision retry requires alternate peer" {
    const base = SyncEndInput{
        .aborted = false,
        .chunks_received = 5,
        .chunks_imported = 0,
        .chunks_pre_finalized = 0,
        .range_attempt = 1,
        .max_attempts = 3,
        .end_reason = .completed,
        .has_alternate_peer = false,
    };
    try std.testing.expectEqual(SyncEndAction.exhausted_fallback, syncEndDecision(base));

    var with_peer = base;
    with_peer.has_alternate_peer = true;
    try std.testing.expectEqual(SyncEndAction.retry, syncEndDecision(with_peer));

    var imported = base;
    imported.chunks_imported = 3;
    try std.testing.expectEqual(SyncEndAction.success_continue, syncEndDecision(imported));
}

test "syncEndDecision all pre-finalized is no-op not retry" {
    const input = SyncEndInput{
        .aborted = false,
        .chunks_received = 4,
        .chunks_imported = 0,
        .chunks_pre_finalized = 4,
        .range_attempt = 1,
        .max_attempts = 3,
        .end_reason = .completed,
        .has_alternate_peer = true,
    };
    try std.testing.expectEqual(SyncEndAction.pre_finalized_complete, syncEndDecision(input));
}

test "isBlocksByRangeUnavailable detects unsupported responses" {
    try std.testing.expect(isBlocksByRangeUnavailable(constants.RPC_ERR_INVALID_REQUEST, "unsupported"));
    try std.testing.expect(isBlocksByRangeUnavailable(99, "Method not supported"));
    try std.testing.expect(!isBlocksByRangeUnavailable(constants.RPC_ERR_RESOURCE_UNAVAILABLE, "outside history window"));
}

test "syncEndDecision unavailable skips retry" {
    const input = SyncEndInput{
        .aborted = false,
        .chunks_received = 0,
        .chunks_imported = 0,
        .chunks_pre_finalized = 0,
        .range_attempt = 1,
        .max_attempts = 3,
        .end_reason = .failed,
        .has_alternate_peer = true,
        .range_unavailable = true,
    };
    try std.testing.expectEqual(SyncEndAction.unavailable_fallback, syncEndDecision(input));
}

test "syncEndDecision fork abort" {
    const input = SyncEndInput{
        .aborted = true,
        .chunks_received = 1,
        .chunks_imported = 0,
        .chunks_pre_finalized = 0,
        .range_attempt = 1,
        .max_attempts = 3,
        .end_reason = .completed,
        .has_alternate_peer = true,
    };
    try std.testing.expectEqual(SyncEndAction.abort_fallback, syncEndDecision(input));
}
