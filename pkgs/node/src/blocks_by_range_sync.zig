//! `blocks_by_range` catch-up helpers (issue #893).
//!
//! Pure gap/decision logic and unit tests live here. `BeamNode` orchestration
//! (RPC handlers, chunk import, retry/fallback) remains in `node.zig` until a
//! dedicated sync-worker module is split out (review on PR #894).

const std = @import("std");

const types = @import("@zeam/types");

/// Pure gap helper for status-driven `blocks_by_range` catch-up (issue #893).
/// Caps the peer-reported gap used for sync thresholding and pagination; per-request
/// size is still bounded separately by `MAX_REQUEST_BLOCKS`.
pub fn cappedSyncGapSlots(peer_head_slot: types.Slot, our_head_slot: types.Slot, wall_slot: types.Slot) u64 {
    if (peer_head_slot <= our_head_slot) return 0;
    const peer_gap: u64 = peer_head_slot - our_head_slot;
    const wall_gap: u64 = if (wall_slot > our_head_slot) wall_slot - our_head_slot else 0;
    return @min(peer_gap, wall_gap);
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
};

pub const SyncEndAction = enum {
    abort_fallback,
    pre_finalized_complete,
    retry,
    exhausted_fallback,
    success_continue,
};

pub fn syncEndDecision(input: SyncEndInput) SyncEndAction {
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

test "cappedSyncGapSlots limits range catch-up to wall-clock head" {
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(100, 100, 200));
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(50, 100, 200));
    try std.testing.expectEqual(@as(u64, 50), cappedSyncGapSlots(200, 100, 150));
    try std.testing.expectEqual(@as(u64, 100), cappedSyncGapSlots(200, 100, 250));
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(200, 150, 100));
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
