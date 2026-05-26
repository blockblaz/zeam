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

pub const PeerStatusRefreshDecision = struct {
    refresh: bool,
    wall_head_lag_slots: u64,
};

/// Pure periodic peer-status refresh policy.
///
/// Callers supply the current interval/slot cadence plus head snapshots; this helper
/// owns the decision about whether a status refresh is useful. Wall-clock head lag is
/// computed through `cappedSyncGapSlots` by treating `wall_slot` as the peer head,
/// keeping all slot-gap arithmetic on one path.
pub fn shouldRefreshPeerStatus(
    sync_status: anytype,
    interval_in_slot: usize,
    slot: types.Slot,
    our_head_slot: types.Slot,
    wall_slot: types.Slot,
    refresh_interval_slots: u64,
    wall_head_lag_threshold_slots: u64,
) PeerStatusRefreshDecision {
    const wall_head_lag_slots = cappedSyncGapSlots(wall_slot, our_head_slot, wall_slot);
    if (interval_in_slot != 0 or slot % refresh_interval_slots != 0) {
        return .{ .refresh = false, .wall_head_lag_slots = wall_head_lag_slots };
    }

    const refresh = switch (sync_status) {
        .fc_initing, .behind_peers => true,
        .synced => wall_head_lag_slots >= wall_head_lag_threshold_slots,
        .no_peers => false,
    };
    return .{ .refresh = refresh, .wall_head_lag_slots = wall_head_lag_slots };
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

/// Result of a non-blocking attempt to hand a block off to the chain-worker
/// from an RPC chunk handler (`processBlockByRootChunk` /
/// `processBlockByRangeChunk`). Distinguishes the four outcomes the libxev
/// caller cares about. Defined here so the disposition is unit-testable
/// without spinning up a `BeamNode`.
///
/// Background (#894 regression discovered on devnet aggregator zeam_8):
/// when the chain-worker is enabled but its block queue is full (typically
/// because the aggregator is also draining a flood of attestations), a
/// `blocks_by_root` / `blocks_by_range` response burst MUST NOT fall back
/// to inline `chain.onBlock` on the libxev thread. Each inline import
/// costs ~0.5s of XMSS verification; one 3.4 MB response burst was observed
/// to wedge libxev for 9.7s, missing block-production duty for the
/// proposing slot. The gossip path already drops on QueueFull
/// (`chain.zig::onGossip`); the RPC chunk paths used to fall through.
pub const ImportSubmitOutcome = enum {
    /// Worker accepted the block. Caller returns immediately.
    submitted,
    /// Worker is configured but its block queue is at capacity. Caller
    /// MUST NOT fall back to inline `chain.onBlock` — that's the path
    /// that starves libxev under aggregator load. Drop with a metric
    /// bump; the next status-driven catch-up cycle will refetch.
    queue_full,
    /// Chain-worker is not configured (test / single-thread mode).
    /// Caller falls through to the inline path — that path is the
    /// legitimate import flow when no worker exists.
    worker_disabled,
    /// `sszClone` or other allocator failure pre-submission. Caller
    /// falls through to inline as a last-resort best effort.
    failed,
};

/// Disposition for the libxev RPC chunk handler after an
/// `ImportSubmitOutcome`. Pure decision logic so it can be exercised in
/// unit tests without a chain-worker. Matches the contract callers in
/// `node.zig::processBlockByRootChunk` / `processBlockByRangeChunk` rely on.
pub const ChunkImportDisposition = enum {
    /// Block handed off; caller returns from the RPC chunk handler.
    handled,
    /// Apply backpressure — drop this chunk, do NOT inline-import on
    /// libxev. The catch-up RPC cycle will refetch on the next status
    /// round.
    drop_backpressure,
    /// Worker is not available (or sszClone failed). Fall through to
    /// the inline `chain.onBlock` path.
    fallback_inline,
};

pub fn classifyChunkImport(outcome: ImportSubmitOutcome) ChunkImportDisposition {
    return switch (outcome) {
        .submitted => .handled,
        .queue_full => .drop_backpressure,
        .worker_disabled, .failed => .fallback_inline,
    };
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

test "shouldRefreshPeerStatus handles cadence sync state and wall lag" {
    const TestSyncStatus = union(enum) {
        synced,
        no_peers,
        fc_initing,
        behind_peers,
    };

    // Wall-lag arithmetic is shared with cappedSyncGapSlots by treating wall_slot as
    // the remote head: no lag at/past wall, positive lag only when wall is ahead.
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(100, 100, 100));
    try std.testing.expectEqual(@as(u64, 0), cappedSyncGapSlots(99, 100, 99));
    try std.testing.expectEqual(@as(u64, 4), cappedSyncGapSlots(104, 100, 104));

    const cases = [_]struct {
        status: TestSyncStatus,
        interval_in_slot: usize,
        slot: types.Slot,
        our_head_slot: types.Slot,
        wall_slot: types.Slot,
        threshold_slots: u64,
        want_refresh: bool,
        want_lag: u64,
    }{
        .{ .status = .synced, .interval_in_slot = 1, .slot = 104, .our_head_slot = 100, .wall_slot = 104, .threshold_slots = 4, .want_refresh = false, .want_lag = 4 },
        .{ .status = .synced, .interval_in_slot = 0, .slot = 103, .our_head_slot = 100, .wall_slot = 104, .threshold_slots = 4, .want_refresh = false, .want_lag = 4 },
        .{ .status = .synced, .interval_in_slot = 0, .slot = 104, .our_head_slot = 100, .wall_slot = 103, .threshold_slots = 4, .want_refresh = false, .want_lag = 3 },
        .{ .status = .synced, .interval_in_slot = 0, .slot = 104, .our_head_slot = 100, .wall_slot = 104, .threshold_slots = 4, .want_refresh = true, .want_lag = 4 },
        .{ .status = .fc_initing, .interval_in_slot = 0, .slot = 104, .our_head_slot = 100, .wall_slot = 100, .threshold_slots = 4, .want_refresh = true, .want_lag = 0 },
        .{ .status = .behind_peers, .interval_in_slot = 0, .slot = 104, .our_head_slot = 100, .wall_slot = 100, .threshold_slots = 4, .want_refresh = true, .want_lag = 0 },
        .{ .status = .no_peers, .interval_in_slot = 0, .slot = 104, .our_head_slot = 100, .wall_slot = 200, .threshold_slots = 4, .want_refresh = false, .want_lag = 100 },
    };

    for (cases) |case| {
        const decision = shouldRefreshPeerStatus(
            case.status,
            case.interval_in_slot,
            case.slot,
            case.our_head_slot,
            case.wall_slot,
            constants.SYNC_STATUS_REFRESH_INTERVAL_SLOTS,
            case.threshold_slots,
        );
        try std.testing.expectEqual(case.want_refresh, decision.refresh);
        try std.testing.expectEqual(case.want_lag, decision.wall_head_lag_slots);
    }
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

test "classifyChunkImport: queue_full drops, never falls back to inline (#894 regression guard)" {
    // The regression: under aggregator load the chain-worker block queue
    // saturates, `trySubmitImportToWorker` returns `queue_full`, and
    // (pre-fix) `processBlockByRootChunk` / `processBlockByRangeChunk`
    // fall through to `chain.onBlock` on libxev. Each inline import
    // costs ~0.5s of XMSS verification; one 3.4 MB `blocks_by_root`
    // burst was observed to wedge libxev for 9.7s on devnet aggregator
    // zeam_8, which then missed its slot 64 block-production duty.
    //
    // The contract under test: `queue_full` MUST classify as
    // `drop_backpressure`, never `fallback_inline`. If a future change
    // re-introduces the inline fallback for this outcome, this test
    // fails before the regression hits production again.
    try std.testing.expectEqual(ChunkImportDisposition.drop_backpressure, classifyChunkImport(.queue_full));
}

test "classifyChunkImport: submitted is handled" {
    try std.testing.expectEqual(ChunkImportDisposition.handled, classifyChunkImport(.submitted));
}

test "classifyChunkImport: worker_disabled and failed fall back to inline" {
    // `worker_disabled`: legitimate test / single-thread mode, no
    // worker exists so inline `chain.onBlock` IS the import path.
    // `failed`: sszClone or allocator failure pre-submission — last-
    // resort best-effort inline. Both must NOT be confused with
    // `queue_full`, which is the load-shedding case.
    try std.testing.expectEqual(ChunkImportDisposition.fallback_inline, classifyChunkImport(.worker_disabled));
    try std.testing.expectEqual(ChunkImportDisposition.fallback_inline, classifyChunkImport(.failed));
}

test "classifyChunkImport: every ImportSubmitOutcome variant has a defined disposition" {
    // Exhaustiveness guard — adding a new `ImportSubmitOutcome` value
    // without updating `classifyChunkImport` is caught by the inline
    // switch in `classifyChunkImport`, but explicitly enumerating
    // the variants here documents the intent and keeps reviewer eyes
    // on the disposition table when the enum grows.
    inline for (std.meta.fields(ImportSubmitOutcome)) |field| {
        const outcome: ImportSubmitOutcome = @field(ImportSubmitOutcome, field.name);
        const disposition = classifyChunkImport(outcome);
        switch (outcome) {
            .submitted => try std.testing.expectEqual(ChunkImportDisposition.handled, disposition),
            .queue_full => try std.testing.expectEqual(ChunkImportDisposition.drop_backpressure, disposition),
            .worker_disabled, .failed => try std.testing.expectEqual(ChunkImportDisposition.fallback_inline, disposition),
        }
    }
}
