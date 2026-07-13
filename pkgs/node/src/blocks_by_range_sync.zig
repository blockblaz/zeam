//! `blocks_by_range` catch-up helpers.
//!
//! Pure gap/decision logic and unit tests live here. `BeamNode` orchestration
//! (RPC handlers, chunk import, retry/fallback) lives in the node module until a
//! dedicated sync-worker module is split out.

const std = @import("std");

const types = @import("@zeam/types");

const constants = @import("./constants.zig");

/// Pure gap helper for status-driven `blocks_by_range` catch-up.
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
        .fc_initing, .peers_materially_ahead => true,
        .synced => wall_head_lag_slots >= wall_head_lag_threshold_slots,
        .no_peers => false,
    };
    return .{ .refresh = refresh, .wall_head_lag_slots = wall_head_lag_slots };
}

/// Rotate a peer batch for rate-limited status refresh.
pub fn peerBatchWindow(total_peers: usize, cursor: usize, batch_size: usize) struct {
    start: usize,
    count: usize,
    next_cursor: usize,
} {
    if (total_peers == 0 or batch_size == 0) {
        return .{ .start = 0, .count = 0, .next_cursor = 0 };
    }
    const start = cursor % total_peers;
    const count = @min(batch_size, total_peers);
    return .{
        .start = start,
        .count = count,
        .next_cursor = (start + count) % total_peers,
    };
}

/// Whether to start RPC catch-up from cached peer status without waiting for
/// a fresh status response (gossip ingress stall + wall-clock head lag).
pub fn shouldInitiateProactiveCatchUp(
    wall_head_lag_slots: u64,
    wall_head_lag_threshold_slots: u64,
    gossip_silent_ms: u64,
    gossip_stall_threshold_ms: u64,
) bool {
    if (wall_head_lag_slots < wall_head_lag_threshold_slots) return false;
    if (gossip_stall_threshold_ms == 0) return true;
    return gossip_silent_ms >= gossip_stall_threshold_ms;
}

/// Whether gossipsub mesh subscriptions should be re-sent.
pub fn shouldHealGossipMesh(
    mesh_peers: u64,
    min_mesh_peers: u64,
    gossip_silent_ms: u64,
    gossip_stall_threshold_ms: u64,
) bool {
    if (mesh_peers < min_mesh_peers) return true;
    if (gossip_stall_threshold_ms == 0) return false;
    return gossip_silent_ms >= gossip_stall_threshold_ms;
}

/// Milliseconds since `last_gossip_rx_ms` (0 when no gossip received yet).
pub fn gossipSilentMs(now_ms: u64, last_gossip_rx_ms: u64) u64 {
    if (last_gossip_rx_ms == 0) return 0;
    return now_ms -| last_gossip_rx_ms;
}

/// Whether a peer status should trigger proactive catch-up.
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

/// Recovery start for a `blocks_by_range` first-chunk fork mismatch.
///
/// A normal range starts at `our_head_slot + 1`, so the first block must extend
/// our head-at-request. If the peer is on a heavier sibling fork, that check
/// fails. Recovery can still use range sync when we have a recent common-ish
/// anchor such as latest justified: request from `anchor_slot + 1` and validate
/// the first chunk against `anchor_root` instead of the stale head.
///
/// Returns null when the anchor cannot improve on the failed request or is
/// likely outside the peer's advertised recent-history window; callers should
/// then fall back to the by-root parent walk from peer head.
pub fn forkMismatchRecoveryStart(
    failed_start_slot: types.Slot,
    anchor_slot: types.Slot,
    peer_head_slot: types.Slot,
    min_slots_for_block_requests: u64,
) ?types.Slot {
    const recovery_start = anchor_slot +| 1;
    if (recovery_start >= failed_start_slot) return null;
    if (recovery_start > peer_head_slot) return null;

    if (peer_head_slot >= min_slots_for_block_requests) {
        const history_start = peer_head_slot - min_slots_for_block_requests;
        if (recovery_start < history_start) return null;
    }

    return recovery_start;
}

pub fn shouldAttemptForkMismatchRangeRecovery(range_attempt: u8, max_attempts: u8) bool {
    return range_attempt < max_attempts;
}

/// Proposal liveness guard for nodes that look "synced" by finalized-slot
/// status but are clearly stale by wall-clock head lag.
pub fn shouldSuppressProposalForHeadLag(
    wall_head_lag_slots: u64,
    max_proposal_head_lag_slots: u64,
    latest_justified_slot: types.Slot,
    has_fresher_peer_near_wall: bool,
) bool {
    if (latest_justified_slot == 0) return false; // preserve pre-justification cold start
    if (!has_fresher_peer_near_wall) return false;
    return wall_head_lag_slots > max_proposal_head_lag_slots;
}

/// Pure decider for the "stuck mesh cluster" recovery path.
///
/// Fires when ALL of:
///   * `best_peer_head_slot` is `wall_head_lag_threshold_slots` or more slots
///     behind wall — i.e. the best status zeam has cached for any connected
///     peer reports a head that's itself materially behind wall-clock. This
///     captures the regime where the entire visible peer pool is stuck and
///     normal `findBestCatchUpPeerStatus` keeps picking the same stale-head
///     target every interval.
///   * `slot - last_force_refresh_slot >= refresh_cooldown_slots` — at least
///     one cooldown window has elapsed since the previous force-refresh, so
///     we don't burst-refresh every interval if the condition stays continuously
///     true (and re-create the en-masse RPC-timeout cascade that
///     motivated the original status-refresh batching).
///   * `best_peer_head_slot < wall_slot` — sanity check; the helper returns
///     false if the best peer is already at or past wall-clock (no stuck cluster).
///
/// Returns `true` when the caller (`maybeForceFullPeerStatusRefresh` in `node.zig`)
/// should bypass the batch cursor and send a status request to every connected
/// peer at once, to try to discover a peer with a fresher head_slot.
pub fn shouldForceFullPeerStatusRefresh(
    best_peer_head_slot: types.Slot,
    wall_slot: types.Slot,
    slot: types.Slot,
    last_force_refresh_slot: types.Slot,
    wall_head_lag_threshold_slots: u64,
    refresh_cooldown_slots: u64,
) bool {
    if (best_peer_head_slot >= wall_slot) return false;
    const peer_lag = wall_slot - best_peer_head_slot;
    if (peer_lag < wall_head_lag_threshold_slots) return false;
    if (slot < last_force_refresh_slot) return false; // monotonic guard
    const since_last = slot - last_force_refresh_slot;
    return since_last >= refresh_cooldown_slots;
}

/// Result of a non-blocking attempt to hand a block off to the chain-worker
/// from an RPC chunk handler (`processBlockByRootChunk` /
/// `processBlockByRangeChunk`). Distinguishes the four outcomes the libxev
/// caller cares about. Defined here so the disposition is unit-testable
/// without spinning up a `BeamNode`.
///
/// Background (regression observed on a loaded aggregator): when the
/// chain-worker is enabled but its block queue is full (typically because the
/// aggregator is also draining a flood of attestations), a `blocks_by_root` /
/// `blocks_by_range` response burst must not fall back to inline `onBlock` on
/// the libxev thread. Each inline import costs ~0.5s of XMSS verification; one
/// 3.4 MB response burst was observed to wedge libxev for 9.7s, missing
/// block-production duty for the proposing slot. The gossip path already drops
/// on QueueFull; the RPC chunk paths used to fall through.
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
    /// `clone` or other allocator failure pre-submission. Caller
    /// falls through to inline as a last-resort best effort.
    failed,
};

/// Disposition for the libxev RPC chunk handler after an
/// `ImportSubmitOutcome`. Pure decision logic so it can be exercised in
/// unit tests without a chain-worker. Matches the contract the RPC chunk
/// handlers (`processBlockByRootChunk` / `processBlockByRangeChunk`) rely on.
pub const ChunkImportDisposition = enum {
    /// Block handed off; caller returns from the RPC chunk handler.
    handled,
    /// Apply backpressure — drop this chunk, do NOT inline-import on
    /// libxev. The catch-up RPC cycle will refetch on the next status
    /// round.
    drop_backpressure,
    /// Worker is not available (or clone failed). Fall through to
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
        peers_materially_ahead,
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
        .{ .status = .peers_materially_ahead, .interval_in_slot = 0, .slot = 104, .our_head_slot = 100, .wall_slot = 100, .threshold_slots = 4, .want_refresh = true, .want_lag = 0 },
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
    // Early network: both finalized at 0, peer head ahead — must catch up via blocks_by_root.
    try std.testing.expect(shouldCatchUpFromPeerStatus(31, 0, 0, 0, 40));
    try std.testing.expect(!shouldCatchUpFromPeerStatus(0, 0, 0, 0, 40));
    try std.testing.expect(shouldCatchUpFromPeerStatus(31, 0, 0, 0, 10)); // wall caps gap but still > 0
    try std.testing.expect(!shouldCatchUpFromPeerStatus(5, 0, 0, 0, 0)); // wall not ahead of us
    // Finalized ahead still triggers even when head gap is zero.
    try std.testing.expect(shouldCatchUpFromPeerStatus(100, 100, 10, 0, 200));
}

test "shouldCatchUpFromPeerStatus small gaps use by-root not threshold gate" {
    // A sub-threshold gap (range/by-root selection happens elsewhere). Expressed relative to the
    // threshold so it stays valid if BLOCKS_BY_RANGE_SYNC_THRESHOLD changes.
    const small_gap_peer = constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD - 1;
    const gap = cappedSyncGapSlots(small_gap_peer, 0, 100);
    try std.testing.expect(gap < constants.BLOCKS_BY_RANGE_SYNC_THRESHOLD);
    try std.testing.expect(shouldCatchUpFromPeerStatus(small_gap_peer, 0, 0, 0, 100));
}

test "forkMismatchRecoveryStart re-anchors to a recent justified ancestor" {
    try std.testing.expectEqual(
        @as(?types.Slot, 12_001),
        forkMismatchRecoveryStart(12_100, 12_000, 14_735, constants.MIN_SLOTS_FOR_BLOCK_REQUESTS),
    );
}

test "forkMismatchRecoveryStart falls back when anchor cannot improve failed range" {
    try std.testing.expectEqual(
        @as(?types.Slot, null),
        forkMismatchRecoveryStart(9340, 9339, 14735, constants.MIN_SLOTS_FOR_BLOCK_REQUESTS),
    );
}

test "forkMismatchRecoveryStart falls back when anchor is outside peer range history" {
    try std.testing.expectEqual(
        @as(?types.Slot, null),
        forkMismatchRecoveryStart(15169, 9337, 15169, constants.MIN_SLOTS_FOR_BLOCK_REQUESTS),
    );
}

test "shouldAttemptForkMismatchRangeRecovery stops before u8 overflow" {
    try std.testing.expect(shouldAttemptForkMismatchRangeRecovery(1, constants.MAX_BLOCKS_BY_RANGE_SYNC_ATTEMPTS));
    try std.testing.expect(!shouldAttemptForkMismatchRangeRecovery(
        constants.MAX_BLOCKS_BY_RANGE_SYNC_ATTEMPTS,
        constants.MAX_BLOCKS_BY_RANGE_SYNC_ATTEMPTS,
    ));
    try std.testing.expect(!shouldAttemptForkMismatchRangeRecovery(255, 255));
}

test "shouldSuppressProposalForHeadLag preserves cold start and blocks stale justified forks" {
    try std.testing.expect(!shouldSuppressProposalForHeadLag(100, 4, 0, true));
    try std.testing.expect(!shouldSuppressProposalForHeadLag(4, 4, 1, true));
    try std.testing.expect(!shouldSuppressProposalForHeadLag(100, 4, 1, false));
    try std.testing.expect(shouldSuppressProposalForHeadLag(5, 4, 1, true));
}

test "shouldForceFullPeerStatusRefresh fires when stuck behind a cluster of stale peers" {
    // The scenario the helper exists to recover from: wall is at
    // slot 300, best peer head zeam knows about is slot 50, no force-refresh has
    // run yet → stuck-mesh-cluster condition is met.
    try std.testing.expect(shouldForceFullPeerStatusRefresh(50, 300, 300, 0, 16, 16));
}

test "shouldForceFullPeerStatusRefresh is off when best peer is at wall-clock" {
    // Best peer is at wall — there's no stuck cluster, normal catch-up handles it.
    try std.testing.expect(!shouldForceFullPeerStatusRefresh(300, 300, 300, 0, 16, 16));
    try std.testing.expect(!shouldForceFullPeerStatusRefresh(305, 300, 300, 0, 16, 16));
}

test "shouldForceFullPeerStatusRefresh is off when best peer lag is under threshold" {
    // Best peer is 10 slots behind wall, threshold is 16 — under threshold, this
    // is just normal proactive-catch-up territory, not a stuck cluster.
    try std.testing.expect(!shouldForceFullPeerStatusRefresh(290, 300, 300, 0, 16, 16));
}

test "shouldForceFullPeerStatusRefresh is rate-limited by cooldown" {
    // Stuck-cluster condition is met but a force-refresh fired just 4 slots ago —
    // cooldown is 16 → suppressed. After 16 slots elapse it fires again.
    try std.testing.expect(!shouldForceFullPeerStatusRefresh(50, 300, 304, 300, 16, 16));
    try std.testing.expect(shouldForceFullPeerStatusRefresh(50, 300, 316, 300, 16, 16));
}

test "shouldForceFullPeerStatusRefresh is safe under non-monotonic slot input" {
    // Defensive: the comparator must not underflow if `slot` somehow arrives
    // less than `last_force_refresh_slot` (slot driver reset / clock skew).
    try std.testing.expect(!shouldForceFullPeerStatusRefresh(50, 300, 100, 200, 16, 16));
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

test "peerBatchWindow rotates through peers" {
    const w0 = peerBatchWindow(10, 0, 8);
    try std.testing.expectEqual(@as(usize, 0), w0.start);
    try std.testing.expectEqual(@as(usize, 8), w0.count);
    try std.testing.expectEqual(@as(usize, 8), w0.next_cursor);

    const w1 = peerBatchWindow(10, 8, 8);
    try std.testing.expectEqual(@as(usize, 8), w1.start);
    try std.testing.expectEqual(@as(usize, 8), w1.count);
    try std.testing.expectEqual(@as(usize, 6), w1.next_cursor);
}

test "shouldInitiateProactiveCatchUp requires wall lag and gossip stall" {
    const threshold_ms: u64 = 8000;
    try std.testing.expect(shouldInitiateProactiveCatchUp(4, 4, threshold_ms, threshold_ms));
    try std.testing.expect(!shouldInitiateProactiveCatchUp(3, 4, threshold_ms, threshold_ms));
    try std.testing.expect(!shouldInitiateProactiveCatchUp(4, 4, threshold_ms - 1, threshold_ms));
}

test "shouldHealGossipMesh on low mesh or gossip stall" {
    const threshold_ms: u64 = 8000;
    try std.testing.expect(shouldHealGossipMesh(3, 4, 0, threshold_ms));
    try std.testing.expect(shouldHealGossipMesh(10, 4, threshold_ms, threshold_ms));
    try std.testing.expect(!shouldHealGossipMesh(10, 4, 0, threshold_ms));
}

test "gossipSilentMs handles never-received and elapsed silence" {
    try std.testing.expectEqual(@as(u64, 0), gossipSilentMs(10_000, 0));
    try std.testing.expectEqual(@as(u64, 3_000), gossipSilentMs(10_000, 7_000));
}

test "classifyChunkImport: queue_full drops, never falls back to inline (regression guard)" {
    // The regression: under aggregator load the chain-worker block queue
    // saturates, `trySubmitImportToWorker` returns `queue_full`, and
    // (pre-fix) `processBlockByRootChunk` / `processBlockByRangeChunk`
    // fall through to `chain.onBlock` on libxev. Each inline import
    // costs ~0.5s of XMSS verification; one 3.4 MB `blocks_by_root`
    // burst was observed to wedge libxev for 9.7s on a loaded aggregator,
    // which then missed its slot 64 block-production duty.
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
    // `failed`: clone or allocator failure pre-submission — last-
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
