const std = @import("std");
const params = @import("@zeam/params");

// a constant fixed only relevant to node operation and hence not in the config or preset
pub const INTERVALS_PER_SLOT = 5;
pub const SECONDS_PER_INTERVAL_MS: isize = @divFloor(params.SECONDS_PER_SLOT * std.time.ms_per_s, INTERVALS_PER_SLOT);

// Future-slot tolerance for gossip attestations, measured in intervals:
//
//     data.slot * INTERVALS_PER_SLOT <= store.time + GOSSIP_DISPARITY_INTERVALS
//
// where store.time is in intervals. One interval is roughly 800 ms at
// SECONDS_PER_SLOT=4 / INTERVALS_PER_SLOT=5.
//
// A whole-slot tolerance would let an adversary pre-publish next-slot
// aggregates ahead of any honest validator (~800 ms head start at 4 s
// slots); tightening to one interval bounds that head start to NTP drift.
//
// Block-included attestations skip this check entirely; they are trusted
// under the block's own validation.
pub const GOSSIP_DISPARITY_INTERVALS = 1;

// Maximum number of slots in the future that a *block* is allowed to reference
// for *immediate* acceptance. Anything beyond this is treated as a future block
// and queued via `pending_blocks`. One slot of tolerance covers the normal race
// between `onInterval` and a neighbouring node's gossip arriving slightly early.
//
// This is a zeam-specific constant, not spec-defined. For blocks there is no
// spec constant, so we follow the Ethereum CL p2p-interface convention of
// allowing future-slot blocks to be queued. Gossip attestations use the
// stricter GOSSIP_DISPARITY_INTERVALS bound instead of this whole-slot
// tolerance — see `validateAttestation` and `onGossipAggregatedAttestation`.
pub const MAX_FUTURE_SLOT_TOLERANCE = 1;

// Maximum number of slots in the future that a *block* may be queued for
// later replay from `pending_blocks`. Under mutex contention the local
// `onInterval` can be delayed long enough that the forkchoice
// clock lags wall-time by tens of slots; gossip blocks for those slots arrive
// at the wall-clock time and would otherwise be rejected with `FutureSlot`,
// causing the fork choice head to fall back to the latest finalized
// checkpoint when no descendants exist in the protoArray. Buffering up to
// `MAX_FUTURE_SLOT_QUEUE_TOLERANCE` slots ahead lets the queue absorb the
// worst observed lag (~160 slots in one incident) so blocks can be replayed
// once the clock catches up. Anything beyond this is almost certainly an
// actually-malicious or buggy peer and is dropped.
//
// 256 is empirical, derived from that worst-case lag; there is no spec analog
// for a future-block queue depth (cf. `MAX_FUTURE_SLOT_TOLERANCE` above, which
// is a partial analog). Revisit this if `zeam_lock_hold_seconds` reaches new
// highs or if `lean_blocks_future_slot_dropped_total` shows sustained drops on
// a healthy network. Don't ossify the magic number.
pub const MAX_FUTURE_SLOT_QUEUE_TOLERANCE: u64 = 256;

// Maximum number of blocks held in the `pending_blocks` future-block queue.
// Bounded to prevent OOM from a malicious or buggy peer that gossips a wide
// range of fake-future blocks. Sized to comfortably exceed the worst observed
// catch-up window without giving an attacker meaningful memory
// pressure: at ~2KB per `SignedBlock` envelope (varies with attestation
// count) this caps the queue at ~2MB which is negligible vs the rest of
// chain state. Older entries (lower-slot, lower-receive-time) are evicted
// first when the cap is hit.
//
// Mirrors the spec's cached-blocks cap (also 1024; same magnitude, same
// FIFO-eviction policy on overflow). Naming differs because `pending_blocks`
// is zeam's pre-existing identifier for the future-block queue and renaming it
// would touch every callsite without behavioural benefit.
pub const MAX_PENDING_BLOCKS: usize = 1024;

// Maximum buffered gossip attestations / aggregations awaiting their
// referenced block to be processed. Mirrors the spec's pending-attestation
// cap (also 1024).
//
// The buffer underwrites the "validate, on failure buffer for replay"
// lifecycle, retried on every successful block processed. Keeping the bound in
// sync with the spec value keeps replay churn within test vectors. FIFO
// eviction matches the spec's "drop oldest" policy.
pub const MAX_PENDING_ATTESTATIONS: usize = 1024;

// Maximum depth for recursive block fetching
// When fetching parent blocks, we stop after this many levels to avoid infinite loops
pub const MAX_BLOCK_FETCH_DEPTH = 512;

// Maximum number of blocks to keep in the fetched blocks cache
// This prevents unbounded memory growth from malicious peers sending orphaned blocks.
//
// Mirrors the spec's cached-blocks cap by name; see `MAX_PENDING_BLOCKS` for
// the related future-block queue cap with a different scope.
pub const MAX_CACHED_BLOCKS = 1024;

// Periodic state pruning interval: prune non-canonical states every N slots
// Set to 7200 slots (approximately 8 hours in Lean, assuming 4 seconds per slot)
pub const FORKCHOICE_PRUNING_INTERVAL_SLOTS: u64 = 7200;

// Forkchoice visualization constants
pub const MAX_FC_DISPLAY_DEPTH = 100;
pub const MAX_FC_DISPLAY_BRANCH = 10;
pub const MAX_FC_CHAIN_PRINT_DEPTH = 5;

// Timeout for pending RPC requests in seconds.
// If a peer does not respond within this duration, the request is finalized and retried
// with a different peer. 2 slots at 4s/slot is generous for latency while ensuring
// stuck sync chains recover quickly.
pub const RPC_REQUEST_TIMEOUT_SECONDS: i64 = 8;

// How often to re-send status requests to connected peers when sync may need
// recovery: always while fc_initing/behind_peers, and while synced only after
// the local head has fallen behind wall-clock slots. Ensures that already-
// connected peers are probed again after a restart and that an early network
// with finalized_slot=0 can recover from a gossip-ingress stall via status-driven
// RPC catch-up. 8 slots = 32 seconds at 4s/slot.
pub const SYNC_STATUS_REFRESH_INTERVAL_SLOTS: u64 = 8;

// If the high-level sync state is `synced` but our head is this many wall-clock
// slots behind, keep probing peers with status RPC anyway. Four slots tolerates
// normal propagation/missed-slot jitter without waiting for the 64-slot proposer
// rotation to reveal the stall. With the 8-slot refresh cadence, worst-case first
// recovery probe is just under 12 slots (~48s) after the node stops advancing.
pub const SYNC_STATUS_WALL_HEAD_LAG_THRESHOLD_SLOTS: u64 = 4;

// Maximum peer status RPCs issued per libxev tick during periodic refresh.
// Batching avoids blasting every connected peer at interval 0, which was
// observed to time out en masse and leave catch-up stuck.
pub const SYNC_STATUS_REFRESH_PEERS_PER_TICK: usize = 8;

// When no gossip has been received for this many wall-clock slots, treat
// ingress as stalled and initiate RPC catch-up from the best known peer
// head without waiting for a status response.
pub const GOSSIP_STALL_THRESHOLD_SLOTS: u64 = 2;

// Re-send gossipsub mesh subscriptions on this cadence when mesh membership
// is low or gossip ingress has stalled.
pub const GOSSIP_MESH_HEAL_INTERVAL_SLOTS: u64 = 32;

// Total gossipsub mesh peers below this triggers a mesh resubscribe attempt.
pub const GOSSIP_MESH_MIN_PEERS: u64 = 4;

/// Wall-clock silence duration that indicates gossip ingress has stalled.
pub fn gossipStallThresholdMs() u64 {
    return GOSSIP_STALL_THRESHOLD_SLOTS *
        @as(u64, @intCast(params.SECONDS_PER_SLOT * std.time.ms_per_s));
}

// Threshold (in slots) above which we prefer a `blocks_by_range` bulk sync over the
// recursive head-by-root walk. When the peer's head is more than this many slots
// ahead of ours, we issue a single ranged request to catch up efficiently rather
// than chasing the parent chain one block at a time.
//
// Kept small: the head-by-root walk fetches one block per request (with peer-rotation
// retries), so it is only cheap for a handful of recently-missed blocks. A
// meaningfully-behind node (e.g. a late joiner) catches up far faster via a single
// batched `blocks_by_range` request, so anything beyond a few slots prefers range sync.
pub const BLOCKS_BY_RANGE_SYNC_THRESHOLD: u64 = 4;

// Maximum `blocks_by_range` catch-up attempts (peer rotation + fallback) before
// switching to head-by-root parent walk.
pub const MAX_BLOCKS_BY_RANGE_SYNC_ATTEMPTS: u8 = 3;

// Minimum number of recent slots that a blocksByRange responder MUST keep available.
// Mirrors the spec's MIN_SLOTS_FOR_BLOCK_REQUESTS networking constant.
// Requests whose start_slot falls before (head_slot - MIN_SLOTS_FOR_BLOCK_REQUESTS)
// receive a RESOURCE_UNAVAILABLE error (code 3).
pub const MIN_SLOTS_FOR_BLOCK_REQUESTS: u64 = 3600;

/// RPC error code for INVALID_REQUEST (per the ReqResp spec, code 1).
/// Peers that do not implement `blocks_by_range` often reply with code 1 + "unsupported".
pub const RPC_ERR_INVALID_REQUEST: u32 = 1;
/// RPC error code for RESOURCE_UNAVAILABLE (per the ReqResp spec, code 3).
pub const RPC_ERR_RESOURCE_UNAVAILABLE: u32 = 3;
