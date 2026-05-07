const std = @import("std");
const params = @import("@zeam/params");

// a constant fixed only relevant to node operation and hence not in the config or preset
pub const INTERVALS_PER_SLOT = 5;
pub const SECONDS_PER_INTERVAL_MS: isize = @divFloor(params.SECONDS_PER_SLOT * std.time.ms_per_s, INTERVALS_PER_SLOT);

// Maximum number of slots in the future that an attestation is allowed to reference
// This prevents accepting attestations that are too far ahead of the current slot
pub const MAX_FUTURE_SLOT_TOLERANCE = 1;

// Maximum depth for recursive block fetching
// When fetching parent blocks, we stop after this many levels to avoid infinite loops
pub const MAX_BLOCK_FETCH_DEPTH = 512;

// Maximum number of blocks to keep in the fetched blocks cache
// This prevents unbounded memory growth from malicious peers sending orphaned blocks
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

// How often to re-send status requests to all connected peers when not synced.
// Ensures that already-connected peers are probed again after a restart, and that
// a node stuck in fc_initing can recover without waiting for new peer connections.
// 8 slots = 32 seconds at 4s/slot.
pub const SYNC_STATUS_REFRESH_INTERVAL_SLOTS: u64 = 8;

// Threshold (in slots) above which we prefer a `blocks_by_range` bulk sync over the
// recursive head-by-root walk. When the peer's head is more than this many slots
// ahead of ours, we issue a single ranged request to catch up efficiently rather
// than chasing the parent chain one block at a time.
pub const BLOCKS_BY_RANGE_SYNC_THRESHOLD: u64 = 64;

// Minimum number of recent slots that a blocksByRange responder MUST keep available.
// Derived from leanSpec networking/config.py MIN_SLOTS_FOR_BLOCK_REQUESTS.
// Requests whose start_slot falls before (head_slot - MIN_SLOTS_FOR_BLOCK_REQUESTS)
// receive a RESOURCE_UNAVAILABLE error (code 3).
pub const MIN_SLOTS_FOR_BLOCK_REQUESTS: u64 = 3600;

// RPC error code for RESOURCE_UNAVAILABLE (per the ReqResp spec).
pub const RPC_ERR_RESOURCE_UNAVAILABLE: u32 = 3;
