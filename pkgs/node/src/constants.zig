const std = @import("std");
const params = @import("@zeam/params");

// a constant fixed only relevant to node operation and hence not in the config or preset
pub const INTERVALS_PER_SLOT = 5;
pub const SECONDS_PER_INTERVAL_MS: isize = @divFloor(params.SECONDS_PER_SLOT * std.time.ms_per_s, INTERVALS_PER_SLOT);

// Maximum number of slots in the future that an attestation/block is allowed to
// reference for *immediate* acceptance. Anything beyond this is treated as a
// future block (queued via `pending_blocks`) or, for attestations, rejected.
// One slot of tolerance covers the normal race between `onInterval` and a
// neighbouring node's gossip arriving slightly early.
//
// leanSpec note: this is a zeam-specific constant, not spec-defined. leanSpec
// uses GOSSIP_DISPARITY_INTERVALS = 1 (~800ms) for *attestations*
// (forks/lstar/spec.py:1022) with an explicit anti-pre-publish argument; for
// blocks no spec constant exists and we follow the Ethereum CL p2p-interface
// convention of allowing future-slot blocks to be queued. 4 s vs 800 ms is
// wider than the attestation analog but matches existing zeam behaviour from
// before #788 (#788 preserves rather than introduces this value).
pub const MAX_FUTURE_SLOT_TOLERANCE = 1;

// Maximum number of slots in the future that a *block* may be queued for
// later replay from `pending_blocks`. Issue #788: under mutex contention
// (#786) the local `onInterval` can be delayed long enough that the forkchoice
// clock lags wall-time by tens of slots; gossip blocks for those slots arrive
// at the wall-clock time and would otherwise be rejected with `FutureSlot`,
// causing the fork choice head to fall back to the latest finalized
// checkpoint when no descendants exist in the protoArray. Buffering up to
// `MAX_FUTURE_SLOT_QUEUE_TOLERANCE` slots ahead lets the queue absorb the
// worst observed lag (~160 slots in the linked devnet-4 incident) so blocks
// can be replayed once the clock catches up. Anything beyond this is almost
// certainly an actually-malicious or buggy peer and is dropped.
//
// Tuning note: 256 is empirical, derived from devnet-4's worst lag. There is
// no leanSpec analog — the spec doesn't define a future-block queue depth
// (cf. `MAX_FUTURE_SLOT_TOLERANCE` above where a partial analog exists). This
// value SHOULD be revisited if `zeam_lock_hold_seconds` reaches new highs
// under devnet-N (N > 4) or if `lean_blocks_future_slot_dropped_total` shows
// sustained drops on a healthy network. Don't ossify the magic number.
pub const MAX_FUTURE_SLOT_QUEUE_TOLERANCE: u64 = 256;

// Maximum number of blocks held in the `pending_blocks` future-block queue.
// Bounded to prevent OOM from a malicious or buggy peer that gossips a wide
// range of fake-future blocks. Sized to comfortably exceed the worst observed
// catch-up window (#788) without giving an attacker meaningful memory
// pressure: at ~2KB per `SignedBlock` envelope (varies with attestation
// count) this caps the queue at ~2MB which is negligible vs the rest of
// chain state. Older entries (lower-slot, lower-receive-time) are evicted
// first when the cap is hit.
//
// leanSpec analog: `subspecs/sync/config.py::MAX_CACHED_BLOCKS` (also 1024;
// same magnitude, same FIFO-eviction policy on overflow). Naming differs
// because `pending_blocks` is zeam's pre-existing identifier for the
// future-block queue and renaming it would touch every callsite without
// behavioural benefit; flag the spec mapping here so future maintainers
// can find the spec source when leanSpec test vectors land.
pub const MAX_PENDING_BLOCKS: usize = 1024;

// Maximum depth for recursive block fetching
// When fetching parent blocks, we stop after this many levels to avoid infinite loops
pub const MAX_BLOCK_FETCH_DEPTH = 512;

// Maximum number of blocks to keep in the fetched blocks cache
// This prevents unbounded memory growth from malicious peers sending orphaned blocks.
//
// leanSpec analog: `subspecs/sync/config.py::MAX_CACHED_BLOCKS` (this constant
// is the direct Zig mirror of the spec name; see `MAX_PENDING_BLOCKS` for the
// related future-block queue cap with a different scope).
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
