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

// Grace window before proto-array rebuild fires on finalization advance,
// measured in *proto-array node count*, not slot distance.
//
// Eager rebase drops the just-finalized block's pre-finalized ancestors from
// proto-array and remaps attestation-tracker indices. In-flight attestations
// whose source / target / head still references one of those dropped blocks
// then fail existence checks with Unknown{Source,Target,Head}Block even
// though they were valid at sign time. 3SF-mini's fast finalization cadence
// makes this race fire across normal gossip delay.
//
// Gate rebase on the finalized node's index inside proto-array: only rebuild
// once at least PRUNE_NODE_THRESHOLD pre-finalized nodes sit before the
// finalized anchor. Below that, leave the prefix in place so in-flight
// attestations still resolve their references. On the canonical chain 64
// nodes corresponds to ~64 slots (≈256 s at SECONDS_PER_SLOT=4), but because
// the index counts every node in proto-array — including fork siblings —
// the wall-clock grace can be shorter under heavy forking. The bound on
// memory is directly in nodes (bounded, small) and is what this threshold
// is sizing for.
pub const PRUNE_NODE_THRESHOLD: usize = 64;

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
