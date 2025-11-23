const std = @import("std");
const params = @import("@zeam/params");

// a constant fixed only relevant to node operation and hence not in the config or preset
pub const INTERVALS_PER_SLOT = 4;
pub const SECONDS_PER_INTERVAL_MS: isize = @divFloor(params.SECONDS_PER_SLOT * std.time.ms_per_s, INTERVALS_PER_SLOT);

// Maximum number of slots in the future that an attestation is allowed to reference
// This prevents accepting attestations that are too far ahead of the current slot
pub const MAX_FUTURE_SLOT_TOLERANCE = 1;

// Maximum depth for recursive block fetching
// When fetching parent blocks, we stop after this many levels to avoid infinite loops
pub const MAX_BLOCK_FETCH_DEPTH = 64;

// Maximum number of blocks to keep in the fetched blocks cache
// This prevents unbounded memory growth from malicious peers sending orphaned blocks
pub const MAX_CACHED_BLOCKS = 1024;
