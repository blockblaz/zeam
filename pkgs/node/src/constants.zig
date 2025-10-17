const std = @import("std");
const params = @import("@zeam/params");

// a constant fixed only relevant to node operation and hence not in the config or preset
pub const INTERVALS_PER_SLOT = 4;
pub const SECONDS_PER_INTERVAL_MS: isize = @divFloor(params.SECONDS_PER_SLOT * std.time.ms_per_s, INTERVALS_PER_SLOT);

// Maximum number of slots in the future that an attestation is allowed to reference
// This prevents accepting attestations that are too far ahead of the current slot
pub const MAX_FUTURE_SLOT_TOLERANCE = 1;
