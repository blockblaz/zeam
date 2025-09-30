const ssz = @import("ssz");
const params = @import("@zeam/params");

const utils = @import("./utils.zig");

pub const Mini3SFCheckpoint = struct {
    root: utils.Root,
    slot: utils.Slot,
};

pub const Mini3SFVote = struct {
    slot: utils.Slot,
    head: Mini3SFCheckpoint,
    target: Mini3SFCheckpoint,
    source: Mini3SFCheckpoint,
};

// this will be updated to correct impl in the followup PR to reflect latest spec changes
pub const SignedVote = struct {
    validator_id: utils.ValidatorIndex,
    message: Mini3SFVote,
    // TODO signature objects to be updated in a followup PR
    signature: utils.Bytes4000,
};

pub const Mini3SFVotes = ssz.utils.List(Mini3SFVote, params.VALIDATOR_REGISTRY_LIMIT);
pub const SignedVotes = ssz.utils.List(SignedVote, params.VALIDATOR_REGISTRY_LIMIT);
