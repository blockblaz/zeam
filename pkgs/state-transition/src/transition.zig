const ssz = @import("ssz");
const std = @import("std");
const json = std.json;
const types = @import("@zeam/types");
const utils = types.utils;

const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");
const xmss = @import("@zeam/xmss");
const zeam_metrics = @import("@zeam/metrics");

const Allocator = std.mem.Allocator;
const debugLog = zeam_utils.zeamLog;
const StateTransitionError = types.StateTransitionError;

// put the active logs at debug level for now by default
pub const StateTransitionOpts = struct {
    // signatures are validated outside for keeping life simple for the STF prover
    // we will trust client will validate them however the flag here
    // represents such dependency and assumption for STF
    validSignatures: bool = true,
    validateResult: bool = true,
    logger: zeam_utils.ModuleLogger,
};

// pub fn process_epoch(state: types.BeamState) void {
//     // right now nothing to do
//     _ = state;
//     return;
// }

// not active in PQ devnet0 - zig will automatically prune this from code
fn process_execution_payload_header(state: *types.BeamState, block: types.BeamBlock) !void {
    const expected_timestamp = state.genesis_time + block.slot * params.SECONDS_PER_SLOT;
    if (expected_timestamp != block.body.execution_payload_header.timestamp) {
        return StateTransitionError.InvalidExecutionPayloadHeaderTimestamp;
    }
}

pub fn apply_raw_block(allocator: Allocator, state: *types.BeamState, block: *types.BeamBlock, logger: zeam_utils.ModuleLogger) !void {
    // prepare pre state to process block for that slot, may be rename prepare_pre_stateCollapse comment
    const transition_timer = zeam_metrics.lean_state_transition_time_seconds.start();
    defer _ = transition_timer.observe();

    // prepare pre state to process block for that slot, may be rename prepare_pre_state
    try state.process_slots(allocator, block.slot, logger);

    // process block and modify the pre state to post state
    try state.process_block(allocator, block.*, logger);

    logger.debug("extracting state root\n", .{});
    // extract the post state root
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
    block.state_root = state_root;
}

// fill this up when we have signature scheme
pub fn verifySignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlockWithAttestation,
) !void {
    const attestations = signed_block.message.block.body.attestations.constSlice();
    const signatures = signed_block.signature.constSlice();

    // Must have exactly one signature per attestation plus one for proposer
    if (attestations.len + 1 != signatures.len) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    // Verify all body attestations
    for (attestations, 0..) |attestation, i| {
        try verifySingleAttestation(
            allocator,
            state,
            &attestation,
            &signatures[i],
        );
    }

    // Verify proposer attestation (last signature in the list)
    try verifySingleAttestation(
        allocator,
        state,
        &signed_block.message.proposer_attestation,
        &signatures[signatures.len - 1],
    );
}

pub fn verifySingleAttestation(
    allocator: Allocator,
    state: *const types.BeamState,
    attestation: *const types.Attestation,
    signatureBytes: *const types.Bytes4000,
) !void {
    const validatorIndex: usize = @intCast(attestation.validator_id);
    const validators = state.validators.constSlice();
    if (validatorIndex >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }

    const validator = &validators[validatorIndex];
    const pubkey = validator.getPubkey();

    var message: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.Attestation, attestation.*, &message, allocator);

    const epoch: u32 = @intCast(attestation.data.slot);

    try xmss.verifyBincode(pubkey, &message, epoch, signatureBytes);
}

// TODO(gballet) check if beam block needs to be a pointer
pub fn apply_transition(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock, opts: StateTransitionOpts) !void {
    opts.logger.debug("applying  state transition state-slot={d} block-slot={d}\n", .{ state.slot, block.slot });

    const transition_timer = zeam_metrics.lean_state_transition_time_seconds.start();
    defer _ = transition_timer.observe();

    // client is supposed to call verify_signatures outside STF to make STF prover friendly
    const validSignatures = opts.validSignatures;
    if (!validSignatures) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    // prepare the pre state for this block slot
    try state.process_slots(allocator, block.slot, opts.logger);

    // process the block
    try state.process_block(allocator, block, opts.logger);

    const validateResult = opts.validateResult;
    if (validateResult) {
        // verify the post state root
        var state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(*types.BeamState, state, &state_root, allocator);
        if (!std.mem.eql(u8, &state_root, &block.state_root)) {
            opts.logger.debug("state root={x:02} block root={x:02}\n", .{ state_root, block.state_root });
            return StateTransitionError.InvalidPostState;
        }
    }
}
