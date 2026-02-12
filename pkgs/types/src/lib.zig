const aggregation = @import("./aggregation.zig");
pub const AggregatedSignatureProof = aggregation.AggregatedSignatureProof;

const attestation = @import("./attestation.zig");
pub const AggregationBits = attestation.AggregationBits;
pub const AttestationData = attestation.AttestationData;
pub const Attestation = attestation.Attestation;
pub const SignedAttestation = attestation.SignedAttestation;
pub const AggregatedAttestation = attestation.AggregatedAttestation;
pub const aggregationBitsEnsureLength = attestation.aggregationBitsEnsureLength;
pub const aggregationBitsSet = attestation.aggregationBitsSet;
pub const aggregationBitsToValidatorIndices = attestation.aggregationBitsToValidatorIndices;

const block = @import("./block.zig");
pub const BlockByRootRequest = block.BlockByRootRequest;
pub const blockByRootRequestToJson = block.blockByRootRequestToJson;
pub const blockByRootRequestToJsonString = block.blockByRootRequestToJsonString;
pub const ProtoBlock = block.ProtoBlock;
pub const BeamBlock = block.BeamBlock;
pub const ExecutionPayloadHeader = block.ExecutionPayloadHeader;
pub const BeamBlockHeader = block.BeamBlockHeader;
pub const BeamBlockBody = block.BeamBlockBody;
pub const BlockWithAttestation = block.BlockWithAttestation;
pub const SignedBlockWithAttestation = block.SignedBlockWithAttestation;
pub const AggregatedAttestations = block.AggregatedAttestations;
pub const AggregatedAttestationsResult = block.AggregatedAttestationsResult;
pub const AttestationSignatures = block.AttestationSignatures;
pub const BlockSignatures = block.BlockSignatures;
pub const createBlockSignatures = block.createBlockSignatures;
pub const SignatureKey = block.SignatureKey;
pub const StoredSignature = block.StoredSignature;
pub const SignaturesMap = block.SignaturesMap;
pub const StoredAggregatedPayload = block.StoredAggregatedPayload;
pub const AggregatedPayloadsList = block.AggregatedPayloadsList;
pub const AggregatedPayloadsMap = block.AggregatedPayloadsMap;

const state = @import("./state.zig");
pub const BeamStateConfig = state.BeamStateConfig;
pub const BeamState = state.BeamState;
pub const HistoricalBlockHashes = state.HistoricalBlockHashes;
pub const JustificationRoots = state.JustificationRoots;
pub const JustifiedSlots = state.JustifiedSlots;
pub const JustificationValidators = state.JustificationValidators;

const validator = @import("./validator.zig");
pub const Validator = validator.Validator;
pub const Validators = validator.Validators;

const mini_3sf = @import("./mini_3sf.zig");
pub const Checkpoint = mini_3sf.Checkpoint;
pub const Status = mini_3sf.Status;

const utils = @import("./utils.zig");
pub const jsonToString = utils.jsonToString;
pub const Bytes32 = utils.Bytes32;
pub const Slot = utils.Slot;
pub const Interval = utils.Interval;
pub const ValidatorIndex = utils.ValidatorIndex;
pub const Bytes48 = utils.Bytes48;
pub const SIGSIZE = utils.SIGSIZE;
pub const SIGBYTES = utils.SIGBYTES;
pub const Root = utils.Root;
pub const RootHex = utils.RootHex;
pub const ZERO_HASH = utils.ZERO_HASH;
pub const ZERO_SIGBYTES = utils.ZERO_SIGBYTES;
pub const StateTransitionError = utils.StateTransitionError;
pub const BytesToHex = utils.BytesToHex;
pub const Bytes52 = utils.Bytes52;
pub const GenesisSpec = utils.GenesisSpec;
pub const ChainSpec = utils.ChainSpec;
pub const sszClone = utils.sszClone;
pub const IsJustifiableSlot = utils.IsJustifiableSlot;

const zk = @import("./zk.zig");
pub const ZkVm = zk.ZkVm;
pub const BeamSTFProof = zk.BeamSTFProof;
pub const BeamSTFProverInput = zk.BeamSTFProverInput;

// TODO: use refAllDeclsRecursive instead of refAllDecls
// Avoids refAllDeclsRecursive as ssz lists tests fail
// SignedAttestation and Validator both have byte array fields
// sszlibrary should use std.meta.eql instead of std.mem.eql for struct types
test "get tests" {
    @import("std").testing.refAllDecls(@This());
}
