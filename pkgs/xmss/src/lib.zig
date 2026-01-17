const aggregate = @import("aggregation.zig");
pub const MAX_AGGREGATE_SIGNATURE_SIZE = aggregate.MAX_AGGREGATE_SIGNATURE_SIZE;
pub const ByteListMiB = aggregate.ByteListMiB;
pub const AggregationError = aggregate.AggregationError;
pub const setupProver = aggregate.setupProver;
pub const setupVerifier = aggregate.setupVerifier;
pub const aggregateSignatures = aggregate.aggregateSignatures;
pub const verifyAggregatedPayload = aggregate.verifyAggregatedPayload;
pub const aggregate_module = aggregate;

const hashsig = @import("hashsig.zig");
pub const KeyPair = hashsig.KeyPair;
pub const Signature = hashsig.Signature;
pub const PublicKey = hashsig.PublicKey;
pub const HashSigError = hashsig.HashSigError;
pub const verifySsz = hashsig.verifySsz;
pub const HashSigKeyPair = hashsig.HashSigKeyPair;
pub const HashSigSignature = hashsig.HashSigSignature;
pub const HashSigPublicKey = hashsig.HashSigPublicKey;
pub const HashSigPrivateKey = hashsig.HashSigPrivateKey;

test "get tests" {
    @import("std").testing.refAllDeclsRecursive(@This());
}
