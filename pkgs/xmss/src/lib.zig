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
pub const HashSigScheme = hashsig.HashSigScheme;
pub const PROD_SIGNATURE_SSZ_LEN = hashsig.PROD_SIGNATURE_SSZ_LEN;
pub const TEST_SIGNATURE_SSZ_LEN = hashsig.TEST_SIGNATURE_SSZ_LEN;
pub const signatureSszLenForScheme = hashsig.signatureSszLenForScheme;
pub const verifySsz = hashsig.verifySsz;
pub const signatureSszFromJson = hashsig.signatureSszFromJson;
pub const HashSigKeyPair = hashsig.HashSigKeyPair;
pub const HashSigSignature = hashsig.HashSigSignature;
pub const HashSigPublicKey = hashsig.HashSigPublicKey;
pub const HashSigPrivateKey = hashsig.HashSigPrivateKey;

test "get tests" {
    @import("std").testing.refAllDeclsRecursive(@This());
}
