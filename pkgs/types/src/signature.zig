const std = @import("std");
const ssz = @import("ssz");
const params = @import("@zeam/params");
const zeam_utils = @import("@zeam/utils");

const Allocator = std.mem.Allocator;

// XMSS configuration constants from params
const HASH_LEN_FE = params.XMSS_HASH_LEN_FE;
const RAND_LEN_FE = params.XMSS_RAND_LEN_FE;
const NODE_LIST_LIMIT = params.XMSS_NODE_LIST_LIMIT;
const FP_BYTES = params.FP_BYTES;

/// KoalaBear field element.
/// Represented as a 4-byte little-endian unsigned integer.
/// The prime is P = 2^31 - 2^24 + 1.
pub const Fp = u32;

/// A single hash digest represented as a fixed-size vector of field elements.
/// In SSZ notation: Vector[Fp, HASH_LEN_FE] where HASH_LEN_FE = 8.
/// Total size: 8 * 4 = 32 bytes.
pub const HashDigestVector = [HASH_LEN_FE]Fp;

/// Zero-initialized hash digest for default values.
pub const ZERO_HASH_DIGEST: HashDigestVector = [_]Fp{0} ** HASH_LEN_FE;

/// Variable-length list of hash digests.
/// In SSZ notation: List[Vector[Fp, HASH_LEN_FE], NODE_LIST_LIMIT]
/// where NODE_LIST_LIMIT = 2^17 = 131072.
pub const HashDigestList = ssz.utils.List(HashDigestVector, NODE_LIST_LIMIT);

/// The randomness rho used during signing.
/// In SSZ notation: Vector[Fp, RAND_LEN_FE] where RAND_LEN_FE = 7.
/// Total size: 7 * 4 = 28 bytes.
pub const Randomness = [RAND_LEN_FE]Fp;

/// Zero-initialized randomness for default values.
pub const ZERO_RANDOMNESS: Randomness = [_]Fp{0} ** RAND_LEN_FE;

/// A Merkle authentication path (HashTreeOpening).
/// Contains the sibling nodes needed to verify a leaf's position in the Merkle tree.
///
/// SSZ Container with fields:
/// - siblings: List[Vector[Fp, HASH_LEN_FE], NODE_LIST_LIMIT]
///
/// This is a variable-size container because siblings is a List (not Vector).
/// The number of siblings varies based on tree depth.
pub const HashTreeOpening = struct {
    siblings: HashDigestList,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        return Self{
            .siblings = try HashDigestList.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.siblings.deinit();
    }

    pub fn clone(self: *const Self, allocator: Allocator) !Self {
        var cloned = try Self.init(allocator);
        errdefer cloned.deinit();

        // Copy siblings one by one
        for (self.siblings.constSlice()) |item| {
            try cloned.siblings.append(item);
        }
        return cloned;
    }

    /// Compute the SSZ hash_tree_root of this container.
    pub fn sszRoot(self: *const Self, allocator: Allocator) ![32]u8 {
        var root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(HashTreeOpening, self.*, &root, allocator);
        return root;
    }
};

/// A signature produced by the Generalized XMSS sign function.
/// Contains all components needed for verification.
///
/// SSZ Container with fields:
/// - path: HashTreeOpening (container with variable-length siblings list)
/// - rho: Vector[Fp, RAND_LEN_FE] (fixed-size, 28 bytes)
/// - hashes: List[Vector[Fp, HASH_LEN_FE], NODE_LIST_LIMIT] (variable-length)
///
/// This matches leanSpec's Signature container structure.
/// The hash_tree_root is computed as:
///   merkle_root([HTR(path), HTR(rho), HTR(hashes)])
///
/// NOT as merkleize(raw 3112 bytes) which would be incorrect.
pub const Signature = struct {
    path: HashTreeOpening,
    rho: Randomness,
    hashes: HashDigestList,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        return Self{
            .path = try HashTreeOpening.init(allocator),
            .rho = ZERO_RANDOMNESS,
            .hashes = try HashDigestList.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.path.deinit();
        self.hashes.deinit();
    }

    pub fn clone(self: *const Self, allocator: Allocator) !Self {
        var cloned = try Self.init(allocator);
        errdefer cloned.deinit();

        // Copy path siblings
        for (self.path.siblings.constSlice()) |item| {
            try cloned.path.siblings.append(item);
        }

        // Copy fixed-size rho directly
        cloned.rho = self.rho;

        // Copy hashes one by one
        for (self.hashes.constSlice()) |item| {
            try cloned.hashes.append(item);
        }

        return cloned;
    }

    /// Compute the SSZ hash_tree_root of this signature container.
    /// This computes: merkle_root([HTR(path), HTR(rho), HTR(hashes)])
    pub fn sszRoot(self: *const Self, allocator: Allocator) ![32]u8 {
        var root: [32]u8 = undefined;
        try zeam_utils.hashTreeRoot(Signature, self.*, &root, allocator);
        return root;
    }

    /// Serialize the signature to SSZ bytes.
    /// The encoding uses offsets for variable-length fields (path, hashes).
    pub fn toSszBytes(self: *const Self, allocator: Allocator) ![]u8 {
        var serialized: std.ArrayList(u8) = .empty;
        try ssz.serialize(Self, self.*, &serialized, allocator);
        return serialized.toOwnedSlice(allocator);
    }

    /// Deserialize a signature from SSZ bytes.
    pub fn fromSszBytes(bytes: []const u8, allocator: Allocator) !Self {
        var result: Self = undefined;
        try ssz.deserialize(Self, bytes, &result, allocator);
        return result;
    }
};

// Tests
test "HashDigestVector size" {
    const size = @sizeOf(HashDigestVector);
    try std.testing.expectEqual(@as(usize, 32), size); // 8 * 4 bytes
}

test "Randomness size" {
    const size = @sizeOf(Randomness);
    try std.testing.expectEqual(@as(usize, 28), size); // 7 * 4 bytes
}

test "HashTreeOpening init and deinit" {
    var opening = try HashTreeOpening.init(std.testing.allocator);
    defer opening.deinit();

    try std.testing.expectEqual(@as(usize, 0), opening.siblings.len());
}

test "Signature init and deinit" {
    var sig = try Signature.init(std.testing.allocator);
    defer sig.deinit();

    try std.testing.expectEqual(@as(usize, 0), sig.path.siblings.len());
    try std.testing.expectEqual(@as(usize, 0), sig.hashes.len());
    try std.testing.expectEqual(ZERO_RANDOMNESS, sig.rho);
}

test "Signature clone" {
    var sig = try Signature.init(std.testing.allocator);
    defer sig.deinit();

    // Add some data
    const digest: HashDigestVector = [_]Fp{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try sig.path.siblings.append(digest);
    try sig.hashes.append(digest);
    sig.rho = [_]Fp{ 10, 20, 30, 40, 50, 60, 70 };

    var cloned = try sig.clone(std.testing.allocator);
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 1), cloned.path.siblings.len());
    try std.testing.expectEqual(@as(usize, 1), cloned.hashes.len());
    try std.testing.expectEqual(sig.rho, cloned.rho);
}

test "XMSS constants are correct" {
    // Verify constants match leanSpec PROD_CONFIG
    try std.testing.expectEqual(@as(u32, 8), HASH_LEN_FE);
    try std.testing.expectEqual(@as(u32, 7), RAND_LEN_FE);
    try std.testing.expectEqual(@as(u32, 131072), NODE_LIST_LIMIT); // 2^17
    try std.testing.expectEqual(@as(u32, 4), FP_BYTES);
}
