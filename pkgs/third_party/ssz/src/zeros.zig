// List of root hashes of zero-subtrees, up to depth 255.
const std = @import("std");

/// Generic function to build zero hashes for any hash function
/// HashType should be a hash type like std.crypto.hash.sha2.Sha256
/// digest_length is the output size of the hash in bytes
pub fn buildHashesOfZero(comptime HashType: type, comptime digest_length: usize, comptime depth: usize) [depth][digest_length]u8 {
    @setEvalBranchQuota(10000000);
    var ret: [depth][digest_length]u8 = undefined;

    var current = [_]u8{0} ** digest_length;

    ret[0] = current;

    var i: usize = 1;
    while (i < depth) : (i += 1) {
        // Hash the current level twice (left and right child are the same)
        var hasher = HashType.init(.{});
        hasher.update(&current);
        hasher.update(&current);
        current = hasher.finalResult();
        ret[i] = current;
    }

    return ret;
}

// SHA256 zero hashes (the default for SSZ)
pub const hashes_of_zero = buildHashesOfZero(std.crypto.hash.sha2.Sha256, 32, 256);
