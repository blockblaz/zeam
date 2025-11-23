const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const Allocator = std.mem.Allocator;

const KeyManagerError = error{
    ValidatorKeyNotFound,
};

pub const KeyManager = struct {
    keys: std.AutoHashMap(usize, xmss.KeyPair),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .keys = std.AutoHashMap(usize, xmss.KeyPair).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.keys.deinit();
    }

    pub fn addKeypair(self: *Self, validator_id: usize, keypair: xmss.KeyPair) !void {
        try self.keys.put(validator_id, keypair);
    }

    pub fn loadFromKeypairDir(_: *Self, _: []const u8) !void {
        // Dummy function for now
        return;
    }

    pub fn signAttestation(
        self: *const Self,
        attestation: *const types.Attestation,
        allocator: Allocator,
    ) !types.SIGBYTES {
        const validator_index: usize = @intCast(attestation.validator_id);

        const keypair = self.keys.get(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;

        var message: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.Attestation, attestation.*, &message, allocator);

        const epoch: u32 = @intCast(attestation.data.slot);
        var signature = try keypair.sign(&message, epoch);
        defer signature.deinit();

        var sig_buffer: types.SIGBYTES = undefined;
        const bytes_written = try signature.toBytes(&sig_buffer);

        if (bytes_written < types.SIGSIZE) {
            @memset(sig_buffer[bytes_written..], 0);
        }

        return sig_buffer;
    }

    pub fn getPublicKeyBytes(
        self: *const Self,
        validator_index: usize,
        buffer: []u8,
    ) !usize {
        const keypair = self.keys.get(validator_index) orelse return KeyManagerError.ValidatorKeyNotFound;
        return try keypair.pubkeyToBytes(buffer);
    }

    /// Extract all validator public keys into an array
    /// Caller owns the returned slice and must free it
    pub fn getAllPubkeys(
        self: *const Self,
        allocator: Allocator,
        num_validators: usize,
    ) ![]types.Bytes52 {
        const pubkeys = try allocator.alloc(types.Bytes52, num_validators);
        errdefer allocator.free(pubkeys);

        // XMSS public keys are always exactly 52 bytes
        for (0..num_validators) |i| {
            _ = try self.getPublicKeyBytes(i, &pubkeys[i]);
        }

        return pubkeys;
    }
};

pub fn getTestKeyManager(
    allocator: Allocator,
    num_validators: usize,
    max_slot: usize,
) !KeyManager {
    var key_manager = KeyManager.init(allocator);
    errdefer key_manager.deinit();

    const num_active_epochs = max_slot + 1;

    for (0..num_validators) |i| {
        const seed = try std.fmt.allocPrint(allocator, "test_validator_{d}", .{i});
        defer allocator.free(seed);

        const keypair = try xmss.KeyPair.generate(
            allocator,
            seed,
            0,
            num_active_epochs,
        );
        try key_manager.addKeypair(i, keypair);
    }

    return key_manager;
}
