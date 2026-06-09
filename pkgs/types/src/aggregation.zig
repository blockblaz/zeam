const std = @import("std");
const params = @import("@zeam/params");
const xmss = @import("@zeam/xmss");

const utils = @import("./utils.zig");

const Allocator = std.mem.Allocator;
const json = std.json;

const attestation = @import("./attestation.zig");

const AggregationBits = attestation.AggregationBits;
pub const ByteList512KiB = xmss.ByteList512KiB;

pub const MessageBinding = xmss.MessageBinding;

const freeJsonValue = utils.freeJsonValue;

/// Protocol-level log inverse rate parameters for aggregation.
pub const LOG_INV_RATE_TEST: usize = 1;
pub const LOG_INV_RATE_PROD: usize = 2;

/// A single-message multi-signature proof: many validators over one message+slot.
/// `participants` is the validator bitfield; `proof` is the compact no-pubkeys wire form.
pub const SingleMessageAggregate = struct {
    participants: attestation.AggregationBits,
    proof: ByteList512KiB,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var participants = try attestation.AggregationBits.init(allocator);
        errdefer participants.deinit();

        var proof = try ByteList512KiB.init(allocator);
        errdefer proof.deinit();

        return Self{
            .participants = participants,
            .proof = proof,
        };
    }

    pub fn deinit(self: *Self) void {
        self.participants.deinit();
        self.proof.deinit();
    }

    pub fn toJson(self: *const Self, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.empty;

        // Serialize participants as array of booleans
        var participants_array = json.Array.init(allocator);
        errdefer participants_array.deinit();
        for (0..self.participants.len()) |i| {
            try participants_array.append(json.Value{ .bool = try self.participants.get(i) });
        }
        try obj.put(allocator, "participants", json.Value{ .array = participants_array });

        // Serialize proof as hex string
        const proof_bytes = self.proof.constSlice();
        const proof_hex = try utils.BytesToHex(allocator, proof_bytes);
        try obj.put(allocator, "proof", json.Value{ .string = proof_hex });

        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    /// Recursively aggregate child Type-1 proofs and raw XMSS signatures into a single Type-1.
    ///
    /// - `xmss_participants`: bitfield for validators represented by raw_xmss. null if no raw sigs.
    /// - `children`: already-aggregated child Type-1 proofs to include.
    /// - `children_pub_keys`: per-child arrays of public key handles (parallel with `children`).
    /// - `raw_xmss_pks`/`raw_xmss_sigs`: raw XMSS public key + signature pairs.
    /// - Validation: at least 1 raw sig or child required; if no raw sigs, need ≥2 children
    ///   (a lone child is already a valid proof — nothing to re-aggregate).
    pub fn aggregate(
        allocator: Allocator,
        xmss_participants: ?AggregationBits,
        children: []const SingleMessageAggregate,
        children_pub_keys: []const []*const xmss.HashSigPublicKey,
        raw_xmss_pks: []*const xmss.HashSigPublicKey,
        raw_xmss_sigs: []*const xmss.HashSigSignature,
        message_hash: *const [32]u8,
        epoch: u64,
        result: *Self,
    ) !void {
        const has_raw = xmss_participants != null;
        const has_children = children.len > 0;

        if (!has_raw and !has_children) return error.AggregationInvalidInput;
        if (!has_raw and children.len < 2) return error.AggregationInvalidInput;

        // Merge participant bitfields
        var merged = try attestation.AggregationBits.init(allocator);
        errdefer merged.deinit();

        // Add gossip participants
        if (xmss_participants) |gp| {
            for (0..gp.len()) |i| {
                if (gp.get(i) catch false) {
                    try attestation.aggregationBitsSet(&merged, i, true);
                }
            }
        }

        // Add all children participants
        for (children) |child| {
            for (0..child.participants.len()) |i| {
                if (child.participants.get(i) catch false) {
                    try attestation.aggregationBitsSet(&merged, i, true);
                }
            }
        }

        // Build per-child proof wire array for the FFI (parallel with children_pub_keys).
        const children_proofs = try allocator.alloc(ByteList512KiB, children.len);
        defer allocator.free(children_proofs);
        for (children, 0..) |child, i| {
            children_proofs[i] = child.proof;
        }

        // FFI call — recursive Type-1 aggregation over raw sigs + child proofs.
        try xmss.aggregateType1(
            raw_xmss_pks,
            raw_xmss_sigs,
            children_pub_keys,
            children_proofs,
            message_hash,
            @intCast(epoch),
            LOG_INV_RATE_PROD,
            &result.proof,
        );

        // Clean up old participants before overwriting.
        result.participants.deinit();
        result.participants = merged;
    }

    /// Verify this Type-1 proof against the participants' public keys, message, and slot.
    pub fn verify(self: *const Self, public_keys: []*const xmss.HashSigPublicKey, message_hash: *const [32]u8, epoch: u64) !void {
        try xmss.verifyType1(public_keys, message_hash, @intCast(epoch), &self.proof);
    }
};

/// A multi-message multi-signature proof: a merge of N Type-1 proofs over distinct messages.
/// On the wire a SignedBlock carries the SSZ-encoded form of this container as its single proof.
/// `proof` is the compact no-pubkeys wire form (lz4+postcard; NOT SSZ-framed).
pub const MultiMessageAggregate = struct {
    proof: ByteList512KiB,

    const Self = @This();

    pub fn init(allocator: Allocator) !Self {
        var proof = try ByteList512KiB.init(allocator);
        errdefer proof.deinit();
        return Self{ .proof = proof };
    }

    pub fn deinit(self: *Self) void {
        self.proof.deinit();
    }

    pub fn toJson(self: *const Self, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.empty;
        const proof_bytes = self.proof.constSlice();
        const proof_hex = try utils.BytesToHex(allocator, proof_bytes);
        try obj.put(allocator, "proof", json.Value{ .string = proof_hex });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const Self, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    /// Merge N Type-1 proofs (each over a distinct message) into one Type-2 proof.
    ///
    /// - `parts`: the Type-1 proofs to merge, in canonical component order (caller's responsibility:
    ///   block attestations in body order, then the proposer entry last).
    /// - `public_keys_per_part`: parallel per-part participant pubkey handles, same order as `parts`.
    /// - `result` must be an init'd, empty `MultiMessageAggregate`.
    pub fn aggregate(
        allocator: Allocator,
        parts: []const SingleMessageAggregate,
        public_keys_per_part: []const []*const xmss.HashSigPublicKey,
        result: *Self,
    ) !void {
        if (parts.len != public_keys_per_part.len) return error.AggregationInvalidInput;
        if (parts.len == 0) return error.AggregationInvalidInput;

        const part_proofs = try allocator.alloc(ByteList512KiB, parts.len);
        defer allocator.free(part_proofs);
        for (parts, 0..) |part, i| {
            part_proofs[i] = part.proof;
        }

        try xmss.mergeType1ToType2(
            part_proofs,
            public_keys_per_part,
            LOG_INV_RATE_PROD,
            &result.proof,
        );
    }

    /// Verify this Type-2 proof against per-component pubkeys and (message, slot) bindings.
    /// `public_keys_per_message` and `messages` are parallel, in component order.
    pub fn verify(
        self: *const Self,
        public_keys_per_message: []const []*const xmss.HashSigPublicKey,
        messages: []const MessageBinding,
    ) !void {
        try xmss.verifyType2(&self.proof, public_keys_per_message, messages);
    }

    /// Recover the Type-1 component bound to `message_hash` out of this Type-2.
    /// `public_keys_per_message` is the per-component pubkey layout the Type-2 was built with.
    /// The recovered Type-1's `participants` is left EMPTY — the caller restores it from the
    /// matching attestation's aggregation bits.
    /// `result` must be an init'd, empty `SingleMessageAggregate`.
    pub fn splitByMessage(
        self: *const Self,
        public_keys_per_message: []const []*const xmss.HashSigPublicKey,
        message_hash: *const [32]u8,
        result: *SingleMessageAggregate,
    ) !void {
        try xmss.splitType2ByMessage(
            &self.proof,
            public_keys_per_message,
            message_hash,
            LOG_INV_RATE_PROD,
            &result.proof,
        );
    }
};
