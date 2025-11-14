const std = @import("std");
const ssz = @import("ssz");

const params = @import("@zeam/params");

const block = @import("./block.zig");
const mini_3sf = @import("./mini_3sf.zig");
const state = @import("./state.zig");
const utils = @import("./utils.zig");
const validator = @import("./validator.zig");

const Allocator = std.mem.Allocator;

const bytesToHex = utils.BytesToHex;
const json = std.json;

fn freeJsonValue(val: *json.Value, allocator: Allocator) void {
    switch (val.*) {
        .object => |*o| {
            var it = o.iterator();
            while (it.next()) |entry| {
                freeJsonValue(&entry.value_ptr.*, allocator);
            }
            o.deinit();
        },
        .array => |*a| {
            for (a.items) |*item| {
                freeJsonValue(item, allocator);
            }
            a.deinit();
        },
        .string => |s| allocator.free(s),
        else => {},
    }
}

// non ssz types, difference is the variable list doesn't need upper boundaries
pub const ZkVm = enum {
    ceno,
    powdr,
    sp1,

    pub fn toJson(self: *const ZkVm, allocator: Allocator) !json.Value {
        _ = allocator; // allocator is unused, but included for API consistency
        return json.Value{ .string = @tagName(self.*) };
    }

    pub fn toJsonString(self: *const ZkVm, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer json_value.deinit();
        return utils.jsonToString(allocator, json_value);
    }
};

pub const BeamSTFProof = struct {
    // zk_vm: ZkVm,
    proof: []const u8,

    pub fn deinit(_: *BeamSTFProof) void {}

    pub fn toJson(self: *const BeamSTFProof, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("proof", json.Value{ .string = try bytesToHex(allocator, self.proof) });
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamSTFProof, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJson(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }

    pub fn freeJson(val: *json.Value, allocator: Allocator) void {
        allocator.free(val.object.get("proof").?.string);
        val.object.deinit();
    }
};

pub const BeamSTFProverInput = struct {
    block: block.BeamBlock,
    state: state.BeamState,

    pub fn toJson(self: *const BeamSTFProverInput, allocator: Allocator) !json.Value {
        var obj = json.ObjectMap.init(allocator);
        try obj.put("block", try self.block.toJson(allocator));
        try obj.put("state", try self.state.toJson(allocator));
        return json.Value{ .object = obj };
    }

    pub fn toJsonString(self: *const BeamSTFProverInput, allocator: Allocator) ![]const u8 {
        var json_value = try self.toJson(allocator);
        defer freeJsonValue(&json_value, allocator);
        return utils.jsonToString(allocator, json_value);
    }
};

test "ssz seralize/deserialize signed stf prover input" {
    const config = state.BeamStateConfig{
        .num_validators = 4,
        .genesis_time = 93,
    };
    const genesis_root = [_]u8{9} ** 32;

    var test_state = state.BeamState{
        .config = config,
        .slot = 99,
        .latest_block_header = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = [_]u8{1} ** 32,
            .state_root = [_]u8{2} ** 32,
            .body_root = [_]u8{3} ** 32,
        },
        // mini3sf
        .latest_justified = .{ .root = [_]u8{5} ** 32, .slot = 0 },
        .latest_finalized = .{ .root = [_]u8{4} ** 32, .slot = 0 },
        .historical_block_hashes = try state.HistoricalBlockHashes.init(std.testing.allocator),
        .justified_slots = try state.JustifiedSlots.init(std.testing.allocator),
        .validators = try validator.Validators.init(std.testing.allocator),
        .justifications_roots = blk: {
            var roots = try ssz.utils.List(utils.Root, params.HISTORICAL_ROOTS_LIMIT).init(std.testing.allocator);
            try roots.append(genesis_root);
            break :blk roots;
        },
        .justifications_validators = blk: {
            var validators = try ssz.utils.Bitlist(params.HISTORICAL_ROOTS_LIMIT * params.VALIDATOR_REGISTRY_LIMIT).init(std.testing.allocator);
            try validators.append(true);
            try validators.append(false);
            try validators.append(true);
            try validators.append(false);
            break :blk validators;
        },
        // .justifications = .{
        //     .roots = &[_]Root{},
        //     .voting_validators = &[_]u8{},
        // },
    };
    defer test_state.deinit();

    var attestations = try block.Attestations.init(std.testing.allocator);

    var test_block = block.SignedBlockWithAttestation{
        .message = .{
            .block = .{
                .slot = 9,
                .proposer_index = 3,
                .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
                .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
                .body = .{
                    .attestations = attestations,
                },
            },
            .proposer_attestation = .{
                .validator_id = 3,
                .data = .{
                    .slot = 9,
                    .head = .{
                        .slot = 9,
                        .root = [_]u8{1} ** 32,
                    },
                    .source = .{
                        .slot = 0,
                        .root = [_]u8{0} ** 32,
                    },
                    .target = .{
                        .slot = 9,
                        .root = [_]u8{1} ** 32,
                    },
                },
            },
        },
        .signature = try block.createBlockSignatures(std.testing.allocator, attestations.len()),
    };
    defer test_block.message.block.body.attestations.deinit();
    defer test_block.signature.deinit();

    const prover_input = BeamSTFProverInput{
        .state = test_state,
        .block = test_block.message.block,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var serialized = std.ArrayList(u8).init(arena_allocator.allocator());
    defer serialized.deinit();
    try ssz.serialize(BeamSTFProverInput, prover_input, &serialized);

    var prover_input_deserialized: BeamSTFProverInput = undefined;
    try ssz.deserialize(BeamSTFProverInput, serialized.items[0..], &prover_input_deserialized, arena_allocator.allocator());

    // TODO create a sszEql fn in ssz to recursively compare two ssz structures
    // for now inspect two items
    try std.testing.expect(prover_input.block.body.attestations.len() == prover_input_deserialized.block.body.attestations.len());
    try std.testing.expect(std.mem.eql(u8, &prover_input.state.latest_block_header.state_root, &prover_input_deserialized.state.latest_block_header.state_root));
}
