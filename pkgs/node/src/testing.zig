const std = @import("std");
const Allocator = std.mem.Allocator;

const database = @import("@zeam/database");
const configs = @import("@zeam/configs");
const key_manager = @import("@zeam/key-manager");
const params = @import("@zeam/params");
const types = @import("@zeam/types");
const zeam_utils = @import("@zeam/utils");
const xev = @import("xev");
const networks = @import("@zeam/network");

const clockFactory = @import("./clock.zig");

pub const NodeTestOptions = struct {
    num_validators: usize = 4,
    key_manager_slots: usize = 10,
    genesis_time: u64 = 0,
    preset: params.Preset = params.Preset.minimal,
    spec_name: []const u8 = "zeamdev",
};

pub const NodeTestContext = struct {
    allocator: Allocator,
    loop: xev.Loop,
    logger_config: zeam_utils.ZeamLoggerConfig,
    key_manager: key_manager.KeyManager,
    validator_pubkeys: []const types.Bytes52,
    genesis_config: types.GenesisSpec,
    anchor_state: types.BeamState,
    tmp_dir: std.testing.TmpDir,
    data_dir: []u8,
    db: database.Db,
    spec_name: []u8,
    chain_config: configs.ChainConfig,
    clock: clockFactory.Clock,
    anchor_state_owned: bool = true,
    spec_name_owned: bool = true,

    pub fn init(allocator: Allocator, opts: NodeTestOptions) !NodeTestContext {
        var loop = try xev.Loop.init(.{});
        errdefer loop.deinit();

        var logger_config = zeam_utils.getTestLoggerConfig();

        var km = try key_manager.getTestKeyManager(allocator, opts.num_validators, opts.key_manager_slots);
        errdefer km.deinit();

        const pubkeys = try km.getAllPubkeys(allocator, opts.num_validators);
        errdefer allocator.free(pubkeys);

        const genesis_config = types.GenesisSpec{
            .genesis_time = opts.genesis_time,
            .validator_pubkeys = pubkeys,
        };

        var anchor_state: types.BeamState = undefined;
        try anchor_state.genGenesisState(allocator, genesis_config);
        errdefer anchor_state.deinit();

        var tmp_dir = std.testing.tmpDir(.{});
        errdefer tmp_dir.cleanup();

        const data_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(data_dir);

        var db = try database.Db.open(allocator, logger_config.logger(.database), data_dir);
        errdefer db.deinit();

        const spec_name = try allocator.dupe(u8, opts.spec_name);
        errdefer allocator.free(spec_name);

        const chain_config = configs.ChainConfig{
            .id = configs.Chain.custom,
            .genesis = genesis_config,
            .spec = .{
                .preset = opts.preset,
                .name = spec_name,
            },
        };

        var clock = try clockFactory.Clock.init(allocator, genesis_config.genesis_time, &loop);
        errdefer clock.deinit(allocator);

        return NodeTestContext{
            .allocator = allocator,
            .loop = loop,
            .logger_config = logger_config,
            .key_manager = km,
            .validator_pubkeys = pubkeys,
            .genesis_config = genesis_config,
            .anchor_state = anchor_state,
            .tmp_dir = tmp_dir,
            .data_dir = data_dir,
            .db = db,
            .spec_name = spec_name,
            .chain_config = chain_config,
            .clock = clock,
        };
    }

    pub fn deinit(self: *NodeTestContext) void {
        self.clock.deinit(self.allocator);
        self.db.deinit();
        self.tmp_dir.cleanup();
        self.allocator.free(self.data_dir);
        if (self.anchor_state_owned) {
            self.anchor_state.deinit();
        }
        self.allocator.free(self.validator_pubkeys);
        self.key_manager.deinit();
        self.loop.deinit();
        if (self.spec_name_owned) {
            self.allocator.free(self.spec_name);
        }
    }

    pub fn loopPtr(self: *NodeTestContext) *xev.Loop {
        return &self.loop;
    }

    pub fn loggerConfig(self: *NodeTestContext) *zeam_utils.ZeamLoggerConfig {
        return &self.logger_config;
    }

    pub fn takeAnchorState(self: *NodeTestContext) *types.BeamState {
        std.debug.assert(self.anchor_state_owned);
        self.anchor_state_owned = false;
        return &self.anchor_state;
    }

    pub fn takeChainConfig(self: *NodeTestContext) configs.ChainConfig {
        std.debug.assert(self.spec_name_owned);
        self.spec_name_owned = false;
        return self.chain_config;
    }

    pub fn clockPtr(self: *NodeTestContext) *clockFactory.Clock {
        return &self.clock;
    }

    pub fn dbInstance(self: *NodeTestContext) database.Db {
        return self.db;
    }

    pub fn genesisConfig(self: *NodeTestContext) types.GenesisSpec {
        return self.genesis_config;
    }

    pub fn signBlockWithValidatorKeys(
        self: *const NodeTestContext,
        allocator: Allocator,
        block: *types.SignedBlockWithAttestation,
    ) !void {
        var attestation_signatures = try types.AttestationSignatures.init(allocator);
        errdefer attestation_signatures.deinit();

        for (block.message.block.body.attestations.constSlice()) |aggregated_attestation| {
            var validator_signatures = try types.NaiveAggregatedSignature.init(allocator);
            errdefer validator_signatures.deinit();

            var indices = try types.aggregationBitsToValidatorIndices(&aggregated_attestation.aggregation_bits, allocator);
            defer indices.deinit();

            for (indices.items) |validator_index| {
                var attestation = types.Attestation{
                    .validator_id = @intCast(validator_index),
                    .data = aggregated_attestation.data,
                };
                const signature = try self.key_manager.signAttestation(&attestation, allocator);
                try validator_signatures.append(signature);
            }

            try attestation_signatures.append(validator_signatures);
        }

        const proposer_signature = try self.key_manager.signAttestation(&block.message.proposer_attestation, allocator);

        const signatures = types.BlockSignatures{
            .attestation_signatures = attestation_signatures,
            .proposer_signature = proposer_signature,
        };

        block.signature.deinit();
        block.signature = signatures;
    }
};
