const std = @import("std");
const json = std.json;

const simargs = @import("simargs");

const types = @import("@zeam/types");
const nodeLib = @import("@zeam/node");
const Clock = nodeLib.Clock;
const stateProvingManager = @import("@zeam/state-proving-manager");
const BeamNode = nodeLib.BeamNode;

const configs = @import("@zeam/configs");
const ChainConfig = configs.ChainConfig;
const Chain = configs.Chain;
const ChainOptions = configs.ChainOptions;

const utilsLib = @import("@zeam/utils");

const sftFactory = @import("@zeam/state-transition");

const ZeamArgs = struct {
    genesis: ?u64,
    num_validators: ?u64,

    __commands__: union(enum) {
        clock: struct {},
        beam: struct {},
        prove: struct {
            dist_dir: []const u8 = "zig-out/bin",

            pub const __shorts__ = .{
                .dist_dir = .d,
            };

            pub const __messages__ = .{
                .dist_dir = "Directory where the zkvm guest programs are found",
            };
        },
    },

    pub const __messages__ = .{
        .genesis = "genesis time",
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const opts = try simargs.parse(allocator, ZeamArgs, "", "0.0.0");
    const genesis = opts.args.genesis orelse 1234;
    const num_validators = opts.args.num_validators orelse 4;
    std.debug.print("opts ={any} genesis={d} num_validators={d}\n", .{ opts, genesis, num_validators });

    switch (opts.args.__commands__) {
        .clock => {
            var clock = try Clock.init(gpa.allocator(), genesis);
            std.debug.print("clock {any}\n", .{clock});

            try clock.run();
        },
        .prove => |provecmd| {
            std.debug.print("distribution dir={s}\n", .{provecmd.dist_dir});
            const options = stateProvingManager.ZKStateTransitionOpts{
                // .powdr = .{
                //     .program_path = "zig-out/bin/zeam-stf-powdr",
                //     .output_dir = "out",
                // },
                .zkvm = .{ .risc0 = .{ .program_path = "zig-out/bin/risc0_runtime.elf" } },
            };

            // generate a mock chain with 5 blocks including genesis i.e. 4 blocks on top of genesis
            const mock_config = types.GenesisSpec{
                .genesis_time = genesis,
                .num_validators = num_validators,
            };
            const mock_chain = try sftFactory.genMockChain(allocator, 5, mock_config);

            // starting beam state
            var beam_state = mock_chain.genesis_state;
            // block 0 is genesis so we have to apply block 1 onwards
            for (mock_chain.blocks[1..]) |block| {
                std.debug.print("\nprestate slot blockslot={d} stateslot={d}\n", .{ block.message.slot, beam_state.slot });
                const proof = try stateProvingManager.prove_transition(beam_state, block, options, allocator);
                // transition beam state for the next block
                try sftFactory.apply_transition(allocator, &beam_state, block, .{});

                // verify the block
                try stateProvingManager.verify_transition(proof, [_]u8{0} ** 32, [_]u8{0} ** 32, options);
            }
        },
        .beam => {
            // some base mainnet spec would be loaded to build this up
            const chain_spec =
                \\{"preset": "mainnet", "name": "beamdev"}
            ;
            const options = json.ParseOptions{
                .ignore_unknown_fields = true,
                .allocate = .alloc_if_needed,
            };
            var chain_options = (try json.parseFromSlice(ChainOptions, gpa.allocator(), chain_spec, options)).value;
            chain_options.genesis_time = genesis;
            const chain_config = try ChainConfig.init(Chain.custom, chain_options);
            const anchorState = try sftFactory.genGenesisState(gpa.allocator(), chain_config.genesis);
            var beam_node = try BeamNode.init(gpa.allocator(), .{ .config = chain_config, .anchorState = anchorState, .db = .{} });
            std.debug.print("chainoptionsinfo={any}\n", .{beam_node});

            try beam_node.run();
        },
    }
}
