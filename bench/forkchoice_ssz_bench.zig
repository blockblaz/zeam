const std = @import("std");
const zbench = @import("zbench");
const types = @import("@zeam/types");
const node = @import("@zeam/node");
const stf = @import("@zeam/state-transition");
const ssz = @import("ssz");
const zeam_utils = @import("@zeam/utils");
const params = @import("@zeam/params");
const configs = @import("@zeam/configs");

const ForkChoice = node.fcFactory.ForkChoice;
const ForkChoiceParams = node.fcFactory.ForkChoiceParams;

// ---------------------------------------------------------------------------
// Globals (built once in main, read-only in bench bodies)
// ---------------------------------------------------------------------------

var g_logger_config: zeam_utils.ZeamLoggerConfig = undefined;
var g_chain_config: ?configs.ChainConfig = null;

// Anchor state — used to init ForkChoice (pointer must remain valid).
var g_anchor_state: ?types.BeamState = null;

// Block[1] from mock chain: applied once to get g_post_state.
var g_post_state: ?types.BeamState = null;
var g_block1: ?types.BeamBlock = null;
var g_signed_block1: ?types.SignedBlock = null;

// Attestation pointing at the genesis block root (always in protoArray).
var g_attestation: ?types.Attestation = null;

// Encoded blobs (built once in main).
var g_encoded_block: ?[]u8 = null;
var g_encoded_state: ?[]u8 = null;

// Counter used by benchFcOnAttestation so each iteration exercises a
// different validator_id, bypassing the "already newest" early-exit.
var g_attest_iter: usize = 0;

// ---------------------------------------------------------------------------
// Helper: build a fresh ForkChoice initialised to the anchor state.
// ---------------------------------------------------------------------------
fn buildForkChoice(allocator: std.mem.Allocator) !ForkChoice {
    return ForkChoice.init(allocator, .{
        .config = g_chain_config.?,
        .anchorState = &g_anchor_state.?,
        .logger = g_logger_config.logger(.forkchoice),
    });
}

// ---------------------------------------------------------------------------
// Benchmark: fc_onBlock
//
// Re-inits the ForkChoice every iteration so the bench body is self-contained.
// The re-init cost is small (~microseconds) compared to onBlock itself.
// ---------------------------------------------------------------------------
fn benchFcOnBlock(allocator: std.mem.Allocator) void {
    var fc = buildForkChoice(allocator) catch unreachable;
    defer fc.deinit();

    const block = g_block1.?;
    const state = &g_post_state.?;

    // Advance the slot clock to match block.slot (required by onBlock).
    fc.onInterval(block.slot * 5, false) catch unreachable; // 5 = INTERVALS_PER_SLOT

    _ = fc.onBlock(block, state, .{
        .currentSlot = block.slot,
        .blockDelayMs = 0,
        .confirmed = true,
    }) catch unreachable;
}

// ---------------------------------------------------------------------------
// Benchmark: fc_onAttestation
//
// Uses is_from_block=true so the slot-clock future-attestation guard is
// skipped.  Head root points at the genesis block root (always in protoArray).
// Different validator_ids per iteration avoid the "already latest" fast-exit.
// ---------------------------------------------------------------------------
fn benchFcOnAttestation(allocator: std.mem.Allocator) void {
    var att = g_attestation.?;
    // Rotate validator_id each call so the tracker is updated every time.
    att.validator_id = g_attest_iter % 256;
    g_attest_iter +%= 1;

    // We need a live ForkChoice for this, so build one per iteration.
    // (The same instance could be reused since the tracker just updates,
    //  but we rebuild to mirror the fc_onBlock pattern and keep it clean.)
    var fc = buildForkChoice(allocator) catch unreachable;
    defer fc.deinit();

    fc.onAttestation(att, true) catch |err| {
        std.debug.panic("fc_onAttestation failed: {}", .{err});
    };
}

// ---------------------------------------------------------------------------
// Benchmark: ssz_block_encode
// ---------------------------------------------------------------------------
fn benchSszBlockEncode(allocator: std.mem.Allocator) void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    ssz.serialize(types.SignedBlock, g_signed_block1.?, &buf, allocator) catch unreachable;
    // Prevent the optimizer from discarding the result.
    std.mem.doNotOptimizeAway(buf.items.len);
}

// ---------------------------------------------------------------------------
// Benchmark: ssz_block_decode
// ---------------------------------------------------------------------------
fn benchSszBlockDecode(allocator: std.mem.Allocator) void {
    var decoded: types.SignedBlock = undefined;
    ssz.deserialize(types.SignedBlock, g_encoded_block.?, &decoded, allocator) catch unreachable;
    defer decoded.deinit();
}

// ---------------------------------------------------------------------------
// Benchmark: ssz_state_encode
// ---------------------------------------------------------------------------
fn benchSszStateEncode(allocator: std.mem.Allocator) void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    ssz.serialize(types.BeamState, g_anchor_state.?, &buf, allocator) catch unreachable;
    std.mem.doNotOptimizeAway(buf.items.len);
}

// ---------------------------------------------------------------------------
// Benchmark: ssz_state_decode
// ---------------------------------------------------------------------------
fn benchSszStateDecode(allocator: std.mem.Allocator) void {
    var decoded: types.BeamState = undefined;
    ssz.deserialize(types.BeamState, g_encoded_state.?, &decoded, allocator) catch unreachable;
    defer decoded.deinit();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
pub fn main(init: std.process.Init) !void {
    _ = init;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    g_logger_config = zeam_utils.getTestLoggerConfig();

    // -----------------------------------------------------------------------
    // Generate a minimal 2-block mock chain.
    // -----------------------------------------------------------------------
    const mock_chain = try stf.genMockChain(allocator, 2, null);
    // NOTE: mock_chain.genesis_state is NOT freed here — we hand it to g_anchor_state
    // and it is freed at the end via g_anchor_state.?.deinit().

    const spec_name = try allocator.dupe(u8, "beamdev");
    defer allocator.free(spec_name);
    const fork_digest = try allocator.dupe(u8, "12345678");
    defer allocator.free(fork_digest);

    g_chain_config = configs.ChainConfig{
        .id = configs.Chain.custom,
        .genesis = mock_chain.genesis_config,
        .spec = .{
            .preset = params.Preset.mainnet,
            .name = spec_name,
            .fork_digest = fork_digest,
            .attestation_committee_count = 1,
            .max_attestations_data = 16,
        },
    };

    // Transfer genesis state ownership to g_anchor_state.
    g_anchor_state = mock_chain.genesis_state;
    defer g_anchor_state.?.deinit();

    // -----------------------------------------------------------------------
    // Apply block[1] to get the post-state for fc_onBlock.
    // -----------------------------------------------------------------------
    {
        // Clone genesis state via SSZ roundtrip (BeamState has no .clone()).
        var tmp_buf: std.ArrayList(u8) = .empty;
        defer tmp_buf.deinit(allocator);
        try ssz.serialize(types.BeamState, g_anchor_state.?, &tmp_buf, allocator);
        var post: types.BeamState = undefined;
        try ssz.deserialize(types.BeamState, tmp_buf.items, &post, allocator);
        g_post_state = post;
    }
    defer g_post_state.?.deinit();

    const signed1 = mock_chain.blocks[1];
    g_block1 = signed1.block;
    g_signed_block1 = signed1;

    const module_logger = g_logger_config.logger(.forkchoice);
    try stf.apply_transition(allocator, &g_post_state.?, signed1.block, .{ .logger = module_logger });

    // Free the rest of mock_chain (blocks array — ownership of blocks[1]
    // content is shared with g_signed_block1 which is stack-copied above;
    // call deinit carefully: only free the slice, not the block data).
    // Actually MockChainData.deinit() frees all blocks — since we kept a
    // stack copy of `signed1` (which shares the heap memory), we must NOT
    // call mock_chain.deinit().  Instead free each slice manually.
    allocator.free(mock_chain.blocks);
    allocator.free(mock_chain.blockRoots);
    allocator.free(mock_chain.latestJustified);
    allocator.free(mock_chain.latestFinalized);
    allocator.free(mock_chain.latestHead);
    allocator.free(mock_chain.justification);
    allocator.free(mock_chain.finalization);

    // -----------------------------------------------------------------------
    // Build g_attestation: points head at the genesis block root (always in
    // protoArray after ForkChoice.init).
    // -----------------------------------------------------------------------
    {
        // After init, the genesis block root is at protoArray.nodes.items[0].blockRoot.
        // We can also derive it from the anchor state's block header hash, but it is
        // easier to build a temporary ForkChoice just to read the head root, then deinit.
        var tmp_fc = try buildForkChoice(allocator);
        const genesis_root = tmp_fc.getHead().blockRoot;
        tmp_fc.deinit();

        const genesis_slot = g_anchor_state.?.slot;
        g_attestation = types.Attestation{
            .validator_id = 0,
            .data = .{
                .slot = genesis_slot,
                .head = .{ .root = genesis_root, .slot = genesis_slot },
                .target = .{ .root = genesis_root, .slot = genesis_slot },
                .source = .{ .root = genesis_root, .slot = genesis_slot },
            },
        };
    }

    // -----------------------------------------------------------------------
    // Pre-encode block and state for decode benchmarks.
    // -----------------------------------------------------------------------
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try ssz.serialize(types.SignedBlock, g_signed_block1.?, &buf, allocator);
        g_encoded_block = try allocator.dupe(u8, buf.items);
    }
    defer allocator.free(g_encoded_block.?);

    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try ssz.serialize(types.BeamState, g_anchor_state.?, &buf, allocator);
        g_encoded_state = try allocator.dupe(u8, buf.items);
    }
    defer allocator.free(g_encoded_state.?);

    std.log.info("encoded_block bytes={d}  encoded_state bytes={d}", .{
        g_encoded_block.?.len,
        g_encoded_state.?.len,
    });

    // -----------------------------------------------------------------------
    // zbench runner
    // -----------------------------------------------------------------------
    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    try bench.add("fc_onBlock", benchFcOnBlock, .{ .iterations = 50 });
    try bench.add("fc_onAttestation", benchFcOnAttestation, .{ .iterations = 500 });
    try bench.add("ssz_block_encode", benchSszBlockEncode, .{ .iterations = 1000 });
    try bench.add("ssz_block_decode", benchSszBlockDecode, .{ .iterations = 1000 });
    try bench.add("ssz_state_encode", benchSszStateEncode, .{ .iterations = 200 });
    try bench.add("ssz_state_decode", benchSszStateDecode, .{ .iterations = 200 });

    const io = std.Io.Threaded.global_single_threaded.io();
    const stdout = std.Io.File.stdout();
    try bench.run(io, stdout);
}
