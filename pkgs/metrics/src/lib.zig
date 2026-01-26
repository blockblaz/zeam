const std = @import("std");
const metrics_lib = @import("metrics");

/// Returns true if the current target is a ZKVM environment.
/// This is used to disable metrics in contexts where they don't make sense.
pub fn isZKVM() bool {
    // Some ZKVMs might emulate linux, so this check might need to be updated.
    return @import("builtin").target.os.tag == .freestanding;
}

// Platform-specific time function
fn getTimestamp() i128 {
    // For freestanding targets, we might not have access to system time
    // In that case, we'll use a simple counter or return 0
    // Use comptime to avoid compiling nanoTimestamp for freestanding targets
    if (comptime isZKVM()) {
        return 0;
    } else {
        return std.time.nanoTimestamp();
    }
}

// Global metrics instance
// Note: Metrics are initialized as no-op by default. When init() is not called,
// or when called on ZKVM targets, all metric operations are no-ops automatically.
// Public so that callers can directly access and record metrics without wrapper functions.
pub var metrics = metrics_lib.initializeNoop(Metrics);
var g_initialized: bool = false;

const Metrics = struct {
    chain_onblock_duration_seconds: ChainHistogram,
    block_processing_duration_seconds: BlockProcessingHistogram,
    lean_head_slot: LeanHeadSlotGauge,
    lean_latest_justified_slot: LeanLatestJustifiedSlotGauge,
    lean_latest_finalized_slot: LeanLatestFinalizedSlotGauge,
    lean_state_transition_time_seconds: StateTransitionHistogram,
    lean_state_transition_slots_processed_total: SlotsProcessedCounter,
    lean_state_transition_slots_processing_time_seconds: SlotsProcessingHistogram,
    lean_state_transition_block_processing_time_seconds: BlockProcessingTimeHistogram,
    lean_state_transition_attestations_processed_total: AttestationsProcessedCounter,
    lean_state_transition_attestations_processing_time_seconds: AttestationsProcessingHistogram,
    lean_validators_count: LeanValidatorsCountGauge,
    lean_fork_choice_block_processing_time_seconds: ForkChoiceBlockProcessingTimeHistogram,
    lean_attestations_valid_total: ForkChoiceAttestationsValidLabeledCounter,
    lean_attestations_invalid_total: ForkChoiceAttestationsInvalidLabeledCounter,
    lean_attestation_validation_time_seconds: ForkChoiceAttestationValidationTimeHistogram,
    lean_pq_signature_attestation_signing_time_seconds: PQSignatureSigningHistogram,
    lean_pq_signature_attestation_verification_time_seconds: PQSignatureVerificationHistogram,
    // Granular metrics for block processing breakdown
    lean_fork_choice_updatehead_time_seconds: ForkChoiceUpdateHeadHistogram,
    lean_chain_database_write_time_seconds: ChainDatabaseWriteHistogram,
    lean_chain_attestation_loop_time_seconds: ChainAttestationLoopHistogram,
    lean_chain_state_clone_time_seconds: ChainStateCloneHistogram,
    lean_chain_onblockfollowup_time_seconds: ChainOnBlockFollowupHistogram,
    lean_fork_choice_computedeltas_time_seconds: ForkChoiceComputeDeltasHistogram,
    lean_fork_choice_applydeltas_time_seconds: ForkChoiceApplyDeltasHistogram,
    lean_chain_signature_verification_time_seconds: ChainSignatureVerificationHistogram,
    lean_chain_proposer_attestation_time_seconds: ChainProposerAttestationHistogram,
    // State transition internal metrics
    lean_state_transition_state_root_validation_time_seconds: StateRootValidationHistogram,
    lean_state_transition_state_root_in_slot_time_seconds: StateRootInSlotHistogram,
    lean_state_transition_block_header_hash_time_seconds: BlockHeaderHashHistogram,
    lean_state_transition_get_justification_time_seconds: GetJustificationHistogram,
    lean_state_transition_with_justifications_time_seconds: WithJustificationsHistogram,
    // Block processing path counters
    lean_chain_blocks_with_cached_state_total: BlocksWithCachedStateCounter,
    lean_chain_blocks_with_computed_state_total: BlocksWithComputedStateCounter,
    // Network peer metrics
    lean_connected_peers: LeanConnectedPeersGauge,
    lean_peer_connection_events_total: PeerConnectionEventsCounter,
    lean_peer_disconnection_events_total: PeerDisconnectionEventsCounter,
    // Node lifecycle metrics
    lean_node_info: LeanNodeInfoGauge,
    lean_node_start_time_seconds: LeanNodeStartTimeGauge,
    lean_current_slot: LeanCurrentSlotGauge,
    lean_safe_target_slot: LeanSafeTargetSlotGauge,
    // Fork choice reorg metrics
    lean_fork_choice_reorgs_total: LeanForkChoiceReorgsTotalCounter,
    lean_fork_choice_reorg_depth: LeanForkChoiceReorgDepthHistogram,
    // Finalization metrics
    lean_finalizations_total: LeanFinalizationsTotalCounter,

    const ChainHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    const BlockProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    const StateTransitionHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.05, 0.075, 0.1, 0.125, 0.15, 0.2, 0.25, 0.3, 0.4, 0.6, 0.8, 1, 1.5, 2 });
    const SlotsProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const BlockProcessingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const AttestationsProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const PQSignatureSigningHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const PQSignatureVerificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    // Granular histogram types
    const ForkChoiceUpdateHeadHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1 });
    const ChainDatabaseWriteHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1 });
    const ChainAttestationLoopHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const ChainStateCloneHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const ChainOnBlockFollowupHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1 });
    const ForkChoiceComputeDeltasHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const ForkChoiceApplyDeltasHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const ChainSignatureVerificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 });
    const ChainProposerAttestationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    // State transition internal histogram types
    const StateRootValidationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 });
    const StateRootInSlotHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const BlockHeaderHashHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const GetJustificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.00001, 0.00002, 0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01 });
    const WithJustificationsHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const LeanHeadSlotGauge = metrics_lib.Gauge(u64);
    const LeanLatestJustifiedSlotGauge = metrics_lib.Gauge(u64);
    const LeanLatestFinalizedSlotGauge = metrics_lib.Gauge(u64);
    const SlotsProcessedCounter = metrics_lib.Counter(u64);
    const AttestationsProcessedCounter = metrics_lib.Counter(u64);
    const LeanValidatorsCountGauge = metrics_lib.Gauge(u64);
    const ForkChoiceBlockProcessingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const ForkChoiceAttestationsValidLabeledCounter = metrics_lib.CounterVec(u64, struct { source: []const u8 });
    const ForkChoiceAttestationsInvalidLabeledCounter = metrics_lib.CounterVec(u64, struct { source: []const u8 });
    const ForkChoiceAttestationValidationTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const BlocksWithCachedStateCounter = metrics_lib.Counter(u64);
    const BlocksWithComputedStateCounter = metrics_lib.Counter(u64);
    // Network peer metric types
    const LeanConnectedPeersGauge = metrics_lib.Gauge(u64);
    const PeerConnectionEventsCounter = metrics_lib.CounterVec(u64, struct { direction: []const u8, result: []const u8 });
    const PeerDisconnectionEventsCounter = metrics_lib.CounterVec(u64, struct { direction: []const u8, reason: []const u8 });
    // Node lifecycle metric types
    const LeanNodeInfoGauge = metrics_lib.GaugeVec(u64, struct { name: []const u8, version: []const u8 });
    const LeanNodeStartTimeGauge = metrics_lib.Gauge(u64);
    const LeanCurrentSlotGauge = metrics_lib.Gauge(u64);
    const LeanSafeTargetSlotGauge = metrics_lib.Gauge(u64);
    // Fork choice reorg metric types
    const LeanForkChoiceReorgsTotalCounter = metrics_lib.Counter(u64);
    const LeanForkChoiceReorgDepthHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1, 2, 3, 5, 7, 10, 20, 30, 50, 100 });
    // Finalization metric types
    const LeanFinalizationsTotalCounter = metrics_lib.CounterVec(u64, struct { result: []const u8 });
};

/// Timer struct returned to the application.
pub const Timer = struct {
    start_time: i128,
    context: ?*anyopaque,
    observe_impl: *const fn (?*anyopaque, f32) void,

    /// Stops the timer and records the duration in the histogram.
    pub fn observe(self: Timer) f32 {
        const end_time = getTimestamp();
        const duration_ns = end_time - self.start_time;

        // For freestanding targets where we can't measure time, just record 0
        const duration_seconds = if (duration_ns == 0) 0.0 else @as(f32, @floatFromInt(duration_ns)) / 1_000_000_000.0;

        self.observe_impl(self.context, duration_seconds);

        return duration_seconds;
    }
};

/// Histogram wrapper for recording metric observations.
pub const Histogram = struct {
    context: ?*anyopaque,
    observe: *const fn (?*anyopaque, f32) void,

    pub fn start(self: *const Histogram) Timer {
        return Timer{
            .start_time = getTimestamp(),
            .context = self.context,
            .observe_impl = self.observe,
        };
    }
};

fn observeChainOnblock(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.ChainHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockProcessing(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.BlockProcessingHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeStateTransition(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.StateTransitionHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeSlotsProcessing(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.SlotsProcessingHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockProcessingTime(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.BlockProcessingTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeAttestationsProcessing(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.AttestationsProcessingHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeFCBlockProcessingTimeHistogram(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.ForkChoiceBlockProcessingTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeFCAttestationValidationTimeHistogram(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.ForkChoiceAttestationValidationTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observePQSignatureAttestationSigning(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.PQSignatureSigningHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observePQSignatureAttestationVerification(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.PQSignatureVerificationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeForkChoiceUpdateHead(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ForkChoiceUpdateHeadHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainDatabaseWrite(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ChainDatabaseWriteHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainAttestationLoop(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ChainAttestationLoopHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainStateClone(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ChainStateCloneHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainOnBlockFollowup(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ChainOnBlockFollowupHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeForkChoiceComputeDeltas(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ForkChoiceComputeDeltasHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeForkChoiceApplyDeltas(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ForkChoiceApplyDeltasHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainSignatureVerification(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ChainSignatureVerificationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainProposerAttestation(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ChainProposerAttestationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeStateRootValidation(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.StateRootValidationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeStateRootInSlot(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.StateRootInSlotHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockHeaderHash(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockHeaderHashHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeGetJustification(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.GetJustificationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeWithJustifications(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.WithJustificationsHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

/// The public variables the application interacts with.
/// Calling `.start()` on these will start a new timer.
pub var chain_onblock_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainOnblock,
};
pub var block_processing_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeBlockProcessing,
};
pub var lean_state_transition_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeStateTransition,
};
pub var lean_state_transition_slots_processing_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeSlotsProcessing,
};
pub var lean_state_transition_block_processing_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeBlockProcessingTime,
};
pub var lean_state_transition_attestations_processing_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeAttestationsProcessing,
};
pub var lean_fork_choice_block_processing_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeFCBlockProcessingTimeHistogram,
};

pub var lean_attestation_validation_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeFCAttestationValidationTimeHistogram,
};
pub var lean_pq_signature_attestation_signing_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSignatureAttestationSigning,
};
pub var lean_pq_signature_attestation_verification_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSignatureAttestationVerification,
};

pub var lean_fork_choice_updatehead_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeForkChoiceUpdateHead,
};
pub var lean_chain_database_write_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainDatabaseWrite,
};
pub var lean_chain_attestation_loop_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainAttestationLoop,
};
pub var lean_chain_state_clone_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainStateClone,
};
pub var lean_chain_onblockfollowup_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainOnBlockFollowup,
};
pub var lean_fork_choice_computedeltas_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeForkChoiceComputeDeltas,
};
pub var lean_fork_choice_applydeltas_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeForkChoiceApplyDeltas,
};
pub var lean_chain_signature_verification_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainSignatureVerification,
};
pub var lean_chain_proposer_attestation_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainProposerAttestation,
};
pub var lean_state_transition_state_root_validation_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeStateRootValidation,
};
pub var lean_state_transition_state_root_in_slot_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeStateRootInSlot,
};
pub var lean_state_transition_block_header_hash_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeBlockHeaderHash,
};
pub var lean_state_transition_get_justification_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeGetJustification,
};
pub var lean_state_transition_with_justifications_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeWithJustifications,
};

/// Initializes the metrics system. Must be called once at startup.
pub fn init(allocator: std.mem.Allocator) !void {
    if (g_initialized) return;

    // For ZKVM targets, use no-op metrics
    if (isZKVM()) {
        std.log.info("Using no-op metrics for ZKVM target", .{});
        g_initialized = true;
        return;
    }

    metrics = .{
        .chain_onblock_duration_seconds = Metrics.ChainHistogram.init("chain_onblock_duration_seconds", .{ .help = "Time taken to process a block in the chain's onBlock function." }, .{}),
        .block_processing_duration_seconds = Metrics.BlockProcessingHistogram.init("block_processing_duration_seconds", .{ .help = "Time taken to process a block in the state transition function." }, .{}),
        .lean_head_slot = Metrics.LeanHeadSlotGauge.init("lean_head_slot", .{ .help = "Latest slot of the lean chain." }, .{}),
        .lean_latest_justified_slot = Metrics.LeanLatestJustifiedSlotGauge.init("lean_latest_justified_slot", .{ .help = "Latest justified slot." }, .{}),
        .lean_latest_finalized_slot = Metrics.LeanLatestFinalizedSlotGauge.init("lean_latest_finalized_slot", .{ .help = "Latest finalized slot." }, .{}),
        .lean_state_transition_time_seconds = Metrics.StateTransitionHistogram.init("lean_state_transition_time_seconds", .{ .help = "Time to process state transition." }, .{}),
        .lean_state_transition_slots_processed_total = Metrics.SlotsProcessedCounter.init("lean_state_transition_slots_processed_total", .{ .help = "Total number of processed slots." }, .{}),
        .lean_state_transition_slots_processing_time_seconds = Metrics.SlotsProcessingHistogram.init("lean_state_transition_slots_processing_time_seconds", .{ .help = "Time taken to process slots." }, .{}),
        .lean_state_transition_block_processing_time_seconds = Metrics.BlockProcessingTimeHistogram.init("lean_state_transition_block_processing_time_seconds", .{ .help = "Time taken to process block." }, .{}),
        .lean_state_transition_attestations_processed_total = Metrics.AttestationsProcessedCounter.init("lean_state_transition_attestations_processed_total", .{ .help = "Total number of processed attestations." }, .{}),
        .lean_state_transition_attestations_processing_time_seconds = Metrics.AttestationsProcessingHistogram.init("lean_state_transition_attestations_processing_time_seconds", .{ .help = "Time taken to process attestations." }, .{}),
        .lean_validators_count = Metrics.LeanValidatorsCountGauge.init("lean_validators_count", .{ .help = "Number of connected validators." }, .{}),
        .lean_fork_choice_block_processing_time_seconds = Metrics.ForkChoiceBlockProcessingTimeHistogram.init("lean_fork_choice_block_processing_time_seconds", .{ .help = "Time taken to process block in fork choice." }, .{}),
        .lean_attestations_valid_total = try Metrics.ForkChoiceAttestationsValidLabeledCounter.init(allocator, "lean_attestations_valid_total", .{ .help = "Total number of valid attestations labeled by source (gossip or block)." }, .{}),
        .lean_attestations_invalid_total = try Metrics.ForkChoiceAttestationsInvalidLabeledCounter.init(allocator, "lean_attestations_invalid_total", .{ .help = "Total number of invalid attestations labeled by source (gossip or block)." }, .{}),
        .lean_attestation_validation_time_seconds = Metrics.ForkChoiceAttestationValidationTimeHistogram.init("lean_attestation_validation_time_seconds", .{ .help = "Time taken to validate attestation." }, .{}),
        .lean_pq_signature_attestation_signing_time_seconds = Metrics.PQSignatureSigningHistogram.init("lean_pq_signature_attestation_signing_time_seconds", .{ .help = "Time taken to sign an attestation." }, .{}),
        .lean_pq_signature_attestation_verification_time_seconds = Metrics.PQSignatureVerificationHistogram.init("lean_pq_signature_attestation_verification_time_seconds", .{ .help = "Time taken to verify an attestation signature." }, .{}),
        .lean_fork_choice_updatehead_time_seconds = Metrics.ForkChoiceUpdateHeadHistogram.init("lean_fork_choice_updatehead_time_seconds", .{ .help = "Fork choice head computation." }, .{}),
        .lean_chain_database_write_time_seconds = Metrics.ChainDatabaseWriteHistogram.init("lean_chain_database_write_time_seconds", .{ .help = "Block and state database writes." }, .{}),
        .lean_chain_attestation_loop_time_seconds = Metrics.ChainAttestationLoopHistogram.init("lean_chain_attestation_loop_time_seconds", .{ .help = "Attestation validation in block processing." }, .{}),
        .lean_chain_state_clone_time_seconds = Metrics.ChainStateCloneHistogram.init("lean_chain_state_clone_time_seconds", .{ .help = "SSZ state cloning." }, .{}),
        .lean_chain_onblockfollowup_time_seconds = Metrics.ChainOnBlockFollowupHistogram.init("lean_chain_onblockfollowup_time_seconds", .{ .help = "Event emission and finalization checks." }, .{}),
        .lean_fork_choice_computedeltas_time_seconds = Metrics.ForkChoiceComputeDeltasHistogram.init("lean_fork_choice_computedeltas_time_seconds", .{ .help = "Validator weight delta computation." }, .{}),
        .lean_fork_choice_applydeltas_time_seconds = Metrics.ForkChoiceApplyDeltasHistogram.init("lean_fork_choice_applydeltas_time_seconds", .{ .help = "Weight delta propagation and best descendant updates." }, .{}),
        .lean_chain_signature_verification_time_seconds = Metrics.ChainSignatureVerificationHistogram.init("lean_chain_signature_verification_time_seconds", .{ .help = "XMSS signature verification for block attestations." }, .{}),
        .lean_chain_proposer_attestation_time_seconds = Metrics.ChainProposerAttestationHistogram.init("lean_chain_proposer_attestation_time_seconds", .{ .help = "Proposer attestation processing." }, .{}),
        .lean_state_transition_state_root_validation_time_seconds = Metrics.StateRootValidationHistogram.init("lean_state_transition_state_root_validation_time_seconds", .{ .help = "State root validation in apply_transition." }, .{}),
        .lean_state_transition_state_root_in_slot_time_seconds = Metrics.StateRootInSlotHistogram.init("lean_state_transition_state_root_in_slot_time_seconds", .{ .help = "State root computation in process_slot." }, .{}),
        .lean_state_transition_block_header_hash_time_seconds = Metrics.BlockHeaderHashHistogram.init("lean_state_transition_block_header_hash_time_seconds", .{ .help = "Block header hash in process_block_header." }, .{}),
        .lean_state_transition_get_justification_time_seconds = Metrics.GetJustificationHistogram.init("lean_state_transition_get_justification_time_seconds", .{ .help = "Justifications HashMap creation from state." }, .{}),
        .lean_state_transition_with_justifications_time_seconds = Metrics.WithJustificationsHistogram.init("lean_state_transition_with_justifications_time_seconds", .{ .help = "State update with justifications HashMap." }, .{}),
        .lean_chain_blocks_with_cached_state_total = Metrics.BlocksWithCachedStateCounter.init("lean_chain_blocks_with_cached_state_total", .{ .help = "Blocks processed with precomputed state (skip apply_transition)." }, .{}),
        .lean_chain_blocks_with_computed_state_total = Metrics.BlocksWithComputedStateCounter.init("lean_chain_blocks_with_computed_state_total", .{ .help = "Blocks processed with computed state (call apply_transition with cache)." }, .{}),
        // Network peer metrics
        .lean_connected_peers = Metrics.LeanConnectedPeersGauge.init("lean_connected_peers", .{ .help = "Number of currently connected peers." }, .{}),
        .lean_peer_connection_events_total = try Metrics.PeerConnectionEventsCounter.init(allocator, "lean_peer_connection_events_total", .{ .help = "Total peer connection events by direction and result." }, .{}),
        .lean_peer_disconnection_events_total = try Metrics.PeerDisconnectionEventsCounter.init(allocator, "lean_peer_disconnection_events_total", .{ .help = "Total peer disconnection events by direction and reason." }, .{}),
        // Node lifecycle metrics
        .lean_node_info = try Metrics.LeanNodeInfoGauge.init(allocator, "lean_node_info", .{ .help = "Node information (always 1)." }, .{}),
        .lean_node_start_time_seconds = Metrics.LeanNodeStartTimeGauge.init("lean_node_start_time_seconds", .{ .help = "Unix timestamp when the node started." }, .{}),
        .lean_current_slot = Metrics.LeanCurrentSlotGauge.init("lean_current_slot", .{ .help = "Current slot of the lean chain based on wall clock." }, .{}),
        .lean_safe_target_slot = Metrics.LeanSafeTargetSlotGauge.init("lean_safe_target_slot", .{ .help = "Safe target slot with 2/3 weight threshold." }, .{}),
        // Fork choice reorg metrics
        .lean_fork_choice_reorgs_total = Metrics.LeanForkChoiceReorgsTotalCounter.init("lean_fork_choice_reorgs_total", .{ .help = "Total number of fork choice reorganizations." }, .{}),
        .lean_fork_choice_reorg_depth = Metrics.LeanForkChoiceReorgDepthHistogram.init("lean_fork_choice_reorg_depth", .{ .help = "Depth of fork choice reorgs in blocks." }, .{}),
        // Finalization metrics
        .lean_finalizations_total = try Metrics.LeanFinalizationsTotalCounter.init(allocator, "lean_finalizations_total", .{ .help = "Total finalization attempts by result." }, .{}),
    };

    // Initialize validators count to 0 by default (spec requires "On scrape" availability)
    metrics.lean_validators_count.set(0);

    // Set context for histogram wrappers (observe functions already assigned at compile time)
    chain_onblock_duration_seconds.context = @ptrCast(&metrics.chain_onblock_duration_seconds);
    block_processing_duration_seconds.context = @ptrCast(&metrics.block_processing_duration_seconds);
    lean_state_transition_time_seconds.context = @ptrCast(&metrics.lean_state_transition_time_seconds);
    lean_state_transition_slots_processing_time_seconds.context = @ptrCast(&metrics.lean_state_transition_slots_processing_time_seconds);
    lean_state_transition_block_processing_time_seconds.context = @ptrCast(&metrics.lean_state_transition_block_processing_time_seconds);
    lean_state_transition_attestations_processing_time_seconds.context = @ptrCast(&metrics.lean_state_transition_attestations_processing_time_seconds);
    lean_fork_choice_block_processing_time_seconds.context = @ptrCast(&metrics.lean_fork_choice_block_processing_time_seconds);
    lean_attestation_validation_time_seconds.context = @ptrCast(&metrics.lean_attestation_validation_time_seconds);
    lean_pq_signature_attestation_signing_time_seconds.context = @ptrCast(&metrics.lean_pq_signature_attestation_signing_time_seconds);
    lean_pq_signature_attestation_verification_time_seconds.context = @ptrCast(&metrics.lean_pq_signature_attestation_verification_time_seconds);
    lean_fork_choice_updatehead_time_seconds.context = @ptrCast(&metrics.lean_fork_choice_updatehead_time_seconds);
    lean_chain_database_write_time_seconds.context = @ptrCast(&metrics.lean_chain_database_write_time_seconds);
    lean_chain_attestation_loop_time_seconds.context = @ptrCast(&metrics.lean_chain_attestation_loop_time_seconds);
    lean_chain_state_clone_time_seconds.context = @ptrCast(&metrics.lean_chain_state_clone_time_seconds);
    lean_chain_onblockfollowup_time_seconds.context = @ptrCast(&metrics.lean_chain_onblockfollowup_time_seconds);
    lean_fork_choice_computedeltas_time_seconds.context = @ptrCast(&metrics.lean_fork_choice_computedeltas_time_seconds);
    lean_fork_choice_applydeltas_time_seconds.context = @ptrCast(&metrics.lean_fork_choice_applydeltas_time_seconds);
    lean_chain_signature_verification_time_seconds.context = @ptrCast(&metrics.lean_chain_signature_verification_time_seconds);
    lean_chain_proposer_attestation_time_seconds.context = @ptrCast(&metrics.lean_chain_proposer_attestation_time_seconds);
    lean_state_transition_state_root_validation_time_seconds.context = @ptrCast(&metrics.lean_state_transition_state_root_validation_time_seconds);
    lean_state_transition_state_root_in_slot_time_seconds.context = @ptrCast(&metrics.lean_state_transition_state_root_in_slot_time_seconds);
    lean_state_transition_block_header_hash_time_seconds.context = @ptrCast(&metrics.lean_state_transition_block_header_hash_time_seconds);
    lean_state_transition_get_justification_time_seconds.context = @ptrCast(&metrics.lean_state_transition_get_justification_time_seconds);
    lean_state_transition_with_justifications_time_seconds.context = @ptrCast(&metrics.lean_state_transition_with_justifications_time_seconds);

    g_initialized = true;
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: anytype) !void {
    if (!g_initialized) return error.NotInitialized;

    // For ZKVM targets, write no metrics
    if (isZKVM()) {
        try writer.writeAll("# Metrics disabled for ZKVM target\n");
        return;
    }

    try metrics_lib.write(&metrics, writer);
}
