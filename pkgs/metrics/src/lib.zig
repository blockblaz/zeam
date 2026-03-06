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
    // Aggregated attestation signature metrics
    lean_pq_sig_aggregated_signatures_total: PQSigAggregatedSignaturesTotalCounter,
    lean_pq_sig_attestations_in_aggregated_signatures_total: PQSigAttestationsInAggregatedTotalCounter,
    lean_pq_sig_attestation_signatures_building_time_seconds: PQSigBuildingTimeHistogram,
    lean_pq_sig_aggregated_signatures_verification_time_seconds: PQSigAggregatedVerificationHistogram,
    lean_pq_sig_aggregated_signatures_valid_total: PQSigAggregatedValidCounter,
    lean_pq_sig_aggregated_signatures_invalid_total: PQSigAggregatedInvalidCounter,
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
    const StateTransitionHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4 });
    const SlotsProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const BlockProcessingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const AttestationsProcessingHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const PQSignatureSigningHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const PQSignatureVerificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
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
    // Aggregated attestation signature metric types
    const PQSigAggregatedSignaturesTotalCounter = metrics_lib.Counter(u64);
    const PQSigAttestationsInAggregatedTotalCounter = metrics_lib.Counter(u64);
    const PQSigBuildingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const PQSigAggregatedVerificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    const PQSigAggregatedValidCounter = metrics_lib.Counter(u64);
    const PQSigAggregatedInvalidCounter = metrics_lib.Counter(u64);
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

fn observePQSigBuildingTime(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.PQSigBuildingTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observePQSigAggregatedVerification(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.PQSigAggregatedVerificationHistogram = @ptrCast(@alignCast(histogram_ptr));
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
pub var lean_pq_sig_attestation_signatures_building_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSigBuildingTime,
};
pub var lean_pq_sig_aggregated_signatures_verification_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSigAggregatedVerification,
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
        // Aggregated attestation signature metrics
        .lean_pq_sig_aggregated_signatures_total = Metrics.PQSigAggregatedSignaturesTotalCounter.init("lean_pq_sig_aggregated_signatures_total", .{ .help = "Total number of aggregated signatures." }, .{}),
        .lean_pq_sig_attestations_in_aggregated_signatures_total = Metrics.PQSigAttestationsInAggregatedTotalCounter.init("lean_pq_sig_attestations_in_aggregated_signatures_total", .{ .help = "Total number of attestations included into aggregated signatures." }, .{}),
        .lean_pq_sig_attestation_signatures_building_time_seconds = Metrics.PQSigBuildingTimeHistogram.init("lean_pq_sig_attestation_signatures_building_time_seconds", .{ .help = "Time taken to build aggregated attestation signatures." }, .{}),
        .lean_pq_sig_aggregated_signatures_verification_time_seconds = Metrics.PQSigAggregatedVerificationHistogram.init("lean_pq_sig_aggregated_signatures_verification_time_seconds", .{ .help = "Time taken to verify an aggregated attestation signature." }, .{}),
        .lean_pq_sig_aggregated_signatures_valid_total = Metrics.PQSigAggregatedValidCounter.init("lean_pq_sig_aggregated_signatures_valid_total", .{ .help = "Total number of valid aggregated signatures." }, .{}),
        .lean_pq_sig_aggregated_signatures_invalid_total = Metrics.PQSigAggregatedInvalidCounter.init("lean_pq_sig_aggregated_signatures_invalid_total", .{ .help = "Total number of invalid aggregated signatures." }, .{}),
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
    lean_pq_sig_attestation_signatures_building_time_seconds.context = @ptrCast(&metrics.lean_pq_sig_attestation_signatures_building_time_seconds);
    lean_pq_sig_aggregated_signatures_verification_time_seconds.context = @ptrCast(&metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds);

    g_initialized = true;
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: *std.Io.Writer) !void {
    if (!g_initialized) return error.NotInitialized;

    // For ZKVM targets, write no metrics
    if (isZKVM()) {
        try writer.writeAll("# Metrics disabled for ZKVM target\n");
        return;
    }

    try metrics_lib.write(&metrics, writer);
}
