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
        var ts: std.posix.timespec = undefined;
        _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
        return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
    }
}

// Global metrics instance
// Note: Metrics are initialized as no-op by default. When init() is not called,
// or when called on ZKVM targets, all metric operations are no-ops automatically.
// Public so that callers can directly access and record metrics without wrapper functions.
pub var metrics = metrics_lib.initializeNoop(Metrics);
var g_initialized: bool = false;

const Metrics = struct {
    zeam_chain_onblock_duration_seconds: ChainHistogram,
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
    // Individual attestation signature metrics (renamed to match spec)
    lean_pq_sig_attestation_signing_time_seconds: PQSignatureSigningHistogram,
    lean_pq_sig_attestation_verification_time_seconds: PQSignatureVerificationHistogram,
    lean_pq_sig_attestation_signatures_total: PQSigAttestationSignaturesTotalCounter,
    lean_pq_sig_attestation_signatures_valid_total: PQSigAttestationSignaturesValidCounter,
    lean_pq_sig_attestation_signatures_invalid_total: PQSigAttestationSignaturesInvalidCounter,
    // Aggregated attestation signature metrics
    lean_pq_sig_aggregated_signatures_total: PQSigAggregatedSignaturesTotalCounter,
    lean_pq_sig_attestations_in_aggregated_signatures_total: PQSigAttestationsInAggregatedTotalCounter,
    lean_pq_sig_aggregated_signatures_building_time_seconds: PQSigBuildingTimeHistogram,
    lean_pq_sig_aggregated_signatures_verification_time_seconds: PQSigAggregatedVerificationHistogram,
    lean_pq_sig_aggregated_signatures_valid_total: PQSigAggregatedValidCounter,
    lean_pq_sig_aggregated_signatures_invalid_total: PQSigAggregatedInvalidCounter,
    // Network peer metrics
    lean_connected_peers: LeanConnectedPeersGauge,
    lean_peer_connection_events_total: PeerConnectionEventsCounter,
    lean_peer_disconnection_events_total: PeerDisconnectionEventsCounter,
    // Issue #808: per-reason count of swarm commands dropped before reaching
    // the rust-libp2p event loop (channel full / closed / uninitialized).
    // Refreshed from a Rust-side atomic on every scrape via a registered
    // refresher — see `registerScrapeRefresher` and the network-layer
    // implementation in `pkgs/network/src/ethlibp2p.zig`.
    zeam_libp2p_swarm_command_dropped_total: LibP2pSwarmCommandDroppedCounter,
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
    // Fork-choice store gauges
    lean_gossip_signatures: LeanGossipSignaturesGauge,
    lean_latest_new_aggregated_payloads: LeanLatestNewAggregatedPayloadsGauge,
    lean_latest_known_aggregated_payloads: LeanLatestKnownAggregatedPayloadsGauge,
    // Committee aggregation histogram
    lean_committee_signatures_aggregation_time_seconds: CommitteeSignaturesAggregationHistogram,
    // Validator status gauges
    lean_is_aggregator: LeanIsAggregatorGauge,
    lean_attestation_committee_subnet: LeanAttestationCommitteeSubnetGauge,
    lean_attestation_committee_count: LeanAttestationCommitteeCountGauge,
    // Block production metrics
    lean_block_building_time_seconds: BlockBuildingTimeHistogram,
    lean_block_building_payload_aggregation_time_seconds: BlockPayloadAggregationTimeHistogram,
    lean_block_aggregated_payloads: BlockAggregatedPayloadsHistogram,
    lean_block_building_success_total: BlockBuildingSuccessCounter,
    lean_block_building_failures_total: BlockBuildingFailuresCounter,
    // Sync status gauge
    lean_node_sync_status: LeanNodeSyncStatusGauge,
    // Gossip message size histograms
    lean_gossip_block_size_bytes: GossipBlockSizeBytesHistogram,
    lean_gossip_attestation_size_bytes: GossipAttestationSizeBytesHistogram,
    lean_gossip_aggregation_size_bytes: GossipAggregationSizeBytesHistogram,
    // Attestation production time histogram
    lean_attestations_production_time_seconds: AttestationProductionTimeHistogram,
    // compactAttestations metrics
    zeam_compact_attestations_time_seconds: CompactAttestationsTimeHistogram,
    zeam_compact_attestations_input_total: CompactAttestationsInputCounter,
    zeam_compact_attestations_output_total: CompactAttestationsOutputCounter,
    // Tick interval duration: actual elapsed time between clock ticks (nominal 0.8s)
    lean_tick_interval_duration_seconds: TickIntervalDurationHistogram,
    // Fork-choice tick interval duration: actual elapsed time between forkchoice tickIntervalUnlocked calls
    zeam_fork_choice_tick_interval_duration_seconds: ForkChoiceTickIntervalDurationHistogram,
    // BeamNode mutex contention metrics (issue #786)
    // Wait time = how long a callsite blocked before acquiring BeamNode.mutex.
    // Hold time = how long the callsite kept the mutex locked.
    // Labeled by callsite so we can attribute stalls to onInterval vs onGossip vs req-resp paths.
    //
    // Slice (a-2) of the threading refactor double-emits into these two
    // histograms via a code-side derived shim (see `pkgs/node/src/locking.zig`
    // LockTimer). The shim keeps existing dashboards working for one release
    // while operators migrate to `zeam_lock_{wait,hold}_seconds{lock,site}`.
    // Drop these two series in the release after slice (a) lands.
    zeam_node_mutex_wait_time_seconds: NodeMutexWaitTimeHistogram,
    zeam_node_mutex_hold_time_seconds: NodeMutexHoldTimeHistogram,
    // Per-resource lock contention metrics (slice a-2 of #803). Wait/hold
    // time labeled by both `lock` (states, pending_blocks, pubkey_cache,
    // root_to_slot, events, block_cache, ...) and `site` (callsite). The
    // legacy `zeam_node_mutex_*` series above is double-emitted into for one
    // release.
    zeam_lock_wait_seconds: LockWaitTimeHistogram,
    zeam_lock_hold_seconds: LockHoldTimeHistogram,
    // Histogram of how many iterations `chain.processPendingBlocks` ran
    // through (slice a-2 doc §Worst-case complexity note). Provides the
    // measurement floor before deciding whether to bound the queue or add
    // a cursor optimisation.
    lean_pending_blocks_drain_iters: PendingBlocksDrainItersHistogram,
    // Chain-worker queue + loop metrics (slice c-1 of #803).
    //   * `_dropped_total{queue="block"|"attestation"}` — producer
    //     `trySend` rejections when the queue was full.
    //   * `_depth{queue="..."}` — instantaneous queue depth, set on
    //     successful sends; for backlog visibility on devnet stress.
    //   * `lean_chain_worker_loop_iters_total` — worker-loop liveness
    //     counter; external watchdogs use the delta between scrapes
    //     to detect stalls without touching queue state.
    lean_chain_queue_dropped_total: LeanChainQueueDroppedCounter,
    lean_chain_queue_depth: LeanChainQueueDepthGauge,
    lean_chain_worker_loop_iters_total: LeanChainWorkerLoopItersCounter,

    const ChainHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
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
    const ForkChoiceBlockProcessingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1, 1.25, 1.5, 2, 4 });
    const ForkChoiceAttestationsValidLabeledCounter = metrics_lib.CounterVec(u64, struct { source: []const u8 });
    const ForkChoiceAttestationsInvalidLabeledCounter = metrics_lib.CounterVec(u64, struct { source: []const u8 });
    const ForkChoiceAttestationValidationTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 1 });
    // Individual attestation signature metric types
    const PQSigAttestationSignaturesTotalCounter = metrics_lib.Counter(u64);
    const PQSigAttestationSignaturesValidCounter = metrics_lib.Counter(u64);
    const PQSigAttestationSignaturesInvalidCounter = metrics_lib.Counter(u64);
    // Aggregated attestation signature metric types
    const PQSigAggregatedSignaturesTotalCounter = metrics_lib.Counter(u64);
    const PQSigAttestationsInAggregatedTotalCounter = metrics_lib.Counter(u64);
    const PQSigBuildingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.1, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 4 });
    const PQSigAggregatedVerificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.1, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 4 });
    const PQSigAggregatedValidCounter = metrics_lib.Counter(u64);
    const PQSigAggregatedInvalidCounter = metrics_lib.Counter(u64);
    // Network peer metric types
    const LeanConnectedPeersGauge = metrics_lib.GaugeVec(u64, struct { client: []const u8, client_type: []const u8 });
    const PeerConnectionEventsCounter = metrics_lib.CounterVec(u64, struct { direction: []const u8, result: []const u8 });
    const PeerDisconnectionEventsCounter = metrics_lib.CounterVec(u64, struct { direction: []const u8, reason: []const u8 });
    const LibP2pSwarmCommandDroppedCounter = metrics_lib.CounterVec(u64, struct { reason: []const u8 });
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
    // Chain-worker queue + loop metric types (slice c-1 of #803).
    const LeanChainQueueDroppedCounter = metrics_lib.CounterVec(u64, struct { queue: []const u8 });
    const LeanChainQueueDepthGauge = metrics_lib.GaugeVec(u64, struct { queue: []const u8 });
    const LeanChainWorkerLoopItersCounter = metrics_lib.Counter(u64);
    // Fork-choice store gauge types
    const LeanGossipSignaturesGauge = metrics_lib.Gauge(u64);
    const LeanLatestNewAggregatedPayloadsGauge = metrics_lib.Gauge(u64);
    const LeanLatestKnownAggregatedPayloadsGauge = metrics_lib.Gauge(u64);
    // Committee aggregation histogram type
    // Buckets widened for Devnet-4: was [0.005..1], now [0.05..4]
    const CommitteeSignaturesAggregationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.05, 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 });
    // Block production metric types
    const BlockBuildingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1 });
    const BlockPayloadAggregationTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 });
    const BlockAggregatedPayloadsHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1, 2, 4, 8, 16, 32, 64, 128 });
    const BlockBuildingSuccessCounter = metrics_lib.Counter(u64);
    const BlockBuildingFailuresCounter = metrics_lib.Counter(u64);
    // Sync status gauge type: 0=idle, 1=syncing, 2=synced
    const LeanNodeSyncStatusGauge = metrics_lib.GaugeVec(u64, struct { status: []const u8 });
    // Gossip message size histogram types
    const GossipBlockSizeBytesHistogram = metrics_lib.Histogram(f32, &[_]f32{ 10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000, 5_000_000 });
    const GossipAttestationSizeBytesHistogram = metrics_lib.Histogram(f32, &[_]f32{ 512, 1_024, 2_048, 4_096, 8_192, 16_384 });
    const GossipAggregationSizeBytesHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1_024, 4_096, 16_384, 65_536, 131_072, 262_144, 524_288, 1_048_576 });
    // Attestation production time histogram type
    const AttestationProductionTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1 });
    // compactAttestations metric types
    const CompactAttestationsTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5 });
    const TickIntervalDurationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6 });
    const ForkChoiceTickIntervalDurationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6 });
    const CompactAttestationsInputCounter = metrics_lib.Counter(u64);
    const CompactAttestationsOutputCounter = metrics_lib.Counter(u64);
    // BeamNode mutex contention histogram types. Buckets span 100us..2s to cover
    // both fast acquisitions and long stalls observed when STF runs under the lock.
    const NodeMutexLabel = struct { site: []const u8 };
    const NODE_MUTEX_BUCKETS = [_]f32{ 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2 };
    const NodeMutexWaitTimeHistogram = metrics_lib.HistogramVec(f32, NodeMutexLabel, &NODE_MUTEX_BUCKETS);
    const NodeMutexHoldTimeHistogram = metrics_lib.HistogramVec(f32, NodeMutexLabel, &NODE_MUTEX_BUCKETS);
    // Per-resource lock contention histograms (slice a-2)
    const LockLabel = struct { lock: []const u8, site: []const u8 };
    const LockWaitTimeHistogram = metrics_lib.HistogramVec(f32, LockLabel, &NODE_MUTEX_BUCKETS);
    const LockHoldTimeHistogram = metrics_lib.HistogramVec(f32, LockLabel, &NODE_MUTEX_BUCKETS);
    // pending_blocks drain iteration histogram type (slice a-2)
    const PendingBlocksDrainItersHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 });
    // Validator status gauge types
    const LeanIsAggregatorGauge = metrics_lib.Gauge(u64);
    const LeanAttestationCommitteeSubnetGauge = metrics_lib.Gauge(u64);
    const LeanAttestationCommitteeCountGauge = metrics_lib.Gauge(u64);
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

    /// Record a value directly without starting a timer.
    pub fn record(self: *const Histogram, value: f32) void {
        self.observe(self.context, value);
    }
};

fn observeChainOnblock(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.ChainHistogram = @ptrCast(@alignCast(histogram_ptr));
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

fn observeBlockBuildingTime(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockBuildingTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockPayloadAggregationTime(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockPayloadAggregationTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockAggregatedPayloads(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockAggregatedPayloadsHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeGossipBlockSizeBytes(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.GossipBlockSizeBytesHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeGossipAttestationSizeBytes(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.GossipAttestationSizeBytesHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeGossipAggregationSizeBytes(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.GossipAggregationSizeBytesHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeCommitteeSignaturesAggregation(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return; // No-op if not initialized
    const histogram: *Metrics.CommitteeSignaturesAggregationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeAttestationProduction(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.AttestationProductionTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeCompactAttestations(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.CompactAttestationsTimeHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeTickIntervalDuration(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.TickIntervalDurationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeForkChoiceTickIntervalDuration(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ForkChoiceTickIntervalDurationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observePendingBlocksDrainIters(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.PendingBlocksDrainItersHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

/// The public variables the application interacts with.
/// Calling `.start()` on these will start a new timer.
pub var zeam_chain_onblock_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeChainOnblock,
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
pub var lean_pq_sig_attestation_signing_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSignatureAttestationSigning,
};
pub var lean_pq_sig_attestation_verification_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSignatureAttestationVerification,
};
pub var lean_pq_sig_aggregated_signatures_building_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSigBuildingTime,
};
pub var lean_pq_sig_aggregated_signatures_verification_time_seconds: Histogram = .{
    .context = null,
    .observe = &observePQSigAggregatedVerification,
};
pub var lean_committee_signatures_aggregation_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeCommitteeSignaturesAggregation,
};

pub var lean_block_building_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeBlockBuildingTime,
};
pub var lean_block_building_payload_aggregation_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeBlockPayloadAggregationTime,
};
pub var lean_block_aggregated_payloads: Histogram = .{
    .context = null,
    .observe = &observeBlockAggregatedPayloads,
};
pub var lean_gossip_block_size_bytes: Histogram = .{
    .context = null,
    .observe = &observeGossipBlockSizeBytes,
};
pub var lean_gossip_attestation_size_bytes: Histogram = .{
    .context = null,
    .observe = &observeGossipAttestationSizeBytes,
};
pub var lean_gossip_aggregation_size_bytes: Histogram = .{
    .context = null,
    .observe = &observeGossipAggregationSizeBytes,
};
pub var lean_attestations_production_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeAttestationProduction,
};
pub var zeam_compact_attestations_time_seconds: Histogram = .{
    .context = null,
    .observe = &observeCompactAttestations,
};
pub var lean_tick_interval_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeTickIntervalDuration,
};
pub var zeam_fork_choice_tick_interval_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeForkChoiceTickIntervalDuration,
};
pub var lean_pending_blocks_drain_iters: Histogram = .{
    .context = null,
    .observe = &observePendingBlocksDrainIters,
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

    const io = std.Io.Threaded.global_single_threaded.io();

    metrics = .{
        .zeam_chain_onblock_duration_seconds = Metrics.ChainHistogram.init("zeam_chain_onblock_duration_seconds", .{ .help = "Time taken to process a block in the chain's onBlock function." }, .{}),
        .lean_head_slot = Metrics.LeanHeadSlotGauge.init("lean_head_slot", .{ .help = "Latest slot of the lean chain" }, .{}),
        .lean_latest_justified_slot = Metrics.LeanLatestJustifiedSlotGauge.init("lean_latest_justified_slot", .{ .help = "Latest justified slot" }, .{}),
        .lean_latest_finalized_slot = Metrics.LeanLatestFinalizedSlotGauge.init("lean_latest_finalized_slot", .{ .help = "Latest finalized slot" }, .{}),
        .lean_state_transition_time_seconds = Metrics.StateTransitionHistogram.init("lean_state_transition_time_seconds", .{ .help = "Time to process state transition" }, .{}),
        .lean_state_transition_slots_processed_total = Metrics.SlotsProcessedCounter.init("lean_state_transition_slots_processed_total", .{ .help = "Total number of processed slots" }, .{}),
        .lean_state_transition_slots_processing_time_seconds = Metrics.SlotsProcessingHistogram.init("lean_state_transition_slots_processing_time_seconds", .{ .help = "Time taken to process slots" }, .{}),
        .lean_state_transition_block_processing_time_seconds = Metrics.BlockProcessingTimeHistogram.init("lean_state_transition_block_processing_time_seconds", .{ .help = "Time taken to process block" }, .{}),
        .lean_state_transition_attestations_processed_total = Metrics.AttestationsProcessedCounter.init("lean_state_transition_attestations_processed_total", .{ .help = "Total number of processed attestations" }, .{}),
        .lean_state_transition_attestations_processing_time_seconds = Metrics.AttestationsProcessingHistogram.init("lean_state_transition_attestations_processing_time_seconds", .{ .help = "Time taken to process attestations" }, .{}),
        .lean_validators_count = Metrics.LeanValidatorsCountGauge.init("lean_validators_count", .{ .help = "Number of validators managed by a node" }, .{}),
        .lean_fork_choice_block_processing_time_seconds = Metrics.ForkChoiceBlockProcessingTimeHistogram.init("lean_fork_choice_block_processing_time_seconds", .{ .help = "Time taken to process block" }, .{}),
        .lean_attestations_valid_total = try Metrics.ForkChoiceAttestationsValidLabeledCounter.init(allocator, io, "lean_attestations_valid_total", .{ .help = "Total number of valid attestations" }, .{}),
        .lean_attestations_invalid_total = try Metrics.ForkChoiceAttestationsInvalidLabeledCounter.init(allocator, io, "lean_attestations_invalid_total", .{ .help = "Total number of invalid attestations" }, .{}),
        .lean_attestation_validation_time_seconds = Metrics.ForkChoiceAttestationValidationTimeHistogram.init("lean_attestation_validation_time_seconds", .{ .help = "Time taken to validate attestation" }, .{}),
        // Individual attestation signature metrics
        .lean_pq_sig_attestation_signing_time_seconds = Metrics.PQSignatureSigningHistogram.init("lean_pq_sig_attestation_signing_time_seconds", .{ .help = "Time taken to sign an attestation" }, .{}),
        .lean_pq_sig_attestation_verification_time_seconds = Metrics.PQSignatureVerificationHistogram.init("lean_pq_sig_attestation_verification_time_seconds", .{ .help = "Time taken to verify an attestation signature" }, .{}),
        .lean_pq_sig_attestation_signatures_total = Metrics.PQSigAttestationSignaturesTotalCounter.init("lean_pq_sig_attestation_signatures_total", .{ .help = "Total number of individual attestation signatures" }, .{}),
        .lean_pq_sig_attestation_signatures_valid_total = Metrics.PQSigAttestationSignaturesValidCounter.init("lean_pq_sig_attestation_signatures_valid_total", .{ .help = "Total number of valid individual attestation signatures" }, .{}),
        .lean_pq_sig_attestation_signatures_invalid_total = Metrics.PQSigAttestationSignaturesInvalidCounter.init("lean_pq_sig_attestation_signatures_invalid_total", .{ .help = "Total number of invalid individual attestation signatures" }, .{}),
        // Aggregated attestation signature metrics
        .lean_pq_sig_aggregated_signatures_total = Metrics.PQSigAggregatedSignaturesTotalCounter.init("lean_pq_sig_aggregated_signatures_total", .{ .help = "Total number of aggregated signatures" }, .{}),
        .lean_pq_sig_attestations_in_aggregated_signatures_total = Metrics.PQSigAttestationsInAggregatedTotalCounter.init("lean_pq_sig_attestations_in_aggregated_signatures_total", .{ .help = "Total number of attestations included into aggregated signatures" }, .{}),
        .lean_pq_sig_aggregated_signatures_building_time_seconds = Metrics.PQSigBuildingTimeHistogram.init("lean_pq_sig_aggregated_signatures_building_time_seconds", .{ .help = "Time taken to build an aggregated attestation signature" }, .{}),
        .lean_pq_sig_aggregated_signatures_verification_time_seconds = Metrics.PQSigAggregatedVerificationHistogram.init("lean_pq_sig_aggregated_signatures_verification_time_seconds", .{ .help = "Time taken to verify an aggregated attestation signature" }, .{}),
        .lean_pq_sig_aggregated_signatures_valid_total = Metrics.PQSigAggregatedValidCounter.init("lean_pq_sig_aggregated_signatures_valid_total", .{ .help = "Total number of valid aggregated signatures" }, .{}),
        .lean_pq_sig_aggregated_signatures_invalid_total = Metrics.PQSigAggregatedInvalidCounter.init("lean_pq_sig_aggregated_signatures_invalid_total", .{ .help = "Total number of invalid aggregated signatures" }, .{}),
        // Network peer metrics
        .lean_connected_peers = try Metrics.LeanConnectedPeersGauge.init(allocator, io, "lean_connected_peers", .{ .help = "Number of connected peers" }, .{}),
        .lean_peer_connection_events_total = try Metrics.PeerConnectionEventsCounter.init(allocator, io, "lean_peer_connection_events_total", .{ .help = "Total number of peer connection events" }, .{}),
        .lean_peer_disconnection_events_total = try Metrics.PeerDisconnectionEventsCounter.init(allocator, io, "lean_peer_disconnection_events_total", .{ .help = "Total number of peer disconnection events" }, .{}),
        .zeam_libp2p_swarm_command_dropped_total = try Metrics.LibP2pSwarmCommandDroppedCounter.init(allocator, io, "zeam_libp2p_swarm_command_dropped_total", .{ .help = "Total number of swarm commands dropped before reaching the rust-libp2p event loop, by reason (issue #808)" }, .{}),
        // Node lifecycle metrics
        .lean_node_info = try Metrics.LeanNodeInfoGauge.init(allocator, io, "lean_node_info", .{ .help = "Node information (always 1)" }, .{}),
        .lean_node_start_time_seconds = Metrics.LeanNodeStartTimeGauge.init("lean_node_start_time_seconds", .{ .help = "Start timestamp" }, .{}),
        .lean_current_slot = Metrics.LeanCurrentSlotGauge.init("lean_current_slot", .{ .help = "Current slot of the lean chain" }, .{}),
        .lean_safe_target_slot = Metrics.LeanSafeTargetSlotGauge.init("lean_safe_target_slot", .{ .help = "Safe target slot" }, .{}),
        // Fork choice reorg metrics
        .lean_fork_choice_reorgs_total = Metrics.LeanForkChoiceReorgsTotalCounter.init("lean_fork_choice_reorgs_total", .{ .help = "Total number of fork choice reorgs" }, .{}),
        .lean_fork_choice_reorg_depth = Metrics.LeanForkChoiceReorgDepthHistogram.init("lean_fork_choice_reorg_depth", .{ .help = "Depth of fork choice reorgs (in blocks)" }, .{}),
        // Finalization metrics
        .lean_finalizations_total = try Metrics.LeanFinalizationsTotalCounter.init(allocator, io, "lean_finalizations_total", .{ .help = "Total number of finalization attempts" }, .{}),
        // Fork-choice store gauges
        .lean_gossip_signatures = Metrics.LeanGossipSignaturesGauge.init("lean_gossip_signatures", .{ .help = "Number of gossip signatures in fork-choice store" }, .{}),
        .lean_latest_new_aggregated_payloads = Metrics.LeanLatestNewAggregatedPayloadsGauge.init("lean_latest_new_aggregated_payloads", .{ .help = "Number of new aggregated payload items" }, .{}),
        .lean_latest_known_aggregated_payloads = Metrics.LeanLatestKnownAggregatedPayloadsGauge.init("lean_latest_known_aggregated_payloads", .{ .help = "Number of known aggregated payload items" }, .{}),
        // Committee aggregation histogram
        .lean_committee_signatures_aggregation_time_seconds = Metrics.CommitteeSignaturesAggregationHistogram.init("lean_committee_signatures_aggregation_time_seconds", .{ .help = "Time taken to aggregate committee signatures" }, .{}),
        // Validator status gauges
        .lean_is_aggregator = Metrics.LeanIsAggregatorGauge.init("lean_is_aggregator", .{ .help = "Validator's is_aggregator status. True=1, False=0" }, .{}),
        .lean_attestation_committee_subnet = Metrics.LeanAttestationCommitteeSubnetGauge.init("lean_attestation_committee_subnet", .{ .help = "Node's attestation committee subnet" }, .{}),
        .lean_attestation_committee_count = Metrics.LeanAttestationCommitteeCountGauge.init("lean_attestation_committee_count", .{ .help = "Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)" }, .{}),
        // Block production metrics
        .lean_block_building_time_seconds = Metrics.BlockBuildingTimeHistogram.init("lean_block_building_time_seconds", .{ .help = "Time taken to build a block" }, .{}),
        .lean_block_building_payload_aggregation_time_seconds = Metrics.BlockPayloadAggregationTimeHistogram.init("lean_block_building_payload_aggregation_time_seconds", .{ .help = "Time taken to build aggregated_payloads during block building" }, .{}),
        .lean_block_aggregated_payloads = Metrics.BlockAggregatedPayloadsHistogram.init("lean_block_aggregated_payloads", .{ .help = "Number of aggregated_payloads in a block" }, .{}),
        .lean_block_building_success_total = Metrics.BlockBuildingSuccessCounter.init("lean_block_building_success_total", .{ .help = "Successful block builds" }, .{}),
        .lean_block_building_failures_total = Metrics.BlockBuildingFailuresCounter.init("lean_block_building_failures_total", .{ .help = "Failed block builds (exception in build_block)" }, .{}),
        // Sync status: labeled gauge with status in {idle, syncing, synced}
        .lean_node_sync_status = try Metrics.LeanNodeSyncStatusGauge.init(allocator, io, "lean_node_sync_status", .{ .help = "Node sync status" }, .{}),
        // Gossip message size histograms
        .lean_gossip_block_size_bytes = Metrics.GossipBlockSizeBytesHistogram.init("lean_gossip_block_size_bytes", .{ .help = "Bytes size of a gossip block message" }, .{}),
        .lean_gossip_attestation_size_bytes = Metrics.GossipAttestationSizeBytesHistogram.init("lean_gossip_attestation_size_bytes", .{ .help = "Bytes size of a gossip attestation message" }, .{}),
        .lean_gossip_aggregation_size_bytes = Metrics.GossipAggregationSizeBytesHistogram.init("lean_gossip_aggregation_size_bytes", .{ .help = "Bytes size of a gossip aggregated attestation message" }, .{}),
        .lean_attestations_production_time_seconds = Metrics.AttestationProductionTimeHistogram.init("lean_attestations_production_time_seconds", .{ .help = "Time taken to produce attestation" }, .{}),
        // compactAttestations metrics
        .zeam_compact_attestations_time_seconds = Metrics.CompactAttestationsTimeHistogram.init("zeam_compact_attestations_time_seconds", .{ .help = "Time taken by compactAttestations to merge payloads sharing the same AttestationData" }, .{}),
        .zeam_compact_attestations_input_total = Metrics.CompactAttestationsInputCounter.init("zeam_compact_attestations_input_total", .{ .help = "Total number of attestations input to compactAttestations" }, .{}),
        .zeam_compact_attestations_output_total = Metrics.CompactAttestationsOutputCounter.init("zeam_compact_attestations_output_total", .{ .help = "Total number of attestations output from compactAttestations after compaction" }, .{}),
        .lean_tick_interval_duration_seconds = Metrics.TickIntervalDurationHistogram.init("lean_tick_interval_duration_seconds", .{ .help = "Elapsed time between clock ticks in seconds (nominal 0.8s = 4s slot / 5 intervals)" }, .{}),
        .zeam_fork_choice_tick_interval_duration_seconds = Metrics.ForkChoiceTickIntervalDurationHistogram.init("zeam_fork_choice_tick_interval_duration_seconds", .{ .help = "Elapsed time between forkchoice tick calls in seconds (nominal 0.8s = 4s slot / 5 intervals)" }, .{}),
        // BeamNode mutex contention metrics (issue #786)
        .zeam_node_mutex_wait_time_seconds = try Metrics.NodeMutexWaitTimeHistogram.init(allocator, io, "zeam_node_mutex_wait_time_seconds", .{ .help = "Time spent waiting to acquire BeamNode.mutex, labeled by callsite (LEGACY — double-emitted from per-resource locks; will be removed after one release)." }, .{}),
        .zeam_node_mutex_hold_time_seconds = try Metrics.NodeMutexHoldTimeHistogram.init(allocator, io, "zeam_node_mutex_hold_time_seconds", .{ .help = "Time BeamNode.mutex was held, labeled by callsite (LEGACY — double-emitted from per-resource locks; will be removed after one release)." }, .{}),
        // Per-resource lock contention metrics (slice a-2 of #803).
        .zeam_lock_wait_seconds = try Metrics.LockWaitTimeHistogram.init(allocator, io, "zeam_lock_wait_seconds", .{ .help = "Time spent waiting to acquire a per-resource lock, labeled by lock and callsite." }, .{}),
        .zeam_lock_hold_seconds = try Metrics.LockHoldTimeHistogram.init(allocator, io, "zeam_lock_hold_seconds", .{ .help = "Time a per-resource lock was held, labeled by lock and callsite." }, .{}),
        .lean_pending_blocks_drain_iters = Metrics.PendingBlocksDrainItersHistogram.init("lean_pending_blocks_drain_iters", .{ .help = "Number of iterations chain.processPendingBlocks ran through before draining the queue or finding nothing ready." }, .{}),
        // Chain-worker queue + loop metrics (slice c-1 of #803).
        .lean_chain_queue_dropped_total = try Metrics.LeanChainQueueDroppedCounter.init(allocator, io, "lean_chain_queue_dropped_total", .{ .help = "Producer trySend rejections on the chain-worker queues, labeled by queue (block|attestation)." }, .{}),
        .lean_chain_queue_depth = try Metrics.LeanChainQueueDepthGauge.init(allocator, io, "lean_chain_queue_depth", .{ .help = "Instantaneous depth of the chain-worker queues, labeled by queue (block|attestation)." }, .{}),
        .lean_chain_worker_loop_iters_total = Metrics.LeanChainWorkerLoopItersCounter.init("lean_chain_worker_loop_iters_total", .{ .help = "Cumulative chain-worker loop iterations. External watchdogs use the delta between scrapes to detect worker stalls." }, .{}),
    };

    // Initialize validators count to 0 by default (spec requires "On scrape" availability)
    metrics.lean_validators_count.set(0);
    // Initialize committee-related gauges to 0 (placeholder until subnet logic is implemented)
    metrics.lean_is_aggregator.set(0);
    metrics.lean_attestation_committee_subnet.set(0);
    metrics.lean_attestation_committee_count.set(0);
    // Initialize fork-choice store gauges to 0
    metrics.lean_gossip_signatures.set(0);
    metrics.lean_latest_new_aggregated_payloads.set(0);
    metrics.lean_latest_known_aggregated_payloads.set(0);

    // Set context for histogram wrappers (observe functions already assigned at compile time)
    zeam_chain_onblock_duration_seconds.context = @ptrCast(&metrics.zeam_chain_onblock_duration_seconds);
    lean_state_transition_time_seconds.context = @ptrCast(&metrics.lean_state_transition_time_seconds);
    lean_state_transition_slots_processing_time_seconds.context = @ptrCast(&metrics.lean_state_transition_slots_processing_time_seconds);
    lean_state_transition_block_processing_time_seconds.context = @ptrCast(&metrics.lean_state_transition_block_processing_time_seconds);
    lean_state_transition_attestations_processing_time_seconds.context = @ptrCast(&metrics.lean_state_transition_attestations_processing_time_seconds);
    lean_fork_choice_block_processing_time_seconds.context = @ptrCast(&metrics.lean_fork_choice_block_processing_time_seconds);
    lean_attestation_validation_time_seconds.context = @ptrCast(&metrics.lean_attestation_validation_time_seconds);
    lean_pq_sig_attestation_signing_time_seconds.context = @ptrCast(&metrics.lean_pq_sig_attestation_signing_time_seconds);
    lean_pq_sig_attestation_verification_time_seconds.context = @ptrCast(&metrics.lean_pq_sig_attestation_verification_time_seconds);
    lean_pq_sig_aggregated_signatures_building_time_seconds.context = @ptrCast(&metrics.lean_pq_sig_aggregated_signatures_building_time_seconds);
    lean_pq_sig_aggregated_signatures_verification_time_seconds.context = @ptrCast(&metrics.lean_pq_sig_aggregated_signatures_verification_time_seconds);
    lean_committee_signatures_aggregation_time_seconds.context = @ptrCast(&metrics.lean_committee_signatures_aggregation_time_seconds);
    // Block production histogram contexts
    lean_block_building_time_seconds.context = @ptrCast(&metrics.lean_block_building_time_seconds);
    lean_block_building_payload_aggregation_time_seconds.context = @ptrCast(&metrics.lean_block_building_payload_aggregation_time_seconds);
    lean_block_aggregated_payloads.context = @ptrCast(&metrics.lean_block_aggregated_payloads);
    // Gossip size histogram contexts
    lean_gossip_block_size_bytes.context = @ptrCast(&metrics.lean_gossip_block_size_bytes);
    lean_gossip_attestation_size_bytes.context = @ptrCast(&metrics.lean_gossip_attestation_size_bytes);
    lean_gossip_aggregation_size_bytes.context = @ptrCast(&metrics.lean_gossip_aggregation_size_bytes);
    lean_attestations_production_time_seconds.context = @ptrCast(&metrics.lean_attestations_production_time_seconds);
    zeam_compact_attestations_time_seconds.context = @ptrCast(&metrics.zeam_compact_attestations_time_seconds);
    lean_tick_interval_duration_seconds.context = @ptrCast(&metrics.lean_tick_interval_duration_seconds);
    zeam_fork_choice_tick_interval_duration_seconds.context = @ptrCast(&metrics.zeam_fork_choice_tick_interval_duration_seconds);
    lean_pending_blocks_drain_iters.context = @ptrCast(&metrics.lean_pending_blocks_drain_iters);
    // Initialize sync status to idle at startup
    try metrics.lean_node_sync_status.set(.{ .status = "idle" }, 1);
    try metrics.lean_node_sync_status.set(.{ .status = "syncing" }, 0);
    try metrics.lean_node_sync_status.set(.{ .status = "synced" }, 0);

    g_initialized = true;
}

/// Optional pre-scrape refresher. Modules that own state outside the
/// `Metrics` struct (e.g. a Rust-side atomic counter accessed via FFI) can
/// register a callback here; it is invoked on every `writeMetrics` so the
/// counter values reflect the latest source-of-truth at scrape time. Issue
/// #808 (libp2p swarm command drops) is the first user.
var g_scrape_refresher: ?*const fn () void = null;

/// Register (or replace) a scrape refresher. Pass `null` to clear. Safe to
/// call before `init()`; the registration sticks regardless of init order.
pub fn registerScrapeRefresher(refresher: ?*const fn () void) void {
    g_scrape_refresher = refresher;
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: *std.Io.Writer) !void {
    if (!g_initialized) return error.NotInitialized;

    // For ZKVM targets, write no metrics
    if (isZKVM()) {
        try writer.writeAll("# Metrics disabled for ZKVM target\n");
        return;
    }

    // Pull in any externally-owned counters (e.g. Rust-side libp2p drops)
    // before serializing so each scrape returns up-to-date values.
    if (g_scrape_refresher) |refresher| refresher();

    try metrics_lib.write(&metrics, writer);
}
