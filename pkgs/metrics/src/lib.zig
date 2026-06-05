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
    // Per-substep timing inside `chain.onBlock` — used to attribute the
    // multi-second tail observed on aggregator nodes. Step labels:
    //   "block_root_compute" — hash_tree_root of the inner block when the
    //       caller did not supply a precomputed root.
    //   "parent_state_clone" — snapshot+clone of parent state under
    //       states_lock.shared.
    //   "verify_signatures" — XMSS verify (per-attestation) under
    //       pubkey_cache_lock.
    //   "state_transition" — `apply_transition` (process_slots +
    //       process_block) under root_to_slot_lock.
    //   "forkchoice_onblock" — `forkChoice.onBlock` integration call.
    //   "block_attestations" — onAttestation/storeAggregatedPayload loop
    //       over the block body.
    //   "db_persist" — block + state write batch + commit.
    //   "ssz_serialize_fallback" — fallback re-serialise when no
    //       precomputed SSZ bytes were supplied.
    //   "total_excluding_io_wait" — observed wall-clock total (mirrors
    //       `_duration_seconds` so dashboards can sanity-check that the
    //       sub-step buckets sum to roughly the total).
    zeam_chain_onblock_step_duration_seconds: ChainOnblockStepHistogram,
    // Per-imported-block weight metrics so the `zeam_chain_onblock_*_duration_seconds`
    // histograms can be correlated with block "heaviness" — whether a slow block
    // carried many attestations/participants or hit a per-block constant cost.
    zeam_chain_onblock_num_aggregated_attestations: BlockAggregatedPayloadsHistogram,
    zeam_chain_onblock_total_participants: BlockTotalParticipantsHistogram,
    // Slot-driver stall watchdog: a dedicated thread samples the
    // libxev tick clock every WATCHDOG_PROBE_MS via `Clock.lastTickMs()`
    // (atomic acquire load); if the value falls more than
    // WATCHDOG_THRESHOLD_MS behind wall clock it logs an ERROR and
    // bumps these counters. The histogram captures the distribution of
    // stall durations across firings.
    zeam_slot_driver_stall_fired_total: ZeamSlotDriverStallFiredCounter,
    zeam_slot_driver_stall_seconds: ZeamSlotDriverStallSecondsHistogram,
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
    // Zeam-specific phase attribution for aggregate production.
    // phase="snapshot" clones live signature/payload maps under signatures_mutex.
    // phase="att_data_prep" serial prepareAggregateAttData (hashTreeRoot, greedy
    // payload pick, handle setup) inside computeAggregatedSignatures.
    // phase="xmss_prove" recursive rec_xmss_aggregate via xmss_aggregate FFI.
    // phase="compute_ffi" full computeAggregatedSignatures (prep + parallel proves).
    // phase="commit" publishes results back into latest_new_aggregated_payloads.
    zeam_pq_sig_aggregated_signatures_building_phase_seconds: PQSigBuildingPhaseHistogram,
    /// Wall time inside `xmss_aggregate` / `rec_xmss_aggregate` only
    /// (one recursive STARK prove per att_data). Compare directly to
    /// `cargo run --release -- recursion --n 2`; zeam worker histograms include
    /// snapshot, prep, child-proof deserialize, and serialize on top of this.
    zeam_xmss_rec_aggregate_prove_seconds: XmssRecAggregateProveHistogram,
    /// Same wall time as `zeam_xmss_rec_aggregate_prove_seconds`, labeled by
    /// coarse `num_raw` / `num_children` input-size buckets so the build
    /// histogram tail can be classified as steady-state full-committee proves
    /// vs partial-input reproves.
    /// Buckets are deliberately low-cardinality — see `numRawBucket` /
    /// `numChildrenBucket` below for the exact mapping.
    zeam_xmss_rec_aggregate_prove_by_input_seconds: XmssRecAggregateProveByInputHistogram,
    /// Per-phase breakdown inside `xmss_aggregate` reported back from the
    /// Rust FFI via out-pointers. The three phases ("marshal", "stark",
    /// "post") sum to a value very close to one observation on
    /// `zeam_xmss_rec_aggregate_prove_seconds` (delta is the FFI call/return
    /// overhead, sub-microsecond). This lets us tell whether zeam's per-call
    /// cost lives in argument deserialization or in the recursive STARK
    /// itself — the two have very different fixes.
    zeam_xmss_rec_aggregate_phase_seconds: XmssRecAggregatePhaseHistogram,
    lean_pq_sig_aggregated_signatures_verification_time_seconds: PQSigAggregatedVerificationHistogram,
    // Per-stage timing for the signature-verify path, labeled by stage, to
    // attribute the `step="verify_signatures"` cost. Registered for verify-cost
    // attribution; not currently observed under the single merged-proof
    // verifySignatures path.
    zeam_stf_verify_signatures_stage_duration_seconds: StfVerifySignaturesStageHistogram,
    // Number of blocks coalesced into one `verifySignaturesParallelMultiBlock`
    // call. K=1 means we routed through the single-block path; K>1 means
    // the chain-worker drained ≥2 blocks together. Pair with the
    // `phase2_batch_verify_multiblock` stage to confirm that batching
    // actually amortises rayon overhead as K grows.
    zeam_stf_verify_signatures_batch_size: StfVerifySignaturesBatchSizeHistogram,
    lean_pq_sig_aggregated_signatures_valid_total: PQSigAggregatedValidCounter,
    lean_pq_sig_aggregated_signatures_invalid_total: PQSigAggregatedInvalidCounter,
    // Network peer metrics
    lean_connected_peers: LeanConnectedPeersGauge,
    lean_peer_connection_events_total: PeerConnectionEventsCounter,
    lean_peer_disconnection_events_total: PeerDisconnectionEventsCounter,
    // Per-reason count of swarm commands dropped before reaching
    // the rust-libp2p event loop (channel full / closed / uninitialized).
    // Refreshed from a Rust-side atomic on every scrape via a registered
    // refresher — see `registerScrapeRefresher` and the network-layer
    // implementation.
    zeam_libp2p_swarm_command_dropped_total: LibP2pSwarmCommandDroppedCounter,
    // Number of remote peers in the gossipsub mesh
    // across all subscribed topics. Refreshed from a Rust-side atomic on
    // every scrape via a registered refresher — see
    // `registerScrapeRefresher` and the network-layer implementation.
    // TODO: per-remote-peer label scheme
    // (matching `lean_connected_peers`) requires subscribing to gossipsub
    // Subscribed/Unsubscribed events; left as follow-up work.
    lean_gossip_mesh_peers: LeanGossipMeshPeersGauge,
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
    // Attestation aggregate coverage gauges. Section labels are the same
    // names printed in the slot/report logs: timely, late, block, combined,
    // agg_start_new, proposal_payloads, proposal_gossip, and proposal_combined.
    // `subnet="combined"` is the all-subnet validator total for the section;
    // `subnet="subnet_N"` is that section's validator coverage on one subnet.
    // Direction labels are block_only and timely_only.
    // Slot is the X-axis (time series progression), not a label dimension.
    lean_attestation_aggregate_coverage_validators: AttestationAggregateCoverageValidatorsGauge,
    lean_attestation_aggregate_coverage_subnets: AttestationAggregateCoverageSubnetsGauge,
    lean_attestation_aggregate_coverage_diff_validators: AttestationAggregateCoverageDiffValidatorsGauge,
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
    /// Count gossip-ingress decode rejections, labeled by
    /// `topic_kind` (block | attestation | aggregation) and `reason`
    /// (snappy_empty | snappy_varint | snappy_oversized | snappy_truncated |
    /// snappy_decode | ssz_decode). Without this counter, the only operator-
    /// visible signal that zeam has stopped accepting gossip is `lean_head_slot`
    /// drifting behind wall-clock — by which point the node is already off
    /// consensus. With it, the failure mode is dashboard-visible the moment
    /// decode starts failing, and the `reason` label attributes upstream
    /// vs. our-side framing mismatches vs. SSZ-body issues separately.
    zeam_gossip_decode_failures_total: ZeamGossipDecodeFailuresCounter,
    // Attestation production time histogram
    lean_attestations_production_time_seconds: AttestationProductionTimeHistogram,
    // compactAttestations metrics
    zeam_compact_attestations_time_seconds: CompactAttestationsTimeHistogram,
    zeam_compact_attestations_input_total: CompactAttestationsInputCounter,
    zeam_compact_attestations_output_total: CompactAttestationsOutputCounter,
    // Block-proposal attestation selection (`getProposalAttestations`). Phase
    // attribution mirrors `zeam_pq_sig_aggregated_signatures_building_phase_seconds`
    // on the interval-2 aggregator path. `lean_block_building_payload_aggregation_time_seconds`
    // remains the cross-client wall-clock total for the whole call.
    lean_block_proposal_attestation_build_phase_seconds: BlockProposalAttestationBuildPhaseHistogram,
    lean_block_proposal_attestation_builds_total: BlockProposalAttestationBuildsTotalCounter,
    lean_block_proposal_child_payloads_consumed_total: BlockProposalChildPayloadsConsumedTotalCounter,
    lean_block_proposal_attestation_data_selected: BlockProposalAttestationDataSelectedHistogram,
    lean_block_proposal_aggregates_selected: BlockProposalAggregatesSelectedHistogram,
    // Interval-aware proposer metrics.
    zeam_proposal_deadline_hits_total: ZeamProposalDeadlineHitsCounter,
    zeam_proposal_partial_prefix_size: ZeamProposalPartialPrefixSizeHistogram,
    zeam_proposal_skipped_empty_total: ZeamProposalSkippedEmptyCounter,
    // Tick interval duration: actual elapsed time between clock ticks (nominal 0.8s)
    lean_tick_interval_duration_seconds: TickIntervalDurationHistogram,
    /// Wall time for one `xev.Loop.run(.until_done)` in `Clock.run`.
    /// Large values imply completion backlog (gossip / reqresp / bridge) before the next tick.
    zeam_xev_clock_until_done_drain_seconds: XevClockUntilDoneDrainHistogram,
    /// Count of clock-loop `run(.until_done)` drains taking ≥500ms wall time.
    zeam_xev_clock_until_done_slow_ge_500ms_total: ZeamXevClockUntilDoneSlowGe500msCounter,
    /// Count of clock-loop `run(.until_done)` drains taking ≥1s wall time.
    zeam_xev_clock_until_done_slow_ge_1s_total: ZeamXevClockUntilDoneSlowGe1sCounter,
    /// Wall time spent inside individual libxev callbacks, labeled by callsite.
    /// Used to attribute slow `zeam_xev_clock_until_done_drain_seconds` to a
    /// specific synchronous chunk of work executed on the libxev thread.
    /// Each callsite name is a fixed low-cardinality string; see
    /// `observeLibxevCallback` for the canonical site list.
    zeam_libxev_callback_duration_seconds: LibxevCallbackDurationHistogram,
    // Fork-choice tick interval duration: actual elapsed time between forkchoice tickIntervalUnlocked calls
    zeam_fork_choice_tick_interval_duration_seconds: ForkChoiceTickIntervalDurationHistogram,
    /// Wall time for the per-slot aggregation tick (interval 2): `maybeAggregateOnInterval`
    /// plus `publishProducedAggregations` when the aggregator produces gossip aggregates.
    zeam_node_aggregation_interval_tick_seconds: AggregationIntervalTickHistogram,
    /// Standard leanMetrics counter for skipped aggregate submissions, labeled by reason.
    /// Reasons: "not_aggregator", "not_synced", "missing_state", "spawn_failed", "other".
    /// (In-flight triggers are coalesced via `zeam_aggregate_coalesced_total`.)
    lean_aggregator_skipped_total: AggregateSkipCounter,
    /// Slot-driver aggregation triggers coalesced while a worker was in flight.
    /// A single catch-up run is scheduled when the worker finishes.
    zeam_aggregate_coalesced_total: AggregateCoalescedCounter,
    /// Histogram for the wall-clock duration of the aggregate FFI worker.
    zeam_aggregate_worker_duration_seconds: AggregateWorkerDurationHistogram,
    /// Counter for SignedAggregatedAttestation messages published by the local
    /// aggregator worker (after the FFI returned), labeled by attestation subnet.
    /// Separate from the standard `lean_pq_sig_aggregated_signatures_total`
    /// (which zeam increments only on the block-proposal path) so cross-client
    /// dashboards keep the standard metric's semantics intact. Operators can
    /// use this counter to tell whether the local aggregator is producing for
    /// its duty subnet at all without inferring it from the worker histogram.
    zeam_aggregator_publish_aggregations_total: AggregatorPublishAggregationsCounter,
    // BeamNode mutex contention metrics.
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
    // Per-resource lock contention metrics. Wait/hold
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
    // Visibility into the future-block queueing path.
    //   * `lean_pending_blocks_depth` — instantaneous queue depth, set on
    //     every successful enqueue and every `processPendingBlocks` drain.
    //     Combined with `_evicted_total{reason="cap"}` it tells operators
    //     when the queue cap is being hit (which would silently drop
    //     legitimate near-future gossip blocks).
    //   * `lean_pending_blocks_evicted_total{reason}` — cumulative count of
    //     blocks dropped from the queue, by reason: `cap` (capacity hit),
    //     `pre_finalized` (slot < finalized), `too_far_future` (slot >
    //     current_slot + MAX_FUTURE_SLOT_QUEUE_TOLERANCE; drain-side
    //     eviction), `duplicate` (same root
    //     already queued), `append_oom` (allocator failure on capacity
    //     reservation; the new block is dropped, the queue is unchanged).
    //   * `lean_pending_blocks_replayed_total{result}` — cumulative count
    //     of replays attempted from `processPendingBlocks`, by
    //     terminal result: `accepted` / `rejected` / `error`.
    //   * `lean_blocks_future_slot_dropped_total` — cumulative count of
    //     gossip blocks hard-rejected as `FutureSlot` (beyond the
    //     queueable window).
    lean_pending_blocks_depth: LeanPendingBlocksDepthGauge,
    lean_pending_blocks_evicted_total: LeanPendingBlocksEvictedCounter,
    lean_pending_blocks_replayed_total: LeanPendingBlocksReplayedCounter,
    lean_blocks_future_slot_dropped_total: LeanBlocksFutureSlotDroppedCounter,
    // Chain-worker queue + loop metrics.
    //   * `_dropped_total{queue="block"|"attestation"|"aggregated_attestation"}` — producer
    //     `trySend` rejections when the queue was full.
    //   * `_depth{queue="..."}` — outstanding accepted work, incremented
    //     on successful sends and decremented after worker processing; for
    //     backlog visibility under stress.
    //   * `lean_chain_worker_loop_iters_total` — worker-loop liveness
    //     counter; external watchdogs use the delta between scrapes
    //     to detect stalls without touching queue state.
    lean_chain_queue_dropped_total: LeanChainQueueDroppedCounter,
    lean_chain_queue_depth: LeanChainQueueDepthGauge,
    lean_chain_worker_loop_iters_total: LeanChainWorkerLoopItersCounter,
    /// PR #966: per-dispatch-path counter so dashboards can see how often
    /// the chain-worker actually managed to batch ≥2 blocks vs falling
    /// back to the single-block path. `path="single"` increments once
    /// per `.on_block` Message dispatched through the unbatched code
    /// path (block queue depth ≤ BLOCK_BATCH_THRESHOLD at drain time);
    /// `path="batch"` increments once per `Handlers.on_blocks_batch`
    /// dispatch. Sum the latter with the K from
    /// `zeam_stf_verify_signatures_batch_size_count` to recover the
    /// total number of blocks that took the batched path.
    zeam_chain_worker_block_dispatch_total: ZeamChainWorkerBlockDispatchCounter,
    /// Total roots inserted into `BeamChain.invalid_block_roots` over the
    /// process lifetime (de-duped — a re-mark of the same root does not
    /// increment). A sustained nonzero rate signals a peer producing
    /// malformed blocks; pair with the cross-client logs from devnet
    /// 2a4b7197 (ream's "Failed to deserialize AggregatedXMSS proof") to
    /// attribute the producer.
    zeam_chain_invalid_block_root_marked_total: ZeamChainInvalidBlockRootMarkedCounter,
    /// Early-drops at `chain.onBlock`'s entry guard. Labeled by site:
    /// "self" = block's own root was already cached; "parent" = cascade
    /// from a cached parent_root (descendant-of-invalid). High and
    /// growing hit rate indicates a peer / orphan-dependents path is
    /// repeatedly redelivering the same known-bad root — exactly the
    /// 12,676-chunks-per-5-min livelock observed on slot=13.
    zeam_chain_invalid_block_root_hit_total: ZeamChainInvalidBlockRootHitCounter,
    /// Tripwire counter (zclawz review on PR #890): bumped from
    /// `chainWorkerProcessPendingBlocksThunk` whenever it returns a
    /// non-empty `missing_roots` slice. The thunk has no production
    /// caller today (the libxev tick runs `processPendingBlocks`
    /// inline), so this metric MUST stay at 0 in steady state. A
    /// non-zero value is a regression signal: a future worker
    /// producer was wired up without first plumbing the missing-
    /// roots backchannel and is silently stranding sync — the
    /// thunk would otherwise just log a warn that's easy to miss.
    lean_chain_worker_process_pending_blocks_dropped_missing_roots_total: LeanChainWorkerProcessPendingBlocksDroppedMissingRootsCounter,
    // Distribution of refcount values across
    // map-resident BeamState entries at scrape time. Sampled by the chain
    // via `recordChainStateRefcountDistribution` registered as a
    // context-bearing scrape refresher (see `registerScrapeRefresherCtx`).
    lean_chain_state_refcount_distribution: LeanChainStateRefcountDistributionHistogram,
    // Visibility into the centralised hash-root
    // cache. Each block ingress now carries the block_root computed
    // once at the gossip / RPC entry point through every downstream
    // consumer (chain.onGossip, enqueuePendingBlock,
    // processPendingBlocks, chain.onBlock, forkchoice.onBlock).
    // This counter bumps every time a downstream consumer was able
    // to skip the second `hashTreeRoot` because the producer threaded
    // a precomputed root through. The `site` label identifies the
    // skip site (e.g. "chain.onGossip", "chain.onBlock",
    // "chain.processPendingBlocks", "chain.enqueuePendingBlock"). A
    // sustained 0 for any site label means the cache plumbing is
    // broken there — useful for catching a regression that drops
    // the root on the floor in a future refactor.
    lean_block_root_compute_skipped_total: LeanBlockRootComputeSkippedCounter,
    // Visibility into the parallel net-fetch +
    // missed-root prune dedup. Bumped per `fetchBlockByRoots` call by
    // outcome bucket. Every entry of the input `roots` lands in
    // exactly one bucket, so the outcome counters sum to `roots.len`
    // per call — useful for asserting `sum(rate(lean_block_fetch_dedup_total))
    // == sum(rate(… by outcome))` as a Grafana invariant. Buckets:
    //   * `already_in_forkchoice` — protoArray hit on `hasBlocksBatch`.
    //   * `already_in_block_cache` — awaiting parent or STF.
    //   * `already_pending` — RPC in flight; another
    //     `fetchBlockByRoots` call is already responsible.
    //   * `fetched` — dispatched to a peer via `blocks_by_root`.
    //   * `fetch_no_peers` — dispatch attempted but `selectPeer`
    //     returned `error.NoPeersAvailable`.
    //   * `fetch_failed` — dispatch attempted but failed for any
    //     other reason (queue full, encode failure, …).
    //   * `dedup_lost_race` — every requested root entered
    //     `network.pending_block_roots` or `network.block_cache`
    //     between our `hasBlocksBatch` snapshot and the network
    //     helper's re-check, so dispatch was suppressed. The benign
    //     TOCTOU window is documented
    //     in `BeamNode.fetchBlockByRoots`.
    lean_block_fetch_dedup_total: LeanBlockFetchDedupCounter,
    // `blocks_by_range` catch-up outcomes (retry, abort, success, …). zeam-specific.
    zeam_blocks_by_range_sync_total: ZeamBlocksByRangeSyncCounter,
    // P2: gossip attestation/aggregation drops on the libxev
    // main thread BEFORE they are routed to the chain-worker. Bumped by
    // `chain.onGossip` for raw attestations and aggregations. zeam-
    // specific (other lean clients shape this differently). Labels:
    //   * `kind` — `attestation` (raw gossip att) or `aggregation`
    //     (aggregated payload).
    //   * `reason`:
    //     - `syncing` — chain.getSyncStatus() is `peers_materially_ahead` /
    //       `fc_initing` / `no_peers`; suppress validation work and the
    //       follow-up `BlocksByRoot` fetch enqueue (the death-spiral fix).
    //       Recovery comes from `BlocksByRange` / gossip block import.
    //     - `future_slot` — `att.slot > current_slot + GOSSIP_FUTURE_SLOT_TOLERANCE`;
    //       no point validating against a head we don't know yet, and the
    //       missing-root would be unhelpful (it's a head we're racing
    //       against, not a real fetch target).
    //     - `worker_validation_failed` — attestation reached the chain-
    //       worker but `validateAttestationData` rejected it on-thread;
    //       includes the unknown-{head,source,target} cases that used to
    //       trigger a fetch storm. The chain-worker path silently drops
    //       these (per the established `chainWorkerOn*Thunk` no-feedback
    //       contract) so this counter is the only signal.
    zeam_gossip_atts_dropped_total: ZeamGossipAttsDroppedCounter,
    // P3: per-resource concurrency cap on outbound
    // `BlocksByRoot` RPCs. The earlier path issued one RPC per
    // attestation that referenced an unknown head, multiplied by 4x
    // subnet fanout for an aggregator — under flood the libxev thread
    // would fork off hundreds of RPCs that themselves timed out and
    // retried, saturating the loop. The cap pins concurrent outbound
    // BlocksByRoot to MAX_CONCURRENT_BLOCKS_BY_ROOT (typically 8) so
    // gossip pressure can't run the request fan-out away. zeam-specific
    // (the cap is a zeam implementation detail, not a spec constraint).
    //   * `zeam_blocks_by_root_inflight` — instantaneous count of
    //     outbound `BlocksByRoot` RPCs that have been dispatched but
    //     have not yet been finalized via `finalizePendingRequest`.
    //   * the cap-rejection bucket is folded into
    //     `lean_block_fetch_dedup_total{outcome="inflight_cap"}` so
    //     dashboards see all suppression causes side by side
    //     with the existing dedup outcomes — keeps the
    //     `sum(rate(... by outcome)) == sum(rate(...))` invariant.
    zeam_blocks_by_root_inflight: ZeamBlocksByRootInflightGauge,
    // P4: Clock.run drain bounding visibility. The earlier
    // shape called `events.run(.until_done)` per pass, which under
    // flood drained for many seconds and starved `tickInterval`.
    // P4 swaps to `.once` (one io_uring CQE batch per pass), which
    // returns to `tickInterval` as soon as the next-interval timer or
    // any other completion fires. This counter is the rate of clock
    // passes — comparing scrape deltas to expected (`5 / SECONDS_PER_SLOT`,
    // ~1.25 Hz at 4s slots) is a quick liveness signal independent of
    // the existing `lean_tick_interval_duration_seconds` histogram.
    zeam_xev_clock_drain_passes_total: ZeamXevClockDrainPassesCounter,
    // Spec parity: gossip attestations
    // and aggregations whose referenced source/target/head block isn't
    // yet imported, or whose slot is still in the future, are buffered
    // for replay after the next successful `onBlock` import (see
    // `_replay_pending_attestations` in the spec; mirrored as
    // `replayPendingAttestations`).
    //
    //   * `lean_pending_attestations_buffered_total{kind, reason}` —
    //     cumulative entries pushed into the pending-attestation buffer.
    //     `kind={attestation,aggregation}`, `reason={unknown_block,future_slot}`.
    //   * `lean_pending_attestations_evicted_total{kind}` — entries
    //     dropped via FIFO eviction at MAX_PENDING_ATTESTATIONS (1024,
    //     spec value).
    //   * `lean_pending_attestations_replay_total{kind, outcome}` —
    //     replay attempts. `outcome={accepted,buffered,dropped}`:
    //     `accepted` = validate+verify succeeded after replay,
    //     `buffered` = still missing block (re-enqueued), `dropped` =
    //     permanent failure (signature, malformed, etc).
    //   * `lean_pending_attestations_size{kind}` — instantaneous buffer
    //     depth, refreshed after every enqueue/replay drain.
    lean_pending_attestations_buffered_total: LeanPendingAttsBufferedCounter,
    lean_pending_attestations_evicted_total: LeanPendingAttsEvictedCounter,
    lean_pending_attestations_replay_total: LeanPendingAttsReplayCounter,
    lean_pending_attestations_size: LeanPendingAttsSizeGauge,
    // Per-site errors swallowed by `BeamNode.onInterval`; sustained non-zero
    // rates mean the node is ticking but a duty/publish layer is failing.
    lean_node_interval_error_total: LeanNodeIntervalErrorCounter,

    const ChainHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 });
    // Per-substep timing inside chain.onBlock.
    // Same bucket layout as ChainHistogram so dashboards can stack the
    // step series and the total side-by-side without bucket-aligned diffs.
    const ChainOnblockStepLabel = struct { step: []const u8 };
    const ChainOnblockStepHistogram = metrics_lib.HistogramVec(
        f32,
        ChainOnblockStepLabel,
        &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 },
    );
    // Same bucket layout as ChainOnblockStepHistogram so dashboards can
    // stack the verify-signatures stages under `step="verify_signatures"`
    // and confirm they sum to roughly the parent step's wall-clock.
    const StfVerifySignaturesStageLabel = struct { stage: []const u8 };
    const StfVerifySignaturesStageHistogram = metrics_lib.HistogramVec(
        f32,
        StfVerifySignaturesStageLabel,
        &[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 },
    );
    // Batch sizes 1..16+ cover the practical range:
    // - K=1: chain-worker drained one block (gossip / locally produced / sparse catch-up)
    // - K=2..4: typical catch-up sweep (BLOCKS_BY_RANGE_SYNC_THRESHOLD = 4)
    // - K=8..16: backlog drain after a stall
    const StfVerifySignaturesBatchSizeHistogram = metrics_lib.Histogram(
        f32,
        &[_]f32{ 1, 2, 4, 8, 16, 32 },
    );
    // Watchdog counters (#863): wall-clock heartbeats from the slot-driver
    // libxev thread. The watchdog thread bumps `_fired_total` whenever it
    // observes a stall over the configured threshold; the per-bucket
    // counters give operators a quick "how bad" without scraping the
    // histogram.
    const ZeamSlotDriverStallFiredCounter = metrics_lib.Counter(u64);
    const ZeamSlotDriverStallSecondsHistogram = metrics_lib.Histogram(
        f32,
        &[_]f32{ 1, 2, 5, 10, 30, 60, 120, 300, 600 },
    );
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
    const PQSigBuildingPhaseHistogram = metrics_lib.HistogramVec(f32, struct { phase: []const u8 }, &[_]f32{ 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4 });
    const XmssRecAggregateProveHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 15.0 });
    const XmssRecAggregateProveByInputLabel = struct { num_raw: []const u8, num_children: []const u8 };
    const XmssRecAggregateProveByInputHistogram = metrics_lib.HistogramVec(f32, XmssRecAggregateProveByInputLabel, &[_]f32{ 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 15.0 });
    // Buckets span sub-millisecond (post phase = pointer wrap, typically ns)
    // through multi-second STARK proves. Phase label values are
    // "marshal" | "stark" | "post" — see XmssRecAggregatePhaseLabel below.
    const XmssRecAggregatePhaseLabel = struct { phase: []const u8 };
    const XmssRecAggregatePhaseHistogram = metrics_lib.HistogramVec(f32, XmssRecAggregatePhaseLabel, &[_]f32{ 0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0 });
    const PQSigAggregatedVerificationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.1, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 4 });
    const PQSigAggregatedValidCounter = metrics_lib.Counter(u64);
    const PQSigAggregatedInvalidCounter = metrics_lib.Counter(u64);
    // Network peer metric types
    const LeanConnectedPeersGauge = metrics_lib.GaugeVec(u64, struct { client: []const u8, client_type: []const u8 });
    const PeerConnectionEventsCounter = metrics_lib.CounterVec(u64, struct { direction: []const u8, result: []const u8 });
    const PeerDisconnectionEventsCounter = metrics_lib.CounterVec(u64, struct { direction: []const u8, reason: []const u8 });
    const LibP2pSwarmCommandDroppedCounter = metrics_lib.CounterVec(u64, struct { reason: []const u8 });
    const LeanGossipMeshPeersGauge = metrics_lib.Gauge(u64);
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
    // Chain-worker queue + loop metric types.
    const LeanChainQueueDroppedCounter = metrics_lib.CounterVec(u64, struct { queue: []const u8 });
    const LeanChainQueueDepthGauge = metrics_lib.GaugeVec(u64, struct { queue: []const u8 });
    const LeanChainWorkerLoopItersCounter = metrics_lib.Counter(u64);
    const ZeamChainWorkerBlockDispatchCounter = metrics_lib.CounterVec(u64, struct { path: []const u8 });
    // Invalid-block-roots cache counters (slot=13 #942 follow-up). `marked`
    // increments once per fresh insert; `hit{site}` increments on every
    // early-drop in `chain.onBlock` so the ratio shows how much wasted
    // verify the cache saved. Two `site` values: "self" (block's own root
    // was previously marked) and "parent" (cascade: parent_root was marked,
    // so child is invalid by descent).
    const ZeamChainInvalidBlockRootMarkedCounter = metrics_lib.Counter(u64);
    const ZeamChainInvalidBlockRootHitCounter = metrics_lib.CounterVec(u64, struct { site: []const u8 });
    const LeanChainWorkerProcessPendingBlocksDroppedMissingRootsCounter = metrics_lib.Counter(u64);
    // Refcount-distribution buckets [1, 2, 4, 8, 16, 32, +Inf]. Typical
    // value is 1 (writer-only); transient 2-4 under reader concurrency;
    // values >16 indicate leaked acquires (a reader forgot to release
    // its borrow). The +Inf bucket is implicit in the Histogram's tail.
    const LeanChainStateRefcountDistributionHistogram = metrics_lib.Histogram(
        f32,
        &[_]f32{ 1, 2, 4, 8, 16, 32 },
    );
    // Fork-choice store gauge types
    const LeanGossipSignaturesGauge = metrics_lib.Gauge(u64);
    const LeanLatestNewAggregatedPayloadsGauge = metrics_lib.Gauge(u64);
    const LeanLatestKnownAggregatedPayloadsGauge = metrics_lib.Gauge(u64);
    const AttestationAggregateCoverageValidatorsGauge = metrics_lib.GaugeVec(u64, struct { section: []const u8, subnet: []const u8 });
    const AttestationAggregateCoverageSubnetsGauge = metrics_lib.GaugeVec(u64, struct { section: []const u8 });
    const AttestationAggregateCoverageDiffValidatorsGauge = metrics_lib.GaugeVec(u64, struct { direction: []const u8 });
    // Committee aggregation histogram type
    // Buckets widened: was [0.005..1], now [0.05..4]
    const CommitteeSignaturesAggregationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.05, 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 });
    // Block production metric types
    const BlockBuildingTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1 });
    const BlockPayloadAggregationTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 });
    const BlockAggregatedPayloadsHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1, 2, 4, 8, 16, 32, 64, 128 });
    // Total participant count summed across all aggregated_attestations in
    // a block. Each attestation can have up to NUM_VALIDATORS participants;
    // realistic block totals on devnet sit in the low hundreds today and
    // grow with the validator set. Buckets cover that range with headroom.
    const BlockTotalParticipantsHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1, 8, 32, 128, 512, 1024, 2048, 4096, 8192 });
    const BlockBuildingSuccessCounter = metrics_lib.Counter(u64);
    const BlockBuildingFailuresCounter = metrics_lib.Counter(u64);
    // Sync status gauge type: 0=idle, 1=syncing, 2=synced
    const LeanNodeSyncStatusGauge = metrics_lib.GaugeVec(u64, struct { status: []const u8 });
    // Gossip message size histogram types
    const GossipBlockSizeBytesHistogram = metrics_lib.Histogram(f32, &[_]f32{ 10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000, 5_000_000 });
    const ZeamGossipDecodeFailuresCounter = metrics_lib.CounterVec(u64, struct { topic_kind: []const u8, reason: []const u8 });
    const GossipAttestationSizeBytesHistogram = metrics_lib.Histogram(f32, &[_]f32{ 512, 1_024, 2_048, 4_096, 8_192, 16_384 });
    const GossipAggregationSizeBytesHistogram = metrics_lib.Histogram(f32, &[_]f32{ 1_024, 4_096, 16_384, 65_536, 131_072, 262_144, 524_288, 1_048_576 });
    // Attestation production time histogram type
    const AttestationProductionTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1 });
    // compactAttestations metric types
    const CompactAttestationsTimeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5 });
    const TickIntervalDurationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6 });
    /// Buckets from sub-ms through multi-second xev drains observed under load.
    const XevClockUntilDoneDrainHistogram = metrics_lib.Histogram(f32, &[_]f32{
        0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60,
    });
    const ZeamXevClockUntilDoneSlowGe500msCounter = metrics_lib.Counter(u64);
    const ZeamXevClockUntilDoneSlowGe1sCounter = metrics_lib.Counter(u64);
    /// Per-callsite libxev callback duration. Buckets span
    /// 100us through 5s to capture both fast dispatches (queue submits,
    /// metric increments) and pathological CPU-bound callbacks
    /// (hashTreeRoot of a multi-MB block, SSZ clones of a STARK proof).
    const LibxevCallbackSiteLabel = struct { site: []const u8 };
    const LibxevCallbackDurationHistogram = metrics_lib.HistogramVec(
        f32,
        LibxevCallbackSiteLabel,
        &[_]f32{ 0.0001, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5 },
    );
    const ForkChoiceTickIntervalDurationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6 });
    /// Aggregation tick (interval-in-slot 2): spans sub-ms through multi-second stalls.
    const AggregationIntervalTickHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0 });
    const CompactAttestationsInputCounter = metrics_lib.Counter(u64);
    const CompactAttestationsOutputCounter = metrics_lib.Counter(u64);
    const BlockProposalAttestationBuildPhaseHistogram = metrics_lib.HistogramVec(f32, struct { phase: []const u8 }, &[_]f32{ 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8 });
    const BlockProposalAttestationBuildsTotalCounter = metrics_lib.Counter(u64);
    const BlockProposalChildPayloadsConsumedTotalCounter = metrics_lib.Counter(u64);
    const BlockProposalAttestationDataSelectedHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0, 1, 2, 4, 8, 16, 32 });
    const BlockProposalAggregatesSelectedHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0, 1, 2, 4, 8, 16, 32, 64, 128 });
    // Interval-aware proposer types.
    const ZeamProposalDeadlineHitsCounter = metrics_lib.Counter(u64);
    const ZeamProposalPartialPrefixSizeHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0, 1, 2, 4, 8, 16 });
    const ZeamProposalSkippedEmptyCounter = metrics_lib.Counter(u64);
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
    // Future-block queue visibility.
    const LeanPendingBlocksDepthGauge = metrics_lib.Gauge(u64);
    const LeanPendingBlocksEvictedCounter = metrics_lib.CounterVec(u64, struct { reason: []const u8 });
    const LeanPendingBlocksReplayedCounter = metrics_lib.CounterVec(u64, struct { result: []const u8 });
    const LeanBlocksFutureSlotDroppedCounter = metrics_lib.Counter(u64);
    const LeanBlockRootComputeSkippedCounter = metrics_lib.CounterVec(u64, struct { site: []const u8 });
    const LeanBlockFetchDedupCounter = metrics_lib.CounterVec(u64, struct { outcome: []const u8 });
    const ZeamBlocksByRangeSyncCounter = metrics_lib.CounterVec(u64, struct { outcome: []const u8 });
    // P2/P3 metric types.
    const ZeamGossipAttsDroppedCounter = metrics_lib.CounterVec(u64, struct { kind: []const u8, reason: []const u8 });
    const ZeamBlocksByRootInflightGauge = metrics_lib.Gauge(u64);
    const ZeamXevClockDrainPassesCounter = metrics_lib.Counter(u64);
    const LeanPendingAttsBufferedCounter = metrics_lib.CounterVec(u64, struct { kind: []const u8, reason: []const u8 });
    const LeanPendingAttsEvictedCounter = metrics_lib.CounterVec(u64, struct { kind: []const u8 });
    const LeanPendingAttsReplayCounter = metrics_lib.CounterVec(u64, struct { kind: []const u8, outcome: []const u8 });
    const LeanPendingAttsSizeGauge = metrics_lib.GaugeVec(u64, struct { kind: []const u8 });
    // See `lean_node_interval_error_total` field doc.
    const LeanNodeIntervalErrorCounter = metrics_lib.CounterVec(u64, struct { site: []const u8 });
    const AggregateSkipCounter = metrics_lib.CounterVec(u64, struct { reason: []const u8 });
    const AggregateCoalescedCounter = metrics_lib.Counter(u64);
    const AggregateWorkerDurationHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0 });
    const AggregatorPublishAggregationsCounter = metrics_lib.CounterVec(u64, struct { subnet: []const u8 });
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

fn observeChainOnblockNumAggregatedAttestations(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockAggregatedPayloadsHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeChainOnblockTotalParticipants(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockTotalParticipantsHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockAggregatedPayloads(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockAggregatedPayloadsHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeStfVerifySignaturesBatchSize(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.StfVerifySignaturesBatchSizeHistogram = @ptrCast(@alignCast(histogram_ptr));
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

fn observeBlockProposalAttestationDataSelected(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockProposalAttestationDataSelectedHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeBlockProposalAggregatesSelected(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.BlockProposalAggregatesSelectedHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeZeamProposalPartialPrefixSize(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ZeamProposalPartialPrefixSizeHistogram = @ptrCast(@alignCast(histogram_ptr));
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

fn observeXevClockUntilDoneDrain(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.XevClockUntilDoneDrainHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeForkChoiceTickIntervalDuration(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.ForkChoiceTickIntervalDurationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeAggregateWorkerDuration(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.AggregateWorkerDurationHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn onXmssRecAggregateProveHistogram(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.XmssRecAggregateProveHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

fn observeAggregationIntervalTick(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.AggregationIntervalTickHistogram = @ptrCast(@alignCast(histogram_ptr));
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
pub var zeam_chain_onblock_num_aggregated_attestations: Histogram = .{
    .context = null,
    .observe = &observeChainOnblockNumAggregatedAttestations,
};
pub var zeam_chain_onblock_total_participants: Histogram = .{
    .context = null,
    .observe = &observeChainOnblockTotalParticipants,
};
pub var zeam_stf_verify_signatures_batch_size: Histogram = .{
    .context = null,
    .observe = &observeStfVerifySignaturesBatchSize,
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
pub var lean_block_proposal_attestation_data_selected: Histogram = .{
    .context = null,
    .observe = &observeBlockProposalAttestationDataSelected,
};
pub var lean_block_proposal_aggregates_selected: Histogram = .{
    .context = null,
    .observe = &observeBlockProposalAggregatesSelected,
};
pub var zeam_proposal_partial_prefix_size: Histogram = .{
    .context = null,
    .observe = &observeZeamProposalPartialPrefixSize,
};
pub var lean_tick_interval_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeTickIntervalDuration,
};
pub var zeam_xev_clock_until_done_drain_seconds: Histogram = .{
    .context = null,
    .observe = &observeXevClockUntilDoneDrain,
};
pub var zeam_fork_choice_tick_interval_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeForkChoiceTickIntervalDuration,
};
pub var zeam_node_aggregation_interval_tick_seconds: Histogram = .{
    .context = null,
    .observe = &observeAggregationIntervalTick,
};
pub var zeam_aggregate_worker_duration_seconds: Histogram = .{
    .context = null,
    .observe = &observeAggregateWorkerDuration,
};
pub var zeam_xmss_rec_aggregate_prove_seconds: Histogram = .{
    .context = null,
    .observe = &onXmssRecAggregateProveHistogram,
};
pub var lean_pending_blocks_drain_iters: Histogram = .{
    .context = null,
    .observe = &observePendingBlocksDrainIters,
};

/// Initializes the metrics system. Must be called once at startup.
pub fn init(io: std.Io, allocator: std.mem.Allocator) !void {
    if (g_initialized) return;

    // For ZKVM targets, use no-op metrics
    if (isZKVM()) {
        std.log.info("Using no-op metrics for ZKVM target", .{});
        g_initialized = true;
        return;
    }

    metrics = .{
        .zeam_chain_onblock_duration_seconds = Metrics.ChainHistogram.init("zeam_chain_onblock_duration_seconds", .{ .help = "Time taken to process a block in the chain's onBlock function." }, .{}),
        .zeam_chain_onblock_step_duration_seconds = try Metrics.ChainOnblockStepHistogram.init(allocator, io, "zeam_chain_onblock_step_duration_seconds", .{ .help = "Per-substep wall-clock duration inside chain.onBlock, labeled by step. See #863 for context. Buckets match zeam_chain_onblock_duration_seconds for stack-aligned dashboarding." }, .{}),
        .zeam_stf_verify_signatures_stage_duration_seconds = try Metrics.StfVerifySignaturesStageHistogram.init(allocator, io, "zeam_stf_verify_signatures_stage_duration_seconds", .{ .help = "Per-stage wall-clock duration inside stf.verifySignaturesParallel, labeled by stage. Splits the step=\"verify_signatures\" cost recorded by zeam_chain_onblock_step_duration_seconds across phase1_prep / phase2_batch_verify / proposer_block_root / proposer_xmss_verify. Multi-block path adds _multiblock suffix to the same stages. See PR #963 / #964." }, .{}),
        .zeam_stf_verify_signatures_batch_size = Metrics.StfVerifySignaturesBatchSizeHistogram.init("zeam_stf_verify_signatures_batch_size", .{ .help = "Number of blocks coalesced into a single stf.verifySignaturesParallelMultiBlock call. K=1 means the single-block path was used; K>1 means the chain-worker batched the drain. Pair with zeam_stf_verify_signatures_stage_duration_seconds{stage=\"phase2_batch_verify_multiblock\"} to measure batching amortisation. See PR #964." }, .{}),
        .zeam_chain_onblock_num_aggregated_attestations = Metrics.BlockAggregatedPayloadsHistogram.init("zeam_chain_onblock_num_aggregated_attestations", .{ .help = "Number of aggregated_attestations in each block processed by chain.onBlock (block import). Pair with zeam_chain_onblock_step_duration_seconds{step=\"verify_signatures\"} to attribute slow-block timings to block heaviness vs per-block constant cost. See PR #963." }, .{}),
        .zeam_chain_onblock_total_participants = Metrics.BlockTotalParticipantsHistogram.init("zeam_chain_onblock_total_participants", .{ .help = "Sum of participants across all aggregated_attestations in each block processed by chain.onBlock. Companion to zeam_chain_onblock_num_aggregated_attestations: same block can have few aggregations but many total participants if the aggregator did its job. See PR #963." }, .{}),
        .zeam_slot_driver_stall_fired_total = Metrics.ZeamSlotDriverStallFiredCounter.init("zeam_slot_driver_stall_fired_total", .{ .help = "Total times the watchdog (#863) observed the libxev slot driver stalled past its threshold (default 5s). Each firing also records the stall duration in zeam_slot_driver_stall_seconds and emits an ERROR log." }, .{}),
        .zeam_slot_driver_stall_seconds = Metrics.ZeamSlotDriverStallSecondsHistogram.init("zeam_slot_driver_stall_seconds", .{ .help = "Distribution of slot-driver stall durations observed by the watchdog (#863). Stalls beyond ~1s indicate the libxev loop, libp2p Rust thread, or chain-worker held the main loop hostage; pair with zeam_chain_onblock_step_duration_seconds to attribute." }, .{}),
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
        .lean_pq_sig_aggregated_signatures_building_time_seconds = Metrics.PQSigBuildingTimeHistogram.init("lean_pq_sig_aggregated_signatures_building_time_seconds", .{ .help = "Per att_data wall time for AggregatedSignatureProof.aggregate (bitfield merge + xmss.aggregateSignatures, including leanMultisig STARK). For bare rec_xmss_aggregate prove time comparable to lean-bench, use zeam_xmss_rec_aggregate_prove_seconds." }, .{}),
        .zeam_pq_sig_aggregated_signatures_building_phase_seconds = try Metrics.PQSigBuildingPhaseHistogram.init(allocator, io, "zeam_pq_sig_aggregated_signatures_building_phase_seconds", .{ .help = "Phase-level time for aggregate production, labeled by phase (snapshot|att_data_prep|xmss_prove|compute_ffi|commit). See #899 / #907." }, .{}),
        .zeam_xmss_rec_aggregate_prove_seconds = Metrics.XmssRecAggregateProveHistogram.init("zeam_xmss_rec_aggregate_prove_seconds", .{ .help = "Wall time inside xmss_aggregate (leanMultisig rec_xmss_aggregate STARK prove + FFI key clones, one att_data). Compare to leanBench aggregate.flat_*_r2; worker/phase metrics add snapshot, prep, child-proof deserialize, and serialize." }, .{}),
        .zeam_xmss_rec_aggregate_prove_by_input_seconds = try Metrics.XmssRecAggregateProveByInputHistogram.init(allocator, io, "zeam_xmss_rec_aggregate_prove_by_input_seconds", .{ .help = "Same observation as zeam_xmss_rec_aggregate_prove_seconds, additionally labeled by num_raw (count of raw gossip XMSS signatures) and num_children (count of recursive child STARK proofs) input-size buckets (#940). Buckets: num_raw in {0,1,2,3,4,5,6,7,8,9-15,16-31,32+}; num_children in {0,1,2,3-4,5-7,8+}. Used to classify the aggregate build histogram tail (steady-state full-committee prove vs partial-input reprove)." }, .{}),
        .zeam_xmss_rec_aggregate_phase_seconds = try Metrics.XmssRecAggregatePhaseHistogram.init(allocator, io, "zeam_xmss_rec_aggregate_phase_seconds", .{ .help = "Per-phase wall time inside xmss_aggregate FFI (#940), reported back from Rust via out-pointers. phase=\"marshal\" covers argument deserialization (raw XMSS PK/sig clones + child PK collection + child proof deserialize). phase=\"stark\" is the leanMultisig rec_xmss_aggregate STARK call — expected to scale linearly with num_raw per lean-bench (~3.6 ms/sig at log_inv_rate=2 on Hetzner 16-core). phase=\"post\" is Box::into_raw of the returned aggregate (pointer wrap, typically nanoseconds). The three phases sum to ~zeam_xmss_rec_aggregate_prove_seconds." }, .{}),
        .lean_pq_sig_aggregated_signatures_verification_time_seconds = Metrics.PQSigAggregatedVerificationHistogram.init("lean_pq_sig_aggregated_signatures_verification_time_seconds", .{ .help = "Time taken to verify an aggregated attestation signature" }, .{}),
        .lean_pq_sig_aggregated_signatures_valid_total = Metrics.PQSigAggregatedValidCounter.init("lean_pq_sig_aggregated_signatures_valid_total", .{ .help = "Total number of valid aggregated signatures" }, .{}),
        .lean_pq_sig_aggregated_signatures_invalid_total = Metrics.PQSigAggregatedInvalidCounter.init("lean_pq_sig_aggregated_signatures_invalid_total", .{ .help = "Total number of invalid aggregated signatures" }, .{}),
        // Network peer metrics
        .lean_connected_peers = try Metrics.LeanConnectedPeersGauge.init(allocator, io, "lean_connected_peers", .{ .help = "Number of connected peers" }, .{}),
        .lean_peer_connection_events_total = try Metrics.PeerConnectionEventsCounter.init(allocator, io, "lean_peer_connection_events_total", .{ .help = "Total number of peer connection events" }, .{}),
        .lean_peer_disconnection_events_total = try Metrics.PeerDisconnectionEventsCounter.init(allocator, io, "lean_peer_disconnection_events_total", .{ .help = "Total number of peer disconnection events" }, .{}),
        .zeam_libp2p_swarm_command_dropped_total = try Metrics.LibP2pSwarmCommandDroppedCounter.init(allocator, io, "zeam_libp2p_swarm_command_dropped_total", .{ .help = "Total number of swarm commands dropped before reaching the rust-libp2p event loop, by reason (issue #808)" }, .{}),
        .lean_gossip_mesh_peers = Metrics.LeanGossipMeshPeersGauge.init("lean_gossip_mesh_peers", .{ .help = "Number of peers in the gossipsub mesh" }, .{}),
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
        .lean_attestation_aggregate_coverage_validators = try Metrics.AttestationAggregateCoverageValidatorsGauge.init(allocator, io, "lean_attestation_aggregate_coverage_validators", .{ .help = "Validator coverage in attestation aggregate reports, labeled by section and subnet. subnet=combined is the section total; subnet=subnet_N is per-subnet coverage. Updated each slot (slot is the X-axis)." }, .{}),
        .lean_attestation_aggregate_coverage_subnets = try Metrics.AttestationAggregateCoverageSubnetsGauge.init(allocator, io, "lean_attestation_aggregate_coverage_subnets", .{ .help = "Number of covered subnets in attestation aggregate reports, labeled by section. Updated each slot (slot is the X-axis)." }, .{}),
        .lean_attestation_aggregate_coverage_diff_validators = try Metrics.AttestationAggregateCoverageDiffValidatorsGauge.init(allocator, io, "lean_attestation_aggregate_coverage_diff_validators", .{ .help = "Validator coverage delta between block payloads and timely pre-merge payloads, labeled by direction (block_only|timely_only). Updated each slot (slot is the X-axis)." }, .{}),
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
        .zeam_gossip_decode_failures_total = try Metrics.ZeamGossipDecodeFailuresCounter.init(allocator, io, "zeam_gossip_decode_failures_total", .{ .help = "Gossip-ingress decode rejections, labeled by topic_kind (block|attestation|aggregation) and reason (snappy_empty|snappy_varint|snappy_oversized|snappy_truncated|snappy_decode|ssz_decode). Operator-visible signal that zeam has stopped accepting gossip BEFORE lean_head_slot drifts off wall-clock. See issue #942." }, .{}),
        .lean_attestations_production_time_seconds = Metrics.AttestationProductionTimeHistogram.init("lean_attestations_production_time_seconds", .{ .help = "Time taken to produce attestation" }, .{}),
        // compactAttestations metrics
        .zeam_compact_attestations_time_seconds = Metrics.CompactAttestationsTimeHistogram.init("zeam_compact_attestations_time_seconds", .{ .help = "Time taken by compactAttestations to merge payloads sharing the same AttestationData" }, .{}),
        .zeam_compact_attestations_input_total = Metrics.CompactAttestationsInputCounter.init("zeam_compact_attestations_input_total", .{ .help = "Total number of attestations input to compactAttestations" }, .{}),
        .zeam_compact_attestations_output_total = Metrics.CompactAttestationsOutputCounter.init("zeam_compact_attestations_output_total", .{ .help = "Total number of attestations output from compactAttestations after compaction" }, .{}),
        .lean_block_proposal_attestation_build_phase_seconds = try Metrics.BlockProposalAttestationBuildPhaseHistogram.init(allocator, io, "lean_block_proposal_attestation_build_phase_seconds", .{ .help = "Phase-level time in block-proposal attestation selection (build_block / getProposalAttestations): select_payloads, compact (recursive merge per AttestationData), stf_simulate." }, .{}),
        .lean_block_proposal_attestation_builds_total = Metrics.BlockProposalAttestationBuildsTotalCounter.init("lean_block_proposal_attestation_builds_total", .{ .help = "Completed block-proposal attestation selection runs (one per proposal attempt)." }, .{}),
        .lean_block_proposal_child_payloads_consumed_total = Metrics.BlockProposalChildPayloadsConsumedTotalCounter.init("lean_block_proposal_child_payloads_consumed_total", .{ .help = "Child aggregated payloads selected during greedy proof picking (before recursive compaction)." }, .{}),
        .lean_block_proposal_attestation_data_selected = Metrics.BlockProposalAttestationDataSelectedHistogram.init("lean_block_proposal_attestation_data_selected", .{ .help = "Distinct AttestationData entries in the proposal block body." }, .{}),
        .lean_block_proposal_aggregates_selected = Metrics.BlockProposalAggregatesSelectedHistogram.init("lean_block_proposal_aggregates_selected", .{ .help = "Aggregated signature proofs in the proposal result after compaction." }, .{}),
        .zeam_proposal_deadline_hits_total = Metrics.ZeamProposalDeadlineHitsCounter.init("zeam_proposal_deadline_hits_total", .{ .help = "Number of compactAttestations runs whose returned prefix was truncated because the caller-supplied deadline elapsed mid-loop." }, .{}),
        .zeam_proposal_partial_prefix_size = Metrics.ZeamProposalPartialPrefixSizeHistogram.init("zeam_proposal_partial_prefix_size", .{ .help = "Number of AttestationData groups fully committed by deadline-aware compactAttestations when the deadline truncated the loop." }, .{}),
        .zeam_proposal_skipped_empty_total = Metrics.ZeamProposalSkippedEmptyCounter.init("zeam_proposal_skipped_empty_total", .{ .help = "Number of interval-0 finalize calls that found no partial proposal body for the proposer's slot." }, .{}),
        .lean_tick_interval_duration_seconds = Metrics.TickIntervalDurationHistogram.init("lean_tick_interval_duration_seconds", .{ .help = "Elapsed time between clock ticks in seconds (nominal 0.8s = 4s slot / 5 intervals)" }, .{}),
        .zeam_xev_clock_until_done_drain_seconds = Metrics.XevClockUntilDoneDrainHistogram.init("zeam_xev_clock_until_done_drain_seconds", .{ .help = "Wall time in seconds for one xev run(.until_done) in the clock driver (issues #863, #867). Captures completion backlog before the next tickInterval()." }, .{}),
        .zeam_xev_clock_until_done_slow_ge_500ms_total = Metrics.ZeamXevClockUntilDoneSlowGe500msCounter.init("zeam_xev_clock_until_done_slow_ge_500ms_total", .{ .help = "Clock-loop xev run(.until_done) drains with wall time >= 0.5s (#863)." }, .{}),
        .zeam_xev_clock_until_done_slow_ge_1s_total = Metrics.ZeamXevClockUntilDoneSlowGe1sCounter.init("zeam_xev_clock_until_done_slow_ge_1s_total", .{ .help = "Clock-loop xev run(.until_done) drains with wall time >= 1s (#863)." }, .{}),
        .zeam_libxev_callback_duration_seconds = try Metrics.LibxevCallbackDurationHistogram.init(allocator, io, "zeam_libxev_callback_duration_seconds", .{ .help = "Wall-clock time spent inside individual libxev callbacks, labeled by site (issue #942). Tracks synchronous CPU work blocking the libxev thread between drain passes. Compare against zeam_xev_clock_until_done_drain_seconds and the slow_ge_*ms counters to attribute slow drains to a specific callsite. Sites include onGossip.block.hash_tree_root, onGossip.block.ssz_clone, onGossip.aggregation.ssz_clone, onGossip.attestation.dispatch, onInterval.tick, chain.onGossip.dispatch." }, .{}),
        .zeam_fork_choice_tick_interval_duration_seconds = Metrics.ForkChoiceTickIntervalDurationHistogram.init("zeam_fork_choice_tick_interval_duration_seconds", .{ .help = "Elapsed time between forkchoice tick calls in seconds (nominal 0.8s = 4s slot / 5 intervals)" }, .{}),
        .zeam_node_aggregation_interval_tick_seconds = Metrics.AggregationIntervalTickHistogram.init("zeam_node_aggregation_interval_tick_seconds", .{ .help = "Wall time for BeamNode at per-slot interval 2: maybeAggregateOnInterval plus publishProducedAggregations (includes null/skip/error paths)." }, .{}),
        .lean_aggregator_skipped_total = try Metrics.AggregateSkipCounter.init(allocator, io, "lean_aggregator_skipped_total", .{ .help = "Number of aggregate submissions skipped, labeled by reason: not_aggregator, not_synced, missing_state, spawn_failed, other. In-flight triggers are coalesced (see zeam_aggregate_coalesced_total)." }, .{}),
        .zeam_aggregate_coalesced_total = Metrics.AggregateCoalescedCounter.init("zeam_aggregate_coalesced_total", .{ .help = "Aggregation slot triggers coalesced while a worker was in flight; one catch-up run is scheduled when the worker finishes." }, .{}),
        .zeam_aggregate_worker_duration_seconds = Metrics.AggregateWorkerDurationHistogram.init("zeam_aggregate_worker_duration_seconds", .{ .help = "Wall-clock duration of one aggregate worker run (snapshot through publishProducedAggregations), including all XMSS recursive STARK FFI inside computeAggregatedSignatures. Primary latency signal for aggregator slot budget (issue #907)." }, .{}),
        .zeam_aggregator_publish_aggregations_total = try Metrics.AggregatorPublishAggregationsCounter.init(allocator, io, "zeam_aggregator_publish_aggregations_total", .{ .help = "SignedAggregatedAttestation messages published by the local aggregator worker, labeled by attestation subnet. Distinct from lean_pq_sig_aggregated_signatures_total (block-proposal path only) so cross-client dashboards keep the standard metric's semantics intact." }, .{}),
        // BeamNode mutex contention metrics.
        .zeam_node_mutex_wait_time_seconds = try Metrics.NodeMutexWaitTimeHistogram.init(allocator, io, "zeam_node_mutex_wait_time_seconds", .{ .help = "Time spent waiting to acquire BeamNode.mutex, labeled by callsite (LEGACY — double-emitted from per-resource locks; will be removed after one release)." }, .{}),
        .zeam_node_mutex_hold_time_seconds = try Metrics.NodeMutexHoldTimeHistogram.init(allocator, io, "zeam_node_mutex_hold_time_seconds", .{ .help = "Time BeamNode.mutex was held, labeled by callsite (LEGACY — double-emitted from per-resource locks; will be removed after one release)." }, .{}),
        // Per-resource lock contention metrics.
        .zeam_lock_wait_seconds = try Metrics.LockWaitTimeHistogram.init(allocator, io, "zeam_lock_wait_seconds", .{ .help = "Time spent waiting to acquire a per-resource lock, labeled by lock and callsite." }, .{}),
        .zeam_lock_hold_seconds = try Metrics.LockHoldTimeHistogram.init(allocator, io, "zeam_lock_hold_seconds", .{ .help = "Time a per-resource lock was held, labeled by lock and callsite." }, .{}),
        .lean_pending_blocks_drain_iters = Metrics.PendingBlocksDrainItersHistogram.init("lean_pending_blocks_drain_iters", .{ .help = "Number of iterations chain.processPendingBlocks ran through before draining the queue or finding nothing ready." }, .{}),
        .lean_pending_blocks_depth = Metrics.LeanPendingBlocksDepthGauge.init("lean_pending_blocks_depth", .{ .help = "Instantaneous depth of the future-block pending queue (issue #788)." }, .{}),
        .lean_pending_blocks_evicted_total = try Metrics.LeanPendingBlocksEvictedCounter.init(allocator, io, "lean_pending_blocks_evicted_total", .{ .help = "Total number of blocks evicted from the pending-blocks queue, by reason (issue #788)." }, .{}),
        .lean_pending_blocks_replayed_total = try Metrics.LeanPendingBlocksReplayedCounter.init(allocator, io, "lean_pending_blocks_replayed_total", .{ .help = "Total number of replays from pending_blocks, by terminal result (issue #788)." }, .{}),
        .lean_blocks_future_slot_dropped_total = Metrics.LeanBlocksFutureSlotDroppedCounter.init("lean_blocks_future_slot_dropped_total", .{ .help = "Total number of gossip blocks hard-rejected as FutureSlot beyond the queueable window (issue #788)." }, .{}),
        // Chain-worker queue + loop metrics.
        .lean_chain_queue_dropped_total = try Metrics.LeanChainQueueDroppedCounter.init(allocator, io, "lean_chain_queue_dropped_total", .{ .help = "Producer trySend rejections on the chain-worker queues, labeled by queue (block|attestation|aggregated_attestation|replay_pending). The `replay_pending` label is a single nudge that drains the in-process pending-attestation buffers — buffer depth itself is exposed via `lean_pending_attestations_size{kind}`." }, .{}),
        .lean_chain_queue_depth = try Metrics.LeanChainQueueDepthGauge.init(allocator, io, "lean_chain_queue_depth", .{ .help = "Outstanding chain-worker messages accepted by producers but not yet fully processed or explicitly discarded during shutdown, labeled by queue (block|attestation|aggregated_attestation)." }, .{}),
        .lean_chain_worker_loop_iters_total = Metrics.LeanChainWorkerLoopItersCounter.init("lean_chain_worker_loop_iters_total", .{ .help = "Cumulative chain-worker loop iterations. External watchdogs use the delta between scrapes to detect worker stalls." }, .{}),
        .zeam_chain_worker_block_dispatch_total = try Metrics.ZeamChainWorkerBlockDispatchCounter.init(allocator, io, "zeam_chain_worker_block_dispatch_total", .{ .help = "Chain-worker block-dispatch path counter. path=\"single\" counts `.on_block` dispatches via the unbatched code path (block queue depth ≤ BLOCK_BATCH_THRESHOLD); path=\"batch\" counts `.on_blocks_batch` dispatches (one per batched call, K blocks each). Combine with zeam_stf_verify_signatures_batch_size_count to recover total blocks taken via the batched path. See PR #966." }, .{}),
        .zeam_chain_invalid_block_root_marked_total = Metrics.ZeamChainInvalidBlockRootMarkedCounter.init("zeam_chain_invalid_block_root_marked_total", .{ .help = "Block roots inserted into the chain's invalid-block-roots cache after a deterministic-failure verify verdict (signature deserialize/verify fail, structural mismatch, proposer-sig fail). De-duped per root. Slot=13 #942 follow-up." }, .{}),
        .zeam_chain_invalid_block_root_hit_total = try Metrics.ZeamChainInvalidBlockRootHitCounter.init(allocator, io, "zeam_chain_invalid_block_root_hit_total", .{ .help = "Early-drops at chain.onBlock's invalid-block-roots guard. site=\"self\" when the block's own root was already cached; site=\"parent\" when the cascade fires on a known-invalid parent_root. High rate signals an orphan-dependents refetch storm against a known-bad root." }, .{}),
        .lean_chain_worker_process_pending_blocks_dropped_missing_roots_total = Metrics.LeanChainWorkerProcessPendingBlocksDroppedMissingRootsCounter.init("lean_chain_worker_process_pending_blocks_dropped_missing_roots_total", .{ .help = "Tripwire (#890): non-zero only if a future worker producer dispatches `process_pending_blocks` without wiring the missing-roots backchannel. MUST stay 0 in steady state." }, .{}),
        .lean_chain_state_refcount_distribution = Metrics.LeanChainStateRefcountDistributionHistogram.init("lean_chain_state_refcount_distribution", .{ .help = "Distribution of refcount values across map-resident BeamState entries at scrape time. Typical value 1 (writer-only); transient 2-4 under reader concurrency; values >16 indicate leaked acquires." }, .{}),
        // See field doc for label semantics.
        .lean_block_root_compute_skipped_total = try Metrics.LeanBlockRootComputeSkippedCounter.init(allocator, io, "lean_block_root_compute_skipped_total", .{ .help = "Total number of times a downstream consumer skipped a `hashTreeRoot(BeamBlock)` because the producer threaded a precomputed root through (slice (e) of #803). Labeled by skip site." }, .{}),
        .lean_block_fetch_dedup_total = try Metrics.LeanBlockFetchDedupCounter.init(allocator, io, "lean_block_fetch_dedup_total", .{ .help = "Total number of `fetchBlockByRoots` per-root outcomes (slice (d) of #803). Labeled by outcome: already_in_forkchoice, already_in_block_cache, already_pending, fetched, fetch_no_peers, fetch_failed, dedup_lost_race, inflight_cap." }, .{}),
        .zeam_blocks_by_range_sync_total = try Metrics.ZeamBlocksByRangeSyncCounter.init(allocator, io, "zeam_blocks_by_range_sync_total", .{ .help = "Total number of `blocks_by_range` catch-up request outcomes (issue #893). zeam-specific. Labeled by outcome: success, retry, exhausted, abort, timeout, pre_finalized_noop." }, .{}),
        // P2/P3/P4 — see field doc for label semantics.
        .zeam_gossip_atts_dropped_total = try Metrics.ZeamGossipAttsDroppedCounter.init(allocator, io, "zeam_gossip_atts_dropped_total", .{ .help = "Total number of gossip attestations/aggregations dropped on the libxev main thread before chain-worker dispatch. Labeled by kind={attestation,aggregation} and reason={syncing,future_slot,worker_validation_failed}. zeam-specific. See blockblaz/zeam#863." }, .{}),
        .zeam_blocks_by_root_inflight = Metrics.ZeamBlocksByRootInflightGauge.init("zeam_blocks_by_root_inflight", .{ .help = "Instantaneous count of outbound `BlocksByRoot` RPCs that have been dispatched but not yet finalized via `finalizePendingRequest`. Capped at MAX_CONCURRENT_BLOCKS_BY_ROOT (8) to bound per-flood dispatch fan-out. zeam-specific. See blockblaz/zeam#863." }, .{}),
        .zeam_xev_clock_drain_passes_total = Metrics.ZeamXevClockDrainPassesCounter.init("zeam_xev_clock_drain_passes_total", .{ .help = "Cumulative passes through `Clock.run`'s libxev drain (one io_uring CQE batch per pass via `events.run(.once)`). Compare scrape deltas against the expected ~1.25 Hz at 4s slots / 5 intervals to detect slot-driver wedges independent of `lean_tick_interval_duration_seconds`. See blockblaz/zeam#863." }, .{}),
        .lean_pending_attestations_buffered_total = try Metrics.LeanPendingAttsBufferedCounter.init(allocator, io, "lean_pending_attestations_buffered_total", .{ .help = "Gossip attestations / aggregations buffered for replay after a future onBlock import. Mirrors leanSpec subspecs/sync/service.py::_pending_attestations buffer push. Labeled by kind={attestation,aggregation} and reason={unknown_block,future_slot,queue_full}." }, .{}),
        .lean_pending_attestations_evicted_total = try Metrics.LeanPendingAttsEvictedCounter.init(allocator, io, "lean_pending_attestations_evicted_total", .{ .help = "Pending-attestation buffer FIFO evictions when MAX_PENDING_ATTESTATIONS (1024, leanSpec subspecs/sync/config.py) is reached. Labeled by kind={attestation,aggregation}." }, .{}),
        .lean_pending_attestations_replay_total = try Metrics.LeanPendingAttsReplayCounter.init(allocator, io, "lean_pending_attestations_replay_total", .{ .help = "Outcomes of replayPendingAttestations attempts (mirrors leanSpec _replay_pending_attestations). Labeled by kind={attestation,aggregation} and outcome={accepted,buffered,dropped}." }, .{}),
        .lean_pending_attestations_size = try Metrics.LeanPendingAttsSizeGauge.init(allocator, io, "lean_pending_attestations_size", .{ .help = "Instantaneous pending-attestation buffer depth, labeled by kind={attestation,aggregation}. Bounded by MAX_PENDING_ATTESTATIONS (1024)." }, .{}),
        .lean_node_interval_error_total = try Metrics.LeanNodeIntervalErrorCounter.init(allocator, io, "lean_node_interval_error_total", .{ .help = "Total number of application-layer failures inside `BeamNode.onInterval` that were logged-and-continued (issue #837). Sustained non-zero rate per site means 'node alive, validator/aggregator silently failing' — ALERT ON THIS, the slot/interval cursor itself no longer wedges. Labeled by site: chain.onInterval, chain.runPeriodicPruning, validator.onInterval, publishBlock, publishAttestation, publishAggregation, publishLocalProducedAggregation, maybeAggregateOnInterval, publishProducedAggregations." }, .{}),
    };
    metrics.zeam_blocks_by_root_inflight.set(0);
    metrics.lean_pending_attestations_size.set(.{ .kind = "attestation" }, 0) catch {};
    metrics.lean_pending_attestations_size.set(.{ .kind = "aggregation" }, 0) catch {};

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
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "timely", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "late", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "block", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "combined", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "agg_start_new", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "proposal_payloads", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "proposal_gossip", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "proposal_combined", .subnet = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "timely" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "late" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "block" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "agg_start_new" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "proposal_payloads" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "proposal_gossip" }, 0);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "proposal_combined" }, 0);
    try metrics.lean_attestation_aggregate_coverage_diff_validators.set(.{ .direction = "block_only" }, 0);
    try metrics.lean_attestation_aggregate_coverage_diff_validators.set(.{ .direction = "timely_only" }, 0);

    // Set context for histogram wrappers (observe functions already assigned at compile time)
    zeam_chain_onblock_duration_seconds.context = @ptrCast(&metrics.zeam_chain_onblock_duration_seconds);
    zeam_chain_onblock_num_aggregated_attestations.context = @ptrCast(&metrics.zeam_chain_onblock_num_aggregated_attestations);
    zeam_chain_onblock_total_participants.context = @ptrCast(&metrics.zeam_chain_onblock_total_participants);
    zeam_stf_verify_signatures_batch_size.context = @ptrCast(&metrics.zeam_stf_verify_signatures_batch_size);
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
    lean_block_proposal_attestation_data_selected.context = @ptrCast(&metrics.lean_block_proposal_attestation_data_selected);
    lean_block_proposal_aggregates_selected.context = @ptrCast(&metrics.lean_block_proposal_aggregates_selected);
    zeam_proposal_partial_prefix_size.context = @ptrCast(&metrics.zeam_proposal_partial_prefix_size);
    lean_tick_interval_duration_seconds.context = @ptrCast(&metrics.lean_tick_interval_duration_seconds);
    zeam_xev_clock_until_done_drain_seconds.context = @ptrCast(&metrics.zeam_xev_clock_until_done_drain_seconds);
    zeam_fork_choice_tick_interval_duration_seconds.context = @ptrCast(&metrics.zeam_fork_choice_tick_interval_duration_seconds);
    zeam_node_aggregation_interval_tick_seconds.context = @ptrCast(&metrics.zeam_node_aggregation_interval_tick_seconds);
    zeam_aggregate_worker_duration_seconds.context = @ptrCast(&metrics.zeam_aggregate_worker_duration_seconds);
    zeam_xmss_rec_aggregate_prove_seconds.context = @ptrCast(&metrics.zeam_xmss_rec_aggregate_prove_seconds);
    lean_pending_blocks_drain_iters.context = @ptrCast(&metrics.lean_pending_blocks_drain_iters);
    // Initialize sync status to idle at startup
    try metrics.lean_node_sync_status.set(.{ .status = "idle" }, 1);
    try metrics.lean_node_sync_status.set(.{ .status = "syncing" }, 0);
    try metrics.lean_node_sync_status.set(.{ .status = "synced" }, 0);

    g_initialized = true;
}

/// Pre-scrape refresher registry. Modules that own state outside the
/// `Metrics` struct (e.g. a Rust-side atomic counter accessed via FFI, or
/// a `*BeamChain` whose in-memory map needs to be sampled) can register
/// callbacks here; every registered callback is invoked on every
/// `writeMetrics` so counter/gauge values reflect the latest source of
/// truth at scrape time.
///
/// Two callback shapes are supported:
///   * `void → void` — for FFI-backed atomic counters that need no
///     context (libp2p swarm command drops, `lean_gossip_mesh_peers`).
///   * `*anyopaque → void` — for callers that need to thread a pointer
///     back to themselves rather than coerce state into a global
///     (`lean_chain_state_refcount_distribution`,
///     where the observer iterates a `*BeamChain` states map under its
///     shared lock).
///
/// Each kind is stored in its own bounded list. Both lists are appended
/// to in registration order; on every scrape the void-list runs first,
/// then the ctx-list, preserving the original `g_scrape_refresher` →
/// `g_scrape_refresher_ctx` ordering so any caller that relies on it
/// (e.g. the FFI counters being refreshed before a context-bearing
/// observer reads from them) keeps working.
///
/// The list is bounded (no allocator dependency: this module is used
/// from ZKVM targets where allocators are constrained, and the registry
/// is touched at startup only). `MAX_SCRAPE_REFRESHERS` is sized
/// generously vs. the current ~2 callsites; if a future contributor
/// needs more, raise the constant rather than adding a parallel slot.
/// Raised 16 → 32 to accommodate the growing node-test suite (each
/// `BeamNode.init` registers a chain-state refcount refresher and the
/// registry is process-global, so every additional node test consumes a
/// slot for the test-binary lifetime).
const MAX_SCRAPE_REFRESHERS: usize = 32;

var g_scrape_refreshers: [MAX_SCRAPE_REFRESHERS]*const fn () void = undefined;
var g_scrape_refreshers_len: usize = 0;

const CtxRefresher = struct {
    refresher: *const fn (?*anyopaque) void,
    ctx: ?*anyopaque,
};
var g_scrape_refreshers_ctx: [MAX_SCRAPE_REFRESHERS]CtxRefresher = undefined;
var g_scrape_refreshers_ctx_len: usize = 0;

/// Append a void-context scrape refresher. Safe to call before `init()`;
/// the registration sticks regardless of init order. Passing `null` is a
/// no-op (kept for API symmetry with prior behaviour where `null` cleared
/// the single slot — the registry is now append-only and individual
/// callbacks cannot be removed at runtime, which mirrors the actual usage
/// pattern: every caller is a process-lifetime singleton). Panics if more
/// than `MAX_SCRAPE_REFRESHERS` callbacks are registered, which would
/// indicate a bug (callers re-registering on every scrape) rather than
/// legitimate growth.
pub fn registerScrapeRefresher(refresher: ?*const fn () void) void {
    const cb = refresher orelse return;
    if (g_scrape_refreshers_len >= MAX_SCRAPE_REFRESHERS) {
        std.debug.panic(
            "registerScrapeRefresher: too many callbacks (limit={d})",
            .{MAX_SCRAPE_REFRESHERS},
        );
    }
    g_scrape_refreshers[g_scrape_refreshers_len] = cb;
    g_scrape_refreshers_len += 1;
}

/// Append a context-bearing scrape refresher. Passing `null` for
/// `refresher` is a no-op (see `registerScrapeRefresher` for the
/// rationale). Panics on overflow for the same reason.
pub fn registerScrapeRefresherCtx(
    ctx: ?*anyopaque,
    refresher: ?*const fn (?*anyopaque) void,
) void {
    const cb = refresher orelse return;
    if (g_scrape_refreshers_ctx_len >= MAX_SCRAPE_REFRESHERS) {
        std.debug.panic(
            "registerScrapeRefresherCtx: too many callbacks (limit={d})",
            .{MAX_SCRAPE_REFRESHERS},
        );
    }
    g_scrape_refreshers_ctx[g_scrape_refreshers_ctx_len] = .{
        .refresher = cb,
        .ctx = ctx,
    };
    g_scrape_refreshers_ctx_len += 1;
}

/// Test-only: drop every registered scrape refresher so unit tests can
/// exercise `writeMetrics` against a known-empty registry. NOT exposed
/// outside test code paths in production callers.
pub fn resetScrapeRefreshersForTest() void {
    g_scrape_refreshers_len = 0;
    g_scrape_refreshers_ctx_len = 0;
}

/// Writes metrics to a writer (for Prometheus endpoint).
pub fn writeMetrics(writer: *std.Io.Writer) !void {
    if (!g_initialized) return error.NotInitialized;

    // For ZKVM targets, write no metrics
    if (isZKVM()) {
        try writer.writeAll("# Metrics disabled for ZKVM target\n");
        return;
    }

    // Pull in any externally-owned counters (e.g. Rust-side libp2p drops,
    // gossipsub mesh peers, BeamChain refcount distribution) before
    // serializing so each scrape returns up-to-date values. Void-context
    // refreshers run first, then context-bearing ones, preserving the
    // legacy ordering between FFI-backed atomic refreshes and
    // context-bearing observers that may read from them.
    var i: usize = 0;
    while (i < g_scrape_refreshers_len) : (i += 1) {
        g_scrape_refreshers[i]();
    }
    i = 0;
    while (i < g_scrape_refreshers_ctx_len) : (i += 1) {
        const entry = g_scrape_refreshers_ctx[i];
        entry.refresher(entry.ctx);
    }

    try metrics_lib.write(&metrics, writer);
}

/// Record wall-clock time spent inside one libxev callback.
/// `site` must be a fixed compile-time string from the canonical list
/// documented on `zeam_libxev_callback_duration_seconds` — runtime-built
/// strings would inflate the Prometheus series cardinality.
pub fn observeLibxevCallback(site: []const u8, elapsed_seconds: f32) void {
    if (!g_initialized or isZKVM()) return;
    metrics.zeam_libxev_callback_duration_seconds.observe(
        .{ .site = site },
        elapsed_seconds,
    ) catch {};
}

/// Record a sub-phase of aggregate attestation production (see
/// `zeam_pq_sig_aggregated_signatures_building_phase_seconds`).
pub fn observeAggregateAttestationBuildPhase(phase: []const u8, elapsed_seconds: f32) void {
    if (!g_initialized or isZKVM()) return;
    metrics.zeam_pq_sig_aggregated_signatures_building_phase_seconds.observe(
        .{ .phase = phase },
        elapsed_seconds,
    ) catch {};
}

/// Record `rec_xmss_aggregate` wall time for one att_data
/// (xmss_aggregate FFI). `num_raw` is the count of raw gossip XMSS signatures
/// fed to this prove; `num_children` is the count of recursive child STARK
/// proofs included. Both flow into the labeled
/// `zeam_xmss_rec_aggregate_prove_by_input_seconds` companion via
/// low-cardinality bucket strings.
pub fn observeXmssRecAggregateProve(elapsed_seconds: f32, num_raw: usize, num_children: usize) void {
    if (!g_initialized or isZKVM()) return;
    metrics.zeam_xmss_rec_aggregate_prove_seconds.observe(elapsed_seconds);
    observeAggregateAttestationBuildPhase("xmss_prove", elapsed_seconds);
    metrics.zeam_xmss_rec_aggregate_prove_by_input_seconds.observe(
        .{ .num_raw = numRawBucket(num_raw), .num_children = numChildrenBucket(num_children) },
        elapsed_seconds,
    ) catch {};
}

/// Coarse low-cardinality bucket for the `num_raw` label on
/// `zeam_xmss_rec_aggregate_prove_by_input_seconds`. Current
/// committees are 8-validator so values 0..8 stay distinct; larger committees
/// roll into wider buckets to bound Prometheus series cardinality.
fn numRawBucket(n: usize) []const u8 {
    return switch (n) {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        4 => "4",
        5 => "5",
        6 => "6",
        7 => "7",
        8 => "8",
        9, 10, 11, 12, 13, 14, 15 => "9-15",
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 => "16-31",
        else => "32+",
    };
}

/// Record one phase of `xmss_aggregate`'s internal timing breakdown
/// (`zeam_xmss_rec_aggregate_phase_seconds`). `phase` must be one of the
/// constants documented on the metric (currently "marshal", "stark", "post");
/// callers are the xmss aggregation module on a successful prove only.
/// `elapsed_ns` is the value the Rust FFI wrote into its out-pointer.
pub fn observeXmssRecAggregatePhase(phase: []const u8, elapsed_ns: u64) void {
    if (!g_initialized or isZKVM()) return;
    const elapsed_s = @as(f32, @floatFromInt(elapsed_ns)) / @as(f32, @floatFromInt(std.time.ns_per_s));
    metrics.zeam_xmss_rec_aggregate_phase_seconds.observe(
        .{ .phase = phase },
        elapsed_s,
    ) catch {};
}

/// Record one gossip-ingress decode rejection. `topic_kind` must
/// be one of "block" | "attestation" | "aggregation"; `reason` is one of
/// "snappy_empty" | "snappy_varint" | "snappy_oversized" | "snappy_truncated"
/// | "snappy_decode" | "ssz_decode" — see the metric help text on
/// `zeam_gossip_decode_failures_total` for the full enumeration.
///
/// Safe to call from FFI / network callback contexts: no allocation, label
/// keys are interned by the registry. Silently no-ops before
/// `metrics.init()` so test runs that haven't started the registry don't
/// crash. Cardinality bound: 3 topic_kinds × 6 reasons = 18 series.
pub fn incrGossipDecodeFailure(topic_kind: []const u8, reason: []const u8) void {
    if (!g_initialized or isZKVM()) return;
    metrics.zeam_gossip_decode_failures_total.incr(
        .{ .topic_kind = topic_kind, .reason = reason },
    ) catch {};
}

/// Coarse low-cardinality bucket for the `num_children` label on
/// `zeam_xmss_rec_aggregate_prove_by_input_seconds`. `num_children=0` is the
/// only value seen on flat aggregation today; other buckets exist for
/// the recursive path.
fn numChildrenBucket(n: usize) []const u8 {
    return switch (n) {
        0 => "0",
        1 => "1",
        2 => "2",
        3, 4 => "3-4",
        5, 6, 7 => "5-7",
        else => "8+",
    };
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

const testing = std.testing;

// Lock the gauge↑scrape contract for
// `lean_gossip_mesh_peers` in code so a future contributor cannot drop
// the gauge from the `Metrics` struct, rename it, or break the
// `writeMetrics` serializer without a CI failure here. The lesson from
// the LockTimer → /metrics output test and the
// `lean_chain_state_refcount_distribution` audit was that
// doc-only audits regress silently — every Prometheus-exposed metric
// earns a 20-line scrape test.
//
// We cannot exercise the FFI side (`get_mesh_peers_total →
// refreshMeshPeersMetric → gauge`) without a real swarm, but the path
// from `gauge.set(N)` through the serializer to the Prometheus body is
// the only place where a future struct-level change would silently
// break the contract. That path is what we cover here.
test "lean_gossip_mesh_peers gauge appears in scrape output" {
    if (isZKVM()) return;

    // The metrics globals (`metrics`, `g_initialized`, the refresher
    // arrays) are process-wide and may have been initialized by an
    // earlier test in this binary. `init` is idempotent (it bails on
    // `g_initialized`); explicitly call it here so this test can run
    // standalone too.
    //
    // Use the page allocator (rather than `testing.allocator`) for the
    // same reason `pkgs/node/src/locking.zig`'s LockTimer test does:
    // the labelled metrics under `metrics` allocate buckets/maps that
    // outlive any single test, and freeing them through a per-test
    // allocator after teardown trips the DebugAllocator. The metrics
    // module is a process-lifetime singleton; tracking its footprint
    // through `testing.allocator` is not the contract we want to assert.
    try init(std.heap.page_allocator);

    // Set a recognisable, non-default value so we can grep for it in
    // the scrape body. Pick something that's unlikely to collide with
    // any other gauge value in the same scrape.
    const expected: u64 = 4242;
    metrics.lean_gossip_mesh_peers.set(expected);

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    // The metric name itself must appear (TYPE / HELP lines plus the
    // value line itself).
    try testing.expect(
        std.mem.indexOf(u8, body, "lean_gossip_mesh_peers") != null,
    );

    // And the value line `lean_gossip_mesh_peers <expected>` (with the
    // surrounding whitespace expected from Prometheus exposition
    // format) must be present — this is what locks the gauge↑scrape
    // contract: the value we set really did make it through
    // `writeMetrics`.
    var expected_line_buf: [128]u8 = undefined;
    const expected_line = std.fmt.bufPrint(
        &expected_line_buf,
        "lean_gossip_mesh_peers {d}",
        .{expected},
    ) catch unreachable;
    try testing.expect(
        std.mem.indexOf(u8, body, expected_line) != null,
    );
}

// Lock the append-only behaviour of the scrape-refresher registry: a
// previous design stored a single callback per kind, and registering a
// second callback silently overwrote the first. The metrics module now
// keeps a bounded list (`MAX_SCRAPE_REFRESHERS`); this test guards the
// list semantics in code so a future contributor cannot regress to a
// single-slot design without CI failing.
test "registerScrapeRefresher fans out to all registered callbacks" {
    if (isZKVM()) return;

    try init(std.heap.page_allocator);

    // Snapshot + reset the registry for this test, then restore the
    // production callbacks afterwards so we don't perturb other tests
    // running in the same binary.
    const saved_void_len = g_scrape_refreshers_len;
    const saved_ctx_len = g_scrape_refreshers_ctx_len;
    var saved_void: [MAX_SCRAPE_REFRESHERS]*const fn () void = undefined;
    var saved_ctx: [MAX_SCRAPE_REFRESHERS]CtxRefresher = undefined;
    @memcpy(saved_void[0..saved_void_len], g_scrape_refreshers[0..saved_void_len]);
    @memcpy(saved_ctx[0..saved_ctx_len], g_scrape_refreshers_ctx[0..saved_ctx_len]);
    defer {
        g_scrape_refreshers_len = saved_void_len;
        g_scrape_refreshers_ctx_len = saved_ctx_len;
        @memcpy(g_scrape_refreshers[0..saved_void_len], saved_void[0..saved_void_len]);
        @memcpy(g_scrape_refreshers_ctx[0..saved_ctx_len], saved_ctx[0..saved_ctx_len]);
    }

    resetScrapeRefreshersForTest();

    const Hits = struct {
        var first: u32 = 0;
        var second: u32 = 0;
        var ctx_first: u32 = 0;
        var ctx_second: u32 = 0;
        var ctx_value: u64 = 0;

        fn firstCb() void {
            first += 1;
        }
        fn secondCb() void {
            second += 1;
        }
        fn ctxFirstCb(p: ?*anyopaque) void {
            ctx_first += 1;
            if (p) |raw| {
                const slot: *u64 = @ptrCast(@alignCast(raw));
                ctx_value = slot.*;
            }
        }
        fn ctxSecondCb(_: ?*anyopaque) void {
            ctx_second += 1;
        }
    };

    Hits.first = 0;
    Hits.second = 0;
    Hits.ctx_first = 0;
    Hits.ctx_second = 0;
    Hits.ctx_value = 0;

    var ctx_payload: u64 = 7;

    registerScrapeRefresher(Hits.firstCb);
    registerScrapeRefresher(Hits.secondCb);
    registerScrapeRefresherCtx(@ptrCast(&ctx_payload), Hits.ctxFirstCb);
    registerScrapeRefresherCtx(null, Hits.ctxSecondCb);

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);

    // Both void-context callbacks fired exactly once — single-slot
    // overwrite would have left `first == 0`.
    try testing.expectEqual(@as(u32, 1), Hits.first);
    try testing.expectEqual(@as(u32, 1), Hits.second);
    // Both context-bearing callbacks fired exactly once.
    try testing.expectEqual(@as(u32, 1), Hits.ctx_first);
    try testing.expectEqual(@as(u32, 1), Hits.ctx_second);
    // The opaque pointer was threaded through to the callback.
    try testing.expectEqual(@as(u64, 7), Hits.ctx_value);

    // Calling writeMetrics again invokes them again, proving the
    // refreshers run on every scrape (not just first scrape).
    var alloc_writer2 = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer2.deinit();
    try writeMetrics(&alloc_writer2.writer);
    try testing.expectEqual(@as(u32, 2), Hits.first);
    try testing.expectEqual(@as(u32, 2), Hits.second);
    try testing.expectEqual(@as(u32, 2), Hits.ctx_first);
    try testing.expectEqual(@as(u32, 2), Hits.ctx_second);
}

// Lock the metrics scrape contract for the per-fetch dedup
// counters and the per-site root-compute-skipped counters
// in code, so a label rename / family drop / serializer regression
// fails CI here, not silently in production. Mirrors the
// LockTimer audit pattern and the future-block-queue
// metric audit.
test "slice (d)/(e) #803: fetch-dedup + root-compute-skipped counters appear in /metrics output" {
    if (isZKVM()) return;

    try init(std.heap.page_allocator);

    // Bump every label the production code emits. `incr` / `incrBy`
    // failures are swallowed to mirror production usage (the chain /
    // node code uses `catch {}` on every metric write).

    // lean_block_root_compute_skipped_total{site}.
    metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "chain.onGossip" }) catch {};
    metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "chain.onBlock" }) catch {};
    metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "chain.processPendingBlocks" }) catch {};
    metrics.lean_block_root_compute_skipped_total.incr(.{ .site = "forkchoice.onBlock" }) catch {};

    // lean_block_fetch_dedup_total{outcome}. Assert all seven
    // outcomes appear so a label rename / drop fails CI.
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "already_in_forkchoice" }, 3) catch {};
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "already_in_block_cache" }, 5) catch {};
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "already_pending" }, 7) catch {};
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "fetched" }, 11) catch {};
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "fetch_no_peers" }, 13) catch {};
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "fetch_failed" }, 17) catch {};
    metrics.lean_block_fetch_dedup_total.incrBy(.{ .outcome = "dedup_lost_race" }, 19) catch {};

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    // Top-level metric families must be advertised.
    try testing.expect(std.mem.indexOf(u8, body, "lean_block_root_compute_skipped_total") != null);
    try testing.expect(std.mem.indexOf(u8, body, "lean_block_fetch_dedup_total") != null);

    const skip_sites = [_][]const u8{
        "site=\"chain.onGossip\"",
        "site=\"chain.onBlock\"",
        "site=\"chain.processPendingBlocks\"",
        "site=\"forkchoice.onBlock\"",
    };
    for (skip_sites) |lbl| {
        try testing.expect(std.mem.indexOf(u8, body, lbl) != null);
    }

    const fetch_outcomes = [_][]const u8{
        "outcome=\"already_in_forkchoice\"",
        "outcome=\"already_in_block_cache\"",
        "outcome=\"already_pending\"",
        "outcome=\"fetched\"",
        "outcome=\"fetch_no_peers\"",
        "outcome=\"fetch_failed\"",
        "outcome=\"dedup_lost_race\"",
    };
    for (fetch_outcomes) |lbl| {
        try testing.expect(std.mem.indexOf(u8, body, lbl) != null);
    }
}

test "attestation aggregate coverage metrics use leanSpec names" {
    if (isZKVM()) return;

    try init(std.heap.page_allocator);

    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "timely", .subnet = "combined" }, 42);
    try metrics.lean_attestation_aggregate_coverage_validators.set(.{ .section = "block", .subnet = "subnet_0" }, 7);
    try metrics.lean_attestation_aggregate_coverage_subnets.set(.{ .section = "timely" }, 3);
    try metrics.lean_attestation_aggregate_coverage_diff_validators.set(.{ .direction = "block_only" }, 5);
    try metrics.lean_attestation_aggregate_coverage_diff_validators.set(.{ .direction = "timely_only" }, 2);

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    try testing.expect(std.mem.indexOf(u8, body, "lean_attestation_aggregate_coverage_validators") != null);
    try testing.expect(std.mem.indexOf(u8, body, "lean_attestation_aggregate_coverage_subnets") != null);
    try testing.expect(std.mem.indexOf(u8, body, "lean_attestation_aggregate_coverage_diff_validators") != null);
    try testing.expect(std.mem.indexOf(u8, body, "zeam_attestation_aggregate_coverage") == null);
    try testing.expect(std.mem.indexOf(u8, body, "section=\"timely\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "subnet=\"combined\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "subnet=\"subnet_0\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "direction=\"block_only\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "direction=\"timely_only\"") != null);
}

test "aggregator skipped metric uses leanMetrics name and reasons" {
    if (isZKVM()) return;

    try init(std.heap.page_allocator);

    const reasons = [_][]const u8{
        "not_aggregator",
        "not_synced",
        "missing_state",
        "spawn_failed",
        "other",
    };
    for (reasons) |reason| {
        metrics.lean_aggregator_skipped_total.incr(.{ .reason = reason }) catch {};
    }

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    try testing.expect(std.mem.indexOf(u8, body, "lean_aggregator_skipped_total") != null);
    try testing.expect(std.mem.indexOf(u8, body, "zeam_aggregate_skip_total") == null);
    for (reasons) |reason| {
        var expected: [64]u8 = undefined;
        const label = try std.fmt.bufPrint(&expected, "reason=\"{s}\"", .{reason});
        try testing.expect(std.mem.indexOf(u8, body, label) != null);
    }
}

// Issues #863 / #867: clock-loop xev drain observability must stay in the
// Prometheus scrape output (histogram + slow-drain counters).
test "issues #863/#867: xev until_done drain metrics appear in /metrics output" {
    if (isZKVM()) return;

    try init(std.heap.page_allocator);

    zeam_xev_clock_until_done_drain_seconds.record(0.012);
    metrics.zeam_xev_clock_until_done_slow_ge_500ms_total.incr();
    metrics.zeam_xev_clock_until_done_slow_ge_1s_total.incr();

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    try testing.expect(std.mem.indexOf(u8, body, "zeam_xev_clock_until_done_drain_seconds") != null);
    try testing.expect(std.mem.indexOf(u8, body, "zeam_xev_clock_until_done_slow_ge_500ms_total") != null);
    try testing.expect(std.mem.indexOf(u8, body, "zeam_xev_clock_until_done_slow_ge_1s_total") != null);
}

// Per-callsite libxev callback duration histogram is the
// primary attribution signal for slow xev drains. Verify both the
// metric name and a representative `site` label show up in the
// Prometheus scrape body.
test "issue #942: libxev callback duration histogram appears in /metrics output" {
    if (isZKVM()) return;

    try init(std.heap.page_allocator);

    observeLibxevCallback("onGossip.block.hash_tree_root", 0.042);
    observeLibxevCallback("onInterval.tick", 0.003);

    var alloc_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc_writer.deinit();
    try writeMetrics(&alloc_writer.writer);
    const body = alloc_writer.writer.buffered();

    try testing.expect(std.mem.indexOf(u8, body, "zeam_libxev_callback_duration_seconds") != null);
    try testing.expect(std.mem.indexOf(u8, body, "site=\"onGossip.block.hash_tree_root\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "site=\"onInterval.tick\"") != null);
}
