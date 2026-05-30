pub mod logger;
pub mod req_resp;

use futures::future::Either;
use futures::Stream;
use futures::StreamExt;
use libp2p::core::{
    multiaddr::Multiaddr, multiaddr::Protocol, muxing::StreamMuxerBox, transport::Boxed,
};

use libp2p::identity::{secp256k1, Keypair};
use libp2p::swarm::{dial_opts::DialOpts, ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{
    core, gossipsub, identify, identity, noise, ping, yamux, PeerId, SwarmBuilder, Transport,
};
use std::convert::TryFrom;
use std::os::raw::c_char;
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::mpsc;

use sha2::Digest;
use snap::raw::Decoder;
use std::ffi::{CStr, CString};

use delay_map::HashMapDelay;
use futures::future::poll_fn;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

use crate::req_resp::{
    configurations::REQUEST_TIMEOUT, configurations::RESPONSE_CHANNEL_IDLE_TIMEOUT,
    LeanSupportedProtocol, ProtocolId, ReqResp, ReqRespMessage, ReqRespMessageError,
    ReqRespMessageReceived, RequestMessage, ResponseMessage,
};

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// Extension trait for `Mutex` that converts a poisoned-mutex `Err` into the
/// inner guard rather than panicking.
///
/// Every Mutex in this crate protects a plain map, atomic counter, or simple
/// state struct with no internal invariants — none of them care whether a
/// previous panic occurred mid-update. Using `lock_recover` everywhere a
/// previous version called `.lock_recover()` lets us avoid the dominant
/// source of panic in this crate, which matters under the `risc0-release`
/// and `openvm-release` profiles where `panic = "abort"` makes `catch_ffi`
/// a no-op.
trait MutexExt<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> MutexExt<T> for std::sync::Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        match self.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Run a closure with `catch_unwind` so panics never unwind across the FFI
/// boundary into Zig (which would be undefined behaviour). On panic the
/// closure's return value is `None`; callers convert that to a sensible
/// "failure" return for their FFI signature (e.g. `false` for a bool, `0`
/// for a u64, no-op for a void).
///
/// **Profile caveat — `panic = "abort"` builds.** `cargo test --release` and
/// the dummy-prover dev path both inherit the workspace default
/// `panic = "unwind"`, so `catch_unwind` works as intended there. The
/// `risc0-release` and `openvm-release` profiles in `rust/Cargo.toml` set
/// `panic = "abort"` for binary-size reasons; under those profiles the panic
/// runtime calls `abort()` directly and `catch_unwind` becomes a no-op (the
/// closure never returns to its caller because the process is gone). We
/// therefore complement `catch_ffi` by routing the dominant panic source —
/// every `Mutex::lock().unwrap()` on a poisoned mutex — through
/// `MutexExt::lock_recover`, which accepts the poison and continues. Other
/// `.unwrap()` sites that remain are either at startup before any FFI call
/// (`tokio::runtime::Builder::build`) or test-only.
///
/// Uses `AssertUnwindSafe` because the closures executed here either do not
/// share state with anything outside the FFI call or only touch lazy-static
/// globals that are themselves panic-safe. The alternative — sprinkling
/// `UnwindSafe` bounds through every FFI helper — buys no real safety since
/// a poisoned mutex is a recoverable error, not an unsafety.
fn catch_ffi<R>(f: impl FnOnce() -> R) -> Option<R> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(payload) => {
            // Best-effort log; never panic from inside the panic handler.
            let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "panic with non-string payload".to_string()
            };
            // logger::rustLogger may itself panic if its handler panics; guard
            // with a second catch_unwind so we always return rather than abort.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                eprintln!("[libp2p-glue] FFI call panicked, recovered: {}", msg);
            }));
            None
        }
    }
}

/// Per-network state, replaces the previous family of `static mut SWARM_STATE*`,
/// `ZIG_HANDLER*`, `SHUTDOWN_NOTIFY*` slots and the `NETWORK_READY_SIGNALS`
/// 3-tuple. Stored inside a `Mutex<HashMap<u32, NetworkSlot>>` so any number of
/// networks can coexist (the previous implementation hardcoded slots 0/1/2 and
/// panicked on a fourth) and so cross-thread access (FFI thread vs the tokio
/// runtime thread) is correctly synchronised.
///
/// The `Swarm` itself is no longer parked in a global. `Network::start_network`
/// now returns it directly to `Network::run_eventloop`, eliminating the only
/// reason the swarm ever needed a global slot. Everything kept here is data
/// the FFI thread legitimately needs to read or update independently of the
/// runtime thread (handler pointer for log forwarding, shutdown notify for
/// `stop_network`, ready flag for `wait_for_network_ready`).
struct NetworkSlot {
    /// Zig-side `*EthLibp2p` value, opaque to rust. Used by free-function
    /// callbacks that need to forward into Zig but don't have access to the
    /// `Network` instance directly (e.g. `forward_log_by_network`). `None`
    /// once `clear_network_slot` has run so post-shutdown FFI dispatches see
    /// "no handler" rather than a freed pointer.
    zig_handler: Option<u64>,
    /// Per-network shutdown signal. The event loop polls a `.notified()`
    /// future; `stop_network` calls `notify_one` to wake it. `notify_one`
    /// stores a permit if no waiter is parked yet, so a `stop_network` that
    /// races the first `.notified().await` is not lost.
    shutdown_notify: Option<Arc<Notify>>,
    /// Set to `true` once `start_network` finishes binding listeners and
    /// publishing the command channel. `wait_for_network_ready` blocks on
    /// `NETWORK_READY_CONDVAR` until this transitions.
    ready: bool,
}

impl NetworkSlot {
    const fn empty() -> Self {
        Self {
            zig_handler: None,
            shutdown_notify: None,
            ready: false,
        }
    }
}

lazy_static::lazy_static! {
    /// One entry per active or pending network. Entries are inserted on the
    /// first FFI call that touches a network id (typically `create_and_run_network`)
    /// and removed by `clear_network_slot` after the event loop has fully
    /// unwound. Holding the lock across awaits is forbidden (every callsite
    /// drops the guard before any `.await`).
    static ref NETWORK_SLOTS: Mutex<HashMap<u32, NetworkSlot>> = Mutex::new(HashMap::new());
}

fn with_slot_mut<R>(network_id: u32, f: impl FnOnce(&mut NetworkSlot) -> R) -> R {
    let mut slots = NETWORK_SLOTS.lock_recover();
    let slot = slots.entry(network_id).or_insert_with(NetworkSlot::empty);
    f(slot)
}

fn set_zig_handler(network_id: u32, handler: u64) {
    with_slot_mut(network_id, |slot| slot.zig_handler = Some(handler));
}

fn get_zig_handler(network_id: u32) -> Option<u64> {
    NETWORK_SLOTS
        .lock_recover()
        .get(&network_id)
        .and_then(|s| s.zig_handler)
}

/// Install a fresh shutdown signal for the given network and return a handle
/// to it. Called by `start_network` *before* `mark_network_ready` so that the
/// invariant "any observer that sees `ready == true` can also `notify_one`
/// the shutdown handle" holds atomically across the start→eventloop handoff.
/// `run_eventloop` later picks the handle up via `get_shutdown_notify`.
fn install_shutdown_notify(network_id: u32) -> Arc<Notify> {
    let notify = Arc::new(Notify::new());
    with_slot_mut(network_id, |slot| {
        slot.shutdown_notify = Some(notify.clone());
    });
    notify
}

/// Get a handle to the shutdown signal for the given network, if one is
/// installed.
fn get_shutdown_notify(network_id: u32) -> Option<Arc<Notify>> {
    NETWORK_SLOTS
        .lock_recover()
        .get(&network_id)
        .and_then(|s| s.shutdown_notify.clone())
}

fn mark_network_ready(network_id: u32) {
    with_slot_mut(network_id, |slot| slot.ready = true);
    NETWORK_READY_CONDVAR.notify_all();
}

fn is_network_ready(network_id: u32) -> bool {
    NETWORK_SLOTS
        .lock_recover()
        .get(&network_id)
        .map(|s| s.ready)
        .unwrap_or(false)
}

/// Tear down per-network state after the event loop has exited. Clears the
/// Zig handler pointer so any in-flight attempts to dispatch into Zig become
/// no-ops, releases the shutdown notify, and resets the ready flag so a
/// post-stop `wait_for_network_ready` does not return a stale `true`.
fn clear_network_slot(network_id: u32) {
    {
        let mut slots = NETWORK_SLOTS.lock_recover();
        slots.remove(&network_id);
    }
    NETWORK_READY_CONDVAR.notify_all();
}

enum SwarmCommand {
    /// Join the gossipsub mesh for `topic` (full wire topic string).
    ///
    /// Issued from Zig when `EthLibp2p.subscribe` runs. The swarm is created
    /// with no topic joins (`new_swarm` does not subscribe anything itself);
    /// every mesh subscription flows through this command, keeping
    /// `gossip.subscribe` on the Zig side as the single source of truth for
    /// what subnets a node joins.
    SubscribeGossip {
        topic: String,
    },
    Publish {
        topic: String,
        data: Vec<u8>,
    },
    SendRpcRequest {
        peer_id: PeerId,
        request_id: u64,
        request_message: RequestMessage,
    },
    /// Pre-resolved on the FFI side under a single `RESPONSE_CHANNEL_MAP` lock so
    /// the executor side does not need to re-lock the map. This avoids a race
    /// against `SendRpcEndOfStream` / the response-channel timeout sweep that
    /// could otherwise drop the chunk and log a spurious `No response channel
    /// found` error between the two locks.
    SendRpcResponseChunk {
        channel_id: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        response_message: ResponseMessage,
    },
    SendRpcEndOfStream {
        channel_id: u64,
    },
    SendRpcErrorResponse {
        channel_id: u64,
        payload: Vec<u8>,
    },
    /// Issued by a detached `tokio::spawn` task scheduled inside
    /// `Network::schedule_reconnection` after sleeping for the per-attempt
    /// backoff. The swarm task is the only place with `&mut swarm`, so the
    /// actual `swarm.dial(...)` happens here. Side-stepped the previous
    /// `RECONNECT_QUEUE: HashMapDelay` polled from arm 3 — that delay-map
    /// interaction with the swarm select! was the trigger for the #942
    /// permanent waker loss.
    DialReconnect {
        peer_id: PeerId,
        addr: Multiaddr,
        attempt: u32,
    },
}

/// Capacity for the per-network swarm command channel.
///
/// The channel is bounded to apply backpressure when FFI publishers run faster
/// than the swarm can drain (slow peer, gossipsub overflow, etc.). Send sites
/// use `try_send` and drop the message with an error log when the channel is
/// full rather than blocking the calling thread or growing memory without
/// bound. Sized for short, bursty traffic; tune with care.
///
/// devnet-4 (issue #808) showed the previous 1024-slot bound saturating under
/// steady-state validator load: ~5 commands/min/node were silently dropped,
/// causing fork-choice divergence because outbound attestations and req-resp
/// parent fetches never made it onto the wire. 8192 gives ~8x headroom for the
/// same workload while still bounding memory.
const SWARM_COMMAND_CHANNEL_CAPACITY: usize = 8192;

/// Maximum number of queued swarm commands the event loop drains in a single
/// iteration before yielding back to the rest of the `tokio::select!` arms
/// (notably swarm event polling). Keeps a command flood from starving gossip
/// ingestion / reqresp completion under load.
///
/// Bumped from 32 to 256 alongside the channel capacity above so we actually
/// drain the new headroom: 32/tick was the symmetric bottleneck paired with
/// the 1024-slot channel. Still small enough that one busy network can't
/// monopolize the executor.
const MAX_SWARM_COMMANDS_PER_TICK: usize = 256;

/// Capacity of the inbound-gossip hand-off channel (issue #942).
///
/// Each slot owns one inbound gossip payload (the compressed bytes moved out
/// of `gossipsub::Message`). The libp2p event loop `try_send`s onto this
/// channel; a single dedicated worker thread drains it and performs the heavy
/// synchronous snappy-decompress + SSZ-deserialize + chain dispatch via
/// `handleMsgFromRustBridge`. The point is to keep that hundreds-of-ms-per-block
/// work OFF the `new_current_thread` tokio runtime that also drives quinn's
/// QUIC I/O — that starvation corrupted the QUIC receive path and stalled
/// gossip (the cross-message byte-bleed pinned in `issue_942_layer.md`, and the
/// earlier 148 broken QUIC handshakes / 8 Status-RPC timeouts).
///
/// Bounded so a burst of large blocks cannot grow memory without limit. On a
/// full channel the message is dropped (counted in `INBOUND_GOSSIP_DROPPED_TOTAL`)
/// — gossip is best-effort and a missed block is recovered via the
/// blocks_by_root / blocks_by_range RPC sync fallback. 256 slots × the common
/// ~286 KB block ≈ 73 MB worst case; drops only occur during a decode backlog,
/// which is exactly when shedding load (instead of stalling the transport) is
/// the right behaviour.
const INBOUND_GOSSIP_CHANNEL_CAPACITY: usize = 256;

/// Count of inbound gossip messages dropped because the decode worker's queue
/// was full (issue #942). Process-wide; surfaced in logs at the drop site.
static INBOUND_GOSSIP_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #942 diagnosis: count of gossipsub `Message` events DELIVERED to the swarm
/// event loop, split by topic kind ([0]=block, [1]=attestation/aggregation,
/// [2]=other). This counts messages gossipsub handed up *before* our decode
/// worker runs, so comparing the block vs attestation arrival rates across the
/// stall tells us whether BLOCK gossip stops ARRIVING (a transport/mesh fault,
/// e.g. QUIC recv-stream wedge or block-topic mesh collapse) or keeps arriving
/// but fails downstream in decode. A periodic event-loop log prints the totals
/// alongside the per-topic mesh size so a frozen block counter with a healthy
/// mesh is immediately visible. Process-wide (one zeam node = one network).
static GOSSIP_RECV_BY_KIND_TOTAL: [AtomicU64; 3] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Classify a gossipsub topic string into a `GOSSIP_RECV_BY_KIND_TOTAL` index.
/// Topics are Ethereum-style `/leanconsensus/<fork>/<kind>/ssz_snappy`.
fn gossip_topic_kind_index(topic: &str) -> usize {
    if topic.contains("/block") {
        0
    } else if topic.contains("agg") || topic.contains("attest") {
        1
    } else {
        2
    }
}

// ===== #942 fix-#5 diagnostic: QUIC inbound recv-stream accounting =====
//
// The #942 stall is now pinned to a narrow band: AFTER the catch-up burst,
// gossipsub delivers zero block-topic messages while attestations keep flowing
// on the SAME QUIC connections (block-topic mesh stays healthy). The fault is
// downstream of the QUIC connection and upstream of gossipsub delivery, and is
// size-dependent (only large multi-frame block streams wedge). Four blind fixes
// (off-thread decode, libp2p 0.56 bump, multi-thread runtime, QUIC recv windows)
// all failed.
//
// This instrumentation wraps the QUIC `StreamMuxer` so we observe per-inbound-
// substream byte flow at the libp2p-quic / quinn boundary, BELOW gossipsub's
// length-delimited frame reassembly. It distinguishes the two remaining
// hypotheses:
//   (A) quinn recv-stream wedge — an open inbound substream's byte counter
//       PLATEAUS and its last-read goes stale (delta==0, idle climbs) while it
//       is still open: bytes have stopped ARRIVING from QUIC on that stream.
//   (B) gossipsub reassembly/delivery stall — byte counters KEEP advancing on
//       open substreams (delta>0) yet no block Message is delivered: bytes
//       arrive but gossipsub never reassembles/hands up the large frame.
// gossipsub keeps one persistent inbound substream per peer carrying all
// topics, so the decisive signal is per-substream: during the freeze, does some
// peer's inbound stream go idle (A) while others flow, or do all keep flowing
// while block delivery is frozen (B)?

/// Monotonic id allocator for instrumented QUIC substreams (both directions
/// share the id space so log lines stay easy to cross-reference).
static QUIC_SUBSTREAM_ID: AtomicU64 = AtomicU64::new(0);

/// Per-substream byte accounting. The same struct is used for both inbound and
/// outbound substreams; the relevant counters depend on direction:
/// - inbound: poll_read drives `bytes` / `last_active_unix` (we primarily READ
///   from peer-opened substreams).
/// - outbound: poll_write drives `bytes` / `last_active_unix`.
///
/// Each direction lives in its own registry below so the diag emitter can
/// report inbound and outbound top-N independently.
struct SubstreamStat {
    id: u64,
    /// Cumulative bytes transferred (read for inbound, written for outbound).
    bytes: AtomicU64,
    /// Largest single transfer (informational; mostly equals quinn's 8 KiB
    /// poll chunk for steady-state streams).
    max_single_xfer: AtomicU64,
    /// Unix seconds of the most recent non-empty transfer.
    last_active_unix: AtomicU64,
    /// `bytes` snapshot at the previous diag log, for per-interval delta.
    logged_bytes: AtomicU64,
    /// Set on Drop so the diag emitter can prune dead entries.
    closed: AtomicBool,
}

/// Registry of live instrumented INBOUND substreams (peer-opened, we read).
static INBOUND_SUBSTREAMS: Mutex<Vec<Arc<SubstreamStat>>> = Mutex::new(Vec::new());

/// Registry of live instrumented OUTBOUND substreams (we opened, we write).
/// If our poll_write stalls mid-frame on these, the freeze is on OUR sender
/// side (hyp A2). If outbound flows fine while inbound wedges, the recv path
/// is at fault (hyp A1).
static OUTBOUND_SUBSTREAMS: Mutex<Vec<Arc<SubstreamStat>>> = Mutex::new(Vec::new());

/// Maximum wall-clock millis taken by ONE iteration of the swarm task's
/// `tokio::select!` since the last diag emit. Devnet evidence (slot 58→61)
/// showed both `poll_read` and `poll_write` freeze simultaneously, which can
/// only happen if the swarm task itself stalled in a synchronous arm body —
/// this counter is the direct measurement of that.
static EVENT_LOOP_MAX_ITER_MS: AtomicU64 = AtomicU64::new(0);
/// Cumulative count of swarm-task iterations whose body wall-time exceeded
/// `EVENT_LOOP_SLOW_ITER_THRESHOLD_MS`. Read by the diag emitter.
static EVENT_LOOP_SLOW_ITERS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Threshold for counting an iteration as "slow". 100 ms is well above the
/// natural cost of a hot arm (gossip rx, reqresp) but well below the 10 s
/// pause observed at slot 58→61, so a healthy run reports zero or single
/// digits and a pathological run lights up clearly.
const EVENT_LOOP_SLOW_ITER_THRESHOLD_MS: u64 = 100;

/// Numeric id of the swarm-task arm whose body was MOST RECENTLY entered.
/// 0 = none seen yet; 1..=7 mapped to the arms in `run_eventloop`'s biased
/// select! (see `arm_name`). The diag emitter reports this together with the
/// unix-second timestamp of when it was set, so a stuck swarm task shows up
/// as `last_arm=X` with a steadily growing `age=Ns` — that pins the wedge
/// to the body of arm X rather than to "somewhere in the loop". Devnet
/// evidence on a7779f91 ruled out a long synchronous body (max_iter_ms=0
/// for 120+ s post-freeze) and pointed at a permanent waker-loss / deadlock
/// inside one arm's body; this probe identifies which arm.
static LAST_ARM_ENTERED: AtomicU32 = AtomicU32::new(0);
/// Unix seconds at which `LAST_ARM_ENTERED` was last updated. Stale value =
/// the loop hasn't entered any arm body since that timestamp = wedged.
static LAST_ARM_ENTERED_UNIX: AtomicU64 = AtomicU64::new(0);
/// Cumulative entry count per arm; index = arm id (1..=7), index 0 unused.
/// Logged as a `cnt[…]` array each diag tick.
static ARM_ENTRY_COUNTS: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Mark the start of arm `idx`'s body. Inlined so the compiler folds the
/// const-id into the atomic store.
#[inline(always)]
fn enter_arm(idx: u32) {
    LAST_ARM_ENTERED.store(idx, Ordering::Relaxed);
    LAST_ARM_ENTERED_UNIX.store(unix_secs(), Ordering::Relaxed);
    if let Some(slot) = ARM_ENTRY_COUNTS.get(idx as usize) {
        slot.fetch_add(1, Ordering::Relaxed);
    }
}

fn arm_name(idx: u32) -> &'static str {
    match idx {
        0 => "none",
        1 => "shutdown",
        2 => "reqresp_timeout",
        // Arm id 3 (was `reconnect`) was removed in the #942 fix; ID kept
        // unused to preserve diagnostic-log compatibility with prior runs.
        3 => "reconnect_removed",
        4 => "response_channel_timeout",
        5 => "swarm_event",
        6 => "cmd_rx",
        7 => "mesh_peers_tick",
        _ => "unknown",
    }
}

/// Sub-probe for arm 5 (`swarm_event`): which `SwarmEvent` variant's match
/// body is the swarm task in. Set at the top of each variant's match arm.
/// 0 = no variant seen yet, 99 = unmatched fallthrough.
static LAST_SWARM_EVENT_VARIANT: AtomicU32 = AtomicU32::new(0);
static LAST_SWARM_EVENT_VARIANT_UNIX: AtomicU64 = AtomicU64::new(0);

/// Sub-probe for arm 6 (`cmd_rx`): which `SwarmCommand` variant's match
/// body is being processed.
static LAST_SWARM_COMMAND_VARIANT: AtomicU32 = AtomicU32::new(0);
static LAST_SWARM_COMMAND_VARIANT_UNIX: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn enter_swarm_event(idx: u32) {
    LAST_SWARM_EVENT_VARIANT.store(idx, Ordering::Relaxed);
    LAST_SWARM_EVENT_VARIANT_UNIX.store(unix_secs(), Ordering::Relaxed);
}

#[inline(always)]
fn enter_swarm_command(idx: u32) {
    LAST_SWARM_COMMAND_VARIANT.store(idx, Ordering::Relaxed);
    LAST_SWARM_COMMAND_VARIANT_UNIX.store(unix_secs(), Ordering::Relaxed);
}

fn swarm_event_name(idx: u32) -> &'static str {
    match idx {
        0 => "none",
        1 => "NewListenAddr",
        2 => "ConnectionEstablished",
        3 => "ConnectionClosed",
        4 => "OutgoingConnectionError",
        5 => "Gossipsub",
        6 => "Reqresp",
        99 => "other",
        _ => "unknown",
    }
}

fn swarm_command_name(idx: u32) -> &'static str {
    match idx {
        0 => "none",
        1 => "SubscribeGossip",
        2 => "Publish",
        3 => "SendRpcRequest",
        4 => "SendRpcResponseChunk",
        5 => "SendRpcEndOfStream",
        6 => "SendRpcErrorResponse",
        7 => "DialReconnect",
        _ => "unknown",
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_substream_stat() -> Arc<SubstreamStat> {
    let now = unix_secs();
    Arc::new(SubstreamStat {
        id: QUIC_SUBSTREAM_ID.fetch_add(1, Ordering::Relaxed),
        bytes: AtomicU64::new(0),
        max_single_xfer: AtomicU64::new(0),
        last_active_unix: AtomicU64::new(now),
        logged_bytes: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    })
}

fn register_inbound_substream() -> Arc<SubstreamStat> {
    let stat = new_substream_stat();
    INBOUND_SUBSTREAMS.lock_recover().push(stat.clone());
    stat
}

fn register_outbound_substream() -> Arc<SubstreamStat> {
    let stat = new_substream_stat();
    OUTBOUND_SUBSTREAMS.lock_recover().push(stat.clone());
    stat
}

/// Emit one diag line for the given direction's substream registry. Bounded
/// output: aggregate + top-8 by cumulative bytes (see the log-overflow note on
/// `forward_log_with_handler`).
fn emit_substream_diag(network_id: u32, label: &str, registry: &Mutex<Vec<Arc<SubstreamStat>>>) {
    let now = unix_secs();
    let mut reg = registry.lock_recover();
    // Prune closed streams and any idle longer than 5 minutes (defensive
    // against a substream whose Drop never runs).
    reg.retain(|s| {
        !s.closed.load(Ordering::Relaxed)
            && now.saturating_sub(s.last_active_unix.load(Ordering::Relaxed)) < 300
    });
    let live = reg.len();
    let mut idle_streams = 0u64;
    let mut bytes_total = 0u64;
    let mut delta_total = 0u64;
    // (bytes, delta, max_xfer, idle, id) per live stream.
    let mut rows: Vec<(u64, u64, u64, u64, u64)> = Vec::with_capacity(live);
    for s in reg.iter() {
        let bytes = s.bytes.load(Ordering::Relaxed);
        let prev = s.logged_bytes.swap(bytes, Ordering::Relaxed);
        let delta = bytes.saturating_sub(prev);
        let idle = now.saturating_sub(s.last_active_unix.load(Ordering::Relaxed));
        let mxr = s.max_single_xfer.load(Ordering::Relaxed);
        bytes_total = bytes_total.saturating_add(bytes);
        delta_total = delta_total.saturating_add(delta);
        if idle > 8 {
            idle_streams += 1;
        }
        rows.push((bytes, delta, mxr, idle, s.id));
    }
    drop(reg);
    rows.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    let mut top = String::new();
    for (bytes, delta, mxr, idle, id) in rows.iter().take(8) {
        top.push_str(&format!(
            " [id={id} b={bytes} d={delta} mx={mxr} idle={idle}s]"
        ));
    }
    // Periodic per-substream diag. Kept at `debug` so production runs (info+
    // by default) stay quiet; flip the Zig logger to debug for the network
    // scope to revive these when triaging a regression. Counters live in the
    // SUBSTREAMS atomic registries regardless of log level so the data is
    // always there to query.
    logger::rustLogger.debug(
        network_id,
        &format!(
            "[{label}] live={live} idle>8s={idle_streams} bytes_total={bytes_total} delta_total={delta_total} | top:{top}"
        ),
    );
}

/// Spawn a dedicated tokio task that emits the per-substream QUIC diag lines
/// every 10s. Lives outside the swarm task's biased `select!` so it keeps
/// running even when reqresp-status retries make the mesh_peers_tick arm
/// permanently starved (which is what kept #942 invisible at the freeze).
fn spawn_quic_diag_emitter(network_id: u32, shutdown: Arc<tokio::sync::Notify>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.notified() => break,
                _ = tick.tick() => {
                    emit_substream_diag(network_id, "#942 quic-recv", &INBOUND_SUBSTREAMS);
                    emit_substream_diag(network_id, "#942 quic-send", &OUTBOUND_SUBSTREAMS);
                    // Event-loop iteration latency + message_id_fn cache stats.
                    // `swap(0)` on the max so each tick reports the worst
                    // single-iteration latency since the previous tick;
                    // `slow_total` is cumulative so we can see whether new
                    // slow iterations are still occurring after the burst.
                    let max_iter_ms = EVENT_LOOP_MAX_ITER_MS.swap(0, Ordering::Relaxed);
                    let slow_total = EVENT_LOOP_SLOW_ITERS_TOTAL.load(Ordering::Relaxed);
                    let (cache_hits, cache_misses, cache_len) = {
                        let c = MESSAGE_ID_CACHE.lock_recover();
                        (c.hits, c.misses, c.map.len())
                    };
                    logger::rustLogger.debug(
                        network_id,
                        &format!(
                            "[#942 loop] max_iter_ms={max_iter_ms} slow_iters>={EVENT_LOOP_SLOW_ITER_THRESHOLD_MS}ms_total={slow_total} | msg_id_cache hits={cache_hits} misses={cache_misses} len={cache_len}/{MESSAGE_ID_CACHE_CAPACITY}"
                        ),
                    );

                    // Per-arm tracking. `last_arm` + `age` pin a wedge to one
                    // arm's body (steadily growing age with no other arm
                    // entries == that arm's body never returned). `cnt[…]`
                    // shows cumulative entry counts so we can tell which arms
                    // are firing in a healthy run.
                    let last_arm = LAST_ARM_ENTERED.load(Ordering::Relaxed);
                    let last_arm_unix = LAST_ARM_ENTERED_UNIX.load(Ordering::Relaxed);
                    let now = unix_secs();
                    let age = now.saturating_sub(last_arm_unix);
                    let cnt: Vec<u64> = (1..=7)
                        .map(|i| ARM_ENTRY_COUNTS[i].load(Ordering::Relaxed))
                        .collect();
                    logger::rustLogger.debug(
                        network_id,
                        &format!(
                            "[#942 arm] last={}({}) age={age}s | shutdown={} reqresp_to={} reconnect={} resp_ch_to={} swarm_ev={} cmd_rx={} mesh_tick={}",
                            last_arm,
                            arm_name(last_arm),
                            cnt[0], cnt[1], cnt[2], cnt[3], cnt[4], cnt[5], cnt[6],
                        ),
                    );

                    // Sub-probes: which variant body the swarm task last
                    // entered inside arm 5 (SwarmEvent) and arm 6
                    // (SwarmCommand). Steady `swarm_ev_var.age` growth while
                    // `last=5` pins the wedge to that specific SwarmEvent
                    // variant; same logic for cmd_rx_var when `last=6`.
                    let sev_var = LAST_SWARM_EVENT_VARIANT.load(Ordering::Relaxed);
                    let sev_age = now
                        .saturating_sub(LAST_SWARM_EVENT_VARIANT_UNIX.load(Ordering::Relaxed));
                    let scmd_var = LAST_SWARM_COMMAND_VARIANT.load(Ordering::Relaxed);
                    let scmd_age = now
                        .saturating_sub(LAST_SWARM_COMMAND_VARIANT_UNIX.load(Ordering::Relaxed));
                    logger::rustLogger.debug(
                        network_id,
                        &format!(
                            "[#942 sub] swarm_ev_var={}({}) age={sev_age}s | cmd_var={}({}) age={scmd_age}s",
                            sev_var,
                            swarm_event_name(sev_var),
                            scmd_var,
                            swarm_command_name(scmd_var),
                        ),
                    );
                }
            }
        }
    });
}

/// A `StreamMuxer` wrapper that tags each inbound substream with an
/// `InboundSubstreamStat`. Outbound substreams are passed through untracked
/// (the recv path is what #942 concerns). Used only on the QUIC transport.
struct InstrumentedMuxer<M> {
    inner: M,
}

/// A substream wrapper that counts bytes transferred in the substream's
/// "natural" direction:
/// - if it came from `poll_inbound`, `read_stat` is `Some` and `poll_read`
///   updates it.
/// - if it came from `poll_outbound`, `write_stat` is `Some` and `poll_write`
///   updates it.
///
/// Both fields are `Option` (rather than one combined) so the diag emitter
/// can keep inbound vs outbound stats in separate registries.
struct InstrumentedSubstream<S> {
    inner: S,
    read_stat: Option<Arc<SubstreamStat>>,
    write_stat: Option<Arc<SubstreamStat>>,
}

impl<S> Drop for InstrumentedSubstream<S> {
    fn drop(&mut self) {
        if let Some(stat) = &self.read_stat {
            stat.closed.store(true, Ordering::Relaxed);
        }
        if let Some(stat) = &self.write_stat {
            stat.closed.store(true, Ordering::Relaxed);
        }
    }
}

impl<S> futures::io::AsyncRead for InstrumentedSubstream<S>
where
    S: futures::io::AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            if let Some(stat) = &this.read_stat {
                let n = *n as u64;
                if n > 0 {
                    stat.bytes.fetch_add(n, Ordering::Relaxed);
                    stat.max_single_xfer.fetch_max(n, Ordering::Relaxed);
                    stat.last_active_unix.store(unix_secs(), Ordering::Relaxed);
                }
            }
        }
        r
    }
}

impl<S> futures::io::AsyncWrite for InstrumentedSubstream<S>
where
    S: futures::io::AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            if let Some(stat) = &this.write_stat {
                let n = *n as u64;
                if n > 0 {
                    stat.bytes.fetch_add(n, Ordering::Relaxed);
                    stat.max_single_xfer.fetch_max(n, Ordering::Relaxed);
                    stat.last_active_unix.store(unix_secs(), Ordering::Relaxed);
                }
            }
        }
        r
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

impl<M> libp2p::core::muxing::StreamMuxer for InstrumentedMuxer<M>
where
    M: libp2p::core::muxing::StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    type Substream = InstrumentedSubstream<M::Substream>;
    type Error = M::Error;

    fn poll_inbound(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner)
            .poll_inbound(cx)
            .map_ok(|s| InstrumentedSubstream {
                inner: s,
                read_stat: Some(register_inbound_substream()),
                write_stat: None,
            })
    }

    fn poll_outbound(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner)
            .poll_outbound(cx)
            .map_ok(|s| InstrumentedSubstream {
                inner: s,
                read_stat: None,
                write_stat: Some(register_outbound_substream()),
            })
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<libp2p::core::muxing::StreamMuxerEvent, Self::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll(cx)
    }
}

/// One inbound gossip message handed from the libp2p event loop to the decode
/// worker thread. Owns every buffer the FFI call reads so the raw pointers
/// passed into Zig stay valid while the call runs off the event-loop thread.
struct InboundGossip {
    network_id: u32,
    zig_handler: u64,
    topic: CString,
    sender_peer_id: CString,
    data: Vec<u8>,
}

/// Drain loop for the dedicated inbound-gossip decode worker thread (issue
/// #942). Blocks on `recv()`; exits once the event loop drops the sender and
/// the channel is drained. Runs `handleMsgFromRustBridge` — i.e. the full
/// snappy decompress + SSZ deserialize + `chain.onGossip` dispatch — here, off
/// the tokio/quinn event-loop thread. A single worker preserves the serial
/// `onGossip` ordering the chain layer assumed when this ran inline.
fn run_inbound_gossip_worker(rx: std::sync::mpsc::Receiver<InboundGossip>) {
    while let Ok(msg) = rx.recv() {
        // #942 forensic: hash the bytes about to cross the FFI boundary into
        // Zig. Moved off the event loop into this worker so the O(len) sha256
        // no longer competes with quinn for event-loop time. Pairs with the
        // Zig-side `sha256_inbound` and the producer's `sha256_compressed` for
        // cross-fleet correlation; remove once the in-transit corruption is
        // confirmed fixed.
        let mut ingress_hasher = sha2::Sha256::new();
        ingress_hasher.update(msg.data.as_slice());
        let ingress_digest = ingress_hasher.finalize();
        logger::rustLogger.debug(
            msg.network_id,
            &format!(
                "[#942 rx] topic={} len={} sha256_libp2p_ingress={} peer={}",
                msg.topic.to_string_lossy(),
                msg.data.len(),
                hex::encode(ingress_digest),
                msg.sender_peer_id.to_string_lossy(),
            ),
        );

        // SAFETY: `msg` owns `topic`, `sender_peer_id` and `data` for the whole
        // duration of this call, so all three pointers are valid until
        // `handleMsgFromRustBridge` returns. The Zig handler copies/consumes
        // what it needs before returning (it must not stash the buffers — see
        // the lifetime invariant comment in `node.onGossip`).
        unsafe {
            handleMsgFromRustBridge(
                msg.zig_handler,
                msg.topic.as_ptr(),
                msg.data.as_ptr(),
                msg.data.len(),
                msg.sender_peer_id.as_ptr(),
            );
        }
    }
}

/// One reqresp FFI dispatch handed off from the swarm task to the dedicated
/// reqresp worker. Owns every buffer the FFI call reads so the raw pointers
/// passed to Zig stay valid for the duration of the call. Mirrors
/// `InboundGossip` for the gossip side.
///
/// The 2026-05-30 a7779f91 / 883318f5 devnet probes showed that the swarm
/// task could spend ~15 s inside one `SwarmEvent::Behaviour(Reqresp(_))`
/// body — the Zig-side `handleRPCResponseFromRustBridge` synchronously runs
/// snappy-framed decompress + SSZ deserialize + chain dispatch on the
/// caller thread (ethlibp2p.zig::handleRPCResponseFromRustBridge:991-1037),
/// and a single BlocksByRangeV1 response can stack many MB of work.
/// Moving the call to a worker thread mirrors the existing fix #59 pattern
/// for inbound gossip and lets quinn + gossipsub keep getting polled while
/// the chain layer is busy.
enum RpcWork {
    Request {
        zig_handler: u64,
        channel_id: u64,
        peer_id: CString,
        protocol: CString,
        payload: Vec<u8>,
    },
    Response {
        zig_handler: u64,
        request_id: u64,
        peer_id: CString,
        protocol: CString,
        payload: Vec<u8>,
    },
    EndOfStream {
        zig_handler: u64,
        request_id: u64,
        peer_id: CString,
        protocol: CString,
    },
    Error {
        zig_handler: u64,
        request_id: u64,
        protocol: CString,
        code: u32,
        message: CString,
    },
}

/// Capacity for the inbound-reqresp dispatch channel. Sized to absorb a
/// burst of `BlocksByRangeV1` chunks (the chain layer typically requests
/// `BLOCKS_BY_RANGE_SYNC_THRESHOLD` blocks per peer per sweep). Drops on
/// overflow are logged + counted via `INBOUND_RPC_DROPPED_TOTAL` so a
/// chronically saturated worker is visible without crashing the loop.
const INBOUND_RPC_CHANNEL_CAPACITY: usize = 256;

/// Cumulative count of reqresp FFI dispatches dropped because the worker's
/// channel was full. Read by the diag emitter (and could be exported via
/// FFI for metrics later).
static INBOUND_RPC_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Drain loop for the dedicated reqresp worker thread. Blocks on `recv()`;
/// exits once the event loop drops the sender and the channel is drained.
/// Single worker so per-request ordering with the Zig chain layer matches
/// the prior inline behavior.
fn run_inbound_rpc_worker(rx: std::sync::mpsc::Receiver<RpcWork>) {
    while let Ok(work) = rx.recv() {
        match work {
            RpcWork::Request {
                zig_handler,
                channel_id,
                peer_id,
                protocol,
                payload,
            } => {
                // SAFETY: `peer_id`, `protocol`, and `payload` are owned by
                // this `RpcWork` value, which stays alive until the FFI
                // call returns. The Zig handler must copy any bytes it
                // wants to retain (it does — see `handleRPCRequestFromRustBridge`
                // in ethlibp2p.zig).
                unsafe {
                    handleRPCRequestFromRustBridge(
                        zig_handler,
                        channel_id,
                        peer_id.as_ptr(),
                        protocol.as_ptr(),
                        payload.as_ptr(),
                        payload.len(),
                    );
                }
            }
            RpcWork::Response {
                zig_handler,
                request_id,
                peer_id,
                protocol,
                payload,
            } => unsafe {
                handleRPCResponseFromRustBridge(
                    zig_handler,
                    request_id,
                    peer_id.as_ptr(),
                    protocol.as_ptr(),
                    payload.as_ptr(),
                    payload.len(),
                );
            },
            RpcWork::EndOfStream {
                zig_handler,
                request_id,
                peer_id,
                protocol,
            } => unsafe {
                handleRPCEndOfStreamFromRustBridge(
                    zig_handler,
                    request_id,
                    peer_id.as_ptr(),
                    protocol.as_ptr(),
                );
            },
            RpcWork::Error {
                zig_handler,
                request_id,
                protocol,
                code,
                message,
            } => unsafe {
                handleRPCErrorFromRustBridge(
                    zig_handler,
                    request_id,
                    protocol.as_ptr(),
                    code,
                    message.as_ptr(),
                );
            },
        }
    }
}

/// Reason tags for `SWARM_COMMAND_DROPPED_TOTAL` and the matching FFI getter
/// `get_swarm_command_dropped_total`. Mirrored on the Zig side as a plain
/// `u32` enum so the Prometheus counter can be labeled by reason without
/// passing strings across the FFI boundary.
///
/// **Stable contract — do not renumber**: the Zig metrics layer scrapes by
/// passing these integer tags back into the FFI getter. Adding a new reason
/// is fine; renumbering an existing one will silently misattribute drops.
#[repr(u32)]
enum SwarmCommandDropReason {
    Full = 0,
    Closed = 1,
    Uninitialized = 2,
}

/// Cumulative count of swarm commands dropped before reaching the event loop,
/// indexed by `SwarmCommandDropReason`. Read via `get_swarm_command_dropped_total`
/// from Zig on each Prometheus scrape; never reset, so a Zig-side tracker can
/// compute deltas against its last-seen value (issue #808).
static SWARM_COMMAND_DROPPED_TOTAL: [AtomicU64; 3] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

fn record_swarm_command_drop(reason: SwarmCommandDropReason) {
    SWARM_COMMAND_DROPPED_TOTAL[reason as usize].fetch_add(1, Ordering::Relaxed);
}

/// Maximum number of concurrent libp2p networks supported in this
/// process. Mirrors the `match network_id { 0|1|2 => …, _ => panic }`
/// hardcoded slot table at the top of this file (`get_swarm_mut`,
/// `set_swarm`, `get_zig_handler`, etc.) — `MESH_PEERS_TOTAL` reuses the
/// same fixed-size shape so a metric write on an unsupported
/// `network_id` cannot grow an unbounded map and stays lock-free.
const MAX_NETWORKS: usize = 3;

/// Store the latest mesh-peer count for `network_id`. Called from the
/// swarm task on the gossipsub events that actually change mesh
/// membership (Subscribed/Unsubscribed/GossipsubNotSupported/SlowPeer
/// — not Message), on every connection close, and on a 1s liveness
/// tick; read by Zig on each Prometheus scrape via
/// `get_mesh_peers_total`.
///
/// Out-of-range `network_id` is a silent no-op rather than a panic so
/// FFI consumers compiled against an older Rust glue cannot crash the
/// swarm task. The matching `get_mesh_peers_total` returns 0 for the
/// same out-of-range values.
fn record_mesh_peers(network_id: u32, count: u64) {
    if let Some(slot) = MESH_PEERS_TOTAL.get(network_id as usize) {
        slot.store(count, Ordering::Relaxed);
    }
}

// `dump_failed_gossip_payload` / `MAX_FAILED_GOSSIP_DUMPS` / `FAILED_GOSSIP_DUMP_COUNTER`
// were removed in #942 phase 4. See the long-form rationale at the call site
// (the `Behaviour::poll`-side comment in the gossipsub `Event::Message` arm):
// the Rust-side per-failure dump duplicated the Zig-side
// `failed_snappyz_decode_*.bin` dumps written by `writeFailedBytes`, and the
// `Decoder::new().decompress_vec` it gated on was the second synchronous
// decompress per gossip message — together they jammed the libp2p event
// loop on broken-snappy bombs on the 2026-05-29 devnet.

/// FFI getter: cumulative count of dropped swarm commands for the given
/// reason tag (see `SwarmCommandDropReason`). Returns 0 for unknown tags so
/// future Zig builds compiled against an older Rust glue do not panic.
///
/// Counts are global across all networks; the Zig caller is expected to scrape
/// once per metrics endpoint hit and turn deltas into a `CounterVec` with
/// `reason` labels.
#[no_mangle]
pub extern "C" fn get_swarm_command_dropped_total(reason_tag: u32) -> u64 {
    catch_ffi(|| {
        SWARM_COMMAND_DROPPED_TOTAL
            .get(reason_tag as usize)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    })
    .unwrap_or(0)
}

/// FFI getter: current number of remote peers in this node's gossipsub mesh
/// across all subscribed topics (single snapshot, kept fresh from the swarm
/// task). Returns 0 for unknown `network_id` so a Zig build compiled against
/// an older Rust glue cannot panic.
///
/// Scrape-vs-lifecycle note: between `stop_network(network_id)` and a
/// subsequent `create_and_run_network(network_id)`, this returns 0
/// (the slot is reset on stop). Operators must distinguish "0 mesh
/// peers on a running network" from "network is restarting" via
/// orthogonal signals (e.g. `lean_node_info`, the swarm task's own
/// liveness logging, or a separate per-network running gauge if that
/// distinction becomes load-bearing — see follow-up TODO in the
/// 1s-tick / event-loop wiring above).
///
/// leanMetrics PR #35 — `lean_gossip_mesh_peers`. The value is updated from
/// inside the swarm task on the gossipsub events that change mesh
/// membership (Subscribed/Unsubscribed/GossipsubNotSupported/SlowPeer
/// — not Message), on every connection close, and on a 1s liveness tick.
///
/// Return type is `u64` for FFI stability across 32-bit and 64-bit
/// architectures (the underlying source is `usize` from
/// `all_mesh_peers().count()`; cast at the recording site).
#[no_mangle]
pub extern "C" fn get_mesh_peers_total(network_id: u32) -> u64 {
    MESH_PEERS_TOTAL
        .get(network_id as usize)
        .map(|a| a.load(Ordering::Relaxed))
        .unwrap_or(0)
}

lazy_static::lazy_static! {
    static ref REQUEST_ID_MAP: Mutex<HashMapDelay<u64, ()>> = Mutex::new(HashMapDelay::new(REQUEST_TIMEOUT));
    static ref REQUEST_PROTOCOL_MAP: Mutex<HashMap<u64, ProtocolId>> = Mutex::new(HashMap::new());
    static ref RESPONSE_CHANNEL_MAP: Mutex<HashMapDelay<u64, PendingResponse>> = Mutex::new(HashMapDelay::new(RESPONSE_CHANNEL_IDLE_TIMEOUT));
    static ref NETWORK_READY_CONDVAR: std::sync::Condvar = std::sync::Condvar::new();
    // #942 fix (post-bypass A/B verdict): the reconnect-scheduling
    // delay map used to live here as `RECONNECT_QUEUE: HashMapDelay`,
    // polled from arm 3 of the swarm task's biased `select!`. The bypass
    // build (883318f5) proved that gating both `schedule_reconnection`
    // call sites converted a deterministic 0/8-zeam-sync failure into
    // 5/8-success — i.e., this delay-map's interaction with the swarm
    // task was the primary trigger of the permanent waker-loss freeze.
    // Replaced with `tokio::spawn` + `tokio::time::sleep` +
    // `SwarmCommand::DialReconnect`: the delayed action is owned by a
    // detached task, not by the swarm task's polling tree.
    static ref RECONNECT_ATTEMPTS: Mutex<HashMap<(u32, PeerId), (Multiaddr, u32)>> = Mutex::new(HashMap::new());
    // Track connection directions for disconnect events (network_id, peer_id, connection_id) -> direction
    static ref CONNECTION_DIRECTIONS: Mutex<HashMap<(u32, PeerId, ConnectionId), u32>> = Mutex::new(HashMap::new());
    static ref COMMAND_SENDERS: Mutex<HashMap<u32, mpsc::Sender<SwarmCommand>>> = Mutex::new(HashMap::new());
    static ref COMMAND_RECEIVERS: Mutex<HashMap<u32, mpsc::Receiver<SwarmCommand>>> = Mutex::new(HashMap::new());

    // #942 fix: cache message_id_fn results so we don't re-decompress the same
    // raw-bytes payload on the gossipsub event-loop thread. With ~21 mesh
    // peers each forwarding the same block, the spec-mandated decompress
    // inside `message_id_fn` was running ~21x per block on the same thread
    // that drives quinn's QUIC poll futures. Devnet evidence pinned a ~10s
    // simultaneous freeze of every poll_read AND poll_write at slot 58→61,
    // which fits an accumulated burst of these synchronous decompresses
    // perfectly. The cache key is `sha2::Sha256(message.data)` (the raw
    // wire bytes); the value is the spec-conformant content-addressed id we
    // would otherwise have just recomputed. Bounded FIFO eviction so the
    // mutex stays small. See `cached_message_id_fn` below.
    static ref MESSAGE_ID_CACHE: Mutex<MessageIdCache> = Mutex::new(MessageIdCache::new(MESSAGE_ID_CACHE_CAPACITY));
}

/// Per-network cap. ~1024 distinct messages comfortably covers the ~12 s
/// gossipsub forward window across 21 mesh peers + heartbeats; tune up if
/// the eviction warning fires often post-deploy.
const MESSAGE_ID_CACHE_CAPACITY: usize = 1024;

/// Bounded FIFO cache keyed on the raw-bytes SHA256 of a gossipsub message.
/// Hits avoid the synchronous snappy-decompress inside `Behaviour::message_id_fn`
/// — see the comment on `MESSAGE_ID_CACHE`.
struct MessageIdCache {
    map: HashMap<[u8; 32], gossipsub::MessageId>,
    order: std::collections::VecDeque<[u8; 32]>,
    cap: usize,
    hits: u64,
    misses: u64,
}

impl MessageIdCache {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap),
            order: std::collections::VecDeque::with_capacity(cap),
            cap,
            hits: 0,
            misses: 0,
        }
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<gossipsub::MessageId> {
        if let Some(id) = self.map.get(key) {
            self.hits += 1;
            Some(id.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, key: [u8; 32], id: gossipsub::MessageId) {
        self.misses += 1;
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.map.insert(key, id);
        self.order.push_back(key);
    }
}

/// Current number of remote peers in this node's gossipsub mesh, across all
/// subscribed topics. Updated from inside the swarm task on the gossipsub
/// events that actually change mesh membership
/// (Subscribed/Unsubscribed/GossipsubNotSupported/SlowPeer — not Message),
/// on every connection close, and on a 1s liveness tick; read by Zig on
/// each Prometheus scrape via `get_mesh_peers_total`.
///
/// One fixed-size lock-free slot per network, indexed by `network_id`,
/// mirroring the `[AtomicU64; 3]` shape used by
/// `SWARM_COMMAND_DROPPED_TOTAL` (issue #808). The hardcoded slot table
/// at the top of this file (`get_swarm_mut`, `set_swarm`, …) caps live
/// networks at `MAX_NETWORKS = 3`, so we don't need a `Mutex<HashMap>`
/// to handle dynamic growth — and avoiding the mutex drops the
/// poisoning concern entirely (no `lock()`, no `unwrap()`, no
/// `Err(poisoned).into_inner()`).
///
/// Access uses `Relaxed` ordering — Prometheus scrapes are eventually
/// consistent and a one-tick lag is fine.
static MESH_PEERS_TOTAL: [AtomicU64; MAX_NETWORKS] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static RESPONSE_CHANNEL_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_RECONNECT_ATTEMPTS: u32 = 5;
const RECONNECT_DELAYS_SECS: [u64; 5] = [5, 10, 20, 40, 80];

#[derive(Clone)]
struct PendingResponse {
    peer_id: PeerId,
    connection_id: ConnectionId,
    stream_id: u64,
    protocol: ProtocolId,
}

/// Signal the event loop for `network_id` to exit.
///
/// Posts a shutdown notification on the per-network `Notify`. The event loop's
/// shutdown arm wakes up, breaks out of the select loop, clears the per-network
/// static state (swarm, handler, notify), and returns from `run_eventloop`,
/// which in turn lets `create_and_run_network` return and the hosting OS
/// thread exit. After calling this, the Zig side is expected to `join` the
/// rust-bridge thread.
///
/// Idempotent: a `stop_network` call for a network that was never started,
/// or that has already been torn down, is a no-op.
///
/// # Safety
///
/// This function is thread-safe and can be called from any thread.
#[no_mangle]
pub unsafe extern "C" fn stop_network(network_id: u32) {
    let _ = catch_ffi(|| {
        // Drop the command sender first so any new FFI publish/RPC sites that
        // call `send_swarm_command` (or look up the channel directly) see a
        // closed channel and bail out cleanly. The receiver is removed too —
        // its drop signals to the event loop that no more commands will
        // arrive — but we still rely on the shutdown notify to break the
        // outer `tokio::select!` because the loop's other arms (swarm events,
        // delay maps) keep firing independently.
        COMMAND_SENDERS.lock_recover().remove(&network_id);
        COMMAND_RECEIVERS.lock_recover().remove(&network_id);
        if let Some(notify) = get_shutdown_notify(network_id) {
            notify.notify_one();
        }
        // Reset the mesh-peers slot so repeated start/stop cycles don't show a
        // stale count from the previous run; `get_mesh_peers_total` returns 0
        // for slots that have never been written. The `[AtomicU64; MAX_NETWORKS]`
        // shape (#818) means there is no entry to remove — just a counter to
        // zero — and no mutex to poison on shutdown.
        if let Some(slot) = MESH_PEERS_TOTAL.get(network_id as usize) {
            slot.store(0, Ordering::Relaxed);
        }
    });
}

/// Wait for a network to be fully initialized and ready to accept messages.
/// Returns true if the network is ready, false on timeout.
///
/// # Safety
///
/// This function is thread-safe and can be called from any thread.
#[no_mangle]
pub unsafe extern "C" fn wait_for_network_ready(network_id: u32, timeout_ms: u64) -> bool {
    catch_ffi(|| {
        let timeout = Duration::from_millis(timeout_ms);
        let deadline = std::time::Instant::now() + timeout;

        // Park on the condvar using a sacrificial mutex; the condition we wake
        // for is checked against `NETWORK_SLOTS` directly so the slot map can
        // remain a regular `Mutex<HashMap>` without nesting awaits under it.
        let dummy = std::sync::Mutex::new(());
        let mut guard = dummy.lock_recover();
        loop {
            if is_network_ready(network_id) {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline - now;
            let (g, timeout_result) = match NETWORK_READY_CONDVAR.wait_timeout(guard, remaining) {
                Ok(result) => result,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard = g;
            if timeout_result.timed_out() {
                return is_network_ready(network_id);
            }
        }
    })
    .unwrap_or(false)
}

/// C-ABI parameters for [`create_and_run_network`].
///
/// `network_id` is followed by explicit padding so `zig_handler` is 8-byte aligned, matching Zig `extern struct`.
#[repr(C)]
pub struct CreateNetworkParams {
    pub network_id: u32,
    pub _padding: u32,
    pub zig_handler: u64,
    pub local_private_key: *const c_char,
    pub listen_addresses: *const c_char,
    pub connect_addresses: *const c_char,
}

/// # Safety
///
/// `params` must be non-null and valid until this function returns. String pointers must point to valid
/// null-terminated C strings for `listen_addresses`, `connect_addresses`, and `local_private_key`.
/// Gossipsub topic subscriptions are no longer passed here; Zig drives them
/// via `subscribe_gossip_topic_to_rust_bridge` after the network is up.
#[no_mangle]
pub unsafe extern "C" fn create_and_run_network(params: *const CreateNetworkParams) {
    if params.is_null() {
        return;
    }
    let p = &*params;
    let network_id = p.network_id;
    let zig_handler = p.zig_handler;
    let local_private_key = p.local_private_key;
    let listen_addresses = p.listen_addresses;
    let connect_addresses = p.connect_addresses;
    // Wrap the rest of the body in catch_unwind so a panic from the runtime,
    // parser, or libp2p does not unwind across the FFI boundary into Zig.
    let _ = catch_ffi(move || {
        create_and_run_network_inner(
            network_id,
            zig_handler,
            local_private_key,
            listen_addresses,
            connect_addresses,
        );
    });
}

unsafe fn create_and_run_network_inner(
    network_id: u32,
    zig_handler: u64,
    local_private_key: *const c_char,
    listen_addresses: *const c_char,
    connect_addresses: *const c_char,
) {
    // Register the handler early so any logs emitted from the parse/validation
    // path below are routed through the Zig logger.
    set_zig_handler(network_id, zig_handler);

    // Release the Zig-allocated parameter strings on every exit path from here on,
    // including parse failures, so the Zig side never leaks the buffers it handed us.
    let release_params = || {
        releaseStartNetworkParams(
            zig_handler,
            local_private_key,
            listen_addresses,
            connect_addresses,
        );
    };

    // Validate every C-string parameter before dereferencing. The Zig side
    // is supposed to hand us null-terminated valid UTF-8 strings, but a bug
    // there would otherwise be UB; explicit null checks turn it into a
    // clean error path.
    //
    // We deliberately do NOT call `release_params()` on this branch.
    // `releaseStartNetworkParams` (Zig side) declares its arguments as
    // `[*:0]const u8`, which is non-nullable; passing one of the offending
    // null pointers back would itself be UB inside `std.mem.span` on the
    // Zig side. Leaking the (presumably also null) buffers is the safer
    // recovery. This branch should be unreachable in practice — the Zig
    // caller never hands us nulls — and reaching it already means the Zig
    // side has a bug; we just want to avoid compounding it.
    if local_private_key.is_null() || listen_addresses.is_null() || connect_addresses.is_null() {
        logger::rustLogger.error(
            network_id,
            "create_and_run_network: null pointer in CreateNetworkParams string fields; not calling releaseStartNetworkParams (Zig side requires non-null)",
        );
        return;
    }

    let listen_str = CStr::from_ptr(listen_addresses).to_string_lossy();
    let listen_multiaddrs: Vec<Multiaddr> = match listen_str
        .split(",")
        .map(|addr| addr.parse::<Multiaddr>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => {
            logger::rustLogger.error(
                network_id,
                &format!("invalid listen multiaddress in \"{}\": {}", listen_str, e),
            );
            release_params();
            return;
        }
    };

    let connect_str = CStr::from_ptr(connect_addresses).to_string_lossy();
    let connect_multiaddrs: Vec<Multiaddr> = match connect_str
        .split(",")
        .filter(|s| !s.trim().is_empty()) // connect_addresses can be empty
        .map(|addr| addr.parse::<Multiaddr>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => {
            logger::rustLogger.error(
                network_id,
                &format!("invalid connect multiaddress in \"{}\": {}", connect_str, e),
            );
            release_params();
            return;
        }
    };

    let local_private_key_hex = CStr::from_ptr(local_private_key)
        .to_string_lossy()
        .into_owned();

    let private_key_hex = local_private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&local_private_key_hex);

    let mut private_key_bytes = match hex::decode(private_key_hex) {
        Ok(b) => b,
        Err(e) => {
            logger::rustLogger.error(
                network_id,
                &format!("invalid hex string for private key: {}", e),
            );
            release_params();
            return;
        }
    };

    let secret_key = match secp256k1::SecretKey::try_from_bytes(&mut private_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            logger::rustLogger.error(
                network_id,
                &format!("invalid secp256k1 private key bytes: {}", e),
            );
            release_params();
            return;
        }
    };
    let local_key_pair = Keypair::from(secp256k1::Keypair::from(secret_key));

    release_params();

    // #942: run the libp2p/quinn stack on a multi-threaded tokio runtime.
    //
    // Previously this was `new_current_thread()`, which drove BOTH the swarm
    // future (which calls the spec-mandated synchronous snappy decompress
    // inside `message_id_fn`) AND quinn's UDP endpoint-driver task on a single
    // thread. A 3.3MB block decompressing for hundreds of ms therefore starved
    // quinn's receive path mid-reassembly -> the cross-copy byte-bleed
    // corruption that only zeam exhibited. The healthy rust-libp2p clients
    // (grandine/ream) run multi-threaded executors, so quinn keeps draining the
    // socket on another worker while the swarm thread decompresses.
    //
    // Safe now that inbound gossip dispatch is on a dedicated worker thread
    // (run_inbound_gossip_worker) which preserves serial onGossip ordering
    // regardless of tokio flavor. 2 workers suffice: one runs the block_on'd
    // event loop, the other keeps the quinn endpoint driver live. Kept low to
    // avoid oversubscribing the box's rayon/chain-worker/libxev threads.
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let mut p2p_net = Network::new(network_id, zig_handler);
        let swarm = p2p_net
            .start_network(local_key_pair, listen_multiaddrs, connect_multiaddrs)
            .await;
        if let Some(swarm) = swarm {
            p2p_net.run_eventloop(swarm).await;
        } else {
            logger::rustLogger.error(
                network_id,
                "create_and_run_network: start_network failed; not entering event loop",
            );
            // Make sure subsequent FFI calls see a fresh slot if start_network
            // populated any partial state.
            clear_network_slot(network_id);
        }
    });
}

/// Get a clone of the per-network swarm command sender, if the network has
/// been initialized. Cloning lets us drop the `COMMAND_SENDERS` lock before
/// performing `try_send`, which is important because `try_send` can block
/// briefly on the channel's internal semaphore.
fn get_command_sender(network_id: u32) -> Option<mpsc::Sender<SwarmCommand>> {
    COMMAND_SENDERS.lock_recover().get(&network_id).cloned()
}

fn send_swarm_command(network_id: u32, cmd: SwarmCommand) -> bool {
    let tx = match get_command_sender(network_id) {
        Some(tx) => tx,
        None => {
            record_swarm_command_drop(SwarmCommandDropReason::Uninitialized);
            logger::rustLogger.error(network_id, "send_swarm_command: network not initialized");
            return false;
        }
    };
    match tx.try_send(cmd) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            record_swarm_command_drop(SwarmCommandDropReason::Full);
            logger::rustLogger.error(
                network_id,
                "send_swarm_command: command channel full, dropping command (slow drain or peer backpressure)",
            );
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            record_swarm_command_drop(SwarmCommandDropReason::Closed);
            logger::rustLogger.error(network_id, "send_swarm_command: command channel closed");
            false
        }
    }
}

/// # Safety
///
/// The caller must ensure that `message_str` points to valid memory of `message_len` bytes.
/// The caller must ensure that `topic` points to valid null-terminated C string.
///
/// Returns `true` if the publish command was successfully enqueued onto the
/// per-network swarm command channel, `false` if the publish was dropped
/// (network not initialized, channel full / closed, or null topic). Callers
/// should treat `false` as "this gossip message did not leave the host" and
/// surface it accordingly (metric, log, retry on next slot, etc.).
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn publish_msg_to_rust_bridge(
    network_id: u32,
    topic: *const c_char,
    message_str: *const u8,
    message_len: usize,
) -> bool {
    catch_ffi(|| {
        if message_str.is_null() && message_len != 0 {
            logger::rustLogger.error(
                network_id,
                "null pointer with non-zero len passed for `message_str` in publish_msg_to_rust_bridge",
            );
            return false;
        }
        if topic.is_null() {
            logger::rustLogger.error(
                network_id,
                "null pointer passed for `topic` in publish_msg_to_rust_bridge",
            );
            return false;
        }

        let message_slice = if message_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(message_str, message_len)
        };
        logger::rustLogger.debug(
            network_id,
            &format!(
                "publishing message s={:?}..({})",
                hex::encode(&message_slice[..message_len.min(100)]),
                message_len
            ),
        );
        let message_data = message_slice.to_vec();

        let topic = CStr::from_ptr(topic).to_string_lossy().to_string();

        send_swarm_command(
            network_id,
            SwarmCommand::Publish {
                topic,
                data: message_data,
            },
        )
    })
    .unwrap_or(false)
}

/// Enqueue a gossipsub mesh subscription for `topic` (full wire topic string).
///
/// Returns `true` when the subscribe command was successfully enqueued onto
/// the per-network swarm command channel, `false` when it was dropped (network
/// not initialized, channel full / closed, or null `topic`). The Zig side
/// treats `false` as a hard subscribe failure so a missed mesh join is
/// surfaced rather than silently leaving the node with an incomplete topic
/// set. Idempotency: gossipsub is fine with re-subscribing to the same topic
/// (the underlying call is a no-op for already-joined topics) so callers do
/// not need to dedupe.
///
/// # Safety
///
/// The caller must ensure that `topic` points to a valid null-terminated C string.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn subscribe_gossip_topic_to_rust_bridge(
    network_id: u32,
    topic: *const c_char,
) -> bool {
    if topic.is_null() {
        logger::rustLogger.error(
            network_id,
            "null pointer passed for `topic` in subscribe_gossip_topic_to_rust_bridge",
        );
        return false;
    }
    let topic = CStr::from_ptr(topic).to_string_lossy().to_string();
    send_swarm_command(network_id, SwarmCommand::SubscribeGossip { topic })
}

/// # Safety
///
/// The caller must ensure that `peer_id` points to a valid null-terminated C string.
/// The caller must ensure that `request_data` points to valid memory of `request_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn send_rpc_request(
    network_id: u32,
    peer_id: *const c_char,
    protocol_tag: u32,
    request_data: *const u8,
    request_len: usize,
) -> u64 {
    catch_ffi(|| {
        send_rpc_request_inner(network_id, peer_id, protocol_tag, request_data, request_len)
    })
    .unwrap_or(0)
}

unsafe fn send_rpc_request_inner(
    network_id: u32,
    peer_id: *const c_char,
    protocol_tag: u32,
    request_data: *const u8,
    request_len: usize,
) -> u64 {
    if peer_id.is_null() {
        logger::rustLogger.error(network_id, "null peer_id pointer in send_rpc_request");
        return 0;
    }
    if request_data.is_null() && request_len != 0 {
        logger::rustLogger.error(
            network_id,
            "null request_data pointer with non-zero len in send_rpc_request",
        );
        return 0;
    }
    let peer_id_str = CStr::from_ptr(peer_id).to_string_lossy().to_string();
    let peer_id: PeerId = match peer_id_str.parse() {
        Ok(id) => id,
        Err(e) => {
            logger::rustLogger.error(network_id, &format!("Invalid peer ID: {}", e));
            return 0;
        }
    };

    let request_slice = if request_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(request_data, request_len)
    };
    let request_bytes = request_slice.to_vec();

    let protocol = match LeanSupportedProtocol::try_from(protocol_tag) {
        Ok(protocol) => protocol,
        Err(_) => {
            logger::rustLogger.error(
                network_id,
                &format!(
                    "Invalid protocol tag {} provided for RPC request to {}",
                    protocol_tag, peer_id_str
                ),
            );
            return 0;
        }
    };

    let protocol_id: ProtocolId = protocol.into();

    // Acquire the sender first so we don't burn a request id on a network that
    // isn't initialized (or is shutting down). The id is still allocated
    // before `try_send` because the command needs to carry it; on send failure
    // we roll the counter back with a `fetch_sub` so ids are not leaked over
    // the lifetime of the process.
    let tx = match get_command_sender(network_id) {
        Some(tx) => tx,
        None => {
            record_swarm_command_drop(SwarmCommandDropReason::Uninitialized);
            logger::rustLogger.error(network_id, "send_rpc_request: network not initialized");
            return 0;
        }
    };

    let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    let request_message = RequestMessage::new(protocol_id.clone(), request_bytes);
    // NOTE: do NOT touch REQUEST_ID_MAP / REQUEST_PROTOCOL_MAP here — both
    // inserts now happen on the event-loop side (`SendRpcRequest` arm). See
    // the comment on `SendRpcRequest` for the rationale: `HashMapDelay::insert`
    // schedules a `tokio::time::sleep` for the entry timeout and panics if
    // called outside a Tokio runtime, but FFI entry points run on whatever
    // thread Zig calls in on (typically the libxev event loop), which has no
    // runtime attached. Issue #837.
    match tx.try_send(SwarmCommand::SendRpcRequest {
        peer_id,
        request_id,
        request_message,
    }) {
        Ok(()) => {}
        Err(e) => {
            // Roll the counter back so the id is not permanently leaked.
            REQUEST_ID_COUNTER.fetch_sub(1, Ordering::Relaxed);
            let (reason_label, reason_tag) = match e {
                mpsc::error::TrySendError::Full(_) => {
                    ("command channel full", SwarmCommandDropReason::Full)
                }
                mpsc::error::TrySendError::Closed(_) => {
                    ("command channel closed", SwarmCommandDropReason::Closed)
                }
            };
            record_swarm_command_drop(reason_tag);
            logger::rustLogger.error(
                network_id,
                &format!(
                    "send_rpc_request: failed to enqueue request: {}",
                    reason_label
                ),
            );
            return 0;
        }
    }
    logger::rustLogger.info(
        network_id,
        &format!(
            "[reqresp] Sent {:?} request to {} (id: {})",
            protocol, peer_id, request_id
        ),
    );
    request_id
}

/// # Safety
/// The caller must ensure that `response_data` points to valid memory of `response_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn send_rpc_response_chunk(
    network_id: u32,
    channel_id: u64,
    response_data: *const u8,
    response_len: usize,
) {
    let _ = catch_ffi(|| {
        send_rpc_response_chunk_inner(network_id, channel_id, response_data, response_len);
    });
}

unsafe fn send_rpc_response_chunk_inner(
    network_id: u32,
    channel_id: u64,
    response_data: *const u8,
    response_len: usize,
) {
    if response_data.is_null() && response_len != 0 {
        logger::rustLogger.error(
            network_id,
            "null response_data pointer with non-zero len in send_rpc_response_chunk",
        );
        return;
    }
    let response_slice = if response_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(response_data, response_len)
    };
    let response_bytes = response_slice.to_vec();

    // Look up the response channel and pass the resolved (peer_id,
    // connection_id, stream_id) inside the command. The executor side then
    // does not need to re-lock `RESPONSE_CHANNEL_MAP` to fan the chunk out,
    // which closes the race against `send_rpc_end_of_stream` / the
    // response-channel timeout sweep that would otherwise drop the chunk and
    // log a spurious `No response channel found` between the two locks.
    //
    // The idle-timeout refresh that used to live in this same locked block
    // was moved to the event-loop side: `HashMapDelay::update_timeout`
    // schedules a `tokio::time::sleep` and panics if called outside a Tokio
    // runtime, which is exactly what happens here when Zig's libxev thread
    // calls in. Refreshing on the executor side is also the more accurate
    // semantic — the timeout reflects "still actively serving" and we are
    // about to call `send_response` over there. #837
    let channel = RESPONSE_CHANNEL_MAP
        .lock_recover()
        .get(&channel_id)
        .cloned();
    if let Some(channel) = channel {
        let response_message = ResponseMessage::new(channel.protocol.clone(), response_bytes);
        send_swarm_command(
            network_id,
            SwarmCommand::SendRpcResponseChunk {
                channel_id,
                peer_id: channel.peer_id,
                connection_id: channel.connection_id,
                stream_id: channel.stream_id,
                response_message,
            },
        );
    } else {
        logger::rustLogger.error(
            network_id,
            &format!("No response channel found for id {}", channel_id),
        );
    }
}

/// # Safety
/// The caller must ensure the channel id is valid for a pending response.
#[no_mangle]
pub unsafe extern "C" fn send_rpc_end_of_stream(network_id: u32, channel_id: u64) {
    let _ = catch_ffi(|| {
        send_swarm_command(network_id, SwarmCommand::SendRpcEndOfStream { channel_id });
    });
}

/// # Safety
/// The caller must ensure `frame_ptr` points to valid memory of `frame_len` bytes.
///
/// `frame` is the complete error-response frame — result-code byte,
/// uncompressed-size varint, and snappy-framed message — already assembled on
/// the Zig side by `buildResponseFrame`. This FFI only relays the bytes and
/// closes the stream; mirrors `send_rpc_response_chunk` for success chunks.
#[no_mangle]
pub unsafe extern "C" fn send_rpc_error_response(
    network_id: u32,
    channel_id: u64,
    frame_ptr: *const u8,
    frame_len: usize,
) {
    let _ = catch_ffi(|| {
        send_rpc_error_response_inner(network_id, channel_id, frame_ptr, frame_len);
    });
}

unsafe fn send_rpc_error_response_inner(
    network_id: u32,
    channel_id: u64,
    frame_ptr: *const u8,
    frame_len: usize,
) {
    if frame_ptr.is_null() && frame_len != 0 {
        logger::rustLogger.error(
            network_id,
            &format!(
                "null frame_ptr with non-zero len in send_rpc_error_response for channel {}",
                channel_id
            ),
        );
        return;
    }

    if frame_len > crate::req_resp::configurations::max_message_size() {
        logger::rustLogger.error(
            network_id,
            &format!(
                "Attempted to send RPC error frame exceeding maximum size on channel {}",
                channel_id
            ),
        );
        return;
    }

    let payload = if frame_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(frame_ptr, frame_len).to_vec()
    };

    send_swarm_command(
        network_id,
        SwarmCommand::SendRpcErrorResponse {
            channel_id,
            payload,
        },
    );
}

extern "C" {
    fn handleMsgFromRustBridge(
        zig_handler: u64,
        topic: *const c_char,
        message_ptr: *const u8,
        message_len: usize,
        sender_peer_id: *const c_char,
    );
}

extern "C" {
    fn handleRPCRequestFromRustBridge(
        zig_handler: u64,
        channel_id: u64,
        peer_id: *const c_char,
        protocol_id: *const c_char,
        request_ptr: *const u8,
        request_len: usize,
    );

    fn handleRPCResponseFromRustBridge(
        zig_handler: u64,
        request_id: u64,
        peer_id: *const c_char,
        protocol_id: *const c_char,
        response_ptr: *const u8,
        response_len: usize,
    );

    fn handleRPCEndOfStreamFromRustBridge(
        zig_handler: u64,
        request_id: u64,
        peer_id: *const c_char,
        protocol_id: *const c_char,
    );

    fn handleRPCErrorFromRustBridge(
        zig_handler: u64,
        request_id: u64,
        protocol_id: *const c_char,
        code: u32,
        message: *const c_char,
    );
}

extern "C" {
    fn handlePeerConnectedFromRustBridge(
        zig_handler: u64,
        peer_id: *const c_char,
        direction: u32, // 0=inbound, 1=outbound, 2=unknown
    );
}

extern "C" {
    fn handlePeerDisconnectedFromRustBridge(
        zig_handler: u64,
        peer_id: *const c_char,
        direction: u32, // 0=inbound, 1=outbound, 2=unknown
        reason: u32,    // 0=timeout, 1=remote_close, 2=local_close, 3=error
    );
}

extern "C" {
    fn handlePeerConnectionFailedFromRustBridge(
        zig_handler: u64,
        peer_id: *const c_char, // may be null for unknown peers
        direction: u32,         // 0=inbound, 1=outbound
        result: u32,            // 1=timeout, 2=error
    );
}

extern "C" {
    fn releaseStartNetworkParams(
        zig_handler: u64,
        local_private_key: *const c_char,
        listen_addresses: *const c_char,
        connect_addresses: *const c_char,
    );
}

extern "C" {
    fn handleLogFromRustBridge(
        zig_handler: u64,
        level: u32,
        message_ptr: *const u8,
        message_len: usize,
    );
}

fn forward_log_with_handler(zig_handler: u64, level: u32, message: &str) {
    // The Zig log sink formats into a fixed 4096-byte stack buffer and does
    // `bufPrint(...) catch @panic` (log.zig), so a message that overflows the
    // buffer aborts the whole node. Defensively cap the message well below
    // that limit (leaving headroom for the Zig-side timestamp/scope prefix),
    // truncating on a UTF-8 char boundary, so an over-length line is truncated
    // rather than fatal.
    const MAX_LOG_BYTES: usize = 3500;
    let message = if message.len() > MAX_LOG_BYTES {
        let mut end = MAX_LOG_BYTES;
        while end > 0 && !message.is_char_boundary(end) {
            end -= 1;
        }
        &message[..end]
    } else {
        message
    };
    unsafe {
        handleLogFromRustBridge(zig_handler, level, message.as_ptr(), message.len());
    }
}

pub(crate) fn forward_log_by_network(network_id: u32, level: u32, message: &str) {
    if let Some(handler) = get_zig_handler(network_id) {
        forward_log_with_handler(handler, level, message);
    }
}

// Legacy rb_log_* helpers removed in favor of logger::rustLogger.*

pub struct Network {
    network_id: u32,
    zig_handler: u64,
    peer_addr_map: HashMap<PeerId, Multiaddr>,
}

impl Network {
    pub fn new(network_id: u32, zig_handler: u64) -> Self {
        Network {
            network_id,
            zig_handler,
            peer_addr_map: HashMap::new(),
        }
    }

    fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
        addr.iter().find_map(|proto| match proto {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
    }

    fn schedule_reconnection(&mut self, peer_id: PeerId, addr: Multiaddr, attempt: u32) {
        if attempt > MAX_RECONNECT_ATTEMPTS {
            logger::rustLogger.warn(
                self.network_id,
                &format!(
                    "Max reconnection attempts ({}) reached for peer {}, giving up",
                    MAX_RECONNECT_ATTEMPTS, addr
                ),
            );
            self.peer_addr_map.remove(&peer_id);
            RECONNECT_ATTEMPTS
                .lock_recover()
                .remove(&(self.network_id, peer_id));
            return;
        }

        let delay_secs = RECONNECT_DELAYS_SECS
            .get((attempt - 1) as usize)
            .copied()
            .unwrap_or(80);

        logger::rustLogger.info(
            self.network_id,
            &format!(
                "Scheduling reconnection to peer {} (attempt {}/{}) in {}s",
                addr, attempt, MAX_RECONNECT_ATTEMPTS, delay_secs
            ),
        );

        // #942 fix: the delayed action runs in a detached tokio task —
        // sleep + send a `SwarmCommand::DialReconnect`. The previous
        // implementation polled a `HashMapDelay` from arm 3 of the swarm
        // task's biased `select!`; that pollNext + the connection-error
        // body's interaction was the trigger for the permanent waker
        // loss that wedged 8/8 zeam nodes at slot ~65 on prior runs
        // (the bypass A/B test in 883318f5 produced 5/8 sync vs 0/8).
        // A detached task only touches the per-network swarm command
        // channel, which is the same channel Zig FFI dispatches use, so
        // we re-use the existing back-pressure / drop bookkeeping.
        let network_id = self.network_id;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            send_swarm_command(
                network_id,
                SwarmCommand::DialReconnect {
                    peer_id,
                    addr,
                    attempt,
                },
            );
        });
    }

    /// Build the swarm, bind listeners, dial connect peers, publish the per-network
    /// command channel, and mark the network ready. Returns the constructed
    /// swarm so `run_eventloop` can drive it directly. Returns `None` on bind
    /// failure (no listener succeeded); callers should not invoke
    /// `run_eventloop` in that case.
    pub(crate) async fn start_network(
        &mut self,
        key_pair: Keypair,
        listen_addresses: Vec<Multiaddr>,
        connect_addresses: Vec<Multiaddr>,
    ) -> Option<libp2p::swarm::Swarm<Behaviour>> {
        let mut swarm = new_swarm(key_pair, self.network_id);
        logger::rustLogger.info(self.network_id, "starting listener");

        let mut listen_success = false;
        for mut addr in listen_addresses {
            strip_peer_id(&mut addr);
            match swarm.listen_on(addr.clone()) {
                Ok(_) => {
                    logger::rustLogger.info(
                        self.network_id,
                        &format!("Successfully started listener on {}", addr),
                    );
                    listen_success = true;
                }
                Err(e) => {
                    logger::rustLogger.error(
                        self.network_id,
                        &format!("Failed to listen on {}: {:?}", addr, e),
                    );
                }
            }
        }

        if !listen_success {
            logger::rustLogger.error(
                self.network_id,
                "Failed to start listener on any address - network initialization failed",
            );
            // Signal failure by NOT setting the ready flag
            return None;
        }

        logger::rustLogger.debug(self.network_id, "going for loop match");

        if !connect_addresses.is_empty() {
            // helper closure for dialing peers
            let mut dial = |mut multiaddr: Multiaddr| {
                // strip the p2p protocol if it exists
                strip_peer_id(&mut multiaddr);
                match swarm.dial(multiaddr.clone()) {
                    Ok(()) => logger::rustLogger.debug(
                        self.network_id,
                        &format!("dialing libp2p peer address: {}", multiaddr),
                    ),
                    Err(err) => {
                        logger::rustLogger.error(
                            self.network_id,
                            &format!(
                                "could not connect to peer address: {} error: {:?}",
                                multiaddr, err
                            ),
                        );
                    }
                };
            };

            for addr in connect_addresses {
                if let Some(peer_id) = Self::extract_peer_id(&addr) {
                    self.peer_addr_map
                        .entry(peer_id)
                        .or_insert_with(|| addr.clone());
                } else {
                    logger::rustLogger.warn(
                        self.network_id,
                        &format!("Connect address missing peer id: {}", addr),
                    );
                }
                dial(addr);
            }
        } else {
            logger::rustLogger.debug(self.network_id, "no connect addresses");
        }

        // Set up actor model command channel
        let (cmd_tx, cmd_rx) = mpsc::channel::<SwarmCommand>(SWARM_COMMAND_CHANNEL_CAPACITY);
        COMMAND_SENDERS
            .lock_recover()
            .insert(self.network_id, cmd_tx);
        COMMAND_RECEIVERS
            .lock_recover()
            .insert(self.network_id, cmd_rx);

        // leanMetrics PR #35: with the fixed-size `[AtomicU64;
        // MAX_NETWORKS]` shape, slots are always present (default 0). No
        // explicit allocation is required. The 1s mesh-peers tick will
        // overwrite the slot with the real count on its first fire, and
        // the Subscribed/ConnectionClosed paths handle transitions in
        // between.

        // Install the shutdown signal *before* publishing readiness. Without
        // this, there is a window after `mark_network_ready` returns and
        // before `run_eventloop` runs where the slot reports `ready = true`
        // but `shutdown_notify` is still `None`. A `stop_network` issued in
        // that window would silently no-op its `notify_one()` call (because
        // `get_shutdown_notify` returns `None`), and the permit would be
        // lost. Installing here makes "ready ⇒ shutdown_notify present" a
        // hard invariant from any concurrent observer's point of view; the
        // event loop just looks up the already-installed handle on entry.
        // `notify_one` stores a permit if no waiter is parked yet, so a
        // `stop_network` that lands between this line and the first
        // `.notified().await` is still observed on the first poll.
        let _ = install_shutdown_notify(self.network_id);

        // Signal that this network is now ready
        mark_network_ready(self.network_id);

        logger::rustLogger.info(self.network_id, "network initialization complete and ready");
        Some(swarm)
    }

    pub(crate) async fn run_eventloop(&mut self, mut swarm: libp2p::swarm::Swarm<Behaviour>) {
        // Borrow `&mut swarm` once so the rest of the body can match the
        // pre-refactor shape (`swarm.dial(...)`, `swarm.behaviour_mut()`, etc.)
        // without further changes.
        let swarm = &mut swarm;

        let mut cmd_rx = match COMMAND_RECEIVERS.lock_recover().remove(&self.network_id) {
            Some(rx) => rx,
            None => {
                logger::rustLogger.error(
                    self.network_id,
                    "run_eventloop called before start_network set up command channel; aborting",
                );
                return;
            }
        };

        // The shutdown signal is installed by `start_network` *before* it
        // marks the network ready, so any `stop_network` racing the
        // start→eventloop handoff has a `Notify` to post on. Here we just
        // pick up the handle that was placed on the slot. If it is somehow
        // missing the slot has been torn down out from under us — bail
        // rather than silently install a fresh one and lose any permit
        // already posted on the original.
        let shutdown = match get_shutdown_notify(self.network_id) {
            Some(n) => n,
            None => {
                logger::rustLogger.error(
                    self.network_id,
                    "run_eventloop: shutdown_notify not installed by start_network; aborting",
                );
                return;
            }
        };

        // leanMetrics PR #35: 1s liveness tick that recomputes the gossipsub
        // mesh-peer count even when no swarm/gossipsub events are firing.
        // Gossipsub events should already cover all transitions; the tick is
        // defensive so an idle topic still reports a fresh value on scrape.
        let mut mesh_peers_tick = tokio::time::interval(Duration::from_secs(1));
        mesh_peers_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // #942 fix-#5 follow-up: per-substream QUIC diag lines run in their own
        // tokio task. The previous in-arm version sat in the LAST arm of this
        // function's biased select! and devnet evidence (slot 65 onward) showed
        // it was starved as soon as reqresp-status retries became continuous,
        // exactly when the freeze deepened. The spawned task only reads atomic
        // counters from the SUBSTREAMS registries and does not need swarm
        // access, so it keeps emitting through the freeze.
        spawn_quic_diag_emitter(self.network_id, shutdown.clone());

        // #942: hand inbound gossip off to a dedicated decode worker thread so
        // the synchronous snappy-decompress + SSZ-deserialize + chain dispatch
        // does not block this tokio thread, which also drives quinn's QUIC I/O.
        // A single worker keeps `onGossip` serialized exactly as it was when the
        // call ran inline below.
        let (gossip_tx, gossip_rx) =
            std::sync::mpsc::sync_channel::<InboundGossip>(INBOUND_GOSSIP_CHANNEL_CAPACITY);
        let gossip_worker = std::thread::Builder::new()
            .name(format!("zeam-gossip-decode-{}", self.network_id))
            .spawn(move || run_inbound_gossip_worker(gossip_rx))
            .expect("failed to spawn inbound gossip decode worker thread");

        // #942 fix: reqresp FFI dispatch also off the event-loop thread.
        // The 15 s arm-body spikes observed on the 883318f5 devnet were
        // SwarmEvent::Behaviour(Reqresp(_)) bodies running synchronous
        // snappy-framed-decompress + SSZ-deserialize + chain dispatch on
        // the swarm task; mirrors the gossip worker pattern above.
        let (rpc_tx, rpc_rx) =
            std::sync::mpsc::sync_channel::<RpcWork>(INBOUND_RPC_CHANNEL_CAPACITY);
        let rpc_worker = std::thread::Builder::new()
            .name(format!("zeam-rpc-dispatch-{}", self.network_id))
            .spawn(move || run_inbound_rpc_worker(rpc_rx))
            .expect("failed to spawn inbound reqresp dispatch worker thread");

        // #942 diagnosis: throttle the per-kind gossip-arrival summary to roughly
        // every 10th mesh_peers tick (~10s) so the log shows the block/attestation
        // delivery trend without flooding.
        let mut diag_tick_count: u64 = 0;

        'eventloop: loop {
            // Measure wall-clock spent inside this iteration's `select!`
            // (which includes the chosen arm's synchronous body). Devnet
            // evidence (slot 58→61, simultaneous bidirectional freeze of
            // every poll_read AND poll_write) implies one arm body ran
            // synchronously for ~10 s, since both directions are driven by
            // this single task. The `dt_ms` capture below pins which
            // iteration spent the time.
            let iter_start = std::time::Instant::now();

            tokio::select! {
            biased;

            _ = shutdown.notified() => {
                enter_arm(1);
                logger::rustLogger.info(
                    self.network_id,
                    "stop_network signaled; exiting libp2p event loop",
                );
                break 'eventloop;
            }

            Some(timeout_result) = poll_fn(|cx| {
                let mut map = REQUEST_ID_MAP.lock_recover();
                std::pin::Pin::new(&mut *map).poll_next(cx)
            }) => {
                enter_arm(2);
                match timeout_result {
                    Ok((request_id, ())) => {
                        logger::rustLogger.warn(
                            self.network_id,
                            &format!("[reqresp] Request {} timed out after {:?}", request_id, REQUEST_TIMEOUT),
                        );
                        if let Some(protocol_id) = REQUEST_PROTOCOL_MAP
                            .lock_recover()
                            .remove(&request_id)
                        {
                            if let (Ok(protocol_cstring), Ok(message_cstring)) = (
                                CString::new(protocol_id.as_str()),
                                CString::new("request timed out"),
                            ) {
                                let work = RpcWork::Error {
                                    zig_handler: self.zig_handler,
                                    request_id,
                                    protocol: protocol_cstring,
                                    code: 408,
                                    message: message_cstring,
                                };
                                if let Err(e) = rpc_tx.try_send(work) {
                                    let total = INBOUND_RPC_DROPPED_TOTAL
                                        .fetch_add(1, Ordering::Relaxed) + 1;
                                    logger::rustLogger.warn(
                                        self.network_id,
                                        &format!(
                                            "[#942] inbound reqresp dispatch queue full (cap={}); dropped Timeout (total={}): {:?}",
                                            INBOUND_RPC_CHANNEL_CAPACITY,
                                            total,
                                            e,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        logger::rustLogger.error(self.network_id, &format!("[reqresp] Error in delay map: {}", e));
                    }
                }
            }

            // arm 3 (RECONNECT_QUEUE poll_next) removed in #942 fix: the
            // delay-map polled here was the trigger of the swarm-task
            // waker loss. Reconnect dials are now driven by
            // `SwarmCommand::DialReconnect` posted by detached
            // `tokio::spawn`s in `schedule_reconnection`.

            Some(response_channel_timeout) = poll_fn(|cx| {
                let mut map = RESPONSE_CHANNEL_MAP.lock_recover();
                std::pin::Pin::new(&mut *map).poll_next(cx)
            }) => {
                enter_arm(4);
                match response_channel_timeout {
                    Ok((channel_id, channel)) => {
                        logger::rustLogger.warn(
                            self.network_id,
                            &format!(
                                "[reqresp] Response channel {} expired after {:?} (peer: {}, protocol: {})",
                                channel_id,
                                RESPONSE_CHANNEL_IDLE_TIMEOUT,
                                channel.peer_id,
                                channel.protocol.as_str(),
                            ),
                        );

                        // Best-effort: close the response stream so the remote does not hang.
                        swarm.behaviour_mut().reqresp.finish_response_stream(
                            channel.peer_id,
                            channel.connection_id,
                            channel.stream_id,
                        );
                    }
                    Err(e) => {
                        logger::rustLogger.error(
                            self.network_id,
                            &format!("[reqresp] Error in response channel delay map: {}", e),
                        );
                    }
                }
            }

            // NOTE on arm ordering: with `biased;` above, arms are polled in source
            // order. Swarm event polling MUST come before the FFI command arm so a
            // burst of commands cannot starve gossip ingestion / reqresp completion
            // (i.e. swarm events get a chance every loop iteration). The command
            // arm additionally caps each iteration at MAX_SWARM_COMMANDS_PER_TICK so
            // we never sit inside it indefinitely.
                event = swarm.select_next_some() => {
                    enter_arm(5);
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            enter_swarm_event(1);
                            logger::rustLogger.info(self.network_id, &format!("Listening on {}", address));
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id, .. } => {
                            enter_swarm_event(2);
                            let peer_id_str = peer_id.to_string();

                            // Determine direction from endpoint: Dialer=outbound, Listener=inbound
                            let direction: u32 = if endpoint.is_dialer() { 1 } else { 0 };

                            // If this was an outbound connection, remember the address we successfully dialed.
                            // This enables reconnection even when the initial connect multiaddr did not include
                            // a `/p2p/<peer_id>` component (in which case we couldn't pre-populate `peer_addr_map`).
                            if let core::connection::ConnectedPoint::Dialer { address, .. } = &endpoint {
                                self.peer_addr_map
                                    .entry(peer_id)
                                    .or_insert_with(|| address.clone());
                            }

                            logger::rustLogger.info(
                                self.network_id,
                                &format!("Connection established with peer: {} direction={}",
                                    peer_id_str,
                                    if direction == 0 { "inbound" } else { "outbound" }),
                            );

                            // Store direction for later use on disconnect
                            CONNECTION_DIRECTIONS.lock_recover().insert(
                                (self.network_id, peer_id, connection_id),
                                direction,
                            );

                            // RECONNECT_QUEUE removed; pending DialReconnect commands for
                            // this peer become no-ops via the swarm.is_connected() guard
                            // in the cmd_rx handler.
                            RECONNECT_ATTEMPTS
                                .lock_recover()
                                .remove(&(self.network_id, peer_id));
                            let peer_id_cstr = match CString::new(peer_id_str.as_str()) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    logger::rustLogger.error(self.network_id, &format!("invalid_peer_id_string={}", peer_id_str));
                                    continue;
                                }
                            };
                            unsafe {
                                handlePeerConnectedFromRustBridge(self.zig_handler, peer_id_cstr.as_ptr(), direction)
                            };
                        }
                            SwarmEvent::ConnectionClosed {
                                peer_id,
                                connection_id,
                                cause,
                                ..
                            } => {
                                enter_swarm_event(3);
                                // leanMetrics PR #35: a peer leaving may evict
                                // it from the gossipsub mesh; recompute first
                                // so the metric reflects the new state even if
                                // a `continue` below skips out early.
                                let mesh_count = swarm.behaviour().gossipsub.all_mesh_peers().count() as u64;
                                record_mesh_peers(self.network_id, mesh_count);

                                let peer_id_string = peer_id.to_string();

                            // Retrieve and remove stored direction
                            let direction = CONNECTION_DIRECTIONS
                                .lock_recover()
                                .remove(&(self.network_id, peer_id, connection_id))
                                .unwrap_or(2); // 2 = unknown if not found

                            // Map cause to reason enum: 0=timeout, 1=remote_close, 2=local_close, 3=error
                            let reason: u32 = match &cause {
                                None => 1, // remote_close (graceful close, no error)
                                Some(err) => {
                                    let err_str = format!("{:?}", err);
                                    if err_str.contains("Timeout") || err_str.contains("timeout") || err_str.contains("TimedOut") || err_str.contains("KeepAlive") {
                                        0 // timeout
                                    } else if err_str.contains("Reset") || err_str.contains("ConnectionReset") {
                                        1 // remote_close
                                    } else {
                                        3 // error (generic)
                                    }
                                }
                            };

                                let cause_desc = match &cause {
                                    Some(err) => format!("{err:?}"),
                                    None => "None".to_string(),
                                };
                                logger::rustLogger.info(
                                    self.network_id,
                                    &format!(
                                        "Connection closed: peer={} connection_id={:?} direction={} reason={} cause={}",
                                        peer_id_string, connection_id, direction, reason, cause_desc
                                    ),
                                );

                                // Drop any pending response channels tied to this connection.
                                // We can't finish streams here (the connection is already gone), but we must
                                // remove them from the map to avoid leaking entries until idle TTL.
                                RESPONSE_CHANNEL_MAP.lock_recover().retain(|_, pending| {
                                    !(pending.peer_id == peer_id && pending.connection_id == connection_id)
                                });

                                // `ConnectionClosed` is emitted per connection. If the peer still has other
                                // established connections, avoid emitting a peer-disconnected event to Zig
                                // and avoid scheduling reconnection.
                                if swarm.is_connected(&peer_id) {
                                    logger::rustLogger.debug(
                                        self.network_id,
                                        &format!(
                                            "Peer {} still has an established connection; skipping disconnect notification/reconnect",
                                            peer_id_string
                                        ),
                                    );
                                    continue;
                                }

                                let peer_id_cstr = match CString::new(peer_id_string.as_str()) {
                                    Ok(cstr) => cstr,
                                    Err(_) => {
                                        logger::rustLogger.error(self.network_id, &format!("invalid_peer_id_string={}", peer_id));
                                        continue;
                                    }
                                };
                                unsafe {
                                    handlePeerDisconnectedFromRustBridge(
                                        self.zig_handler,
                                        peer_id_cstr.as_ptr(),
                                        direction,
                                        reason,
                                    )
                                };

                                if let Some(peer_addr) = self.peer_addr_map.get(&peer_id).cloned() {
                                    self.schedule_reconnection(peer_id, peer_addr, 1);
                                }
                            }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            enter_swarm_event(4);
                            let peer_str = peer_id.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string());

                            // Determine if timeout or other error: 1=timeout, 2=error
                            let result: u32 = {
                                let err_str = format!("{:?}", error);
                                if err_str.contains("Timeout") || err_str.contains("timeout") {
                                    1 // timeout
                                } else {
                                    2 // error
                                }
                            };

                            logger::rustLogger.warn(
                                self.network_id,
                                &format!("Outgoing connection failed: peer={} error={:?} result={}", peer_str, error, result),
                            );

                            // Notify Zig of failed connection attempt and handle reconnection
                            if let Some(pid) = peer_id {
                                let peer_id_cstr = match CString::new(pid.to_string()) {
                                    Ok(cstr) => cstr,
                                    Err(_) => {
                                        // Invalid peer_id string - can't communicate with Zig, don't retry
                                        logger::rustLogger.error(self.network_id, &format!("invalid_peer_id_string={}", pid));
                                        continue;
                                    }
                                };
                                unsafe {
                                    handlePeerConnectionFailedFromRustBridge(
                                        self.zig_handler,
                                        peer_id_cstr.as_ptr(),
                                        1, // outbound
                                        result,
                                    )
                                };

                                // Schedule reconnection if this was a tracked connection attempt.
                                //
                                // IMPORTANT: bind the `.remove()` result to a let *before* the
                                // `if let`, so the `RECONNECT_ATTEMPTS` MutexGuard is dropped
                                // at the end of the let-statement instead of living until the
                                // end of the if-let block (Rust 2021 temporary-scope rules).
                                // `schedule_reconnection` re-acquires the same Mutex on the
                                // `attempt > MAX_RECONNECT_ATTEMPTS` branch — with the guard
                                // still held, that's a re-entrant std::Mutex deadlock on the
                                // same thread, which is exactly the wedge that re-appeared
                                // on the c6cf2241 devnet run (all 8 zeam nodes frozen with
                                // `swarm_ev_var=4(OutgoingConnectionError) age=1000s+`,
                                // probabilistic because it only triggers once a peer's
                                // attempt count climbs past 5).
                                let prior_attempt = RECONNECT_ATTEMPTS
                                    .lock_recover()
                                    .remove(&(self.network_id, pid));
                                if let Some((addr, attempt)) = prior_attempt {
                                    self.schedule_reconnection(pid, addr, attempt + 1);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub_event)) => {
                            enter_swarm_event(5);
                            // leanMetrics PR #35: gate the mesh-peer recompute on
                            // the gossipsub event variants that actually change
                            // mesh membership. `Message` does NOT — a busy node
                            // can deliver hundreds of `Message` events per second
                            // and the prior "recompute on every event" path
                            // turned the metric refresh into O(peers²) cumulative
                            // work just for the gauge.
                            //
                            // Variants that DO change mesh membership:
                            //   * `Subscribed` / `Unsubscribed` — a peer joined or
                            //     left a topic this node subscribes to.
                            //   * `GossipsubNotSupported` — a connected peer
                            //     turned out not to speak gossipsub; gossipsub
                            //     drops it from any future mesh.
                            //   * `SlowPeer` — gossipsub may evict the peer from
                            //     the mesh under backpressure.
                            //
                            // The 1s liveness tick (`mesh_peers_tick.tick()`) and
                            // the `ConnectionClosed` recompute already cover
                            // "events occurred outside this branch" so a missed
                            // gauge update inside `Message` cannot drift longer
                            // than ~1s in the worst case. `all_mesh_peers().count()`
                            // is itself O(peers) and lock-free for the atomic
                            // store — the cost we are avoiding here is the
                            // walk per event, not the store.
                            let mesh_changed = matches!(
                                gossipsub_event,
                                gossipsub::Event::Subscribed { .. }
                                    | gossipsub::Event::Unsubscribed { .. }
                                    | gossipsub::Event::GossipsubNotSupported { .. }
                                    | gossipsub::Event::SlowPeer { .. }
                            );
                            if mesh_changed {
                                let mesh_count =
                                    swarm.behaviour().gossipsub.all_mesh_peers().count() as u64;
                                record_mesh_peers(self.network_id, mesh_count);
                            }

                            if let gossipsub::Event::Message { message, .. } = gossipsub_event {
                                // #942: do NOT decode here. The full
                                // snappy-decompress + SSZ-deserialize + chain
                                // dispatch (`handleMsgFromRustBridge`) used to
                                // run inline on this thread, which also drives
                                // quinn's QUIC I/O. On a 286 KB–9 MB block that
                                // blocked the event loop for hundreds of ms,
                                // starving the QUIC receive path — the root
                                // cause of the inbound snappy corruption (the
                                // cross-message byte-bleed in issue_942_layer.md)
                                // and the earlier 148 broken QUIC handshakes / 8
                                // Status-RPC timeouts. We now only build the
                                // hand-off record (cheap) and pass ownership of
                                // the payload to the decode worker thread; the
                                // ingress sha256 forensic log moved there too.
                                let topic_str = message.topic.as_str();
                                // #942 diagnosis: count this DELIVERED message by
                                // topic kind before any decode work, so the
                                // periodic log can show whether block-topic
                                // delivery has gone silent while the mesh is up.
                                GOSSIP_RECV_BY_KIND_TOTAL[gossip_topic_kind_index(topic_str)]
                                    .fetch_add(1, Ordering::Relaxed);
                                let topic = match CString::new(topic_str) {
                                    Ok(cstr) => cstr,
                                    Err(_) => {
                                        logger::rustLogger.error(self.network_id, &format!("invalid_topic_string={}", topic_str));
                                        continue;
                                    }
                                };

                                let sender_peer_id_string = message.source.map(|p| p.to_string()).unwrap_or_else(|| "unknown_peer".to_string());
                                let sender_peer_id = match CString::new(sender_peer_id_string.as_str()) {
                                    Ok(cstring) => cstring,
                                    Err(_) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            &format!("Failed to create C string for peer id {}", sender_peer_id_string),
                                        );
                                        continue;
                                    }
                                };

                                let work = InboundGossip {
                                    network_id: self.network_id,
                                    zig_handler: self.zig_handler,
                                    topic,
                                    sender_peer_id,
                                    // Move the owned payload off the event loop;
                                    // the worker holds it for the FFI call.
                                    data: message.data,
                                };

                                match gossip_tx.try_send(work) {
                                    Ok(()) => {}
                                    Err(std::sync::mpsc::TrySendError::Full(dropped)) => {
                                        let total = INBOUND_GOSSIP_DROPPED_TOTAL
                                            .fetch_add(1, Ordering::Relaxed)
                                            + 1;
                                        logger::rustLogger.warn(self.network_id, &format!(
                                            "[#942] inbound gossip decode queue full (cap={}); dropped topic={} len={} (dropped_total={}). Missed block recoverable via blocks_by_root/range RPC sync.",
                                            INBOUND_GOSSIP_CHANNEL_CAPACITY,
                                            dropped.topic.to_string_lossy(),
                                            dropped.data.len(),
                                            total,
                                        ));
                                    }
                                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            "[#942] inbound gossip decode worker gone; dropping message",
                                        );
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Reqresp(ReqRespMessage {
                            peer_id,
                            connection_id,
                            message,
                        })) => {
                            enter_swarm_event(6);
                            match message {
                            Ok(ReqRespMessageReceived::Request { stream_id, message }) => {
                                let request_message = *message;
                                let protocol = request_message.protocol.clone();
                                let payload = request_message.payload;
                                logger::rustLogger.info(
                                    self.network_id,
                                    &format!("[reqresp] Received request from {} for protocol {} ({} bytes)", peer_id, protocol.as_str(), payload.len()),
                                );

                                let channel_id =
                                    RESPONSE_CHANNEL_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
                                RESPONSE_CHANNEL_MAP.lock_recover().insert(
                                    channel_id,
                                    PendingResponse {
                                        peer_id,
                                        connection_id,
                                        stream_id,
                                        protocol: protocol.clone(),
                                    },
                                );

                                let peer_id_string = peer_id.to_string();
                                let peer_id_cstring = match CString::new(peer_id_string) {
                                    Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            &format!("[reqresp] Failed to create C string for peer id {}: {}", peer_id, err),
                                        );
                                        continue;
                                    }
                                };

                                let protocol_cstring = match CString::new(protocol.as_str()) {
                                    Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            &format!("[reqresp] Failed to create C string for protocol {}: {}", protocol.as_str(), err),
                                        );
                                        continue;
                                    }
                                };

                                // Hand off to the reqresp worker thread; the
                                // FFI call's synchronous snappy + SSZ +
                                // chain work used to stall the swarm task
                                // for many seconds (see RpcWork comment).
                                let work = RpcWork::Request {
                                    zig_handler: self.zig_handler,
                                    channel_id,
                                    peer_id: peer_id_cstring,
                                    protocol: protocol_cstring,
                                    payload,
                                };
                                if let Err(e) = rpc_tx.try_send(work) {
                                    let total = INBOUND_RPC_DROPPED_TOTAL
                                        .fetch_add(1, Ordering::Relaxed) + 1;
                                    logger::rustLogger.warn(
                                        self.network_id,
                                        &format!(
                                            "[#942] inbound reqresp dispatch queue full (cap={}); dropped Request (total={}): {:?}",
                                            INBOUND_RPC_CHANNEL_CAPACITY,
                                            total,
                                            e,
                                        ),
                                    );
                                }
                            }
                            Ok(ReqRespMessageReceived::Response { request_id, message }) => {
                                {
                                    let mut map = REQUEST_ID_MAP.lock_recover();
                                    if !map.update_timeout(&request_id, REQUEST_TIMEOUT) {
                                        map.insert(request_id, ());
                                    }
                                }
                                let response_message = *message;
                                logger::rustLogger.info(
                                    self.network_id,
                                    &format!("[reqresp] Received response from {} for request id {} ({} bytes)", peer_id, request_id, response_message.payload.len()),
                                );
                                let peer_id_string = peer_id.to_string();
                                let peer_id_cstring = match CString::new(peer_id_string) {
                                    Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            &format!("[reqresp] Failed to create C string for peer id {}: {}", peer_id, err),
                                        );
                                        continue;
                                    }
                                };
                                let protocol_cstring = match CString::new(
                                    response_message.protocol.as_str(),
                                ) {
                                    Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            &format!("[reqresp] Failed to create C string for protocol {}: {}", response_message.protocol.as_str(), err),
                                        );
                                        continue;
                                    }
                                };

                                // Hand off to the reqresp worker thread. The
                                // synchronous Zig handler does snappy-framed
                                // decompress + SSZ deserialize + chain
                                // dispatch (handleRPCResponseFromRustBridge);
                                // on the 883318f5 devnet this stalled the
                                // swarm task for ~15 s per large response.
                                let work = RpcWork::Response {
                                    zig_handler: self.zig_handler,
                                    request_id,
                                    peer_id: peer_id_cstring,
                                    protocol: protocol_cstring,
                                    payload: response_message.payload,
                                };
                                if let Err(e) = rpc_tx.try_send(work) {
                                    let total = INBOUND_RPC_DROPPED_TOTAL
                                        .fetch_add(1, Ordering::Relaxed) + 1;
                                    logger::rustLogger.warn(
                                        self.network_id,
                                        &format!(
                                            "[#942] inbound reqresp dispatch queue full (cap={}); dropped Response (total={}): {:?}",
                                            INBOUND_RPC_CHANNEL_CAPACITY,
                                            total,
                                            e,
                                        ),
                                    );
                                }
                            }
                            Ok(ReqRespMessageReceived::EndOfStream { request_id }) => {
                                REQUEST_ID_MAP.lock_recover().remove(&request_id);
                                let protocol = REQUEST_PROTOCOL_MAP
                                    .lock_recover()
                                    .remove(&request_id);

                                if let Some(protocol_id) = protocol {
                                    let peer_id_string = peer_id.to_string();
                                    let peer_id_cstring = match CString::new(peer_id_string) {
                                        Ok(cstring) => cstring,
                                        Err(err) => {
                                            logger::rustLogger.error(
                                                self.network_id,
                                                &format!("[reqresp] Failed to create C string for peer id {} on end-of-stream: {}", peer_id, err),
                                            );
                                            continue;
                                        }
                                    };
                                    let protocol_cstring = match CString::new(protocol_id.as_str()) {
                                        Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::rustLogger.error(
                                            self.network_id,
                                            &format!("[reqresp] Failed to create C string for protocol {} on end-of-stream: {}", protocol_id.as_str(), err),
                                        );
                                            continue;
                                        }
                                    };

                                    let work = RpcWork::EndOfStream {
                                        zig_handler: self.zig_handler,
                                        request_id,
                                        peer_id: peer_id_cstring,
                                        protocol: protocol_cstring,
                                    };
                                    if let Err(e) = rpc_tx.try_send(work) {
                                        let total = INBOUND_RPC_DROPPED_TOTAL
                                            .fetch_add(1, Ordering::Relaxed) + 1;
                                        logger::rustLogger.warn(
                                            self.network_id,
                                            &format!(
                                                "[#942] inbound reqresp dispatch queue full (cap={}); dropped EndOfStream (total={}): {:?}",
                                                INBOUND_RPC_CHANNEL_CAPACITY,
                                                total,
                                                e,
                                            ),
                                        );
                                    }
                                } else {
                                    logger::rustLogger.warn(
                                        self.network_id,
                                        &format!("[reqresp] Received end-of-stream for request id {} without protocol mapping", request_id),
                                    );
                                }
                            }
                            Err(ReqRespMessageError::Inbound { stream_id, err }) => {
                                logger::rustLogger.error(
                                    self.network_id,
                                    &format!("[reqresp] Inbound error from {} on stream {}: {:?}", peer_id, stream_id, err),
                                );
                                RESPONSE_CHANNEL_MAP
                                    .lock_recover()
                                    .retain(|_, pending| {
                                        !(
                                            pending.peer_id == peer_id
                                                && pending.connection_id == connection_id
                                                && pending.stream_id == stream_id
                                        )
                                    });
                            }
                            Err(ReqRespMessageError::Outbound { request_id, err }) => {
                                REQUEST_ID_MAP.lock_recover().remove(&request_id);
                                let protocol = REQUEST_PROTOCOL_MAP
                                    .lock_recover()
                                    .remove(&request_id);

                                if let Some(protocol_id) = protocol {
                                    if let (Ok(protocol_cstring), Ok(message_cstring)) = (
                                        CString::new(protocol_id.as_str()),
                                        CString::new(format!("{:?}", err)),
                                    ) {
                                        let work = RpcWork::Error {
                                            zig_handler: self.zig_handler,
                                            request_id,
                                            protocol: protocol_cstring,
                                            code: 3,
                                            message: message_cstring,
                                        };
                                        if let Err(e) = rpc_tx.try_send(work) {
                                            let total = INBOUND_RPC_DROPPED_TOTAL
                                                .fetch_add(1, Ordering::Relaxed) + 1;
                                            logger::rustLogger.warn(
                                                self.network_id,
                                                &format!(
                                                    "[#942] inbound reqresp dispatch queue full (cap={}); dropped OutboundError (total={}): {:?}",
                                                    INBOUND_RPC_CHANNEL_CAPACITY,
                                                    total,
                                                    e,
                                                ),
                                            );
                                        }
                                    }
                                }
                                logger::rustLogger.error(
                                    self.network_id,
                                    &format!("[reqresp] Outbound error for request {} with {}: {:?}", request_id, peer_id, err),
                                );
                            }
                        }
                        }
                        e => {
                            enter_swarm_event(99);
                            logger::rustLogger.debug(self.network_id, &format!("{:?}", e));
                        }
                    }
                }

            // Drain a bounded burst of swarm commands per loop iteration. We
            // pull up to `MAX_SWARM_COMMANDS_PER_TICK` commands here (without
            // awaiting between them, so we never yield in the middle of a
            // burst), then break out so the next `select!` iteration can
            // service swarm events / timeouts. The combination of `biased;`
            // (above) plus this cap means a flood of FFI publishes cannot
            // starve gossip ingestion or reqresp event handling.
            Some(first_cmd) = cmd_rx.recv() => {
                enter_arm(6);
                let mut cmd = first_cmd;
                let mut drained = 0usize;
                loop {
                    match cmd {
                    SwarmCommand::SubscribeGossip { topic } => {
                        enter_swarm_command(1);
                        let gossipsub_topic = gossipsub::IdentTopic::new(topic.clone());
                        if let Err(e) =
                            swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic)
                        {
                            logger::rustLogger.error(
                                self.network_id,
                                &format!("SubscribeGossip error for topic {topic}: {e:?}"),
                            );
                        } else {
                            logger::rustLogger.debug(
                                self.network_id,
                                &format!("Subscribed gossipsub mesh: {topic}"),
                            );
                        }
                    }
                    SwarmCommand::Publish { topic, data } => {
                        enter_swarm_command(2);
                        let t = gossipsub::IdentTopic::new(topic);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(t, data) {
                            logger::rustLogger.error(self.network_id, &format!("Publish error: {e:?}"));
                        }
                    }
                    SwarmCommand::SendRpcRequest { peer_id, request_id, request_message } => {
                        enter_swarm_command(3);
                        // Register the request on the timeout/protocol maps
                        // BEFORE handing the request to the swarm: by the time
                        // libp2p surfaces a response, timeout, or error event,
                        // both maps must already contain `request_id` for the
                        // reqresp arms below to match it. The inserts live here
                        // (and not in the FFI entry point) because
                        // `HashMapDelay::insert` requires a live Tokio runtime
                        // — see the matching note in `send_rpc_request`. #837
                        REQUEST_ID_MAP.lock_recover().insert(request_id, ());
                        REQUEST_PROTOCOL_MAP
                            .lock_recover()
                            .insert(request_id, request_message.protocol.clone());
                        swarm.behaviour_mut().reqresp.send_request(peer_id, request_id, request_message);
                    }
                    SwarmCommand::SendRpcResponseChunk { channel_id, peer_id, connection_id, stream_id, response_message } => {
                        enter_swarm_command(4);
                        // Channel coordinates were resolved on the FFI side
                        // under a single `RESPONSE_CHANNEL_MAP` lock; we just
                        // forward the response and log it. We do not re-look
                        // up the channel here, so an interleaved
                        // `SendRpcEndOfStream` (or timeout sweep) cannot make
                        // this chunk silently disappear.
                        swarm.behaviour_mut().reqresp.send_response(
                            peer_id, connection_id, stream_id, response_message,
                        );
                        // Refresh the response-channel idle timeout now that
                        // we've made progress. This used to be done on the
                        // FFI side under the same lock as the lookup, but
                        // `update_timeout` schedules a `tokio::time::sleep`
                        // and panics outside a Tokio runtime — see the note
                        // in `send_rpc_response_chunk`. If the channel was
                        // already torn down (end-of-stream / sweep) between
                        // dispatch and now, `update_timeout` is a no-op,
                        // which is the desired semantics. #837
                        let _ = RESPONSE_CHANNEL_MAP
                            .lock_recover()
                            .update_timeout(&channel_id, RESPONSE_CHANNEL_IDLE_TIMEOUT);
                        logger::rustLogger.info(self.network_id, &format!(
                            "[reqresp] Sent response chunk on channel {} (peer: {})", channel_id, peer_id));
                    }
                    SwarmCommand::SendRpcEndOfStream { channel_id } => {
                        enter_swarm_command(5);
                        let channel = RESPONSE_CHANNEL_MAP.lock_recover().remove(&channel_id);
                        if let Some(channel) = channel {
                            let peer_id = channel.peer_id;
                            swarm.behaviour_mut().reqresp.finish_response_stream(
                                peer_id, channel.connection_id, channel.stream_id,
                            );
                            logger::rustLogger.info(self.network_id, &format!(
                                "[reqresp] Sent end-of-stream on channel {} (peer: {})", channel_id, peer_id));
                        } else {
                            logger::rustLogger.error(self.network_id, &format!(
                                "No response channel found for id {} (SendRpcEndOfStream)", channel_id));
                        }
                    }
                    SwarmCommand::SendRpcErrorResponse { channel_id, payload } => {
                        enter_swarm_command(6);
                        let channel = RESPONSE_CHANNEL_MAP.lock_recover().remove(&channel_id);
                        if let Some(channel) = channel {
                            let peer_id = channel.peer_id;
                            let protocol = channel.protocol.clone();
                            let response_message = ResponseMessage::new(protocol, payload);
                            swarm.behaviour_mut().reqresp.send_response(
                                peer_id, channel.connection_id, channel.stream_id, response_message.clone(),
                            );
                            swarm.behaviour_mut().reqresp.finish_response_stream(
                                peer_id, channel.connection_id, channel.stream_id,
                            );
                            logger::rustLogger.info(self.network_id, &format!(
                                "[reqresp] Sent error response on channel {} (peer: {})", channel_id, peer_id));
                        } else {
                            logger::rustLogger.error(self.network_id, &format!(
                                "No response channel found for id {} (SendRpcErrorResponse)", channel_id));
                        }
                    }
                    SwarmCommand::DialReconnect { peer_id, addr, attempt } => {
                        enter_swarm_command(7);
                        // The detached `tokio::spawn` task scheduled this after
                        // sleeping for the backoff. Re-check liveness here (the
                        // peer may have reconnected via some other path in the
                        // meantime) before issuing the dial.
                        if swarm.is_connected(&peer_id) {
                            logger::rustLogger.debug(
                                self.network_id,
                                &format!(
                                    "Skipping reconnection attempt to peer {} because it is already connected",
                                    peer_id
                                ),
                            );
                        } else {
                            logger::rustLogger.info(
                                self.network_id,
                                &format!("Attempting reconnection to {} (attempt {}/{})", addr, attempt, MAX_RECONNECT_ATTEMPTS),
                            );
                            RECONNECT_ATTEMPTS
                                .lock_recover()
                                .insert((self.network_id, peer_id), (addr.clone(), attempt));

                            let mut dial_addr = addr.clone();
                            strip_peer_id(&mut dial_addr);

                            match swarm.dial(
                                DialOpts::peer_id(peer_id)
                                    .addresses(vec![dial_addr.clone()])
                                    .build(),
                            ) {
                                Ok(()) => {
                                    logger::rustLogger.info(
                                        self.network_id,
                                        &format!("Dialing peer {} at {} for reconnection", peer_id, dial_addr),
                                    );
                                }
                                Err(e) => {
                                    logger::rustLogger.error(
                                        self.network_id,
                                        &format!("Failed to dial peer {} at {}: {:?}", peer_id, dial_addr, e),
                                    );
                                    RECONNECT_ATTEMPTS
                                        .lock_recover()
                                        .remove(&(self.network_id, peer_id));
                                    self.schedule_reconnection(peer_id, addr, attempt + 1);
                                }
                            }
                        }
                    }
                    }
                    drained += 1;
                    if drained >= MAX_SWARM_COMMANDS_PER_TICK {
                        break;
                    }
                    match cmd_rx.try_recv() {
                        Ok(next) => cmd = next,
                        Err(_) => break,
                    }
                }
            }

            // leanMetrics PR #35: 1s defensive recompute of the gossipsub
            // mesh-peer count. Gossipsub events / connection closes already
            // cover transitions, but this guarantees liveness on idle topics.
            // `all_mesh_peers().count()` is cheap (O(peers)) and the atomic
            // store is lock-free; no `await` here, so the swarm task is
            // never blocked.
            _ = mesh_peers_tick.tick() => {
                enter_arm(7);
                let mesh_count = swarm.behaviour().gossipsub.all_mesh_peers().count() as u64;
                record_mesh_peers(self.network_id, mesh_count);

                // #942 diagnosis: every ~10s, log the per-topic-kind count of
                // gossipsub Messages delivered so far plus the per-topic mesh
                // size. If the block counter stops climbing while the block
                // topic still has mesh peers, blocks have stopped ARRIVING
                // (transport/mesh fault) rather than failing to decode.
                diag_tick_count = diag_tick_count.wrapping_add(1);
                if diag_tick_count.is_multiple_of(10) {
                    let block_recv = GOSSIP_RECV_BY_KIND_TOTAL[0].load(Ordering::Relaxed);
                    let attn_recv = GOSSIP_RECV_BY_KIND_TOTAL[1].load(Ordering::Relaxed);
                    let other_recv = GOSSIP_RECV_BY_KIND_TOTAL[2].load(Ordering::Relaxed);
                    let gs = &swarm.behaviour().gossipsub;
                    let mut topic_mesh = String::new();
                    for topic in gs.topics() {
                        let n = gs.mesh_peers(topic).count();
                        let label = match gossip_topic_kind_index(&topic.to_string()) {
                            0 => "block",
                            1 => "attn",
                            _ => "other",
                        };
                        topic_mesh.push_str(&format!(" {label}={n}"));
                    }
                    logger::rustLogger.debug(
                        self.network_id,
                        &format!(
                            "[#942 gossip-recv] delivered_total block={block_recv} attn={attn_recv} other={other_recv} | mesh_peers total={mesh_count}{topic_mesh} | inbound_decode_dropped={}",
                            INBOUND_GOSSIP_DROPPED_TOTAL.load(Ordering::Relaxed),
                        ),
                    );
                    // NOTE: the per-substream QUIC accounting lines
                    // ([#942 quic-recv] / [#942 quic-send]) are emitted from a
                    // dedicated spawned task (spawn_quic_diag_emitter, started in
                    // run_eventloop). They MUST NOT live in this arm: it is the
                    // last arm of a biased select! and devnet data showed it
                    // never gets polled once reqresp-status retries become
                    // continuous, so the per-stream signal disappears exactly
                    // when the freeze deepens. The spawned task uses its own
                    // tokio::time::interval and only reads atomic counters, so
                    // it keeps emitting even while the swarm task is busy.
                }
            }

            }

            // #942 iteration-latency probe: record how long this iteration
            // of the swarm task's `select!` took. The atomics are read by
            // `spawn_quic_diag_emitter` and reset (max) each tick.
            let dt_ms = iter_start.elapsed().as_millis() as u64;
            EVENT_LOOP_MAX_ITER_MS.fetch_max(dt_ms, Ordering::Relaxed);
            if dt_ms >= EVENT_LOOP_SLOW_ITER_THRESHOLD_MS {
                EVENT_LOOP_SLOW_ITERS_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }

        // #942: stop the inbound gossip decode worker. Dropping the sender makes
        // the worker's blocking `recv()` return `Err` once the channel drains,
        // so it finishes any queued messages and exits. Joining here — on the
        // rust-bridge thread, before this function returns and Zig joins it —
        // guarantees no in-flight `handleMsgFromRustBridge` call is still running
        // when Zig tears down the EthLibp2p handler after `stop_network`.
        drop(gossip_tx);
        if let Err(panic) = gossip_worker.join() {
            logger::rustLogger.error(
                self.network_id,
                &format!("inbound gossip decode worker thread panicked: {:?}", panic),
            );
        }

        // Mirror cleanup for the reqresp dispatch worker.
        drop(rpc_tx);
        if let Err(panic) = rpc_worker.join() {
            logger::rustLogger.error(
                self.network_id,
                &format!(
                    "inbound reqresp dispatch worker thread panicked: {:?}",
                    panic
                ),
            );
        }

        // Clean up per-network state so any later `stop_network`/`start_network`
        // calls start from a blank slate and any in-flight dispatchers into Zig
        // see an absent handler rather than a pointer to a freed EthLibp2p.
        clear_network_slot(self.network_id);
        // The owned `swarm` argument is dropped here on return, closing
        // sockets and peer connections.
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
    reqresp: ReqResp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)] // store as 4-byte value
pub enum MessageDomain {
    ValidSnappy = 0x01000000,
    InvalidSnappy = 0x00000000,
}

impl From<MessageDomain> for [u8; 4] {
    fn from(domain: MessageDomain) -> Self {
        (domain as u32).to_be_bytes()
    }
}

impl Behaviour {
    fn message_id_fn(message: &gossipsub::Message) -> gossipsub::MessageId {
        // #942 follow-up: restore spec-conformant content-addressed
        // `message_id` (Ethereum gossipsub convention:
        //   `SHA256(domain_tag || topic_len || topic || decompressed_bytes)`).
        //
        // The raw-bytes form that was here previously caused zeam to assign
        // distinct message-ids to byte-different but content-identical
        // copies of the same logical message. On the 2026-05-28/29 devnet
        // we observed 8 distinct corrupted-snappy encodings of the same
        // slot=1 block (`data_len=285473`, same `sha256_first32` prefix)
        // arriving at zeam_8 in 70 s, all from forwarder peers' mcaches
        // (gean_1, zeam_13, _14, _15). Under raw-bytes hashing zeam
        // computed 8 distinct ids, attempted to decode all 8, failed all 8.
        // Under content-addressed hashing, the first clean copy wins; all
        // subsequent copies with the same decompressed content dedupe to
        // the same id and are dropped by gossipsub before the application
        // layer ever sees them.
        //
        // Cost: synchronous decompress on the gossipsub event loop. With
        // ~21 mesh peers each forwarding the same block, this used to run
        // ~21x per block on the same thread that drives quinn's QUIC poll
        // futures; devnet evidence (slot 58→61 simultaneous freeze of every
        // poll_read AND poll_write) pinned that accumulation as the proximal
        // cause of the libp2p event-loop stall. Mitigated below by an FIFO
        // cache keyed on the raw-bytes SHA256: identical-bytes re-forwards
        // skip the decompress entirely.

        // Fast path: cheap SHA256 of the raw wire bytes, then cache lookup.
        // SHA256 over even a 10 MB block is ~10 ms on modern hw; snappy
        // decompress of the same block is ~10x that AND allocates the full
        // decoded buffer.
        let mut raw_hasher = sha2::Sha256::new();
        raw_hasher.update(&message.data);
        let raw_digest = raw_hasher.finalize();
        let raw_key: [u8; 32] = raw_digest.into();
        if let Some(id) = MESSAGE_ID_CACHE.lock_recover().get(&raw_key) {
            return id;
        }

        // Slow path: decompress + content-addressed hash, then cache.
        let mut hasher = sha2::Sha256::new();
        let (data_for_hash, domain): (Vec<u8>, [u8; 4]) =
            match Decoder::new().decompress_vec(&message.data) {
                Ok(decoded) => (decoded, MessageDomain::ValidSnappy.into()),
                Err(_) => (message.data.clone(), MessageDomain::InvalidSnappy.into()),
            };
        hasher.update(domain);
        hasher.update(message.topic.as_str().len().to_le_bytes());
        hasher.update(message.topic.as_str().as_bytes());
        hasher.update(&data_for_hash);
        let digest = hasher.finalize();
        let id = gossipsub::MessageId::from(&digest[..20]);
        MESSAGE_ID_CACHE.lock_recover().insert(raw_key, id.clone());
        id
    }

    fn new(key: identity::Keypair) -> Self {
        let local_public_key = key.public();
        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &gossipsub::Message| Self::message_id_fn(message);

        // Set a custom gossipsub configuration
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .mesh_n(8)
            .mesh_n_low(6)
            .mesh_n_high(12)
            .gossip_lazy(6)
            .heartbeat_interval(Duration::from_millis(700))
            .validation_mode(gossipsub::ValidationMode::Anonymous)
            .history_length(6)
            .duplicate_cache_time(Duration::from_secs(3 * 4 * 2))
            .max_transmit_size(crate::req_resp::configurations::max_message_size())
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .build()
            .unwrap();
        // .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

        // build a gossipsub network behaviour with Anonymous mode for multi-client compatibility
        // Anonymous mode ensures interoperability with other clients (ream, lanten, qlean)
        let gossipsub =
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, gossipsub_config)
                .unwrap();

        let reqresp = ReqResp::new(vec![
            LeanSupportedProtocol::StatusV1.into(),
            LeanSupportedProtocol::BlocksByRootV1.into(),
            LeanSupportedProtocol::BlocksByRangeV1.into(),
        ]);

        Self {
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/0.1.0".into(),
                local_public_key.clone(),
            )),
            ping: ping::Behaviour::default(),
            gossipsub,
            reqresp,
        }
    }
}

fn new_swarm(local_keypair: Keypair, network_id: u32) -> libp2p::swarm::Swarm<Behaviour> {
    // #942 transport bisection: the inbound snappy corruption is provably
    // introduced on zeam's receive path after AEAD decryption (ingress hash
    // differs from the producer's publish hash, and both QUIC and TCP+noise
    // are integrity-protected, ruling out the wire). To split the search
    // between the QUIC stack (quinn/libp2p-quic) and the TCP stack
    // (yamux/gossipsub codec), set ZEAM_DISABLE_QUIC=1 to run TCP+yamux+noise
    // only. If `error.Corrupt` vanishes, the bug is in the QUIC reassembly;
    // if it persists, it is in yamux or the gossipsub length-delimited codec.
    // Default (unset) keeps QUIC enabled, i.e. current behaviour.
    let quic_support = !matches!(
        std::env::var("ZEAM_DISABLE_QUIC").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    );
    logger::rustLogger.info(
        network_id,
        &format!("[#942 transport] quic_support={quic_support} (set ZEAM_DISABLE_QUIC=1 to force TCP+yamux+noise only)"),
    );
    let transport = build_transport(local_keypair.clone(), quic_support).unwrap();
    logger::rustLogger.debug(network_id, "build the transport");

    // No gossipsub topics joined here. Mesh subscriptions are driven from
    // Zig via `SwarmCommand::SubscribeGossip` after `start_network` makes
    // the swarm command channel available; that keeps `gossip.subscribe` on
    // the Zig side as the single source of truth for joined subnets.
    SwarmBuilder::with_existing_identity(local_keypair)
        .with_tokio()
        .with_other_transport(|_key| transport)
        .expect("infalible")
        .with_behaviour(|key| Behaviour::new(key.clone()))
        .unwrap()
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build()
}

fn build_transport(
    local_private_key: Keypair,
    quic_support: bool,
) -> std::io::Result<BoxedTransport> {
    // #942: yamux-only on the TCP side. Previously this transport also
    // negotiated `libp2p-mplex` via `SelectUpgrade::new(yamux, mplex)`, which
    // caused gossip messages larger than ~100 KB to arrive corrupted at the
    // gossipsub layer — `snap::raw::Decoder` rejected 38 of 72 incoming
    // blocks and 28 of 402 incoming aggregations on the 2026-05-28 devnet
    // while ream / grandine on the same network saw zero gossip decode
    // failures. mplex is deprecated upstream and is the only differing
    // transport feature between zeam and the clients that worked. Dropping
    // it means TCP connections use yamux exclusively, QUIC keeps its native
    // streams, and the gossipsub ingress path stops fragmenting/reassembling
    // large messages through the buggy code path.
    let yamux_config = yamux::Config::default();
    // Creates the TCP transport layer
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
        .upgrade(core::upgrade::Version::V1)
        .authenticate(generate_noise_config(&local_private_key))
        .multiplex(yamux_config)
        .timeout(Duration::from_secs(10));
    let transport = if quic_support {
        // Enables Quic
        //
        // #942 fix #4 — QUIC receive flow-control windows.
        //
        // libp2p-quic's defaults are max_stream_data = 10 MB and
        // max_connection_data = 15 MB. Two problems on this gossip workload:
        //
        // 1. A single Ethereum-consensus gossip message can be up to
        //    `max_message_size()` ≈ 12.2 MB (snappy worst-case of the 10 MiB
        //    payload + framing). That is LARGER than the 10 MB per-stream
        //    receive window, so a max-size block cannot be received within one
        //    stream's flow-control window — quinn stalls waiting for a window
        //    update that gossipsub never triggers mid-message.
        // 2. The 15 MB connection window is shared across ALL concurrent
        //    streams on a peer connection (block topic + every attestation
        //    subnet + RPC). During a catch-up burst of ~3.3 MB blocks plus the
        //    attestation fan-in, the connection-level window exhausts; QUIC
        //    flow control then blocks new STREAM_DATA frames. Small
        //    attestation streams that already arrived still complete and get
        //    delivered, but new LARGE block streams wedge mid-reassembly —
        //    exactly the pinned #942 signature (block-topic delivery goes
        //    silent after the burst while attestations keep flowing on the
        //    same healthy connections).
        //
        // Raise both windows so one max-size message fits comfortably in a
        // stream window and many concurrent large streams cannot exhaust the
        // connection window. `max_stream_data` / `max_connection_data` are
        // public fields on the config; they map to quinn's
        // stream_receive_window / receive_window.
        let mut quic_config = libp2p::quic::Config::new(&local_private_key);
        quic_config.max_stream_data = 16 * 1024 * 1024; // 16 MB > max_message_size (~12.2 MB)
        quic_config.max_connection_data = 64 * 1024 * 1024; // 64 MB headroom for concurrent large streams
        let quic = libp2p::quic::tokio::Transport::new(quic_config);
        let transport = tcp
            .or_transport(quic)
            .map(|either_output, _| match either_output {
                Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
                // #942 fix-#5 diagnostic: wrap the QUIC muxer so inbound
                // substream byte flow is accounted at the quinn boundary.
                Either::Right((peer_id, muxer)) => (
                    peer_id,
                    StreamMuxerBox::new(InstrumentedMuxer { inner: muxer }),
                ),
            });
        transport.boxed()
    } else {
        tcp.boxed()
    };

    // Enables DNS over the transport.
    let transport = libp2p::dns::tokio::Transport::system(transport)?.boxed();

    Ok(transport)
}

/// Generate authenticated XX Noise config from identity keys
fn generate_noise_config(identity_keypair: &Keypair) -> noise::Config {
    noise::Config::new(identity_keypair).expect("signing can fail only once during starting a node")
}

/// For a multiaddr that ends with a peer id, this strips this suffix. Rust-libp2p
/// only supports dialing to an address without providing the peer id.
fn strip_peer_id(addr: &mut Multiaddr) {
    let last = addr.pop();
    match last {
        Some(Protocol::P2p(_)) => {}
        Some(other) => addr.push(other),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::gossipsub::IdentTopic;
    use libp2p::gossipsub::MessageId;
    use snap::raw::Encoder;

    // Mock FFI functions for testing
    #[no_mangle]
    extern "C" fn handleLogFromRustBridge(
        _zig_handler: u64,
        _level: u32,
        _message_ptr: *const u8,
        _message_len: usize,
    ) {
        // Mock: do nothing
    }

    /// Per-test `network_id` allocator.
    ///
    /// `cargo test` runs tests in parallel within the same process, so any
    /// state keyed by `network_id` (the `COMMAND_SENDERS` map, the
    /// `NETWORK_SLOTS` map, the `MESH_PEERS_TOTAL` array) is shared. Tests
    /// that install a sender for a given id can otherwise race tests that
    /// assume that same id is uninitialized — the failure mode is a flaky
    /// "should return false when not initialized" assertion that depends on
    /// scheduler order. Every test that touches per-network state must pull
    /// its id from this counter so collisions are structurally impossible.
    ///
    /// Starts at 1000 to stay well above any id a hypothetical Zig caller
    /// might use during a future integration test, and below `MAX_NETWORKS`
    /// (so `MESH_PEERS_TOTAL` indexing remains valid).
    static TEST_NETWORK_ID_COUNTER: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(1000);

    fn next_test_network_id() -> u32 {
        TEST_NETWORK_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn test_message_id_computation_with_snappy() {
        let compressed_data = {
            let mut encoder = Encoder::new();
            encoder.compress_vec(b"hello").unwrap()
        };
        let message = gossipsub::Message {
            source: None,
            data: compressed_data,
            sequence_number: None,
            topic: IdentTopic::new("test").into(),
        };
        let message_id = Behaviour::message_id_fn(&message);
        let expected_hex = "2e40c861545cc5b46d2220062e7440b9190bc383";
        let expected_bytes = hex::decode(expected_hex).unwrap();
        assert_eq!(message_id, MessageId::new(&expected_bytes));
    }

    #[test]
    fn test_message_id_computation_basic() {
        // Test basic message ID computation without snappy decompression
        let message_id = Behaviour::message_id_fn(&gossipsub::Message {
            source: None,
            data: b"hello".to_vec(),
            sequence_number: None,
            topic: IdentTopic::new("test").into(),
        });

        // Verify the ID is correct
        let expected_hex = "a7f41aaccd241477955c981714eb92244c2efc98";
        let expected_bytes = hex::decode(expected_hex).unwrap();
        assert_eq!(message_id, MessageId::new(&expected_bytes));
    }

    #[test]
    fn test_wait_for_network_ready_timeout() {
        // Test that wait_for_network_ready times out when network is not initialized.
        let network_id = next_test_network_id();
        let result = unsafe { wait_for_network_ready(network_id, 100) }; // 100ms timeout
        assert!(!result, "Should timeout when network is not initialized");
    }

    #[test]
    fn test_send_rpc_request_before_initialization_returns_zero() {
        // Test that sending RPC request before initialization returns 0
        let network_id = next_test_network_id();
        let peer_id = std::ffi::CString::new("12D3KooWTest").unwrap();
        let request_data = b"test request";

        let request_id = unsafe {
            send_rpc_request(
                network_id,
                peer_id.as_ptr(),
                0, // protocol_tag
                request_data.as_ptr(),
                request_data.len(),
            )
        };

        assert_eq!(
            request_id, 0,
            "Should return 0 when network is not initialized"
        );
    }

    #[test]
    fn test_send_rpc_request_does_not_panic_outside_tokio_runtime() {
        // Regression test for #837. Before the fix, `send_rpc_request`
        // called `REQUEST_ID_MAP.lock().insert(...)` on whatever thread the
        // FFI was invoked from. `HashMapDelay::insert` schedules a
        // `tokio::time::sleep` for the entry timeout and panics with
        // "there is no reactor running" when called outside a Tokio runtime
        // — which is exactly what happens when Zig's libxev event loop
        // calls in. Under the panic="abort" prover profiles this aborts the
        // whole process; here it would surface as a panicked test thread.
        //
        // We install a per-network command sender (so the function actually
        // gets past `get_command_sender` and reaches the formerly-panicking
        // code path) and call `send_rpc_request` from a freshly-spawned
        // OS thread that is guaranteed to have no Tokio context attached.
        // The fix moves both delay-map inserts to the event-loop side, so
        // this call must now succeed (non-zero id, no panic).
        let network_id = next_test_network_id();
        let (tx, mut rx) = mpsc::channel::<SwarmCommand>(8);
        COMMAND_SENDERS.lock_recover().insert(network_id, tx);

        let peer_id =
            std::ffi::CString::new("12D3KooWGRUacXc8jUuvtJYCgxUYHFYCCREXSjkZnzGqUwYj4Mxo").unwrap();
        let request_data = b"test request";

        let request_id = std::thread::spawn(move || unsafe {
            send_rpc_request(
                network_id,
                peer_id.as_ptr(),
                LeanSupportedProtocol::StatusV1 as u32,
                request_data.as_ptr(),
                request_data.len(),
            )
        })
        .join()
        .expect("send_rpc_request panicked outside Tokio runtime — #837 regression");

        assert!(
            request_id > 0,
            "send_rpc_request should return a non-zero id on success, got {}",
            request_id
        );
        assert!(
            matches!(rx.try_recv(), Ok(SwarmCommand::SendRpcRequest { request_id: r, .. }) if r == request_id),
            "command channel should have received the SendRpcRequest with the same id"
        );

        COMMAND_SENDERS.lock_recover().remove(&network_id);
    }

    #[test]
    fn test_send_rpc_request_does_not_burn_id_on_uninitialized_network() {
        // Regression test for the comment on PR #789: when the per-network
        // command channel is missing, `send_rpc_request` must not advance
        // `REQUEST_ID_COUNTER`. Otherwise every failed FFI call permanently
        // leaks a request id and successive ids skip values.
        let network_id = next_test_network_id();
        let peer_id = std::ffi::CString::new("12D3KooWTest").unwrap();
        let request_data = b"test request";

        let before = REQUEST_ID_COUNTER.load(Ordering::Relaxed);
        for _ in 0..5 {
            let request_id = unsafe {
                send_rpc_request(
                    network_id,
                    peer_id.as_ptr(),
                    0,
                    request_data.as_ptr(),
                    request_data.len(),
                )
            };
            assert_eq!(
                request_id, 0,
                "Should return 0 when network is not initialized"
            );
        }
        let after = REQUEST_ID_COUNTER.load(Ordering::Relaxed);
        assert_eq!(
            before, after,
            "REQUEST_ID_COUNTER must not advance when send_rpc_request fails"
        );
    }

    #[test]
    fn test_shutdown_notify_installed_before_mark_ready() {
        // Regression test for the review comment on PR #819: previously
        // `start_network` called `mark_network_ready` *before* the event loop
        // had installed `shutdown_notify` on the slot. Any `stop_network`
        // racing the start→eventloop handoff therefore saw `ready == true`
        // but `get_shutdown_notify == None`, silently dropping its
        // `notify_one()` permit. After the fix `start_network` installs the
        // notify first, so the invariant "ready ⇒ shutdown_notify present"
        // holds atomically from any concurrent observer's point of view.
        //
        // We can't call `start_network` from a unit test (it needs a real
        // libp2p swarm + tokio runtime), but the fix lives in the ordering
        // of two free functions, so we exercise that ordering directly:
        // `install_shutdown_notify` then `mark_network_ready`, then assert
        // `get_shutdown_notify` returns the *same* `Arc<Notify>` and that a
        // `notify_one` posted on it is observed by a subsequent
        // `notified().await`.
        let network_id = next_test_network_id();
        clear_network_slot(network_id);

        let installed = install_shutdown_notify(network_id);
        mark_network_ready(network_id);

        assert!(
            is_network_ready(network_id),
            "network must be marked ready after mark_network_ready"
        );
        let observed = get_shutdown_notify(network_id)
            .expect("shutdown_notify must be present once the network is marked ready");
        assert!(
            Arc::ptr_eq(&installed, &observed),
            "get_shutdown_notify must return the handle install_shutdown_notify just placed"
        );

        observed.notify_one();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let woke = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), installed.notified())
                .await
                .is_ok()
        });
        assert!(
            woke,
            "notify_one posted before any waiter must be observed by the first notified().await — \
             this is the property stop_network depends on across the start→eventloop handoff"
        );

        clear_network_slot(network_id);
    }

    #[test]
    fn test_publish_msg_to_rust_bridge_returns_false_when_uninitialized() {
        // Regression test for issue #808: publish_msg_to_rust_bridge must
        // return false when the per-network swarm command channel does not
        // exist (i.e. the network was never started or has been torn down),
        // so the Zig-side caller can stop logging "published" for messages
        // that never actually reached the wire.
        let network_id = next_test_network_id();
        let topic = std::ffi::CString::new("test/topic").unwrap();
        let payload = b"hello";

        let ok = unsafe {
            publish_msg_to_rust_bridge(network_id, topic.as_ptr(), payload.as_ptr(), payload.len())
        };
        assert!(
            !ok,
            "publish_msg_to_rust_bridge must return false when the network is not initialized"
        );
    }

    #[test]
    fn test_publish_msg_to_rust_bridge_returns_false_on_null_topic() {
        // Defensive check: the FFI guard against a null topic pointer must
        // also surface as `false` so the Zig caller treats it as a dropped
        // publish (issue #808).
        let network_id = next_test_network_id();
        let payload = b"hello";
        let ok = unsafe {
            publish_msg_to_rust_bridge(
                network_id,
                std::ptr::null(),
                payload.as_ptr(),
                payload.len(),
            )
        };
        assert!(
            !ok,
            "publish_msg_to_rust_bridge must return false when topic pointer is null"
        );
    }

    #[test]
    fn test_subscribe_gossip_topic_to_rust_bridge_returns_false_when_uninitialized() {
        // The Zig side treats `false` as a hard failure (mesh join did not
        // happen), so a missing per-network command channel must surface as
        // `false` rather than panicking or silently succeeding.
        let network_id = next_test_network_id();
        let topic = std::ffi::CString::new("leanconsensus/foo/ssz_snappy").unwrap();
        let ok = unsafe { subscribe_gossip_topic_to_rust_bridge(network_id, topic.as_ptr()) };
        assert!(
            !ok,
            "subscribe_gossip_topic_to_rust_bridge must return false when the network is not initialized"
        );
    }

    #[test]
    fn test_subscribe_gossip_topic_to_rust_bridge_returns_false_on_null_topic() {
        let network_id = next_test_network_id();
        let ok = unsafe { subscribe_gossip_topic_to_rust_bridge(network_id, std::ptr::null()) };
        assert!(
            !ok,
            "subscribe_gossip_topic_to_rust_bridge must return false when topic pointer is null"
        );
    }

    #[test]
    fn test_swarm_command_drop_counter_increments_on_uninitialized() {
        // Issue #808: every dropped swarm command must bump the per-reason
        // counter exposed via `get_swarm_command_dropped_total` so the Zig
        // metrics layer can publish it as `zeam_libp2p_swarm_command_dropped_total`.
        // Tests run in-process so the counter is shared; assert *delta*, not absolute.
        let before = get_swarm_command_dropped_total(SwarmCommandDropReason::Uninitialized as u32);

        // Send to a network slot that was never initialized: must return false.
        let network_id = next_test_network_id();
        let topic = std::ffi::CString::new("test/topic").unwrap();
        let payload = b"hello";
        for _ in 0..3 {
            let ok = unsafe {
                publish_msg_to_rust_bridge(
                    network_id,
                    topic.as_ptr(),
                    payload.as_ptr(),
                    payload.len(),
                )
            };
            assert!(!ok);
        }

        let after = get_swarm_command_dropped_total(SwarmCommandDropReason::Uninitialized as u32);
        assert!(
            after - before >= 3,
            "Uninitialized drop counter must advance by at least 3 (before={before}, after={after})"
        );
    }

    #[test]
    fn test_swarm_command_drop_counter_unknown_reason_is_zero() {
        // The FFI getter must return 0 for unknown reason tags so a Zig
        // build compiled against an older Rust glue cannot panic on scrape.
        assert_eq!(get_swarm_command_dropped_total(999), 0);
    }

    #[test]
    fn test_swarm_command_full_channel_drops_and_counts() {
        // Issue #808 review point #3: exercise the actual full-channel path
        // by installing a bounded sender into COMMAND_SENDERS without a
        // matching drainer, pushing past capacity, and asserting the
        // overflow returns false and bumps the Full counter.
        //
        // We use a small dedicated network_id and a tiny channel so the test
        // runs in microseconds instead of allocating SWARM_COMMAND_CHANNEL_CAPACITY
        // commands.
        let network_id = next_test_network_id();
        let cap: usize = 4;
        let (tx, _rx) = mpsc::channel::<SwarmCommand>(cap);
        // Keep _rx alive (no drainer => first `cap` sends fill the channel,
        // anything beyond returns Full instead of Closed).
        COMMAND_SENDERS.lock_recover().insert(network_id, tx);

        let before_full = get_swarm_command_dropped_total(SwarmCommandDropReason::Full as u32);

        // Fill the channel exactly to capacity — every send must succeed.
        for i in 0..cap {
            let ok = send_swarm_command(
                network_id,
                SwarmCommand::Publish {
                    topic: format!("t/{i}"),
                    data: vec![0u8; 4],
                },
            );
            assert!(ok, "send #{i} into a non-full channel must succeed");
        }

        // Next 3 sends must all return false and each bump the Full counter.
        let overflow_attempts = 3;
        for i in 0..overflow_attempts {
            let ok = send_swarm_command(
                network_id,
                SwarmCommand::Publish {
                    topic: format!("overflow/{i}"),
                    data: vec![0u8; 4],
                },
            );
            assert!(!ok, "overflow send #{i} must return false");
        }

        let after_full = get_swarm_command_dropped_total(SwarmCommandDropReason::Full as u32);
        assert!(
            after_full - before_full >= overflow_attempts as u64,
            "Full drop counter must advance by at least {overflow_attempts} (before={before_full}, after={after_full})"
        );

        // Cleanup: remove the test sender so this network_id is reusable.
        COMMAND_SENDERS.lock_recover().remove(&network_id);
    }
}
