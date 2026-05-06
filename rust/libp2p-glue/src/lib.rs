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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

use crate::req_resp::{
    configurations::REQUEST_TIMEOUT,
    configurations::RESPONSE_CHANNEL_IDLE_TIMEOUT,
    varint::{encode_varint, MAX_VARINT_BYTES},
    LeanSupportedProtocol, ProtocolId, ReqResp, ReqRespMessage, ReqRespMessageError,
    ReqRespMessageReceived, RequestMessage, ResponseMessage,
};

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

// TODO: protect the access by mutex
#[allow(static_mut_refs)]
static mut SWARM_STATE: Option<libp2p::swarm::Swarm<Behaviour>> = None;
// additional network slots for multi-node testing
#[allow(static_mut_refs)]
static mut SWARM_STATE1: Option<libp2p::swarm::Swarm<Behaviour>> = None;
#[allow(static_mut_refs)]
static mut SWARM_STATE2: Option<libp2p::swarm::Swarm<Behaviour>> = None;

// Store Zig handler pointers per network id so free functions can forward logs
#[allow(static_mut_refs)]
static mut ZIG_HANDLER0: Option<u64> = None;
#[allow(static_mut_refs)]
static mut ZIG_HANDLER1: Option<u64> = None;
#[allow(static_mut_refs)]
static mut ZIG_HANDLER2: Option<u64> = None;

// Per-network shutdown signal. The event loop polls a `.notified()` future on
// the matching slot; `stop_network` calls `notify_one` to wake it. `notify_one`
// stores a permit if no waiter is parked yet, so a `stop_network` call that
// races the first `.notified().await` is not lost.
#[allow(static_mut_refs)]
static mut SHUTDOWN_NOTIFY0: Option<Arc<Notify>> = None;
#[allow(static_mut_refs)]
static mut SHUTDOWN_NOTIFY1: Option<Arc<Notify>> = None;
#[allow(static_mut_refs)]
static mut SHUTDOWN_NOTIFY2: Option<Arc<Notify>> = None;

/// Get a mutable reference to the swarm for the given network id.
///
/// # Safety
/// The caller must ensure no other thread is concurrently writing to the same slot.
#[allow(static_mut_refs)]
unsafe fn get_swarm_mut(network_id: u32) -> Option<&'static mut libp2p::swarm::Swarm<Behaviour>> {
    match network_id {
        0 => SWARM_STATE.as_mut(),
        1 => SWARM_STATE1.as_mut(),
        2 => SWARM_STATE2.as_mut(),
        _ => None,
    }
}

/// Store a swarm in the global slot for the given network id.
///
/// # Safety
/// The caller must ensure no other thread is concurrently accessing the same slot.
unsafe fn set_swarm(network_id: u32, swarm: libp2p::swarm::Swarm<Behaviour>) {
    match network_id {
        0 => SWARM_STATE = Some(swarm),
        1 => SWARM_STATE1 = Some(swarm),
        2 => SWARM_STATE2 = Some(swarm),
        _ => panic!("unsupported network_id: {}", network_id),
    }
}

/// Store the Zig handler pointer for the given network id.
///
/// # Safety
/// The caller must ensure no other thread is concurrently accessing the same slot.
unsafe fn set_zig_handler(network_id: u32, handler: u64) {
    match network_id {
        0 => ZIG_HANDLER0 = Some(handler),
        1 => ZIG_HANDLER1 = Some(handler),
        2 => ZIG_HANDLER2 = Some(handler),
        _ => {}
    }
}

/// Get the Zig handler pointer for the given network id.
///
/// # Safety
/// The caller must ensure no other thread is concurrently writing to the same slot.
unsafe fn get_zig_handler(network_id: u32) -> Option<u64> {
    match network_id {
        0 => ZIG_HANDLER0,
        1 => ZIG_HANDLER1,
        2 => ZIG_HANDLER2,
        _ => None,
    }
}

/// Install a fresh shutdown signal for the given network and return a handle
/// to it. Called by the event loop owner so a subsequent `stop_network` call
/// has somewhere to post its wake-up permit.
///
/// # Safety
/// The caller must ensure no other thread is concurrently accessing the same slot.
#[allow(static_mut_refs)]
unsafe fn install_shutdown_notify(network_id: u32) -> Option<Arc<Notify>> {
    let notify = Arc::new(Notify::new());
    match network_id {
        0 => SHUTDOWN_NOTIFY0 = Some(notify.clone()),
        1 => SHUTDOWN_NOTIFY1 = Some(notify.clone()),
        2 => SHUTDOWN_NOTIFY2 = Some(notify.clone()),
        _ => return None,
    }
    Some(notify)
}

/// Get a handle to the shutdown signal for the given network, if one is
/// installed.
///
/// # Safety
/// The caller must ensure no other thread is concurrently writing to the same slot.
#[allow(static_mut_refs)]
unsafe fn get_shutdown_notify(network_id: u32) -> Option<Arc<Notify>> {
    match network_id {
        0 => SHUTDOWN_NOTIFY0.clone(),
        1 => SHUTDOWN_NOTIFY1.clone(),
        2 => SHUTDOWN_NOTIFY2.clone(),
        _ => None,
    }
}

/// Tear down per-network state after the event loop has exited. Drops the
/// swarm (closing sockets), clears the Zig handler pointer so any in-flight
/// attempts to dispatch into Zig become no-ops, and releases the shutdown
/// notify.
///
/// # Safety
/// The caller must ensure no other thread is concurrently accessing these slots.
unsafe fn clear_network_state(network_id: u32) {
    match network_id {
        0 => {
            SWARM_STATE = None;
            ZIG_HANDLER0 = None;
            SHUTDOWN_NOTIFY0 = None;
        }
        1 => {
            SWARM_STATE1 = None;
            ZIG_HANDLER1 = None;
            SHUTDOWN_NOTIFY1 = None;
        }
        2 => {
            SWARM_STATE2 = None;
            ZIG_HANDLER2 = None;
            SHUTDOWN_NOTIFY2 = None;
        }
        _ => {}
    }

    // Clear the ready flag so a post-stop `wait_for_network_ready` does not
    // return a stale `true` left over from the previous session. Wake any
    // current waiters so they re-check the (now-false) flag and return
    // `false` on the next deadline instead of parking indefinitely.
    let mut ready = NETWORK_READY_SIGNALS.lock().unwrap();
    match network_id {
        0 => ready.0 = false,
        1 => ready.1 = false,
        2 => ready.2 = false,
        _ => {}
    }
    drop(ready);
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

/// FFI getter: cumulative count of dropped swarm commands for the given
/// reason tag (see `SwarmCommandDropReason`). Returns 0 for unknown tags so
/// future Zig builds compiled against an older Rust glue do not panic.
///
/// Counts are global across all networks; the Zig caller is expected to scrape
/// once per metrics endpoint hit and turn deltas into a `CounterVec` with
/// `reason` labels.
#[no_mangle]
pub extern "C" fn get_swarm_command_dropped_total(reason_tag: u32) -> u64 {
    SWARM_COMMAND_DROPPED_TOTAL
        .get(reason_tag as usize)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

lazy_static::lazy_static! {
    static ref REQUEST_ID_MAP: Mutex<HashMapDelay<u64, ()>> = Mutex::new(HashMapDelay::new(REQUEST_TIMEOUT));
    static ref REQUEST_PROTOCOL_MAP: Mutex<HashMap<u64, ProtocolId>> = Mutex::new(HashMap::new());
    static ref RESPONSE_CHANNEL_MAP: Mutex<HashMapDelay<u64, PendingResponse>> = Mutex::new(HashMapDelay::new(RESPONSE_CHANNEL_IDLE_TIMEOUT));
    static ref NETWORK_READY_SIGNALS: std::sync::Mutex<(bool, bool, bool)> = std::sync::Mutex::new((false, false, false));
    static ref NETWORK_READY_CONDVAR: std::sync::Condvar = std::sync::Condvar::new();
    static ref RECONNECT_QUEUE: Mutex<HashMapDelay<(u32, PeerId), (Multiaddr, u32)>> =
        Mutex::new(HashMapDelay::new(Duration::from_secs(5))); // default delay, will be overridden
    static ref RECONNECT_ATTEMPTS: Mutex<HashMap<(u32, PeerId), (Multiaddr, u32)>> = Mutex::new(HashMap::new());
    // Track connection directions for disconnect events (network_id, peer_id, connection_id) -> direction
    static ref CONNECTION_DIRECTIONS: Mutex<HashMap<(u32, PeerId, ConnectionId), u32>> = Mutex::new(HashMap::new());
    static ref COMMAND_SENDERS: Mutex<HashMap<u32, mpsc::Sender<SwarmCommand>>> = Mutex::new(HashMap::new());
    static ref COMMAND_RECEIVERS: Mutex<HashMap<u32, mpsc::Receiver<SwarmCommand>>> = Mutex::new(HashMap::new());
}

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
    if let Some(notify) = get_shutdown_notify(network_id) {
        notify.notify_one();
    }
    COMMAND_SENDERS.lock().unwrap().remove(&network_id);
    COMMAND_RECEIVERS.lock().unwrap().remove(&network_id);
}

/// Wait for a network to be fully initialized and ready to accept messages.
/// Returns true if the network is ready, false on timeout.
///
/// # Safety
///
/// This function is thread-safe and can be called from any thread.
#[no_mangle]
pub unsafe extern "C" fn wait_for_network_ready(network_id: u32, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms);
    let deadline = std::time::Instant::now() + timeout;

    let mut ready = NETWORK_READY_SIGNALS.lock().unwrap();
    loop {
        if match network_id {
            0 => ready.0,
            1 => ready.1,
            2 => ready.2,
            _ => false,
        } {
            return true;
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }

        let remaining = deadline - now;
        let (guard, timeout_result) = NETWORK_READY_CONDVAR
            .wait_timeout(ready, remaining)
            .unwrap();
        ready = guard;

        if timeout_result.timed_out() {
            return false;
        }
    }
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();

    rt.block_on(async move {
        let mut p2p_net = Network::new(network_id, zig_handler);
        p2p_net
            .start_network(local_key_pair, listen_multiaddrs, connect_multiaddrs)
            .await;
        p2p_net.run_eventloop().await;
    });
}

/// Get a clone of the per-network swarm command sender, if the network has
/// been initialized. Cloning lets us drop the `COMMAND_SENDERS` lock before
/// performing `try_send`, which is important because `try_send` can block
/// briefly on the channel's internal semaphore.
fn get_command_sender(network_id: u32) -> Option<mpsc::Sender<SwarmCommand>> {
    COMMAND_SENDERS.lock().unwrap().get(&network_id).cloned()
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
    let message_slice = std::slice::from_raw_parts(message_str, message_len);
    logger::rustLogger.debug(
        network_id,
        &format!(
            "publishing message s={:?}..({})",
            hex::encode(&message_slice[..message_len.min(100)]),
            message_len
        ),
    );
    let message_data = message_slice.to_vec();

    if topic.is_null() {
        logger::rustLogger.error(
            network_id,
            "null pointer passed for `topic` in publish_msg_to_rust_bridge",
        );
        return false;
    }

    let topic = CStr::from_ptr(topic).to_string_lossy().to_string();

    send_swarm_command(
        network_id,
        SwarmCommand::Publish {
            topic,
            data: message_data,
        },
    )
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
    let peer_id_str = CStr::from_ptr(peer_id).to_string_lossy().to_string();
    let peer_id: PeerId = match peer_id_str.parse() {
        Ok(id) => id,
        Err(e) => {
            logger::rustLogger.error(network_id, &format!("Invalid peer ID: {}", e));
            return 0;
        }
    };

    let request_slice = std::slice::from_raw_parts(request_data, request_len);
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
    REQUEST_ID_MAP.lock().unwrap().insert(request_id, ());
    REQUEST_PROTOCOL_MAP
        .lock()
        .unwrap()
        .insert(request_id, protocol_id.clone());
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
    let response_slice = std::slice::from_raw_parts(response_data, response_len);
    let response_bytes = response_slice.to_vec();

    // Look up the response channel and refresh its timeout under a single lock,
    // and pass the resolved (peer_id, connection_id, stream_id) inside the
    // command. The executor side then does not need to re-lock
    // `RESPONSE_CHANNEL_MAP`, which closes the race against
    // `send_rpc_end_of_stream` / the response-channel timeout sweep that
    // would otherwise drop the chunk and log a spurious `No response channel
    // found` between the two locks.
    let channel = {
        let mut response_map = RESPONSE_CHANNEL_MAP.lock().unwrap();
        let c = response_map.get(&channel_id).cloned();
        if c.is_some() {
            _ = response_map.update_timeout(&channel_id, RESPONSE_CHANNEL_IDLE_TIMEOUT);
        }
        c
    };
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
    send_swarm_command(network_id, SwarmCommand::SendRpcEndOfStream { channel_id });
}

/// # Safety
/// The caller must ensure `message_ptr` points to a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn send_rpc_error_response(
    network_id: u32,
    channel_id: u64,
    message_ptr: *const c_char,
) {
    if message_ptr.is_null() {
        logger::rustLogger.error(
            network_id,
            &format!(
                "Attempted to send RPC error response with null message pointer for channel {}",
                channel_id
            ),
        );
        return;
    }

    let message = CStr::from_ptr(message_ptr).to_string_lossy().to_string();
    let message_bytes = message.as_bytes();

    if message_bytes.len() > crate::req_resp::configurations::max_message_size() {
        logger::rustLogger.error(
            network_id,
            &format!(
                "Attempted to send RPC error payload exceeding maximum size on channel {}",
                channel_id
            ),
        );
        return;
    }

    let mut payload = Vec::with_capacity(1 + MAX_VARINT_BYTES + message_bytes.len());
    payload.push(2);
    encode_varint(message_bytes.len(), &mut payload);
    payload.extend_from_slice(message_bytes);

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
    unsafe {
        handleLogFromRustBridge(zig_handler, level, message.as_ptr(), message.len());
    }
}

pub(crate) fn forward_log_by_network(network_id: u32, level: u32, message: &str) {
    let handler_opt = unsafe { get_zig_handler(network_id) };
    if let Some(handler) = handler_opt {
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
                .lock()
                .unwrap()
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

        let mut queue = RECONNECT_QUEUE.lock().unwrap();
        queue.insert_at(
            (self.network_id, peer_id),
            (addr, attempt),
            Duration::from_secs(delay_secs),
        );
    }

    pub async fn start_network(
        &mut self,
        key_pair: Keypair,
        listen_addresses: Vec<Multiaddr>,
        connect_addresses: Vec<Multiaddr>,
    ) {
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
            return;
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

        unsafe {
            set_swarm(self.network_id, swarm);
        }

        // Set up actor model command channel
        let (cmd_tx, cmd_rx) = mpsc::channel::<SwarmCommand>(SWARM_COMMAND_CHANNEL_CAPACITY);
        COMMAND_SENDERS
            .lock()
            .unwrap()
            .insert(self.network_id, cmd_tx);
        COMMAND_RECEIVERS
            .lock()
            .unwrap()
            .insert(self.network_id, cmd_rx);

        // Signal that this network is now ready
        {
            let mut ready = NETWORK_READY_SIGNALS.lock().unwrap();
            match self.network_id {
                0 => ready.0 = true,
                1 => ready.1 = true,
                2 => ready.2 = true,
                _ => {}
            }
            NETWORK_READY_CONDVAR.notify_all();
        }

        logger::rustLogger.info(self.network_id, "network initialization complete and ready");
    }

    pub async fn run_eventloop(&mut self) {
        let swarm = unsafe { get_swarm_mut(self.network_id) }
            .expect("run_eventloop called before start_network stored the swarm");

        let mut cmd_rx = COMMAND_RECEIVERS
            .lock()
            .unwrap()
            .remove(&self.network_id)
            .expect("run_eventloop called before start_network set up command channel");

        // Install the shutdown signal before entering the loop so `stop_network`
        // calls issued between here and the first `.notified().await` land on
        // this slot. `notify_one` stores a permit if no waiter is parked yet,
        // so the first iteration's shutdown arm will see the permit and break.
        let shutdown = unsafe { install_shutdown_notify(self.network_id) }
            .expect("unsupported network_id for shutdown signal");

        'eventloop: loop {
            tokio::select! {
            biased;

            _ = shutdown.notified() => {
                logger::rustLogger.info(
                    self.network_id,
                    "stop_network signaled; exiting libp2p event loop",
                );
                break 'eventloop;
            }

            Some(timeout_result) = poll_fn(|cx| {
                let mut map = REQUEST_ID_MAP.lock().unwrap();
                std::pin::Pin::new(&mut *map).poll_next(cx)
            }) => {
                match timeout_result {
                    Ok((request_id, ())) => {
                        logger::rustLogger.warn(
                            self.network_id,
                            &format!("[reqresp] Request {} timed out after {:?}", request_id, REQUEST_TIMEOUT),
                        );
                        if let Some(protocol_id) = REQUEST_PROTOCOL_MAP
                            .lock()
                            .unwrap()
                            .remove(&request_id)
                        {
                            if let (Ok(protocol_cstring), Ok(message_cstring)) = (
                                CString::new(protocol_id.as_str()),
                                CString::new("request timed out"),
                            ) {
                                unsafe {
                                    handleRPCErrorFromRustBridge(
                                        self.zig_handler,
                                        request_id,
                                        protocol_cstring.as_ptr(),
                                        408,
                                        message_cstring.as_ptr(),
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

            Some(reconnect_result) = poll_fn(|cx| {
                let mut queue = RECONNECT_QUEUE.lock().unwrap();
                std::pin::Pin::new(&mut *queue).poll_next(cx)
            }) => {
                    match reconnect_result {
                        Ok(((network_id, peer_id), (addr, attempt))) => {
                            if network_id == self.network_id {
                                if swarm.is_connected(&peer_id) {
                                    logger::rustLogger.debug(
                                        self.network_id,
                                        &format!(
                                            "Skipping reconnection attempt to peer {} because it is already connected",
                                            peer_id
                                        ),
                                    );
                                    continue;
                                }

                                logger::rustLogger.info(
                                    self.network_id,
                                    &format!("Attempting reconnection to {} (attempt {}/{})", addr, attempt, MAX_RECONNECT_ATTEMPTS),
                                );

                            RECONNECT_ATTEMPTS
                                .lock()
                                .unwrap()
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
                                        .lock()
                                        .unwrap()
                                        .remove(&(self.network_id, peer_id));
                                    self.schedule_reconnection(peer_id, addr, attempt + 1);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        logger::rustLogger.error(self.network_id, &format!("Error in reconnect queue: {}", e));
                    }
                }
            }

            Some(response_channel_timeout) = poll_fn(|cx| {
                let mut map = RESPONSE_CHANNEL_MAP.lock().unwrap();
                std::pin::Pin::new(&mut *map).poll_next(cx)
            }) => {
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
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            logger::rustLogger.info(self.network_id, &format!("Listening on {}", address));
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id, .. } => {
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
                            CONNECTION_DIRECTIONS.lock().unwrap().insert(
                                (self.network_id, peer_id, connection_id),
                                direction,
                            );

                            RECONNECT_QUEUE.lock().unwrap().remove(&(self.network_id, peer_id));
                            RECONNECT_ATTEMPTS
                                .lock()
                                .unwrap()
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
                                let peer_id_string = peer_id.to_string();

                            // Retrieve and remove stored direction
                            let direction = CONNECTION_DIRECTIONS
                                .lock()
                                .unwrap()
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
                                RESPONSE_CHANNEL_MAP.lock().unwrap().retain(|_, pending| {
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

                                // Schedule reconnection if this was a tracked connection attempt
                                if let Some((addr, attempt)) = RECONNECT_ATTEMPTS
                                    .lock()
                                    .unwrap()
                                    .remove(&(self.network_id, pid))
                                {
                                    self.schedule_reconnection(pid, addr, attempt + 1);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            message,
                            ..
                        })) => {
                            let topic = message.topic.as_str();
                            let topic = match CString::new(topic) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    logger::rustLogger.error(self.network_id, &format!("invalid_topic_string={}", topic));
                                    continue;
                                }
                            };
                            let topic = topic.as_ptr();

                            let message_ptr = message.data.as_ptr();
                            let message_len = message.data.len();

                            let sender_peer_id_string = message.source.map(|p| p.to_string()).unwrap_or_else(|| "unknown_peer".to_string());
                            let sender_peer_id_cstring = match CString::new(sender_peer_id_string.clone()) {
                                Ok(cstring) => cstring,
                                Err(_) => {
                                    logger::rustLogger.error(
                                        self.network_id,
                                        &format!("Failed to create C string for peer id {}", sender_peer_id_string),
                                    );
                                    continue;
                                }
                            };

                            unsafe {
                                handleMsgFromRustBridge(self.zig_handler, topic, message_ptr, message_len, sender_peer_id_cstring.as_ptr())
                            };
                            logger::rustLogger.debug(self.network_id, "zig callback completed");
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Reqresp(ReqRespMessage {
                            peer_id,
                            connection_id,
                            message,
                        })) => match message {
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
                                RESPONSE_CHANNEL_MAP.lock().unwrap().insert(
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

                                unsafe {
                                    handleRPCRequestFromRustBridge(
                                        self.zig_handler,
                                        channel_id,
                                        peer_id_cstring.as_ptr(),
                                        protocol_cstring.as_ptr(),
                                        payload.as_ptr(),
                                        payload.len(),
                                    );
                                }
                            }
                            Ok(ReqRespMessageReceived::Response { request_id, message }) => {
                                {
                                    let mut map = REQUEST_ID_MAP.lock().unwrap();
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

                                unsafe {
                                    handleRPCResponseFromRustBridge(
                                        self.zig_handler,
                                        request_id,
                                        peer_id_cstring.as_ptr(),
                                        protocol_cstring.as_ptr(),
                                        response_message.payload.as_ptr(),
                                        response_message.payload.len(),
                                    );
                                }
                            }
                            Ok(ReqRespMessageReceived::EndOfStream { request_id }) => {
                                REQUEST_ID_MAP.lock().unwrap().remove(&request_id);
                                let protocol = REQUEST_PROTOCOL_MAP
                                    .lock()
                                    .unwrap()
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

                                    unsafe {
                                        handleRPCEndOfStreamFromRustBridge(
                                            self.zig_handler,
                                            request_id,
                                            peer_id_cstring.as_ptr(),
                                            protocol_cstring.as_ptr(),
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
                                    .lock()
                                    .unwrap()
                                    .retain(|_, pending| {
                                        !(
                                            pending.peer_id == peer_id
                                                && pending.connection_id == connection_id
                                                && pending.stream_id == stream_id
                                        )
                                    });
                            }
                            Err(ReqRespMessageError::Outbound { request_id, err }) => {
                                REQUEST_ID_MAP.lock().unwrap().remove(&request_id);
                                let protocol = REQUEST_PROTOCOL_MAP
                                    .lock()
                                    .unwrap()
                                    .remove(&request_id);

                                if let Some(protocol_id) = protocol {
                                    if let (Ok(protocol_cstring), Ok(message_cstring)) = (
                                        CString::new(protocol_id.as_str()),
                                        CString::new(format!("{:?}", err)),
                                    ) {
                                        unsafe {
                                            handleRPCErrorFromRustBridge(
                                                self.zig_handler,
                                                request_id,
                                                protocol_cstring.as_ptr(),
                                                3,
                                                message_cstring.as_ptr(),
                                            );
                                        }
                                    }
                                }
                                logger::rustLogger.error(
                                    self.network_id,
                                    &format!("[reqresp] Outbound error for request {} with {}: {:?}", request_id, peer_id, err),
                                );
                            }
                        },
                        e => logger::rustLogger.debug(self.network_id, &format!("{:?}", e)),
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
                let mut cmd = first_cmd;
                let mut drained = 0usize;
                loop {
                    match cmd {
                    SwarmCommand::SubscribeGossip { topic } => {
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
                        let t = gossipsub::IdentTopic::new(topic);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(t, data) {
                            logger::rustLogger.error(self.network_id, &format!("Publish error: {e:?}"));
                        }
                    }
                    SwarmCommand::SendRpcRequest { peer_id, request_id, request_message } => {
                        swarm.behaviour_mut().reqresp.send_request(peer_id, request_id, request_message);
                    }
                    SwarmCommand::SendRpcResponseChunk { channel_id, peer_id, connection_id, stream_id, response_message } => {
                        // Channel coordinates were resolved on the FFI side
                        // under a single `RESPONSE_CHANNEL_MAP` lock; we just
                        // forward the response and log it. We do not re-look
                        // up the channel here, so an interleaved
                        // `SendRpcEndOfStream` (or timeout sweep) cannot make
                        // this chunk silently disappear.
                        swarm.behaviour_mut().reqresp.send_response(
                            peer_id, connection_id, stream_id, response_message,
                        );
                        logger::rustLogger.info(self.network_id, &format!(
                            "[reqresp] Sent response chunk on channel {} (peer: {})", channel_id, peer_id));
                    }
                    SwarmCommand::SendRpcEndOfStream { channel_id } => {
                        let channel = RESPONSE_CHANNEL_MAP.lock().unwrap().remove(&channel_id);
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
                        let channel = RESPONSE_CHANNEL_MAP.lock().unwrap().remove(&channel_id);
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


            }
        }

        // Clean up per-network state so any later `stop_network`/`start_network`
        // calls start from a blank slate and any in-flight dispatchers into Zig
        // see an absent handler rather than a pointer to a freed EthLibp2p.
        unsafe { clear_network_state(self.network_id) };
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
        // Try to decompress; fallback to raw data
        let (data_for_hash, domain): (Vec<u8>, [u8; 4]) =
            match Decoder::new().decompress_vec(&message.data) {
                Ok(decoded) => (decoded, MessageDomain::ValidSnappy.into()),
                Err(_) => (message.data.clone(), MessageDomain::InvalidSnappy.into()),
            };

        // Prepare hashing
        let mut hasher = sha2::Sha256::new();
        hasher.update(domain);
        hasher.update(message.topic.as_str().len().to_le_bytes());
        hasher.update(message.topic.as_str().as_bytes());
        hasher.update(&data_for_hash);

        // Take first 20 bytes as message-id
        let digest = hasher.finalize();
        gossipsub::MessageId::from(&digest[..20])
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
    let transport = build_transport(local_keypair.clone(), true).unwrap();
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
    // mplex config
    let mut mplex_config = libp2p_mplex::Config::new();
    mplex_config.set_max_buffer_size(256);
    mplex_config.set_max_buffer_behaviour(libp2p_mplex::MaxBufferBehaviour::Block);

    // yamux config
    let yamux_config = yamux::Config::default();
    // Creates the TCP transport layer
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
        .upgrade(core::upgrade::Version::V1)
        .authenticate(generate_noise_config(&local_private_key))
        .multiplex(core::upgrade::SelectUpgrade::new(
            yamux_config,
            mplex_config,
        ))
        .timeout(Duration::from_secs(10));
    let transport = if quic_support {
        // Enables Quic
        // The default quic configuration suits us for now.
        let quic_config = libp2p::quic::Config::new(&local_private_key);
        let quic = libp2p::quic::tokio::Transport::new(quic_config);
        let transport = tcp
            .or_transport(quic)
            .map(|either_output, _| match either_output {
                Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
                Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
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
        // Test that wait_for_network_ready times out when network is not initialized
        // Use network_id 99 which we won't initialize
        let result = unsafe { wait_for_network_ready(99, 100) }; // 100ms timeout
        assert!(!result, "Should timeout when network is not initialized");
    }

    #[test]
    fn test_send_rpc_request_before_initialization_returns_zero() {
        // Test that sending RPC request before initialization returns 0
        let network_id = 99;
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
    fn test_send_rpc_request_does_not_burn_id_on_uninitialized_network() {
        // Regression test for the comment on PR #789: when the per-network
        // command channel is missing, `send_rpc_request` must not advance
        // `REQUEST_ID_COUNTER`. Otherwise every failed FFI call permanently
        // leaks a request id and successive ids skip values.
        let network_id = 100; // unused network slot
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
    fn test_publish_msg_to_rust_bridge_returns_false_when_uninitialized() {
        // Regression test for issue #808: publish_msg_to_rust_bridge must
        // return false when the per-network swarm command channel does not
        // exist (i.e. the network was never started or has been torn down),
        // so the Zig-side caller can stop logging "published" for messages
        // that never actually reached the wire.
        let network_id = 101; // unused network slot
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
        let network_id = 102;
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
        let network_id = 104;
        let topic = std::ffi::CString::new("leanconsensus/foo/ssz_snappy").unwrap();
        let ok = unsafe { subscribe_gossip_topic_to_rust_bridge(network_id, topic.as_ptr()) };
        assert!(
            !ok,
            "subscribe_gossip_topic_to_rust_bridge must return false when the network is not initialized"
        );
    }

    #[test]
    fn test_subscribe_gossip_topic_to_rust_bridge_returns_false_on_null_topic() {
        let network_id = 105;
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
        let network_id = 103;
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
        let network_id = 104;
        let cap: usize = 4;
        let (tx, _rx) = mpsc::channel::<SwarmCommand>(cap);
        // Keep _rx alive (no drainer => first `cap` sends fill the channel,
        // anything beyond returns Full instead of Closed).
        COMMAND_SENDERS.lock().unwrap().insert(network_id, tx);

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
        COMMAND_SENDERS.lock().unwrap().remove(&network_id);
    }
}
