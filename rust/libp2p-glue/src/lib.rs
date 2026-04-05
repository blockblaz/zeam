pub mod logger;

use futures::future::Either;
use futures::Stream;
use futures::StreamExt;
use libp2p::core::{
    multiaddr::Multiaddr, multiaddr::Protocol, muxing::StreamMuxerBox, transport::Boxed,
};

use libp2p::identity::{secp256k1, Keypair};
use libp2p::swarm::{dial_opts::DialOpts, ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{core, identify, identity, noise, ping, yamux, PeerId, SwarmBuilder, Transport};
use std::os::raw::c_char;
use std::time::Duration;
use tokio::runtime::Builder;

use std::ffi::{CStr, CString};

use delay_map::HashMapDelay;
use futures::future::poll_fn;
use std::collections::HashMap;
use std::sync::Mutex;

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

lazy_static::lazy_static! {
    static ref NETWORK_READY_SIGNALS: std::sync::Mutex<(bool, bool, bool)> = std::sync::Mutex::new((false, false, false));
    static ref NETWORK_READY_CONDVAR: std::sync::Condvar = std::sync::Condvar::new();
    static ref RECONNECT_QUEUE: Mutex<HashMapDelay<(u32, PeerId), (Multiaddr, u32)>> =
        Mutex::new(HashMapDelay::new(Duration::from_secs(5))); // default delay, will be overridden
    static ref RECONNECT_ATTEMPTS: Mutex<HashMap<(u32, PeerId), (Multiaddr, u32)>> = Mutex::new(HashMap::new());
    // Track connection directions for disconnect events (network_id, peer_id, connection_id) -> direction
    static ref CONNECTION_DIRECTIONS: Mutex<HashMap<(u32, PeerId, ConnectionId), u32>> = Mutex::new(HashMap::new());
}

type ReconnectQueueItem = Result<((u32, PeerId), (Multiaddr, u32)), String>;

const MAX_RECONNECT_ATTEMPTS: u32 = 5;
const RECONNECT_DELAYS_SECS: [u64; 5] = [5, 10, 20, 40, 80];

/// Wait for a network to be fully initialized and ready to accept messages.
/// Returns true if the network is ready, false on timeout.
///
/// # Safety
///
/// This function is thread-safe and can be called from any thread.
#[no_mangle]
pub unsafe fn wait_for_network_ready(network_id: u32, timeout_ms: u64) -> bool {
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

/// # Safety
///
/// The caller must ensure that `listen_addresses` and `connect_addresses` point to valid null-terminated C strings.
#[no_mangle]
pub unsafe fn create_and_run_network(
    network_id: u32,
    zig_handler: u64,
    local_private_key: *const c_char,
    listen_addresses: *const c_char,
    connect_addresses: *const c_char,
    topics_str: *const c_char, // retained for ABI compatibility; gossip is now handled by zig-ethp2p
) {
    let listen_multiaddrs = CStr::from_ptr(listen_addresses)
        .to_string_lossy()
        .split(",")
        .map(|addr| addr.parse::<Multiaddr>().expect("Invalid multiaddress"))
        .collect::<Vec<_>>();

    let connect_multiaddrs = CStr::from_ptr(connect_addresses)
        .to_string_lossy()
        .split(",")
        .filter(|s| !s.trim().is_empty()) // filter out empty strings because connect_addresses can be empty
        .map(|addr| addr.parse::<Multiaddr>().expect("Invalid multiaddress"))
        .collect::<Vec<_>>();

    let local_private_key_hex = CStr::from_ptr(local_private_key)
        .to_string_lossy()
        .into_owned();

    let private_key_hex = local_private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&local_private_key_hex);

    let mut private_key_bytes =
        hex::decode(private_key_hex).expect("Invalid hex string for private key");

    let local_key_pair = Keypair::from(secp256k1::Keypair::from(
        secp256k1::SecretKey::try_from_bytes(&mut private_key_bytes)
            .expect("Invalid private key bytes"),
    ));

    // Store zig_handler for this network id for use by free functions
    set_zig_handler(network_id, zig_handler);

    releaseStartNetworkParams(
        zig_handler,
        local_private_key,
        listen_addresses,
        connect_addresses,
        topics_str,
    );

    let rt = Builder::new_current_thread().enable_all().build().unwrap();

    rt.block_on(async move {
        let mut p2p_net = Network::new(network_id, zig_handler);
        p2p_net
            .start_network(local_key_pair, listen_multiaddrs, connect_multiaddrs)
            .await;
        p2p_net.run_eventloop().await;
    });
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
        topics: *const c_char,
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
            let mut dial = |mut multiaddr: Multiaddr| {
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

        loop {
            tokio::select! {

            Some(reconnect_result) = poll_fn(|cx| -> std::task::Poll<Option<ReconnectQueueItem>> {
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
                        e => logger::rustLogger.debug(self.network_id, &format!("{:?}", e)),
                    }
                }
            }
        }
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

impl Behaviour {
    fn new(key: identity::Keypair) -> Self {
        let local_public_key = key.public();
        Self {
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/0.1.0".into(),
                local_public_key.clone(),
            )),
            ping: ping::Behaviour::default(),
        }
    }
}

fn new_swarm(local_keypair: Keypair, network_id: u32) -> libp2p::swarm::Swarm<Behaviour> {
    let transport = build_transport(local_keypair.clone(), true).unwrap();
    logger::rustLogger.debug(network_id, "build the transport");

    let builder = SwarmBuilder::with_existing_identity(local_keypair)
        .with_tokio()
        .with_other_transport(|_key| transport)
        .expect("infalible");

    builder
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
    fn test_wait_for_network_ready_timeout() {
        // Test that wait_for_network_ready times out when network is not initialized
        // Use network_id 99 which we won't initialize
        let result = unsafe { wait_for_network_ready(99, 100) }; // 100ms timeout
        assert!(!result, "Should timeout when network is not initialized");
    }
}
