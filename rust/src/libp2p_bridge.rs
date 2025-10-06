use futures::future::Either;
use futures::StreamExt;
use libp2p::core::{
    multiaddr::Multiaddr, multiaddr::Protocol, muxing::StreamMuxerBox, transport::Boxed,
};

use libp2p::identity::{secp256k1, Keypair};
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::StreamProtocol;
use libp2p::{
    core, gossipsub, identify, identity, noise, ping, yamux, PeerId, SwarmBuilder, Transport,
};
use std::os::raw::c_char;
use std::time::Duration;
use tokio::runtime::Builder;

use sha2::Digest;
use snap::raw::Decoder;
use std::ffi::{CStr, CString};

use delay_map::HashMapDelay;
use futures::future::poll_fn;
use futures::Stream;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

// TODO: protect the access by mutex
#[allow(static_mut_refs)]
static mut SWARM_STATE: Option<libp2p::swarm::Swarm<Behaviour>> = None;
// a hack to start a second network for self testing purposes
#[allow(static_mut_refs)]
static mut SWARM_STATE1: Option<libp2p::swarm::Swarm<Behaviour>> = None;

lazy_static::lazy_static! {
    static ref REQUEST_ID_MAP: Mutex<HashMapDelay<OutboundRequestId, u64>> = Mutex::new(HashMapDelay::new(Duration::from_secs(10)));
    static ref RESPONSE_CHANNEL_MAP: Mutex<HashMap<u64, request_response::ResponseChannel<Vec<u8>>>> = Mutex::new(HashMap::new());
}

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static RESPONSE_CHANNEL_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    topics_str: *const c_char,
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

    let topics = CStr::from_ptr(topics_str)
        .to_string_lossy()
        .split(",")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
            .start_network(
                local_key_pair,
                listen_multiaddrs,
                connect_multiaddrs,
                topics,
            )
            .await;
        p2p_net.run_eventloop().await;
    });
}

/// # Safety
///
/// The caller must ensure that `message_str` points to valid memory of `message_len` bytes.
/// The caller must ensure that `topic` points to valid null-terminated C string.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn publish_msg_to_rust_bridge(
    network_id: u32,
    topic: *const c_char,
    message_str: *const u8,
    message_len: usize,
) {
    let message_slice = std::slice::from_raw_parts(message_str, message_len);
    println!(
        "rustbridge-{network_id}:: publishing message s={:?}..({:?})",
        hex::encode(&message_slice[..100]),
        message_len
    );
    let message_data = message_slice.to_vec();

    if topic.is_null() {
        eprintln!("Error: null pointer passed for `topic` in publish_msg_to_rust_bridge");
        return;
    }

    let topic = CStr::from_ptr(topic).to_string_lossy().to_string();
    let topic = gossipsub::IdentTopic::new(topic);

    #[allow(static_mut_refs)]
    let swarm = if network_id < 1 {
        unsafe { SWARM_STATE.as_mut().unwrap() }
    } else {
        unsafe { SWARM_STATE1.as_mut().unwrap() }
    };
    // let mut swarm = unsafe {SWARM_STATE.as_mut().unwrap()};
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), message_data)
    {
        println!("Publish error: {e:?}");
    }
}

/// # Safety
///
/// The caller must ensure that `peer_id` points to a valid null-terminated C string.
/// The caller must ensure that `request_data` points to valid memory of `request_len` bytes.
#[no_mangle]
pub unsafe fn send_rpc_request(
    network_id: u32,
    peer_id: *const c_char,
    request_data: *const u8,
    request_len: usize,
) -> u64 {
    let peer_id_str = CStr::from_ptr(peer_id).to_string_lossy().to_string();
    let peer_id: PeerId = match peer_id_str.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Invalid peer ID: {}", e);
            return 0;
        }
    };

    let request_slice = std::slice::from_raw_parts(request_data, request_len);
    let request_bytes = request_slice.to_vec();

    #[allow(static_mut_refs)]
    let swarm = if network_id < 1 {
        SWARM_STATE.as_mut().unwrap()
    } else {
        SWARM_STATE1.as_mut().unwrap()
    };

    let libp2p_request_id = swarm
        .behaviour_mut()
        .reqresp
        .send_request(&peer_id, request_bytes);

    let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

    REQUEST_ID_MAP
        .lock()
        .unwrap()
        .insert(libp2p_request_id, request_id);

    println!(
        "reqresp:: Sent request to {} (id: {:?})",
        peer_id, request_id
    );

    request_id
}

/// # Safety
/// The caller must ensure that `response_data` points to valid memory of `response_len` bytes.
/// The caller must ensure that `channel_id` corresponds to a valid response channel.
pub unsafe fn send_rpc_response(
    network_id: u32,
    channel_id: u64,
    response_data: *const u8,
    response_len: usize,
) {
    let response_slice = std::slice::from_raw_parts(response_data, response_len);
    let response_bytes = response_slice.to_vec();
    let mut response_map = RESPONSE_CHANNEL_MAP.lock().unwrap();
    if let Some(channel) = response_map.remove(&channel_id) {
        #[allow(static_mut_refs)]
        let swarm = if network_id < 1 {
            SWARM_STATE.as_mut().unwrap()
        } else {
            SWARM_STATE1.as_mut().unwrap()
        };
        if let Err(e) = swarm
            .behaviour_mut()
            .reqresp
            .send_response(channel, response_bytes)
        {
            eprintln!("Failed to send response: {:?}", e);
        } else {
            println!("Sent response on channel {}", channel_id);
        }
    } else {
        eprintln!("No response channel found for id {}", channel_id);
    }
}

extern "C" {
    fn handleMsgFromRustBridge(
        zig_handler: u64,
        topic: *const c_char,
        message_ptr: *const u8,
        message_len: usize,
    );
}

extern "C" {
    fn handlePeerConnectedFromRustBridge(zig_handler: u64, peer_id: *const c_char);
}

extern "C" {
    fn handlePeerDisconnectedFromRustBridge(zig_handler: u64, peer_id: *const c_char);
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

pub struct Network {
    network_id: u32,
    zig_handler: u64,
}
impl Network {
    pub fn new(network_id: u32, zig_handler: u64) -> Self {
        let network: Network = Network {
            network_id,
            zig_handler,
        };

        network
    }

    pub async fn start_network(
        &mut self,
        key_pair: Keypair,
        listen_addresses: Vec<Multiaddr>,
        connect_addresses: Vec<Multiaddr>,
        topics: Vec<String>,
    ) {
        let mut swarm = new_swarm(key_pair, topics);
        println!("starting listener");

        for mut addr in listen_addresses {
            strip_peer_id(&mut addr);
            swarm.listen_on(addr).unwrap();
        }

        println!("going for loop match");

        if !connect_addresses.is_empty() {
            // helper closure for dialing peers
            let mut dial = |mut multiaddr: Multiaddr| {
                // strip the p2p protocol if it exists
                strip_peer_id(&mut multiaddr);
                match swarm.dial(multiaddr.clone()) {
                    Ok(()) => println!("dialing libp2p peer address: {multiaddr}"),
                    Err(err) => {
                        println!("could not connect to peer address: {multiaddr} error: {err}");
                    }
                };
            };

            for addr in connect_addresses {
                dial(addr);
            }
        } else {
            println!("no connect addresses");
        }

        if self.network_id < 1 {
            unsafe {
                SWARM_STATE = Some(swarm);
            }
        } else {
            unsafe {
                SWARM_STATE1 = Some(swarm);
            }
        }
    }

    pub async fn run_eventloop(&mut self) {
        #[allow(static_mut_refs)]
        let swarm = if self.network_id < 1 {
            unsafe { SWARM_STATE.as_mut().unwrap() }
        } else {
            unsafe { SWARM_STATE1.as_mut().unwrap() }
        };

        loop {
            tokio::select! {

            Some(timeout_result) = poll_fn(|cx| {
                let mut map = REQUEST_ID_MAP.lock().unwrap();
                std::pin::Pin::new(&mut *map).poll_next(cx)
            }) => {
                match timeout_result {
                    Ok((libp2p_id, request_id)) => {
                        println!(
                            "reqresp:: Request {} (libp2p_id: {:?}) timed out after 10 seconds",
                            request_id, libp2p_id
                        );

                        // unsafe {
                        //     handleReqRespResult(
                        //         self.zig_handler,
                        //         request_id,
                        //         1, // Timeout error code
                        //         std::ptr::null(),
                        //         0,
                        //     );
                        // }
                    }
                    Err(e) => {
                        eprintln!("reqresp:: Error in delay map: {}", e);
                    }
                }
            }

                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("\nListening on {address:?}\n");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            let peer_id = peer_id.to_string();
                            let peer_id = peer_id.as_str();
                            println!(
                                "\nrustbridge{}:: Connection established with peer: {}\n",
                                self.network_id, peer_id
                            );
                            let peer_id_cstr = match CString::new(peer_id) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    eprintln!(
                                        "rustbridge{}:: invalid_peer_id_string={}",
                                        self.network_id, peer_id
                                    );
                                    continue;
                                }
                            };
                            unsafe {
                                handlePeerConnectedFromRustBridge(self.zig_handler, peer_id_cstr.as_ptr())
                            };
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            let peer_id = peer_id.to_string();
                            let peer_id = peer_id.as_str();
                            println!(
                                "\nrustbridge{}:: Connection closed with peer: {}\n",
                                self.network_id, peer_id
                            );
                            let peer_id_cstr = match CString::new(peer_id) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    eprintln!(
                                        "rustbridge{}:: invalid_peer_id_string={}",
                                        self.network_id, peer_id
                                    );
                                    continue;
                                }
                            };
                            unsafe {
                                handlePeerDisconnectedFromRustBridge(
                                    self.zig_handler,
                                    peer_id_cstr.as_ptr(),
                                )
                            };
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            message,
                            ..
                        })) => {
                            let topic = message.topic.as_str();
                            let topic = match CString::new(topic) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    eprintln!(
                                        "rustbridge{}:: invalid_topic_string={}",
                                        self.network_id, topic
                                    );
                                    continue;
                                }
                            };
                            let topic = topic.as_ptr();

                            let message_ptr = message.data.as_ptr();
                            let message_len = message.data.len();

                            unsafe {
                                handleMsgFromRustBridge(self.zig_handler, topic, message_ptr, message_len)
                            };
                            println!(
                                "\nrustbridge{0}:: zig callback completed\n",
                                self.network_id
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Reqresp(
                            request_response::Event::Message { peer, message },
                        )) => match message {
                            request_response::Message::Request {
                                request_id: _,
                                request,
                                channel,
                            } => {
                                println!(
                                    "reqresp:: Received request from {} ({} bytes)",
                                    peer,
                                    request.len()
                                );

                                let channel_id = RESPONSE_CHANNEL_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
                                RESPONSE_CHANNEL_MAP.lock().unwrap().insert(channel_id, channel);

                                // unsafe {
                                //     handleReqRespRequest(
                                //         self.zig_handler,
                                //         channel_id,
                                //         request.as_ptr(),
                                //         request.len(),
                                //     );
                                // }
                            }
                            request_response::Message::Response {
                                request_id,
                                response,
                            } => {
                                let maybe_request_id = REQUEST_ID_MAP.lock().unwrap().remove(&request_id);
                                if let Some(mapped_id) = maybe_request_id {
                                    println!(
                                        "reqresp:: Received response from {} for request id {} ({} bytes)",
                                        peer,
                                        mapped_id,
                                        response.len()
                                    );

                                    // unsafe {
                                    //     handleReqRespResult(
                                    //         self.zig_handler,
                                    //         mapped_id,
                                    //         0, // success
                                    //         response.as_ptr(),
                                    //         response.len(),
                                    //     );
                                    // }
                                } else {
                                    println!(
                                        "reqresp:: Received response from {} for unknown request id {:?} ({} bytes)",
                                        peer,
                                        request_id,
                                        response.len()
                                    );
                                }
                            }
                        },
                        e => println!("{e:?}"),
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
    gossipsub: gossipsub::Behaviour,
    reqresp: request_response::Behaviour<BytesCodec>,
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
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .build()
            .unwrap();
        // .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

        // build a gossipsub network behaviour
        let gossipsub =
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, gossipsub_config)
                .unwrap();

        let reqresp = {
            let protocols = vec![
                "/leanconsensus/req/status/1/ssz_snappy",
                "/leanconsensus/req/lean_blocks_by_root/1/ssz_snappy",
            ]
            .into_iter()
            .map(|protocol| (StreamProtocol::new(protocol), ProtocolSupport::Full));

            let cfg =
                request_response::Config::default().with_request_timeout(Duration::from_secs(10));

            request_response::Behaviour::new(protocols, cfg)
        };

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

fn new_swarm(local_keypair: Keypair, topics: Vec<String>) -> libp2p::swarm::Swarm<Behaviour> {
    let transport = build_transport(local_keypair.clone(), true).unwrap();
    println!("build the transport");

    let builder = SwarmBuilder::with_existing_identity(local_keypair)
        .with_tokio()
        .with_other_transport(|_key| transport)
        .expect("infalible");

    let mut swarm = builder
        .with_behaviour(|key| Behaviour::new(key.clone()))
        .unwrap()
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    // subscribe all the topics
    for topic in topics {
        let gossipsub_topic = gossipsub::IdentTopic::new(topic);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub_topic)
            .unwrap();
    }

    swarm
}

fn build_transport(
    local_private_key: Keypair,
    quic_support: bool,
) -> std::io::Result<BoxedTransport> {
    // mplex config
    let mut mplex_config = libp2p_mplex::MplexConfig::new();
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

#[derive(Debug, Clone, Default)]
pub struct BytesCodec;

#[async_trait::async_trait]
impl request_response::Codec for BytesCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut data = Vec::new();
        io.read_to_end(&mut data).await?;
        Ok(data)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut data = Vec::new();
        io.read_to_end(&mut data).await?;
        Ok(data)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        io.write_all(&req).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        io.write_all(&res).await?;
        io.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::gossipsub::IdentTopic;
    use libp2p::gossipsub::MessageId;
    use snap::raw::Encoder;

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
}
