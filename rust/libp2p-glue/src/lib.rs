pub mod logger;
pub mod req_resp;

use futures::future::Either;
use futures::Stream;
use futures::StreamExt;
use libp2p::core::{
    multiaddr::Multiaddr, multiaddr::Protocol, muxing::StreamMuxerBox, transport::Boxed,
};

use libp2p::identity::{secp256k1, Keypair};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{
    core, gossipsub, identify, identity, noise, ping, yamux, PeerId, SwarmBuilder, Transport,
};
use std::convert::TryFrom;
use std::os::raw::c_char;
use std::time::Duration;
use tokio::runtime::Builder;

use sha2::Digest;
use snap::raw::Decoder;
use std::ffi::{CStr, CString};

use delay_map::HashMapDelay;
use futures::future::poll_fn;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::req_resp::{
    configurations::REQUEST_TIMEOUT,
    varint::{encode_varint, MAX_VARINT_BYTES},
    LeanSupportedProtocol, ProtocolId, ReqResp, ReqRespMessage, ReqRespMessageError,
    ReqRespMessageReceived, RequestMessage, ResponseMessage,
};

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

// TODO: protect the access by mutex
#[allow(static_mut_refs)]
static mut SWARM_STATE: Option<libp2p::swarm::Swarm<Behaviour>> = None;
// a hack to start a second network for self testing purposes
#[allow(static_mut_refs)]
static mut SWARM_STATE1: Option<libp2p::swarm::Swarm<Behaviour>> = None;

lazy_static::lazy_static! {
    static ref REQUEST_ID_MAP: Mutex<HashMapDelay<u64, ()>> = Mutex::new(HashMapDelay::new(REQUEST_TIMEOUT));
    static ref REQUEST_PROTOCOL_MAP: Mutex<HashMap<u64, ProtocolId>> = Mutex::new(HashMap::new());
    static ref RESPONSE_CHANNEL_MAP: Mutex<HashMap<u64, PendingResponse>> = Mutex::new(HashMap::new());
}

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static RESPONSE_CHANNEL_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct PendingResponse {
    peer_id: PeerId,
    connection_id: ConnectionId,
    stream_id: u64,
    protocol: ProtocolId,
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
    logger::log_debug(
        network_id,
        &format!(
            "publishing message s={:?}..({})",
            hex::encode(&message_slice[..message_len.min(100)]),
            message_len
        ),
    );
    let message_data = message_slice.to_vec();

    if topic.is_null() {
        logger::log_error(
            network_id,
            "null pointer passed for `topic` in publish_msg_to_rust_bridge",
        );
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
        logger::log_error(network_id, &format!("Publish error: {e:?}"));
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
    protocol_tag: u32,
    request_data: *const u8,
    request_len: usize,
) -> u64 {
    let peer_id_str = CStr::from_ptr(peer_id).to_string_lossy().to_string();
    let peer_id: PeerId = match peer_id_str.parse() {
        Ok(id) => id,
        Err(e) => {
            logger::log_error(network_id, &format!("Invalid peer ID: {}", e));
            return 0;
        }
    };

    let request_slice = std::slice::from_raw_parts(request_data, request_len);
    let request_bytes = request_slice.to_vec();

    let protocol = match LeanSupportedProtocol::try_from(protocol_tag) {
        Ok(protocol) => protocol,
        Err(_) => {
            logger::log_error(
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

    #[allow(static_mut_refs)]
    let swarm = if network_id < 1 {
        SWARM_STATE.as_mut().unwrap()
    } else {
        SWARM_STATE1.as_mut().unwrap()
    };

    let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

    let request_message = RequestMessage::new(protocol_id.clone(), request_bytes);

    swarm
        .behaviour_mut()
        .reqresp
        .send_request(peer_id, request_id, request_message);

    REQUEST_ID_MAP.lock().unwrap().insert(request_id, ());
    REQUEST_PROTOCOL_MAP
        .lock()
        .unwrap()
        .insert(request_id, protocol_id.clone());

    logger::log_info_module(
        network_id,
        "reqresp",
        &format!(
            "Sent {:?} request to {} (id: {})",
            protocol, peer_id, request_id
        ),
    );

    request_id
}

/// # Safety
/// The caller must ensure that `response_data` points to valid memory of `response_len` bytes.
#[no_mangle]
pub unsafe fn send_rpc_response_chunk(
    network_id: u32,
    channel_id: u64,
    response_data: *const u8,
    response_len: usize,
) {
    let response_slice = std::slice::from_raw_parts(response_data, response_len);
    let response_bytes = response_slice.to_vec();

    let channel = {
        let response_map = RESPONSE_CHANNEL_MAP.lock().unwrap();
        response_map.get(&channel_id).cloned()
    };

    if let Some(channel) = channel {
        #[allow(static_mut_refs)]
        let swarm = if network_id < 1 {
            SWARM_STATE.as_mut().unwrap()
        } else {
            SWARM_STATE1.as_mut().unwrap()
        };

        let response_message = ResponseMessage::new(channel.protocol.clone(), response_bytes);

        swarm.behaviour_mut().reqresp.send_response(
            channel.peer_id,
            channel.connection_id,
            channel.stream_id,
            response_message,
        );
        logger::log_info_module(
            network_id,
            "reqresp",
            &format!(
                "Sent response payload on channel {} (peer: {})",
                channel_id, channel.peer_id
            ),
        );
    } else {
        logger::log_error(
            network_id,
            &format!("No response channel found for id {}", channel_id),
        );
    }
}

/// # Safety
/// The caller must ensure the channel id is valid for a pending response.
#[no_mangle]
pub unsafe fn send_rpc_end_of_stream(network_id: u32, channel_id: u64) {
    let channel = {
        let mut response_map = RESPONSE_CHANNEL_MAP.lock().unwrap();
        response_map.remove(&channel_id)
    };

    if let Some(channel) = channel {
        #[allow(static_mut_refs)]
        let swarm = if network_id < 1 {
            SWARM_STATE.as_mut().unwrap()
        } else {
            SWARM_STATE1.as_mut().unwrap()
        };

        swarm.behaviour_mut().reqresp.finish_response_stream(
            channel.peer_id,
            channel.connection_id,
            channel.stream_id,
        );
        logger::log_info_module(
            network_id,
            "reqresp",
            &format!(
                "Sent end-of-stream on channel {} (peer: {})",
                channel_id, channel.peer_id
            ),
        );
    } else {
        logger::log_error(
            network_id,
            &format!("No response channel found for id {}", channel_id),
        );
    }
}

/// # Safety
/// The caller must ensure `message_ptr` points to a valid null-terminated C string.
#[no_mangle]
pub unsafe fn send_rpc_error_response(
    network_id: u32,
    channel_id: u64,
    message_ptr: *const c_char,
) {
    if message_ptr.is_null() {
        logger::log_error(
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
        logger::log_error(
            network_id,
            &format!(
                "Attempted to send RPC error payload exceeding maximum size on channel {}",
                channel_id
            ),
        );
        return;
    }

    let channel = {
        let mut response_map = RESPONSE_CHANNEL_MAP.lock().unwrap();
        response_map.remove(&channel_id)
    };

    if let Some(channel) = channel {
        #[allow(static_mut_refs)]
        let swarm = if network_id < 1 {
            SWARM_STATE.as_mut().unwrap()
        } else {
            SWARM_STATE1.as_mut().unwrap()
        };

        let mut payload = Vec::with_capacity(1 + MAX_VARINT_BYTES + message_bytes.len());
        payload.push(2);
        encode_varint(message_bytes.len(), &mut payload);
        payload.extend_from_slice(message_bytes);

        let response_message = ResponseMessage::new(channel.protocol.clone(), payload);

        let peer_id = channel.peer_id;

        swarm.behaviour_mut().reqresp.send_response(
            peer_id,
            channel.connection_id,
            channel.stream_id,
            response_message,
        );
        swarm.behaviour_mut().reqresp.finish_response_stream(
            peer_id,
            channel.connection_id,
            channel.stream_id,
        );
        logger::log_info_module(
            network_id,
            "reqresp",
            &format!(
                "Sent error response on channel {} (peer: {}): {}",
                channel_id, peer_id, message
            ),
        );
    } else {
        logger::log_error(
            network_id,
            &format!("No response channel found for id {}", channel_id),
        );
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
        protocol_id: *const c_char,
        response_ptr: *const u8,
        response_len: usize,
    );

    fn handleRPCEndOfStreamFromRustBridge(
        zig_handler: u64,
        request_id: u64,
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
        let mut swarm = new_swarm(key_pair, topics, self.network_id);
        logger::log_info(self.network_id, "starting listener");

        for mut addr in listen_addresses {
            strip_peer_id(&mut addr);
            swarm.listen_on(addr).unwrap();
        }

        logger::log_debug(self.network_id, "going for loop match");

        if !connect_addresses.is_empty() {
            // helper closure for dialing peers
            let mut dial = |mut multiaddr: Multiaddr| {
                // strip the p2p protocol if it exists
                strip_peer_id(&mut multiaddr);
                match swarm.dial(multiaddr.clone()) {
                    Ok(()) => logger::log_debug(
                        self.network_id,
                        &format!("dialing libp2p peer address: {}", multiaddr),
                    ),
                    Err(err) => {
                        logger::log_error(
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
                dial(addr);
            }
        } else {
            logger::log_debug(self.network_id, "no connect addresses");
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
                    Ok((request_id, ())) => {
                        logger::log_warn_module(
                            self.network_id,
                            "reqresp",
                            &format!("Request {} timed out after {:?}", request_id, REQUEST_TIMEOUT),
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
                        logger::log_error_module(self.network_id, "reqresp", &format!("Error in delay map: {}", e));
                    }
                }
            }

                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            logger::log_info(self.network_id, &format!("\nListening on {}\n", address));
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            let peer_id = peer_id.to_string();
                            let peer_id = peer_id.as_str();
                            logger::log_info(
                                self.network_id,
                                &format!("\nConnection established with peer: {}\n", peer_id),
                            );
                            let peer_id_cstr = match CString::new(peer_id) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    logger::log_error(self.network_id, &format!("invalid_peer_id_string={}", peer_id));
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
                            logger::log_info(
                                self.network_id,
                                &format!("\nConnection closed with peer: {}\n", peer_id),
                            );
                            let peer_id_cstr = match CString::new(peer_id) {
                                Ok(cstr) => cstr,
                                Err(_) => {
                                    logger::log_error(self.network_id, &format!("invalid_peer_id_string={}", peer_id));
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
                                    logger::log_error(self.network_id, &format!("invalid_topic_string={}", topic));
                                    continue;
                                }
                            };
                            let topic = topic.as_ptr();

                            let message_ptr = message.data.as_ptr();
                            let message_len = message.data.len();

                            unsafe {
                                handleMsgFromRustBridge(self.zig_handler, topic, message_ptr, message_len)
                            };
                            logger::log_debug(self.network_id, "\nzig callback completed\n");
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
                                logger::log_info_module(
                                    self.network_id,
                                    "reqresp",
                                    &format!("Received request from {} for protocol {} ({} bytes)", peer_id, protocol.as_str(), payload.len()),
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
                                        logger::log_error_module(
                                            self.network_id,
                                            "reqresp",
                                            &format!("Failed to create C string for peer id {}: {}", peer_id, err),
                                        );
                                        continue;
                                    }
                                };

                                let protocol_cstring = match CString::new(protocol.as_str()) {
                                    Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::log_error_module(
                                            self.network_id,
                                            "reqresp",
                                            &format!("Failed to create C string for protocol {}: {}", protocol.as_str(), err),
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
                                logger::log_info_module(
                                    self.network_id,
                                    "reqresp",
                                    &format!("Received response from {} for request id {} ({} bytes)", peer_id, request_id, response_message.payload.len()),
                                );
                                let protocol_cstring = match CString::new(
                                    response_message.protocol.as_str(),
                                ) {
                                    Ok(cstring) => cstring,
                                    Err(err) => {
                                        logger::log_error_module(
                                            self.network_id,
                                            "reqresp",
                                            &format!("Failed to create C string for protocol {}: {}", response_message.protocol.as_str(), err),
                                        );
                                        continue;
                                    }
                                };

                                unsafe {
                                    handleRPCResponseFromRustBridge(
                                        self.zig_handler,
                                        request_id,
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
                                    let protocol_cstring = match CString::new(protocol_id.as_str()) {
                                        Ok(cstring) => cstring,
                                        Err(err) => {
                                            logger::log_error_module(
                                                self.network_id,
                                                "reqresp",
                                                &format!("Failed to create C string for protocol {} on end-of-stream: {}", protocol_id.as_str(), err),
                                            );
                                            continue;
                                        }
                                    };

                                    unsafe {
                                        handleRPCEndOfStreamFromRustBridge(
                                            self.zig_handler,
                                            request_id,
                                            protocol_cstring.as_ptr(),
                                        );
                                    }
                                } else {
                                    logger::log_warn_module(
                                        self.network_id,
                                        "reqresp",
                                        &format!("Received end-of-stream for request id {} without protocol mapping", request_id),
                                    );
                                }
                            }
                            Err(ReqRespMessageError::Inbound { stream_id, err }) => {
                                logger::log_error_module(
                                    self.network_id,
                                    "reqresp",
                                    &format!("Inbound error from {} on stream {}: {:?}", peer_id, stream_id, err),
                                );
                                RESPONSE_CHANNEL_MAP
                                    .lock()
                                    .unwrap()
                                    .retain(|_, pending| {
                                        !(pending.peer_id == peer_id
                                            && pending.connection_id == connection_id
                                            && pending.stream_id == stream_id)
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
                                logger::log_error_module(
                                    self.network_id,
                                    "reqresp",
                                    &format!("Outbound error for request {} with {}: {:?}", request_id, peer_id, err),
                                );
                            }
                        },
                        e => logger::log_debug(self.network_id, &format!("{:?}", e)),
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
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .build()
            .unwrap();
        // .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

        // build a gossipsub network behaviour
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

fn new_swarm(
    local_keypair: Keypair,
    topics: Vec<String>,
    network_id: u32,
) -> libp2p::swarm::Swarm<Behaviour> {
    let transport = build_transport(local_keypair.clone(), true).unwrap();
    logger::log_debug(network_id, "build the transport");

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
