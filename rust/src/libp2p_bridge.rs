use futures::future::Either;
use futures::StreamExt;
use libp2p::core::{
    multiaddr::Multiaddr, multiaddr::Protocol, muxing::StreamMuxerBox, transport::Boxed,
};
use libp2p::identity::{secp256k1, Keypair};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    core, gossipsub, identify, identity, noise, ping, yamux, PeerId, SwarmBuilder, Transport,
};
use std::os::raw::c_char;
use std::time::Duration;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};
use tokio::runtime::Builder;

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

// TODO: protect the access by mutex
#[allow(static_mut_refs)]
static mut SWARM_STATE: Option<libp2p::swarm::Swarm<Behaviour>> = None;
// a hack to start a second network for self testing purposes
#[allow(static_mut_refs)]
static mut SWARM_STATE1: Option<libp2p::swarm::Swarm<Behaviour>> = None;

/// # Safety
///
/// The caller must ensure that `listen_addresses` and `connect_addresses` point to valid null-terminated C strings.
#[no_mangle]
pub unsafe fn create_and_run_network(
    network_id: u32,
    zig_handler: u64,
    listen_addresses: *const c_char,
    connect_addresses: *const c_char,
) {
    let listen_multiaddrs = std::ffi::CStr::from_ptr(listen_addresses)
        .to_string_lossy()
        .split(",")
        .map(|addr| addr.parse::<Multiaddr>().expect("Invalid multiaddress"))
        .collect::<Vec<_>>();

    let connect_multiaddrs = std::ffi::CStr::from_ptr(connect_addresses)
        .to_string_lossy()
        .split(",")
        .filter(|s| !s.trim().is_empty()) // filter out empty strings because connect_addresses can be empty
        .map(|addr| addr.parse::<Multiaddr>().expect("Invalid multiaddress"))
        .collect::<Vec<_>>();

    releaseAddresses(zig_handler, listen_addresses, connect_addresses);

    let rt = Builder::new_current_thread().enable_all().build().unwrap();

    rt.block_on(async move {
        let mut p2p_net = Network::new(network_id, zig_handler);
        p2p_net
            .start_network(listen_multiaddrs, connect_multiaddrs)
            .await;
        p2p_net.run_eventloop().await;
    });
}

/// # Safety
/// The caller must ensure that `message_str` points to valid memory of `message_len` bytes.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn publish_msg_to_rust_bridge(
    network_id: u32,
    topic_id: u32,
    message_str: *const u8,
    message_len: usize,
) {
    let message_slice = std::slice::from_raw_parts(message_str, message_len);
    println!(
        "rustbridge-{network_id}:: publishing message s={:?}",
        message_slice
    );
    let message_data = message_slice.to_vec();

    // TODO: get the topic mapping from topic_id
    let topic = match topic_id {
        0 => gossipsub::IdentTopic::new("block"),
        1 => gossipsub::IdentTopic::new("vote"),
        unknown_id => {
            println!("Invalid topic_id: {unknown_id}");
            return;
        }
    };

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

extern "C" {
    fn handleMsgFromRustBridge(
        zig_handler: u64,
        topic_id: u32,
        message_ptr: *const u8,
        message_len: usize,
    );
}

extern "C" {
    fn releaseAddresses(
        zig_handler: u64,
        listen_addresses: *const c_char,
        connect_addresses: *const c_char,
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
        listen_addresses: Vec<Multiaddr>,
        connect_addresses: Vec<Multiaddr>,
    ) {
        let mut swarm = new_swarm();
        println!("starting listner");

        for addr in listen_addresses {
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
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("\nListening on {address:?}\n");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    {
                        let topic = message.topic.as_str();
                        let topic_id: u32 = match topic {
                            "block" => 0,
                            "vote" => 1,
                            unknown_topic => {
                                println!(
                                    "\nrustbridge{0}:: unknown_topic={unknown_topic}\n",
                                    self.network_id
                                );
                                // Will return here return from event loop or return from the match poll to go
                                // for next iteration of loop
                                return;
                            }
                        };

                        let message_ptr = message.data.as_ptr();
                        let message_len = message.data.len();
                        unsafe {
                            handleMsgFromRustBridge(
                                self.zig_handler,
                                topic_id,
                                message_ptr,
                                message_len,
                            )
                        };
                        println!(
                            "\nrustbridge{0}:: zig callback completed\n",
                            self.network_id
                        );
                    }
                }
                e => println!("{e:?}"),
            }
        }
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

impl Behaviour {
    fn new(key: identity::Keypair) -> Self {
        let local_public_key = key.public();
        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        // Set a custom gossipsub configuration
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            // .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
            .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message
            // signing)
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .build()
            .unwrap();
        // .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

        // build a gossipsub network behaviour
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
        )
        .unwrap();

        Self {
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/0.1.0".into(),
                local_public_key.clone(),
            )),
            ping: ping::Behaviour::default(),
            gossipsub,
        }
    }
}

fn new_swarm() -> libp2p::swarm::Swarm<Behaviour> {
    let local_private_key = secp256k1::Keypair::generate();
    let local_keypair: Keypair = local_private_key.into();
    let transport = build_transport(local_keypair.clone(), false).unwrap();
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

    // get all the topics to subscribe. infact impl the subscribe call from zig
    let block_topic = gossipsub::IdentTopic::new("block");
    let vote_topic = gossipsub::IdentTopic::new("vote");
    // subscribes to our topic
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_topic)
        .unwrap();
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&vote_topic)
        .unwrap();

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
