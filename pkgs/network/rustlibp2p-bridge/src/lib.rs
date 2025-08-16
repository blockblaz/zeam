use libp2p::core::{multiaddr::Protocol, multiaddr::Multiaddr, muxing::StreamMuxerBox, transport::Boxed};
use libp2p::identity::{secp256k1, Keypair};
use libp2p::{gossipsub, identify, identity, core, noise, ping, yamux, PeerId, Transport, SwarmBuilder};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use std::time::Duration;
use futures::future::Either;
use std::{error::Error, net::Ipv4Addr,collections::hash_map::DefaultHasher,hash::{Hash, Hasher},};
use futures::StreamExt;
use slog::{crit, debug, info, o, trace, warn};
use tokio::{io, io::AsyncBufReadExt, select};
use std::num::{NonZeroU8, NonZeroUsize};
use tokio::runtime::{Builder, Runtime};
use std::ffi::CString;
use std::os::raw::c_char;

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

// TODO: protect the access by mutex
static mut swarm_state: Option<libp2p::swarm::Swarm<Behaviour>> = None;
// a hack to start a second network for self testing purposes
static mut swarm_state1: Option<libp2p::swarm::Swarm<Behaviour>> = None;

#[no_mangle]
pub fn createAndRunNetwork(network_id: u32, zig_handler: u64, self_port: i32, connect_port: i32) {

    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

        rt.block_on(async move {
            let mut p2p_net = Network::new(network_id, zig_handler);
           p2p_net.start_network(self_port, connect_port).await;
           p2p_net.run_eventloop().await;

        });
}

#[no_mangle]
pub fn publish_msg_to_rust_bridge(network_id:u32, topic_id: u32, message_str: *const u8, message_len: usize){
        let message_slice = unsafe { std::slice::from_raw_parts(message_str, message_len) };
        println!("rustbridge-{network_id}:: publishing message s={:?}",message_slice);
        let message_data = message_slice.to_vec();

        // TODO: get the topic mapping from topic_id
        let topic = gossipsub::IdentTopic::new("block");
         let swarm = if(network_id < 1) {unsafe {swarm_state.as_mut().unwrap()}} else {unsafe {swarm_state1.as_mut().unwrap()}};
        // let mut swarm = unsafe {swarm_state.as_mut().unwrap()};
        if let Err(e) = swarm.behaviour_mut().gossipsub
                    .publish(topic.clone(), message_data){
                    println!("Publish error: {e:?}");
                }
}

extern "C" {
    fn handleMsgFromRustBridge(zig_handler: u64, topic_id: u32, message_ptr: *const u8, message_len: usize);
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

pub async fn start_network(&mut self,self_port: i32, connect_port: i32) {
    let mut swarm = new_swarm();
        println!("starting listner");

    swarm.listen_on(
        Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::UNSPECIFIED))
            .with(Protocol::Tcp(self_port as u16)),
    ).unwrap();

    println!("going for loop match");

    if(connect_port > 0){
        let connect_string = format!("/ip4/127.0.0.1/tcp/{}", connect_port);
        let addr: Multiaddr = connect_string.parse().unwrap();

        // helper closure for dialing peers
        let mut dial = |mut multiaddr: Multiaddr| {
            // strip the p2p protocol if it exists
            strip_peer_id(&mut multiaddr);
            match swarm.dial(multiaddr.clone()) {
                Ok(()) => println!("Dialing libp2p peer address: {multiaddr}"),
                Err(err) => {
                    println!("Could not connect to peer address: {multiaddr} error: {err}");
                }
            };
        };

        dial(addr.clone());
        println!("spinning on {self_port} and connecting on {connect_port}");
    }else{
        println!("spinning on {self_port} and standing by...");
    }

    if self.network_id < 1 {
        unsafe{
        swarm_state = Some(swarm);
      }
    }else{
        unsafe{
        swarm_state1 = Some(swarm);
      }
    }

    // unsafe{
    //     swarm_state = Some(swarm);
    //   }

}

pub async fn run_eventloop(&mut self) {
    let swarm = if self.network_id < 1 {unsafe {swarm_state.as_mut().unwrap()}} else {unsafe {swarm_state1.as_mut().unwrap()}};
    // let mut swarm = unsafe {swarm_state.as_mut().unwrap()};

    loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("\nListening on {address:?}\n");
                },
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message, ..
                    })) => {
                    {
                        let topic = message.topic.as_str();
                        let _topic_ptr = topic.as_ptr();
                        let _topic_len = topic.len();
                        let message_ptr = message.data.as_ptr();
                        let message_len = message.data.len();
                        unsafe {handleMsgFromRustBridge(self.zig_handler, 0 , message_ptr, message_len)};
                        println!("\nrustbridge{0}:: zig callback completed\n", self.network_id);
                    }

                    
                },
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
        .build().unwrap();
        // .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

        // build a gossipsub network behaviour
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
        ).unwrap();

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
    let local_keypair:Keypair = local_private_key.into();
    let transport = build_transport(local_keypair.clone(), false).unwrap();
    println!("build the transport");

    let builder = SwarmBuilder::with_existing_identity(local_keypair)
        .with_tokio()
        .with_other_transport(|_key| transport)
        .expect("infalible");
    
    let mut swarm = builder
    .with_behaviour(|key| Behaviour::new(key.clone())).unwrap()
    .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
    .build();

    // get all the topics to subscribe. infact impl the subscribe call from zig
    let topic = gossipsub::IdentTopic::new("block");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

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
