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

#[no_mangle]
pub fn createNetwork(zigHandler: u64, selfPort: i32, connectPort: i32) {

    let rt = Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

        rt.block_on(async move {
            let mut p2p_net = Network::new(zigHandler);
           p2p_net.start_network(selfPort, connectPort).await;       
           p2p_net.run_eventloop().await;

        });
}

static mut swarm_state: Option<libp2p::swarm::Swarm<Behaviour>> = None;


#[no_mangle]
pub fn publishMsg(message_str: *const u8, message_len: usize){
        let message_slice = unsafe { std::slice::from_raw_parts(message_str, message_len) };
        println!("publishing message s={:?}",message_slice);
        let message_data = message_slice.to_vec();

        let topic = gossipsub::IdentTopic::new("test-net");
        let mut swarm = unsafe {swarm_state.as_mut().unwrap()};
        if let Err(e) = swarm.behaviour_mut().gossipsub
                    .publish(topic.clone(), message_data){
                    println!("Publish error: {e:?}");
                }
}

extern "C" {
    fn zig_add(libp2pEvents: u64, a: i32, b: i32, message: *mut c_char) -> i32;
}

fn newSwarm() -> libp2p::swarm::Swarm<Behaviour> {
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

    let topic = gossipsub::IdentTopic::new("test-net");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic);

    swarm
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


pub struct Network {
    zigHandler: u64,
}
impl Network {
    pub fn new(zigHandler: u64) -> Self {
    

    // // use the executor for libp2p
    // let config = libp2p::swarm::Config::without_executor()
    //             .with_notify_handler_buffer_size(NonZeroUsize::new(7).expect("Not zero"))
    //             .with_per_connection_event_buffer_size(4)
    //             .with_idle_connection_timeout(Duration::from_secs(10)) // Other clients can timeout
    //             // during negotiation
    //             .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap());

    // let connection_limits = {
    //     let limits = libp2p::connection_limits::ConnectionLimits::default()
    //         .with_max_pending_incoming(Some(5))
    //         .with_max_pending_outgoing(Some(16))
    //         .with_max_established_incoming(Some(10))
    //         .with_max_established_outgoing(Some(10))
    //         .with_max_established(Some(10))
    //         .with_max_established_per_peer(Some(1));

    //     libp2p::connection_limits::Behaviour::new(limits)
    // };

    // let mut swarm = ;


    // .with_swarm_config(|_| config)

    let network: Network = Network {
        zigHandler,
    };

    network
}

pub async fn start_network(&mut self,selfPort: i32, connectPort: i32) {
    let mut p2p_net = self;
    let mut swarm = newSwarm();
        println!("starting listner");

    swarm.listen_on(
        Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::UNSPECIFIED))
            .with(Protocol::Tcp(selfPort as u16)),
    );

    println!("going for loop match");

    if(connectPort > 0){
        let connectString = format!("/ip4/127.0.0.1/tcp/{}", connectPort);
        let addr: Multiaddr = connectString.parse().unwrap();

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
        println!("spinning on {selfPort} and connecting on {connectPort}");
    }else{
        println!("spinning on {selfPort} and standing by...");
    }

    unsafe{
        swarm_state = Some(swarm);
    }

}

pub async fn run_eventloop(&mut self) {
    let mut swarm = unsafe {swarm_state.as_mut().unwrap()};
     loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("\nListening on {address:?}\n");
                },
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message, ..
                    })) => {
                    {

                        let my_vec: Vec<u8> =  message.data;
                        let raw_ptr: *mut c_char = CString::new(my_vec).expect("cstring").into_raw(); 
                        let result = unsafe {zig_add(self.zigHandler,23,42, raw_ptr)};
                        println!("\nzig callback result {result}\n");
                    }

                    
                },
                e => println!("{e:?}"),
            }
        }
}
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


// Note: Safely ignore this
// Below is some code experimented upon (although didn't exactly work out) to figure out how to best run rustlibp2p 
// with evenloop in nonblocking way


// #[no_mangle]
// pub fn startNetwork1(p2p_ref: *mut Network, selfPort: i32, connectPort: i32){
//     // unsafe{
//         // let p2p_net1 = & mut *p2p_ref;
//         // tokio::runtime::Builder::new_multi_thread()
//         //     .enable_all()
//         //     .build()
//         //     .unwrap()
//         //     .block_on(async {
//         //         p2p_net.start_network(9001, -1).await;
//         //     });


//         // let runtime = tokio::runtime::Builder::new_multi_thread()
//         // .worker_threads(1)
//         // .enable_all()
//         // .build()
//         // .unwrap();

//         // let handle = runtime.spawn(async {
//         //     let mut p2p_net = Network::new();
//         //     p2p_net.start_network(9001, -1).await;
//         //     println!("second tokio spawn !!!!!!!");
                
//         //     loop {
//         //         println!("looping --------- second tokio spawn !!!!!!!");
                
//         //         tokio::select! {
//         //             event = p2p_net.swarm.next() => {
//         //                 match event.unwrap() {
//         //                     SwarmEvent::NewListenAddr { address, .. } => {
//         //                         let result = unsafe {zig_add(23,42)};
//         //                         println!("Listening on {address:?} result {result}");
//         //                     },
//         //                     SwarmEvent::Behaviour(event) => {
//         //                         let result = unsafe {zig_add(23,42)};
//         //                         println!("{event:?} result {result}");
//         //                     },
//         //                     e => println!("{e:?}"),
//         //                 }
//         //             }
//         //         }
                
//         //     }
//         // });

//         // runtime.block_on(handle).unwrap();

//         // tokio::runtime::Builder::new_multi_thread()
//             // .enable_all()
//             // .build()
//             // .unwrap()
//             // .block_on(async {
//             //     // p2p_net.start_network(selfPort, connectPort).await;
                
//             //     tokio::spawn(async {
//             //         let mut p2p_net = Network::new();
//             //         p2p_net.start_network(9001, -1).await;
//             //         println!("second tokio spawn !!!!!!!");
                        
//             //         loop {
//             //             println!("looping --------- second tokio spawn !!!!!!!");
                        
//             //             tokio::select! {
//             //                 event = p2p_net.swarm.next() => {
//             //                     match event.unwrap() {
//             //                         SwarmEvent::NewListenAddr { address, .. } => {
//             //                             let result = unsafe {zig_add(23,42)};
//             //                             println!("Listening on {address:?} result {result}");
//             //                         },
//             //                         SwarmEvent::Behaviour(event) => {
//             //                             let result = unsafe {zig_add(23,42)};
//             //                             println!("{event:?} result {result}");
//             //                         },
//             //                         e => println!("{e:?}"),
//             //                     }
//             //                 }
//             //             }
                        
//             //         }
//             //     }).await;

//             //     tokio::spawn(async {
//             //         println!("first tokio spawn------------");
//             //       });

//             //     println!("Hello world11111 ********");
//             // })
// // }


//     unsafe {
//         let p2p_net = & mut *p2p_ref;
//         let mut rt = tokio::runtime::Builder::new_multi_thread()
//         .enable_all()
//         .build()
//         .unwrap();
//         rt.block_on(async {
//             p2p_net.start_network(selfPort, connectPort).await;

//             loop {
//                 match p2p_net.swarm.select_next_some().await {
//                     SwarmEvent::NewListenAddr { address, .. } => {
//                         let result = unsafe {zig_add(23,42)};
//                         println!("Listening on {address:?} result {result}");
//                     },
//                     SwarmEvent::Behaviour(event) => {
//                         let result = unsafe {zig_add(23,42)};
//                         println!("{event:?} result {result}");
//                     },
//                     e => println!("{e:?}"),
//                 }
//             }

//             // tokio::spawn(async move {
//             //     println!("first tokio spawn");
//             // });

//             // tokio::spawn(async move {
//             //     println!("second tokio spawn");
                
//             // }).await;

//             // tokio::spawn(async move {
//             //     println!("thrird tokio spawn");
//             // });

            
//         })
//     }
// }



// pub async fn next_event(&mut self) -> NetworkEvent {
//     loop {
//         tokio::select! {
//             // Poll the libp2p `Swarm`.
//             // This will poll the swarm and do maintenance routines.
//             Some(event) = self.swarm.next() => {
//                 if let Some(event) = self.parse_swarm_event(event) {
//                     return event;
//                 }
//             },
//         }
//     }
// }