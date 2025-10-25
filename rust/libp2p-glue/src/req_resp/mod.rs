/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/mod.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
pub mod configurations;
pub mod error;
pub mod handler;
pub mod inbound_protocol;
pub mod messages;
pub mod outbound_protocol;
pub mod protocol_id;
pub(crate) mod varint;

pub use handler::{
    ConnectionRequest, HandlerEvent, ReqRespConnectionHandler, ReqRespMessageError,
    ReqRespMessageReceived,
};
pub use messages::{RequestMessage, ResponseMessage};
pub use protocol_id::{LeanSupportedProtocol, ProtocolId};

use std::task::{Context, Poll};

use handler::HandlerEvent as ConnectionHandlerEventWrapper;
use inbound_protocol::InboundReqRespProtocol;
use libp2p::{
    core::{transport::PortUse, Endpoint},
    swarm::{
        CloseConnection, ConnectionClosed, ConnectionDenied, ConnectionHandler, ConnectionId,
        FromSwarm, NetworkBehaviour, NotifyHandler, SubstreamProtocol, THandler, THandlerInEvent,
        ToSwarm,
    },
    Multiaddr, PeerId,
};
use tracing::{debug, trace};

/// Maximum number of concurrent requests per protocol ID that a client may issue.
pub const MAX_CONCURRENT_REQUESTS: usize = 2;

#[derive(Debug)]
pub struct ReqRespMessage {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub message: Result<ReqRespMessageReceived, ReqRespMessageError>,
}

pub struct ReqResp {
    pub events: Vec<ToSwarm<ReqRespMessage, ConnectionRequest>>,
    pub protocols: Vec<ProtocolId>,
}

impl ReqResp {
    pub fn new(protocols: Vec<ProtocolId>) -> Self {
        Self {
            events: vec![],
            protocols,
        }
    }

    pub fn send_request(&mut self, peer_id: PeerId, request_id: u64, message: RequestMessage) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: ConnectionRequest::Request {
                request_id,
                message,
            },
        });
    }

    pub fn send_response(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        message: ResponseMessage,
    ) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection_id),
            event: ConnectionRequest::Response {
                stream_id,
                message: Box::new(message),
            },
        });
    }

    pub fn finish_response_stream(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
    ) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection_id),
            event: ConnectionRequest::CloseStream { stream_id },
        });
    }

    pub fn shutdown(&mut self, peer_id: PeerId, connection_id: ConnectionId) {
        self.events.push(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection_id),
            event: ConnectionRequest::Shutdown,
        });
    }
}

impl NetworkBehaviour for ReqResp {
    type ConnectionHandler = ReqRespConnectionHandler;

    type ToSwarm = ReqRespMessage;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        debug!("REQRESP: inbound connection established {connection_id:?} {peer:?}");
        let listen_protocol = SubstreamProtocol::new(
            InboundReqRespProtocol {
                protocols: self.protocols.clone(),
            },
            (),
        );
        Ok(ReqRespConnectionHandler::new(listen_protocol))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        debug!("REQRESP: outbound connection established {connection_id:?} {peer:?}");
        let listen_protocol = SubstreamProtocol::new(
            InboundReqRespProtocol {
                protocols: self.protocols.clone(),
            },
            (),
        );
        Ok(ReqRespConnectionHandler::new(listen_protocol))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            connection_id,
            cause,
            remaining_established: _,
            ..
        }) = event
        {
            trace!("REQRESP: connection closed {peer_id} {connection_id:?} cause={cause:?}");
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: <Self::ConnectionHandler as ConnectionHandler>::ToBehaviour,
    ) {
        match event {
            ConnectionHandlerEventWrapper::Ok(message) => {
                self.events.push(ToSwarm::GenerateEvent(ReqRespMessage {
                    peer_id,
                    connection_id,
                    message: Ok(*message),
                }))
            }
            ConnectionHandlerEventWrapper::Err(err) => {
                self.events.push(ToSwarm::GenerateEvent(ReqRespMessage {
                    peer_id,
                    connection_id,
                    message: Err(err),
                }))
            }
            ConnectionHandlerEventWrapper::Close => self.events.push(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::All,
            }),
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }

        Poll::Pending
    }
}
