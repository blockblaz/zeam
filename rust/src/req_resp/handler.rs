/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/handler.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use delay_map::HashSetDelay;
use futures::{Future, FutureExt, Sink, SinkExt, StreamExt};
use libp2p::{
    swarm::{
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
        ConnectionHandler, ConnectionHandlerEvent, StreamUpgradeError, SubstreamProtocol,
    },
    Stream,
};
use tracing::{error, trace};

use crate::req_resp::{
    configurations::REQUEST_TIMEOUT,
    error::ReqRespError,
    inbound_protocol::{InboundFramed, InboundOutput, InboundReqRespProtocol},
    messages::{RequestMessage, ResponseMessage},
    outbound_protocol::{OutboundFramed, OutboundReqRespProtocol},
};

#[derive(Debug)]
pub enum ReqRespMessageReceived {
    Request {
        stream_id: u64,
        message: Box<RequestMessage>,
    },
    Response {
        request_id: u64,
        message: Box<ResponseMessage>,
    },
    EndOfStream {
        request_id: u64,
    },
}

#[derive(Debug)]
pub enum HandlerEvent {
    Ok(Box<ReqRespMessageReceived>),
    Err(ReqRespMessageError),
    Close,
}

type BusyInboundStream =
    Pin<Box<dyn Future<Output = Result<Option<InboundFramed<Stream>>, ReqRespError>> + Send>>;

enum InboundStreamState {
    Idle(InboundFramed<Stream>),
    Busy(BusyInboundStream),
}

struct InboundStream {
    state: Option<InboundStreamState>,
    response_queue: VecDeque<ResponseAction>,
}

enum ResponseAction {
    Message(ResponseMessage),
    CloseStream,
}

enum OutboundStreamState {
    PendingResponse { stream: Box<OutboundFramed<Stream>> },
    Closing(Box<OutboundFramed<Stream>>),
}

struct OutboundStream {
    state: Option<OutboundStreamState>,
    request_id: u64,
}

#[derive(Debug)]
pub struct OutboundOpenInfo {
    pub request_id: u64,
    pub message: RequestMessage,
}

pub struct ReqRespConnectionHandler {
    listen_protocol: SubstreamProtocol<InboundReqRespProtocol, ()>,
    behaviour_events: Vec<HandlerEvent>,
    inbound_stream_id: u64,
    outbound_stream_id: u64,
    inbound_streams: HashMap<u64, InboundStream>,
    inbound_stream_timeouts: HashSetDelay<u64>,
    outbound_streams: HashMap<u64, OutboundStream>,
    outbound_stream_timeouts: HashSetDelay<u64>,
    pending_outbound_streams: Vec<OutboundOpenInfo>,
    connection_state: ConnectionState,
}

impl ReqRespConnectionHandler {
    pub fn new(listen_protocol: SubstreamProtocol<InboundReqRespProtocol, ()>) -> Self {
        Self {
            listen_protocol,
            pending_outbound_streams: vec![],
            behaviour_events: vec![],
            inbound_stream_id: 0,
            outbound_stream_id: 0,
            inbound_streams: HashMap::new(),
            outbound_streams: HashMap::new(),
            connection_state: ConnectionState::Live,
            inbound_stream_timeouts: HashSetDelay::new(REQUEST_TIMEOUT),
            outbound_stream_timeouts: HashSetDelay::new(REQUEST_TIMEOUT),
        }
    }

    fn on_fully_negotiated_inbound(&mut self, inbound_output: InboundOutput<Stream>, _info: ()) {
        let (message, inbound_framed) = inbound_output;

        self.inbound_stream_timeouts.insert(self.inbound_stream_id);
        self.inbound_streams.insert(
            self.inbound_stream_id,
            InboundStream {
                state: Some(InboundStreamState::Idle(inbound_framed)),
                response_queue: VecDeque::new(),
            },
        );

        self.behaviour_events.push(HandlerEvent::Ok(Box::new(
            ReqRespMessageReceived::Request {
                stream_id: self.inbound_stream_id,
                message: Box::new(message),
            },
        )));

        self.inbound_stream_id += 1;
    }

    fn on_fully_negotiated_outbound(
        &mut self,
        outbound_output: OutboundFramed<Stream>,
        info: OutboundOpenInfo,
    ) {
        let OutboundOpenInfo { request_id, .. } = info;

        self.outbound_stream_timeouts
            .insert(self.outbound_stream_id);
        self.outbound_streams.insert(
            self.outbound_stream_id,
            OutboundStream {
                state: Some(OutboundStreamState::PendingResponse {
                    stream: Box::new(outbound_output),
                }),
                request_id,
            },
        );

        self.outbound_stream_id += 1;
    }

    fn on_dial_upgrade_error(
        &mut self,
        error: StreamUpgradeError<ReqRespError>,
        info: OutboundOpenInfo,
    ) {
        trace!(
            "REQRESP: Dial upgrade error: {:?} {:?}",
            error,
            info.request_id
        );
        self.behaviour_events
            .push(HandlerEvent::Err(ReqRespMessageError::Outbound {
                request_id: info.request_id,
                err: ReqRespError::Disconnected,
            }));
    }

    fn request(&mut self, request_id: u64, message: RequestMessage) {
        if let ConnectionState::Live = self.connection_state {
            self.pending_outbound_streams.push(OutboundOpenInfo {
                request_id,
                message,
            });
        } else {
            self.behaviour_events
                .push(HandlerEvent::Err(ReqRespMessageError::Outbound {
                    request_id,
                    err: ReqRespError::Disconnected,
                }));
        }
    }

    fn response(&mut self, stream_id: u64, message: ResponseMessage) {
        let Some(inbound_stream) = self.inbound_streams.get_mut(&stream_id) else {
            error!("REQRESP: Inbound stream not found: {stream_id}");
            return;
        };

        if let ConnectionState::Closed = self.connection_state {
            return;
        }

        inbound_stream
            .response_queue
            .push_back(ResponseAction::Message(message));
    }

    fn close_stream(&mut self, stream_id: u64) {
        let Some(inbound_stream) = self.inbound_streams.get_mut(&stream_id) else {
            error!("REQRESP: Inbound stream not found for close: {stream_id}");
            return;
        };

        inbound_stream
            .response_queue
            .push_back(ResponseAction::CloseStream);
    }

    fn shutdown(&mut self) {
        if matches!(
            self.connection_state,
            ConnectionState::ShuttingDown | ConnectionState::Closed
        ) {
            return;
        }

        self.connection_state = ConnectionState::ShuttingDown;
    }
}

impl ConnectionHandler for ReqRespConnectionHandler {
    type FromBehaviour = ConnectionRequest;
    type ToBehaviour = HandlerEvent;
    type InboundProtocol = InboundReqRespProtocol;
    type OutboundProtocol = OutboundReqRespProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = OutboundOpenInfo;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        self.listen_protocol.clone()
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if !self.behaviour_events.is_empty() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                self.behaviour_events.remove(0),
            ));
        }

        while let Poll::Ready(Some(Ok(stream_id))) =
            self.inbound_stream_timeouts.poll_expired(context)
        {
            if self.inbound_streams.get_mut(&stream_id).is_some() {
                self.behaviour_events
                    .push(HandlerEvent::Err(ReqRespMessageError::Inbound {
                        stream_id,
                        err: ReqRespError::StreamTimedOut,
                    }));
            }
        }

        while let Poll::Ready(Some(Ok(outbound_id))) =
            self.outbound_stream_timeouts.poll_expired(context)
        {
            if let Some(OutboundStream { request_id, .. }) =
                self.outbound_streams.remove(&outbound_id)
            {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(HandlerEvent::Err(
                    ReqRespMessageError::Outbound {
                        request_id,
                        err: ReqRespError::StreamTimedOut,
                    },
                )));
            }
        }

        let mut streams_to_remove = vec![];
        for (stream_id, inbound_stream) in self.inbound_streams.iter_mut() {
            loop {
                let Some(inbound_stream_state) = inbound_stream.state.take() else {
                    unreachable!(
                        "InboundStreamState should always be present; poll() must not run in parallel"
                    );
                };

                match inbound_stream_state {
                    InboundStreamState::Idle(mut framed) => {
                        if let ConnectionState::Closed = self.connection_state {
                            match framed.close().poll_unpin(context) {
                                Poll::Ready(result) => {
                                    streams_to_remove.push(*stream_id);
                                    self.inbound_stream_timeouts.remove(stream_id);
                                    if let Err(err) = result {
                                        self.behaviour_events.push(HandlerEvent::Err(
                                            ReqRespMessageError::Inbound {
                                                stream_id: *stream_id,
                                                err,
                                            },
                                        ));
                                    }
                                }
                                Poll::Pending => {
                                    inbound_stream.state = Some(InboundStreamState::Idle(framed));
                                }
                            }
                            break;
                        }

                        let Some(action) = inbound_stream.response_queue.pop_front() else {
                            inbound_stream.state = Some(InboundStreamState::Idle(framed));
                            break;
                        };

                        inbound_stream.state = Some(InboundStreamState::Busy(Box::pin(
                            send_response_message_to_inbound_stream(framed, action).boxed(),
                        )));
                    }
                    InboundStreamState::Busy(mut pin) => match pin.poll_unpin(context) {
                        Poll::Ready(Ok(framed)) => {
                            let Some(framed) = framed else {
                                streams_to_remove.push(*stream_id);
                                self.inbound_stream_timeouts.remove(stream_id);
                                break;
                            };

                            self.inbound_stream_timeouts.insert(*stream_id);
                            if matches!(self.connection_state, ConnectionState::Closed)
                                || inbound_stream.response_queue.is_empty()
                            {
                                inbound_stream.state = Some(InboundStreamState::Idle(framed));
                                break;
                            }

                            if let Some(action) = inbound_stream.response_queue.pop_front() {
                                inbound_stream.state = Some(InboundStreamState::Busy(Box::pin(
                                    send_response_message_to_inbound_stream(framed, action).boxed(),
                                )));
                            }
                        }
                        Poll::Ready(Err(err)) => {
                            streams_to_remove.push(*stream_id);
                            self.inbound_stream_timeouts.remove(stream_id);
                            self.behaviour_events.push(HandlerEvent::Err(
                                ReqRespMessageError::Inbound {
                                    stream_id: *stream_id,
                                    err,
                                },
                            ));
                            break;
                        }
                        Poll::Pending => {
                            inbound_stream.state = Some(InboundStreamState::Busy(pin));
                            break;
                        }
                    },
                }
            }
        }

        for stream_id in streams_to_remove {
            self.inbound_streams.remove(&stream_id);
        }

        for stream_id in self.outbound_streams.keys().cloned().collect::<Vec<_>>() {
            let mut entry = match self.outbound_streams.entry(stream_id) {
                Entry::Occupied(entry) => entry,
                Entry::Vacant(_) => {
                    unreachable!(
                        "Outbound stream must exist; poll() should not run in parallel {stream_id}",
                    );
                }
            };

            let request_id = entry.get().request_id;

            let Some(outbound_stream_state) = entry.get_mut().state.take() else {
                unreachable!(
                    "OutboundStreamState should always be present; poll() must not run in parallel {stream_id}",
                );
            };

            match outbound_stream_state {
                OutboundStreamState::PendingResponse { mut stream } => {
                    if let ConnectionState::Closed = self.connection_state {
                        entry.get_mut().state = Some(OutboundStreamState::Closing(stream));
                        self.behaviour_events.push(HandlerEvent::Err(
                            ReqRespMessageError::Outbound {
                                request_id,
                                err: ReqRespError::Disconnected,
                            },
                        ));
                        continue;
                    }

                    match stream.poll_next_unpin(context) {
                        Poll::Ready(response_message) => {
                            let Some(response_message) = response_message else {
                                entry.remove_entry();
                                self.outbound_stream_timeouts.remove(&stream_id);
                                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                    HandlerEvent::Ok(Box::new(
                                        ReqRespMessageReceived::EndOfStream { request_id },
                                    )),
                                ));
                            };

                            let response_message = match response_message {
                                Ok(message) => message,
                                Err(err) => {
                                    entry.remove_entry();
                                    self.outbound_stream_timeouts.remove(&stream_id);
                                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                        HandlerEvent::Err(ReqRespMessageError::Outbound {
                                            request_id,
                                            err,
                                        }),
                                    ));
                                }
                            };

                            self.outbound_stream_timeouts.insert(stream_id);
                            entry.get_mut().state =
                                Some(OutboundStreamState::PendingResponse { stream });

                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                HandlerEvent::Ok(Box::new(ReqRespMessageReceived::Response {
                                    request_id,
                                    message: Box::new(response_message),
                                })),
                            ));
                        }
                        Poll::Pending => {
                            entry.get_mut().state =
                                Some(OutboundStreamState::PendingResponse { stream });
                        }
                    }
                }
                OutboundStreamState::Closing(mut stream) => {
                    match Sink::poll_close(Pin::new(&mut stream), context) {
                        Poll::Ready(_) => {
                            entry.remove_entry();
                            self.outbound_stream_timeouts.remove(&stream_id);
                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                HandlerEvent::Ok(Box::new(ReqRespMessageReceived::EndOfStream {
                                    request_id,
                                })),
                            ));
                        }
                        Poll::Pending => {
                            entry.get_mut().state = Some(OutboundStreamState::Closing(stream));
                        }
                    }
                }
            }
        }

        if let Some(open_info) = self.pending_outbound_streams.pop() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    OutboundReqRespProtocol {
                        request: open_info.message.clone(),
                    },
                    open_info,
                ),
            });
        }

        if matches!(self.connection_state, ConnectionState::ShuttingDown)
            && self.inbound_streams.is_empty()
            && self.outbound_streams.is_empty()
            && self.pending_outbound_streams.is_empty()
            && self.behaviour_events.is_empty()
        {
            self.connection_state = ConnectionState::Closed;
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(HandlerEvent::Close));
        }

        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: ConnectionRequest) {
        match event {
            ConnectionRequest::Request {
                request_id,
                message,
            } => self.request(request_id, message),
            ConnectionRequest::Response { stream_id, message } => {
                self.response(stream_id, *message)
            }
            ConnectionRequest::CloseStream { stream_id } => self.close_stream(stream_id),
            ConnectionRequest::Shutdown => self.shutdown(),
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound { protocol, info }) => {
                self.on_fully_negotiated_inbound(protocol, info)
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info,
            }) => {
                self.on_fully_negotiated_outbound(protocol, info);
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, info }) => {
                self.on_dial_upgrade_error(error, info);
            }
            _ => {}
        }
    }

    fn connection_keep_alive(&self) -> bool {
        matches!(
            self.connection_state,
            ConnectionState::Live | ConnectionState::ShuttingDown
        )
    }
}

async fn send_response_message_to_inbound_stream(
    mut inbound_stream: InboundFramed<Stream>,
    action: ResponseAction,
) -> Result<Option<InboundFramed<Stream>>, ReqRespError> {
    match action {
        ResponseAction::Message(message) => {
            inbound_stream.send(message).await?;
            Ok(Some(inbound_stream))
        }
        ResponseAction::CloseStream => {
            inbound_stream.close().await?;
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub enum ReqRespMessageError {
    Inbound { stream_id: u64, err: ReqRespError },
    Outbound { request_id: u64, err: ReqRespError },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Live,
    ShuttingDown,
    Closed,
}

#[derive(Debug, Clone)]
pub enum ConnectionRequest {
    Request {
        request_id: u64,
        message: RequestMessage,
    },
    Response {
        stream_id: u64,
        message: Box<ResponseMessage>,
    },
    CloseStream {
        stream_id: u64,
    },
    Shutdown,
}
