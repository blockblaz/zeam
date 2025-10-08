use std::pin::Pin;

use bytes::{BufMut, BytesMut};
use futures::StreamExt;
use libp2p::core::UpgradeInfo;
use libp2p::InboundUpgrade;
use tokio::time::timeout;
use tokio_io_timeout::TimeoutStream;
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use unsigned_varint::codec::Uvi;

use crate::req_resp::{
    configurations::{max_message_size, REQUEST_TIMEOUT},
    error::ReqRespError,
    handler::RespMessage,
    messages::RequestMessage,
    protocol_id::ProtocolId,
};

#[derive(Clone)]
pub struct InboundReqRespProtocol {
    pub protocols: Vec<ProtocolId>,
}

pub type InboundOutput<S> = (RequestMessage, InboundFramed<S>);
pub type InboundFramed<S> = Framed<Pin<Box<TimeoutStream<Compat<S>>>>, InboundCodec>;

impl<S> InboundUpgrade<S> for InboundReqRespProtocol
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    type Output = InboundOutput<S>;
    type Error = ReqRespError;
    type Future = futures::future::BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: S, info: ProtocolId) -> Self::Future {
        Box::pin(async move {
            let mut timed_socket = TimeoutStream::new(socket.compat());
            timed_socket.set_read_timeout(Some(REQUEST_TIMEOUT));

            let mut stream = Framed::new(
                Box::pin(timed_socket),
                InboundCodec {
                    protocol: info.clone(),
                },
            );

            match timeout(REQUEST_TIMEOUT, stream.next()).await {
                Ok(Some(Ok(message))) => Ok((message, stream)),
                Ok(Some(Err(err))) => Err(err),
                Ok(None) => Err(ReqRespError::IncompleteStream),
                Err(_) => Err(ReqRespError::StreamTimedOut),
            }
        })
    }
}

impl UpgradeInfo for InboundReqRespProtocol {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone()
    }
}

#[derive(Clone)]
pub struct InboundCodec {
    protocol: ProtocolId,
}

impl Encoder<RespMessage> for InboundCodec {
    type Error = ReqRespError;

    fn encode(&mut self, item: RespMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.clear();

        let response_code = item
            .as_response_code()
            .ok_or_else(|| ReqRespError::InvalidData("Cannot encode EndOfStream".into()))?;
        dst.put_u8(u8::from(response_code));

        match item {
            RespMessage::Response(message) => {
                if self.protocol.has_context_bytes() {
                    if let Some(context_bytes) = message.context_bytes {
                        dst.extend_from_slice(&context_bytes);
                    } else {
                        return Err(ReqRespError::InvalidData(
                            "Missing context bytes for protocol".into(),
                        ));
                    }
                }

                if message.payload.len() > max_message_size() {
                    return Err(ReqRespError::InvalidData(format!(
                        "Message size exceeds maximum: {} > {}",
                        message.payload.len(),
                        max_message_size()
                    )));
                }

                Uvi::<usize>::default()
                    .encode(message.payload.len(), dst)
                    .map_err(ReqRespError::from)?;
                dst.extend_from_slice(&message.payload);
                Ok(())
            }
            RespMessage::Error(err) => {
                let payload = err.to_string().into_bytes();
                Uvi::<usize>::default()
                    .encode(payload.len(), dst)
                    .map_err(ReqRespError::from)?;
                dst.extend_from_slice(&payload);
                Ok(())
            }
            RespMessage::EndOfStream => Err(ReqRespError::InvalidData(
                "EndOfStream cannot be encoded".into(),
            )),
        }
    }
}

impl Decoder for InboundCodec {
    type Item = RequestMessage;
    type Error = ReqRespError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let length = match Uvi::<usize>::default()
            .decode(src)
            .map_err(|err| ReqRespError::InvalidData(err.to_string()))?
        {
            Some(length) => length,
            None => return Ok(None),
        };

        if length > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                length,
                max_message_size()
            )));
        }

        if src.len() < length {
            return Ok(None);
        }

        let payload = src.split_to(length).to_vec();

        Ok(Some(RequestMessage::new(self.protocol.clone(), payload)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    Success,
    InvalidRequest,
    ServerError,
    ResourceUnavailable,
    ReservedCode(u8),
    ErroneousCode(u8),
}

impl From<u8> for ResponseCode {
    fn from(byte: u8) -> Self {
        match byte {
            0 => ResponseCode::Success,
            1 => ResponseCode::InvalidRequest,
            2 => ResponseCode::ServerError,
            3 => ResponseCode::ResourceUnavailable,
            4..=127 => ResponseCode::ReservedCode(byte),
            _ => ResponseCode::ErroneousCode(byte),
        }
    }
}

impl From<ResponseCode> for u8 {
    fn from(code: ResponseCode) -> u8 {
        match code {
            ResponseCode::Success => 0,
            ResponseCode::InvalidRequest => 1,
            ResponseCode::ServerError => 2,
            ResponseCode::ResourceUnavailable => 3,
            ResponseCode::ReservedCode(byte) => byte,
            ResponseCode::ErroneousCode(byte) => byte,
        }
    }
}
