/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/inbound_protocol.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
/// we changed the encode/decode logic to delegate the framing to zig side, but we still need to inspect the varint prefix to determine the frame length.
use std::pin::Pin;

use super::varint::{decode_varint_prefix, MAX_VARINT_BYTES};
use crate::req_resp::{
    configurations::{max_message_size, REQUEST_TIMEOUT},
    error::ReqRespError,
    messages::{RequestMessage, ResponseMessage},
    protocol_id::ProtocolId,
};
use bytes::BytesMut;
use futures::StreamExt;
use libp2p::core::UpgradeInfo;
use libp2p::InboundUpgrade;
use tokio::time::timeout;
use tokio_io_timeout::TimeoutStream;
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    compat::{Compat, FuturesAsyncReadCompatExt},
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

impl Encoder<ResponseMessage> for InboundCodec {
    type Error = ReqRespError;

    fn encode(&mut self, item: ResponseMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.payload.is_empty() {
            return Err(ReqRespError::InvalidData(
                "Response payload must not be empty".into(),
            ));
        }

        if item.payload.len() < 2 {
            return Err(ReqRespError::InvalidData(
                "Response payload missing length prefix".into(),
            ));
        }

        let (body_len, prefix_len) = decode_varint_prefix(&item.payload[1..])?
            .ok_or_else(|| ReqRespError::InvalidData("Incomplete response length prefix".into()))?;

        if body_len > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                body_len,
                max_message_size()
            )));
        }

        let expected_len = 1 + prefix_len + body_len;
        if item.payload.len() != expected_len {
            return Err(ReqRespError::InvalidData(format!(
                "Response payload length mismatch (expected {}, got {})",
                expected_len,
                item.payload.len()
            )));
        }

        if expected_len > max_message_size() + MAX_VARINT_BYTES + 1 {
            return Err(ReqRespError::InvalidData(
                "Framed response exceeds maximum envelope size".into(),
            ));
        }

        dst.clear();
        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}

impl Decoder for InboundCodec {
    type Item = RequestMessage;
    type Error = ReqRespError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let (body_len, prefix_len) = match decode_varint_prefix(&src[..])? {
            Some(result) => result,
            None => return Ok(None),
        };

        if body_len > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                body_len,
                max_message_size()
            )));
        }

        let total_len = prefix_len + body_len;
        if total_len > max_message_size() + MAX_VARINT_BYTES {
            return Err(ReqRespError::InvalidData(
                "Framed request exceeds maximum envelope size".into(),
            ));
        }

        if src.len() < total_len {
            return Ok(None);
        }

        let payload = src.split_to(total_len).to_vec();
        Ok(Some(RequestMessage::new(self.protocol.clone(), payload)))
    }
}
