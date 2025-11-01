/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/outbound_protocol.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
/// we changed the encode/decode logic to delegate the framing to zig side, but we still need to inspect the varint prefix to determine the frame length.
use super::varint::{decode_varint_prefix, MAX_VARINT_BYTES};
use crate::req_resp::{
    configurations::max_message_size,
    error::ReqRespError,
    messages::{RequestMessage, ResponseMessage},
    protocol_id::ProtocolId,
};
use bytes::BytesMut;
use futures::{FutureExt, SinkExt};
use libp2p::core::UpgradeInfo;
use libp2p::OutboundUpgrade;
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    compat::{Compat, FuturesAsyncReadCompatExt},
};

pub struct OutboundReqRespProtocol {
    pub request: RequestMessage,
}

pub type OutboundFramed<S> = Framed<Compat<S>, OutboundCodec>;

impl<S> OutboundUpgrade<S> for OutboundReqRespProtocol
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    type Output = OutboundFramed<S>;
    type Error = ReqRespError;
    type Future = futures::future::BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: S, protocol: ProtocolId) -> Self::Future {
        let mut socket = Framed::new(socket.compat(), OutboundCodec { protocol });

        async move {
            socket.send(self.request).await?;
            socket.close().await?;
            Ok(socket)
        }
        .boxed()
    }
}

impl UpgradeInfo for OutboundReqRespProtocol {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.request.protocol.clone()]
    }
}

pub struct OutboundCodec {
    protocol: ProtocolId,
}

impl Encoder<RequestMessage> for OutboundCodec {
    type Error = ReqRespError;

    fn encode(&mut self, item: RequestMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.payload.is_empty() {
            return Err(ReqRespError::InvalidData(
                "Request payload must not be empty".into(),
            ));
        }

        let (body_len, prefix_len) = decode_varint_prefix(&item.payload)?
            .ok_or_else(|| ReqRespError::InvalidData("Incomplete request length prefix".into()))?;

        if body_len > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                body_len,
                max_message_size()
            )));
        }

        let expected_len = prefix_len + body_len;
        if item.payload.len() != expected_len {
            return Err(ReqRespError::InvalidData(format!(
                "Request payload length mismatch (expected {}, got {})",
                expected_len,
                item.payload.len()
            )));
        }

        if expected_len > max_message_size() + MAX_VARINT_BYTES {
            return Err(ReqRespError::InvalidData(
                "Framed request exceeds maximum envelope size".into(),
            ));
        }

        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}

impl Decoder for OutboundCodec {
    type Item = ResponseMessage;
    type Error = ReqRespError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }

        // Zig is responsible for constructing the response frame, but the codec still needs
        // to inspect the varint prefix to figure out the total frame length so that we know
        // when a full message has been received from the stream.
        let (body_len, prefix_len) = match decode_varint_prefix(&src[1..])? {
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

        let total_len = 1 + prefix_len + body_len;
        if total_len > max_message_size() + MAX_VARINT_BYTES + 1 {
            return Err(ReqRespError::InvalidData(
                "Framed response exceeds maximum envelope size".into(),
            ));
        }

        if src.len() < total_len {
            return Ok(None);
        }

        let payload = src.split_to(total_len).to_vec();
        Ok(Some(ResponseMessage {
            protocol: self.protocol.clone(),
            payload,
        }))
    }
}
