/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/outbound_protocol.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
/// we changed the encode/decode logic to delegate the framing to zig side, but we still need to inspect the varint prefix to determine the frame length.
use super::varint::{calculate_snappy_frame_size, decode_varint_prefix};
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

        // Request format: varint (uncompressed len) + snappy frame
        let (uncompressed_len, prefix_len) = decode_varint_prefix(&item.payload)?
            .ok_or_else(|| ReqRespError::InvalidData("Incomplete request length prefix".into()))?;

        if uncompressed_len > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                uncompressed_len,
                max_message_size()
            )));
        }

        // Validate the snappy frame that follows
        if item.payload.len() <= prefix_len {
            return Err(ReqRespError::InvalidData(
                "Request payload missing snappy frame".into(),
            ));
        }

        let snappy_frame_size =
            calculate_snappy_frame_size(&item.payload[prefix_len..], uncompressed_len)?
                .ok_or_else(|| {
                    ReqRespError::InvalidData("Incomplete snappy frame in request".into())
                })?;

        let expected_len = prefix_len + snappy_frame_size;
        if item.payload.len() != expected_len {
            return Err(ReqRespError::InvalidData(format!(
                "Request payload length mismatch (expected {}, got {})",
                expected_len,
                item.payload.len()
            )));
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

        // Response format: response_code (1 byte) + varint (uncompressed len) + snappy frame
        let (uncompressed_len, prefix_len) = match decode_varint_prefix(&src[1..])? {
            Some(result) => result,
            None => return Ok(None),
        };

        if uncompressed_len > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                uncompressed_len,
                max_message_size()
            )));
        }

        // Now parse the snappy-framed data that follows to determine the actual frame size
        let snappy_start = 1 + prefix_len;
        if src.len() <= snappy_start {
            return Ok(None);
        }

        let snappy_frame_size =
            match calculate_snappy_frame_size(&src[snappy_start..], uncompressed_len)? {
                Some(size) => size,
                None => return Ok(None),
            };

        let total_len = 1 + prefix_len + snappy_frame_size;

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
