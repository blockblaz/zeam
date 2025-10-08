use bytes::BytesMut;
use futures::{FutureExt, SinkExt};
use libp2p::core::UpgradeInfo;
use libp2p::OutboundUpgrade;
use tokio_util::{
    codec::{Decoder, Encoder, Framed},
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use unsigned_varint::codec::Uvi;

use crate::req_resp::{
    configurations::max_message_size,
    error::ReqRespError,
    handler::RespMessage,
    inbound_protocol::ResponseCode,
    messages::{RequestMessage, ResponseMessage},
    protocol_id::ProtocolId,
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
        let mut socket = Framed::new(
            socket.compat(),
            OutboundCodec {
                protocol,
                current_response_code: None,
                context_bytes: None,
                expected_length: None,
            },
        );

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
    current_response_code: Option<ResponseCode>,
    context_bytes: Option<[u8; 4]>,
    expected_length: Option<usize>,
}

impl Encoder<RequestMessage> for OutboundCodec {
    type Error = ReqRespError;

    fn encode(&mut self, item: RequestMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.payload.len() > max_message_size() {
            return Err(ReqRespError::InvalidData(format!(
                "Message size exceeds maximum: {} > {}",
                item.payload.len(),
                max_message_size()
            )));
        }

        Uvi::<usize>::default()
            .encode(item.payload.len(), dst)
            .map_err(ReqRespError::from)?;
        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}

impl Decoder for OutboundCodec {
    type Item = RespMessage;
    type Error = ReqRespError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let response_code = match self.current_response_code {
            Some(code) => code,
            None => {
                if src.is_empty() {
                    return Ok(None);
                }
                let byte = src.split_to(1)[0];
                let code = ResponseCode::from(byte);
                self.current_response_code = Some(code);
                code
            }
        };

        if self.protocol.has_context_bytes()
            && response_code == ResponseCode::Success
            && self.context_bytes.is_none()
        {
            if src.len() < 4 {
                return Ok(None);
            }
            let mut context = [0u8; 4];
            context.copy_from_slice(&src.split_to(4));
            self.context_bytes = Some(context);
        }

        let length = match self.expected_length {
            Some(length) => length,
            None => {
                let decoded = match Uvi::<usize>::default()
                    .decode(src)
                    .map_err(|err| ReqRespError::InvalidData(err.to_string()))?
                {
                    Some(length) => length,
                    None => return Ok(None),
                };
                if decoded > max_message_size() {
                    return Err(ReqRespError::InvalidData(format!(
                        "Message size exceeds maximum: {} > {}",
                        decoded,
                        max_message_size()
                    )));
                }
                self.expected_length = Some(decoded);
                decoded
            }
        };

        if src.len() < length {
            return Ok(None);
        }

        let payload = src.split_to(length).to_vec();
        self.expected_length = None;
        let code = self.current_response_code.take().unwrap();

        match code {
            ResponseCode::Success => {
                let message = ResponseMessage {
                    protocol: self.protocol.clone(),
                    payload,
                    context_bytes: self.context_bytes.take(),
                };
                Ok(Some(RespMessage::Response(Box::new(message))))
            }
            ResponseCode::InvalidRequest
            | ResponseCode::ServerError
            | ResponseCode::ResourceUnavailable => {
                let message = String::from_utf8(payload)
                    .unwrap_or_else(|_| "Invalid UTF-8 error message".into());
                Ok(Some(RespMessage::Error(ReqRespError::RawError(message))))
            }
            ResponseCode::ReservedCode(code) | ResponseCode::ErroneousCode(code) => {
                Ok(Some(RespMessage::Error(ReqRespError::InvalidData(
                    format!("Unexpected response code: {code}",),
                ))))
            }
        }
    }
}
