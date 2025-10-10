use crate::req_resp::protocol_id::ProtocolId;

/// Represents an outbound or inbound req/resp payload.
///
/// At this stage we keep the payload as raw bytes. The caller is expected to
/// interpret the contents based on the associated `ProtocolId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMessage {
    pub protocol: ProtocolId,
    pub payload: Vec<u8>,
}

impl RequestMessage {
    pub fn new(protocol: ProtocolId, payload: Vec<u8>) -> Self {
        Self { protocol, payload }
    }

    /// Returns the protocols that can satisfy this request. For now we only
    /// support a single protocol per request but we keep the API mirroring
    /// libp2p's expectations for future extensibility.
    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![self.protocol.clone()]
    }
}

/// Represents a single response payload for a request-response exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseMessage {
    pub protocol: ProtocolId,
    pub payload: Vec<u8>,
}

impl ResponseMessage {
    pub fn new(protocol: ProtocolId, payload: Vec<u8>) -> Self {
        Self { protocol, payload }
    }
}
