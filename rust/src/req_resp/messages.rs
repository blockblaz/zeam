/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/messages.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
/// we changed the `RequestMessage` and `ResponseMessage` to keep the payload as raw bytes and delegate the framing to zig side. The caller is expected to
/// interpret the contents based on the associated `ProtocolId`.
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
