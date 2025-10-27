/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/protocol_id.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
use libp2p::StreamProtocol;
use std::fmt;
use std::hash::{Hash, Hasher};

const LEAN_BLOCKS_BY_ROOT_V1: &str = "/leanconsensus/req/lean_blocks_by_root/1/ssz_snappy";
const LEAN_STATUS_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanSupportedProtocol {
    BlocksByRootV1,
    StatusV1,
}

impl LeanSupportedProtocol {
    pub fn message_name(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => "lean_blocks_by_root",
            LeanSupportedProtocol::StatusV1 => "status",
        }
    }

    pub fn schema_version(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => "1",
            LeanSupportedProtocol::StatusV1 => "1",
        }
    }

    pub fn has_context_bytes(&self) -> bool {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => false,
            LeanSupportedProtocol::StatusV1 => false,
        }
    }

    pub fn protocol_id(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => LEAN_BLOCKS_BY_ROOT_V1,
            LeanSupportedProtocol::StatusV1 => LEAN_STATUS_V1,
        }
    }
}

impl TryFrom<u32> for LeanSupportedProtocol {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LeanSupportedProtocol::BlocksByRootV1),
            1 => Ok(LeanSupportedProtocol::StatusV1),
            _ => Err(()),
        }
    }
}

/// Identifies an RPC protocol supported by the network.
///
/// The underlying value is the canonical libp2p protocol string
/// (e.g. `/eth2/beacon_chain/req/status/1/ssz_snappy`).
#[derive(Clone)]
pub struct ProtocolId {
    protocol: StreamProtocol,
    has_context_bytes: bool,
}

impl ProtocolId {
    pub fn new(protocol: StreamProtocol, has_context_bytes: bool) -> Self {
        Self {
            protocol,
            has_context_bytes,
        }
    }

    pub fn from_static(protocol: &'static str, has_context_bytes: bool) -> Self {
        Self::new(StreamProtocol::new(protocol), has_context_bytes)
    }

    pub fn as_str(&self) -> &str {
        self.protocol.as_ref()
    }

    pub fn has_context_bytes(&self) -> bool {
        self.has_context_bytes
    }

    pub fn with_context_bytes(mut self, has_context_bytes: bool) -> Self {
        self.has_context_bytes = has_context_bytes;
        self
    }

    pub fn stream_protocol(&self) -> &StreamProtocol {
        &self.protocol
    }
}

impl From<LeanSupportedProtocol> for ProtocolId {
    fn from(protocol: LeanSupportedProtocol) -> Self {
        ProtocolId::from_static(protocol.protocol_id(), protocol.has_context_bytes())
    }
}

impl fmt::Debug for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolId")
            .field("protocol", &self.protocol)
            .field("has_context_bytes", &self.has_context_bytes)
            .finish()
    }
}

impl PartialEq for ProtocolId {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
    }
}

impl Eq for ProtocolId {}

impl Hash for ProtocolId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.as_ref().hash(state);
    }
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.protocol.as_ref()
    }
}
