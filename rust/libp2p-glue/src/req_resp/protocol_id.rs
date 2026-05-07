/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/protocol_id.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
use libp2p::StreamProtocol;
use std::fmt;
use std::hash::{Hash, Hasher};

const LEAN_BLOCKS_BY_ROOT_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
const LEAN_BLOCKS_BY_RANGE_V1: &str = "/leanconsensus/req/blocks_by_range/1/ssz_snappy";
const LEAN_STATUS_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";

/// Identifier for the wire-level RPC protocol negotiated over libp2p.
///
/// The discriminant values MUST stay in sync with the Zig side
/// (`pkgs/network/src/interface.zig::LeanSupportedProtocol`) and with the
/// `TryFrom<u32>` impl below. The cross-FFI invariant runs in BOTH
/// directions:
///
///   * Zig u32 → `try_from(u32)` → `LeanSupportedProtocol` (incoming RPC tag
///     from the chain side).
///   * `LeanSupportedProtocol as u32` → Zig u32 (outgoing tag, e.g. for
///     metric labels or any future ABI-level pinning).
///
/// `#[repr(u32)]` plus explicit discriminants pin the round-trip and
/// kill the foot-gun where Rust's default fieldless-enum `as u32` follows
/// declaration order while a hand-rolled `TryFrom` uses a different
/// mapping. Reported by @ch4r10t33r on PR #824.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanSupportedProtocol {
    BlocksByRootV1 = 0,
    StatusV1 = 1,
    BlocksByRangeV1 = 2,
}

impl LeanSupportedProtocol {
    pub fn message_name(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => "blocks_by_root",
            LeanSupportedProtocol::BlocksByRangeV1 => "blocks_by_range",
            LeanSupportedProtocol::StatusV1 => "status",
        }
    }

    pub fn schema_version(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => "1",
            LeanSupportedProtocol::BlocksByRangeV1 => "1",
            LeanSupportedProtocol::StatusV1 => "1",
        }
    }

    pub fn has_context_bytes(&self) -> bool {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => false,
            LeanSupportedProtocol::BlocksByRangeV1 => false,
            LeanSupportedProtocol::StatusV1 => false,
        }
    }

    pub fn protocol_id(&self) -> &'static str {
        match self {
            LeanSupportedProtocol::BlocksByRootV1 => LEAN_BLOCKS_BY_ROOT_V1,
            LeanSupportedProtocol::BlocksByRangeV1 => LEAN_BLOCKS_BY_RANGE_V1,
            LeanSupportedProtocol::StatusV1 => LEAN_STATUS_V1,
        }
    }
}

impl TryFrom<u32> for LeanSupportedProtocol {
    type Error = ();

    /// Inverse of the `#[repr(u32)]` discriminants on the enum above.
    /// Keep these arms in lock-step with the explicit discriminants
    /// (`BlocksByRootV1 = 0`, `StatusV1 = 1`, `BlocksByRangeV1 = 2`)
    /// so `LeanSupportedProtocol::try_from(p as u32) == Ok(p)` holds
    /// for every variant. Verified by `try_from_round_trip_matches_repr`
    /// below.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LeanSupportedProtocol::BlocksByRootV1),
            1 => Ok(LeanSupportedProtocol::StatusV1),
            2 => Ok(LeanSupportedProtocol::BlocksByRangeV1),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the cross-FFI invariant: every variant must satisfy
    /// `try_from(p as u32) == Ok(p)`. Catches the foot-gun where the
    /// `TryFrom<u32>` mapping silently disagrees with Rust's default
    /// fieldless-enum `as u32` (declaration-order).
    ///
    /// Reported by @ch4r10t33r on PR #824 — prior to the
    /// `#[repr(u32)]` + explicit-discriminant fix, `StatusV1 as u32`
    /// returned 2 (declaration ord) while `try_from(2)` returned
    /// `BlocksByRangeV1`, so a Rust→u32 emission followed by a
    /// `TryFrom<u32>` decode would lie. Today nothing exercises
    /// `as u32` on this enum, but the asymmetry was a foot-shaped
    /// trap left in the codebase. This test makes any future
    /// regression compile-fail-equivalent (test-fail).
    #[test]
    fn try_from_round_trip_matches_repr() {
        for p in [
            LeanSupportedProtocol::BlocksByRootV1,
            LeanSupportedProtocol::StatusV1,
            LeanSupportedProtocol::BlocksByRangeV1,
        ] {
            let raw = p as u32;
            let decoded = LeanSupportedProtocol::try_from(raw)
                .unwrap_or_else(|_| panic!("variant {:?} (raw {}) failed try_from", p, raw));
            assert_eq!(
                decoded, p,
                "round-trip mismatch for variant {:?}: as u32 = {} but try_from({}) = {:?}",
                p, raw, raw, decoded
            );
        }
    }

    /// Pin the explicit discriminant values so any reorder/edit that
    /// breaks the Zig-side mapping (interface.zig::LeanSupportedProtocol)
    /// trips this test instead of corrupting wire traffic at runtime.
    /// Zig side declares `blocks_by_root = 0, status = 1, blocks_by_range = 2`.
    #[test]
    fn discriminants_match_zig_side() {
        assert_eq!(LeanSupportedProtocol::BlocksByRootV1 as u32, 0);
        assert_eq!(LeanSupportedProtocol::StatusV1 as u32, 1);
        assert_eq!(LeanSupportedProtocol::BlocksByRangeV1 as u32, 2);
    }

    /// Pin the rejection of out-of-range u32s. Today only 0/1/2 are
    /// valid; anything else MUST be `Err(())`.
    #[test]
    fn try_from_rejects_out_of_range() {
        assert!(LeanSupportedProtocol::try_from(3).is_err());
        assert!(LeanSupportedProtocol::try_from(42).is_err());
        assert!(LeanSupportedProtocol::try_from(u32::MAX).is_err());
    }
}
