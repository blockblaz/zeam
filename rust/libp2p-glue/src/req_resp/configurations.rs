/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/configurations.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
use std::time::Duration;

/// Maximum uncompressed payload size (10 MiB), per Ethereum consensus spec.
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Snappy worst-case compressed length for a payload of size `n`.
pub const fn max_compressed_len(n: usize) -> usize {
    32 + n + n / 6
}

/// Spec-derived maximum message size: snappy worst-case of MAX_PAYLOAD_SIZE + 1024 bytes
/// framing overhead, with a floor of 1 MiB.
/// Matches ream / grandine / lighthouse: `max(max_compressed_len(MAX_PAYLOAD_SIZE) + 1024, 1 MiB)`.
pub fn max_message_size() -> usize {
    std::cmp::max(max_compressed_len(MAX_PAYLOAD_SIZE) + 1024, 1024 * 1024)
}

/// Timeout applied to reading requests and responses from a substream.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Idle timeout for server-side response streams.
pub const RESPONSE_CHANNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
