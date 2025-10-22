/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/configurations.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
use std::time::Duration;

/// Maximum allowed size for a single RPC payload (compressed).
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Timeout applied to reading requests and responses from a substream.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub fn max_message_size() -> usize {
    MAX_MESSAGE_SIZE
}
