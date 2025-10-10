use std::time::Duration;

/// Maximum allowed size for a single RPC payload (compressed).
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Timeout applied to reading requests and responses from a substream.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub fn max_message_size() -> usize {
    MAX_MESSAGE_SIZE
}
