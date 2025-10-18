/// The code originally comes from Ream https://github.com/ReamLabs/ream/blob/5a4b3cb42d5646a0d12ec1825ace03645dbfd59b/crates/networking/p2p/src/req_resp/error.rs
/// as we still need rust-libp2p until we fully migrate to zig-libp2p. It needs the custom RPC protocol implementation.
use std::io;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ReqRespError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Incomplete stream")]
    IncompleteStream,
    #[error("Stream timed out")]
    StreamTimedOut,
    #[error("Disconnected")]
    Disconnected,
    #[error("Raw error message: {0}")]
    RawError(String),
}

impl From<io::Error> for ReqRespError {
    fn from(err: io::Error) -> Self {
        ReqRespError::IoError(err.to_string())
    }
}
