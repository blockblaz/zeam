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
