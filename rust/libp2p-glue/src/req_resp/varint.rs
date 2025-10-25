use crate::req_resp::error::ReqRespError;
use unsigned_varint::{decode, encode};

pub const MAX_VARINT_BYTES: usize = 10;

/// These helpers intentionally stay on the low-level `unsigned-varint` APIs rather than the
/// convenience `Uvi` codec so callers can inspect the prefix without mutating the input buffer.
/// `decode_varint_prefix` reports incomplete prefixes via `Ok(None)` and lets Zig continue to own
/// the actual frame assembly.
/// Attempts to decode an unsigned varint prefix from the provided slice without consuming it.
///
/// Returns `Ok(Some((value, prefix_len)))` when a complete varint is present, where `value` is the
/// decoded number and `prefix_len` is the number of bytes making up the prefix. If the slice does
/// not yet contain enough bytes to finish decoding the varint, `Ok(None)` is returned so the caller
/// can await more data. Any malformed encoding results in a `ReqRespError::InvalidData`.
pub fn decode_varint_prefix(src: &[u8]) -> Result<Option<(usize, usize)>, ReqRespError> {
    match decode::usize(src) {
        Ok((value, remaining)) => {
            let prefix_len = src.len() - remaining.len();
            Ok(Some((value, prefix_len)))
        }
        Err(decode::Error::Insufficient) => Ok(None),
        Err(err) => Err(ReqRespError::InvalidData(format!(
            "Invalid length prefix: {err}",
        ))),
    }
}

pub fn encode_varint(value: usize, dst: &mut Vec<u8>) {
    let mut buffer = encode::usize_buffer();
    let encoded = encode::usize(value, &mut buffer);
    dst.extend_from_slice(encoded);
}
