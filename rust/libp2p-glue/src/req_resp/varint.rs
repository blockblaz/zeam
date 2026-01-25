use crate::req_resp::error::ReqRespError;
use unsigned_varint::{decode, encode};

pub const MAX_VARINT_BYTES: usize = 10;

/// Snappy framing format constants
const SNAPPY_STREAM_IDENTIFIER: [u8; 10] =
    [0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
const CHUNK_TYPE_COMPRESSED: u8 = 0x00;
const CHUNK_TYPE_UNCOMPRESSED: u8 = 0x01;
const CHUNK_TYPE_PADDING: u8 = 0xfe;
const CHUNK_TYPE_STREAM_ID: u8 = 0xff;

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

/// Calculates the total size of a snappy-framed payload by parsing chunk headers.
pub fn calculate_snappy_frame_size(src: &[u8]) -> Result<Option<usize>, ReqRespError> {
    if src.len() < SNAPPY_STREAM_IDENTIFIER.len() {
        return Ok(None);
    }

    // Verify stream identifier
    if src[..SNAPPY_STREAM_IDENTIFIER.len()] != SNAPPY_STREAM_IDENTIFIER {
        return Err(ReqRespError::InvalidData(
            "Invalid snappy stream identifier".into(),
        ));
    }

    let mut pos = SNAPPY_STREAM_IDENTIFIER.len();

    // Parse chunks until we find a complete data chunk
    while pos < src.len() {
        // Need at least 4 bytes for chunk header (1 type + 3 length)
        if pos + 4 > src.len() {
            return Ok(None);
        }

        let chunk_type = src[pos];
        let chunk_len = u32::from_le_bytes([src[pos + 1], src[pos + 2], src[pos + 3], 0]) as usize;

        // Validate chunk type
        match chunk_type {
            CHUNK_TYPE_COMPRESSED | CHUNK_TYPE_UNCOMPRESSED => {
                // Data chunk - this is what we're looking for
                let chunk_end = pos + 4 + chunk_len;
                if src.len() < chunk_end {
                    return Ok(None);
                }
                // For req/resp protocol, we expect exactly one data chunk after the stream id
                // Return the total size once we've parsed the first data chunk
                return Ok(Some(chunk_end));
            }
            CHUNK_TYPE_PADDING => {
                // Padding chunk - skip it
                let chunk_end = pos + 4 + chunk_len;
                if src.len() < chunk_end {
                    return Ok(None);
                }
                pos = chunk_end;
            }
            CHUNK_TYPE_STREAM_ID => {
                // Another stream identifier (shouldn't happen mid-stream, but handle gracefully)
                let chunk_end = pos + 4 + chunk_len;
                if src.len() < chunk_end {
                    return Ok(None);
                }
                pos = chunk_end;
            }
            0x02..=0x7f => {
                // Reserved unskippable chunk types - treat as error
                return Err(ReqRespError::InvalidData(format!(
                    "Unknown unskippable snappy chunk type: 0x{:02x}",
                    chunk_type
                )));
            }
            _ => {
                // Reserved skippable chunk types (0x80-0xfd) - skip them
                let chunk_end = pos + 4 + chunk_len;
                if src.len() < chunk_end {
                    return Ok(None);
                }
                pos = chunk_end;
            }
        }
    }

    // If we've parsed everything but found no data chunk, we need more data
    Ok(None)
}
