use crate::req_resp::error::ReqRespError;
use snap::raw::max_compress_len;
use unsigned_varint::{decode, encode};

pub const MAX_VARINT_BYTES: usize = 10;

/// Snappy framing format constants
const SNAPPY_STREAM_IDENTIFIER: [u8; 10] =
    [0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
const CHUNK_TYPE_COMPRESSED: u8 = 0x00;
const CHUNK_TYPE_UNCOMPRESSED: u8 = 0x01;
const CHUNK_TYPE_PADDING: u8 = 0xfe;
const CHUNK_TYPE_STREAM_ID: u8 = 0xff;
const MAX_CHUNK_LEN: usize = (1 << 24) - 1;
const MAX_UNCOMPRESSED_CHUNK: usize = 1 << 16;
const CHUNK_HEADER_AND_CRC_SIZE: usize = 8;

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

fn read_u24_le(bytes: &[u8]) -> usize {
    bytes[0] as usize | ((bytes[1] as usize) << 8) | ((bytes[2] as usize) << 16)
}

fn max_framed_len(expected_uncompressed: usize) -> Result<usize, ReqRespError> {
    let mut remaining = expected_uncompressed;
    let mut total = SNAPPY_STREAM_IDENTIFIER.len();

    while remaining > 0 {
        let chunk_len = remaining.min(MAX_UNCOMPRESSED_CHUNK);
        let max_chunk = max_compress_len(chunk_len);
        total = total
            .checked_add(CHUNK_HEADER_AND_CRC_SIZE)
            .and_then(|value| value.checked_add(max_chunk))
            .ok_or_else(|| ReqRespError::InvalidData("Snappy frame length overflow".into()))?;
        remaining -= chunk_len;
    }

    Ok(total)
}

/// Calculates the total size of a snappy-framed payload by parsing chunk headers.
pub fn calculate_snappy_frame_size(
    src: &[u8],
    expected_uncompressed: usize,
) -> Result<Option<usize>, ReqRespError> {
    if src.len() < SNAPPY_STREAM_IDENTIFIER.len() {
        return Ok(None);
    }

    // Verify stream identifier
    if src[..SNAPPY_STREAM_IDENTIFIER.len()] != SNAPPY_STREAM_IDENTIFIER {
        return Err(ReqRespError::InvalidData(
            "Invalid snappy stream identifier".into(),
        ));
    }

    let max_frame_len = max_framed_len(expected_uncompressed)?;
    let mut pos = SNAPPY_STREAM_IDENTIFIER.len();
    let mut total_uncompressed: usize = 0;

    if expected_uncompressed == 0 {
        return Ok(Some(SNAPPY_STREAM_IDENTIFIER.len()));
    }

    // Parse chunks until we've accounted for the declared uncompressed length.
    while pos < src.len() {
        // Need at least 4 bytes for chunk header (1 type + 3 length)
        if pos + 4 > src.len() {
            return Ok(None);
        }

        let chunk_type = src[pos];
        let chunk_len = read_u24_le(&src[pos + 1..pos + 4]);
        let header_end = pos
            .checked_add(4)
            .ok_or_else(|| ReqRespError::InvalidData("Snappy frame overflow".into()))?;
        let chunk_end = header_end
            .checked_add(chunk_len)
            .ok_or_else(|| ReqRespError::InvalidData("Snappy frame overflow".into()))?;
        if chunk_len > MAX_CHUNK_LEN {
            return Err(ReqRespError::InvalidData("Snappy chunk too large".into()));
        }
        if chunk_end > max_frame_len {
            return Err(ReqRespError::InvalidData(
                "Snappy frame exceeds maximum compressed length".into(),
            ));
        }

        // Validate chunk type
        match chunk_type {
            CHUNK_TYPE_COMPRESSED | CHUNK_TYPE_UNCOMPRESSED => {
                // Data chunk containing up to 64KiB of uncompressed data.
                if src.len() < chunk_end {
                    return Ok(None);
                }
                let chunk = &src[header_end..chunk_end];
                if chunk_len < 4 {
                    return Err(ReqRespError::InvalidData("Snappy chunk too short".into()));
                }
                if chunk_type == CHUNK_TYPE_COMPRESSED {
                    let compressed = &chunk[4..];
                    let uncompressed_len =
                        snap::raw::decompress_len(compressed).map_err(|err| {
                            ReqRespError::InvalidData(format!(
                                "Invalid snappy compressed chunk: {err}"
                            ))
                        })?;
                    if uncompressed_len > MAX_UNCOMPRESSED_CHUNK {
                        return Err(ReqRespError::InvalidData(
                            "Snappy chunk exceeds maximum uncompressed length".into(),
                        ));
                    }
                    total_uncompressed = total_uncompressed
                        .checked_add(uncompressed_len)
                        .ok_or_else(|| {
                            ReqRespError::InvalidData("Snappy length overflow".into())
                        })?;
                } else {
                    let data_len = chunk_len - 4;
                    if data_len > MAX_UNCOMPRESSED_CHUNK {
                        return Err(ReqRespError::InvalidData(
                            "Snappy chunk exceeds maximum uncompressed length".into(),
                        ));
                    }
                    total_uncompressed =
                        total_uncompressed.checked_add(data_len).ok_or_else(|| {
                            ReqRespError::InvalidData("Snappy length overflow".into())
                        })?;
                }
                if total_uncompressed == expected_uncompressed {
                    return Ok(Some(chunk_end));
                }
                if total_uncompressed > expected_uncompressed {
                    return Err(ReqRespError::InvalidData(
                        "Snappy frame exceeds declared length".into(),
                    ));
                }
                pos = chunk_end;
            }
            CHUNK_TYPE_PADDING => {
                // Padding chunk - skip it
                if src.len() < chunk_end {
                    return Ok(None);
                }
                pos = chunk_end;
            }
            CHUNK_TYPE_STREAM_ID => {
                // Another stream identifier (shouldn't happen mid-stream, but handle gracefully)
                if src.len() < chunk_end {
                    return Ok(None);
                }
                let chunk = &src[header_end..chunk_end];
                if chunk_len != 6 || chunk != &SNAPPY_STREAM_IDENTIFIER[4..] {
                    return Err(ReqRespError::InvalidData(
                        "Invalid snappy stream identifier".into(),
                    ));
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
                if src.len() < chunk_end {
                    return Ok(None);
                }
                pos = chunk_end;
            }
        }
    }

    Ok(None)
}
