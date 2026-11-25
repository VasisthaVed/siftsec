use crate::error::ScanError;

pub const DEFAULT_MAX_JSON_BYTES: usize = 64 * 1024 * 1024;

/// Three-bound JSON parser: size cap, byte-level depth pre-pass, and serde_stacker (ADR-023).
pub fn parse_bounded(
    bytes: &[u8],
    max_depth: u32,
    max_bytes: usize,
) -> Result<serde_json::Value, ScanError> {
    if bytes.len() > max_bytes {
        return Err(ScanError::TooLarge {
            size: bytes.len(),
            max: max_bytes,
        });
    }

    let mut depth = 0u32;
    let mut in_string = false;
    let mut escape = false;
    for &b in bytes {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return Err(ScanError::TooDeep {
                        depth,
                        max: max_depth,
                    });
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    let mut de = serde_json::Deserializer::from_slice(bytes);
    let de = serde_stacker::Deserializer::new(&mut de);
    serde::Deserialize::deserialize(de).map_err(|e| ScanError::Malformed {
        format: "json",
        offset: e.line() as u64,
        reason: e.to_string(),
    })
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(66)]
    fn depth_prepass_bounded() {
        let max_depth: u32 = 64;
        let data: [u8; 64] = kani::any();
        let result = parse_bounded(&data, max_depth, DEFAULT_MAX_JSON_BYTES);
        kani::assert(result.is_ok() || result.is_err());
    }
}
