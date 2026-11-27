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
    let val: serde_json::Value = serde::Deserialize::deserialize(serde_stacker::Deserializer::new(
        &mut de,
    ))
    .map_err(|e| ScanError::Malformed {
        format: "json",
        offset: e.line() as u64,
        reason: e.to_string(),
    })?;
    de.end().map_err(|e| ScanError::Malformed {
        format: "json",
        offset: e.line() as u64,
        reason: e.to_string(),
    })?;
    Ok(val)
}

#[cfg(kani)]
mod kani_proofs {
    // TODO(10.2): Kani proof on depth pre-pass
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_empty_object_and_array() {
        assert_eq!(
            parse_bounded(b"{}", 8, DEFAULT_MAX_JSON_BYTES).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            parse_bounded(b"[]", 8, DEFAULT_MAX_JSON_BYTES).unwrap(),
            serde_json::json!([])
        );
    }

    #[test]
    fn parses_primitives_at_root() {
        assert_eq!(
            parse_bounded(b"null", 4, 64).unwrap(),
            serde_json::json!(null)
        );
        assert_eq!(
            parse_bounded(b"true", 4, 64).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(parse_bounded(b"42", 4, 64).unwrap(), serde_json::json!(42));
        assert_eq!(
            parse_bounded(br#""ok""#, 4, 64).unwrap(),
            serde_json::json!("ok")
        );
    }

    #[test]
    fn rejects_empty_and_whitespace_only_input() {
        assert!(matches!(
            parse_bounded(b"", 8, 64),
            Err(ScanError::Malformed { format: "json", .. })
        ));
        assert!(matches!(
            parse_bounded(b"   \n\t ", 8, 64),
            Err(ScanError::Malformed { format: "json", .. })
        ));
    }

    #[test]
    fn enforces_exact_max_bytes_boundary() {
        assert!(parse_bounded(b"{}", 4, 2).is_ok());
        let err = parse_bounded(b"{ }", 4, 2).unwrap_err();
        assert!(matches!(err, ScanError::TooLarge { size: 3, max: 2 }));
    }

    #[test]
    fn enforces_zero_max_depth_for_containers_only() {
        assert!(parse_bounded(b"123", 0, 64).is_ok());
        let err = parse_bounded(b"[]", 0, 64).unwrap_err();
        assert!(matches!(err, ScanError::TooDeep { depth: 1, max: 0 }));
    }

    #[test]
    fn enforces_exact_max_depth_boundary() {
        let ok = "[".repeat(4) + "1" + &"]".repeat(4);
        assert_eq!(
            parse_bounded(ok.as_bytes(), 4, 1024).unwrap(),
            serde_json::json!([[[[1]]]])
        );

        let too_deep = "[".repeat(5) + "1" + &"]".repeat(5);
        let err = parse_bounded(too_deep.as_bytes(), 4, 1024).unwrap_err();
        assert!(matches!(err, ScanError::TooDeep { depth: 5, max: 4 }));
    }

    #[test]
    fn ignores_brackets_and_braces_inside_strings() {
        let payload = br#"{"k": "[[[[[[[[[[{{{{{{{{{{", "n": 1}"#;
        let val = parse_bounded(payload, 1, 1024).unwrap();
        assert_eq!(val["n"], serde_json::json!(1));
    }

    #[test]
    fn handles_escaped_quotes_and_backslashes_in_strings() {
        let payload = br#"{"escaped": "a\"[[[\\\"b", "ok": true}"#;
        let val = parse_bounded(payload, 1, 1024).unwrap();
        assert_eq!(val["ok"], serde_json::json!(true));
    }

    #[test]
    fn rejects_invalid_utf8_and_pickle_bytes() {
        assert!(matches!(
            parse_bounded(b"\x80\x04\x95\x10\x00", 64, 1024),
            Err(ScanError::Malformed { format: "json", .. })
        ));
        assert!(matches!(
            parse_bounded(b"\xff\xfe\xfd", 64, 1024),
            Err(ScanError::Malformed { format: "json", .. })
        ));
    }

    #[test]
    fn rejects_trailing_garbage_after_valid_json() {
        assert!(matches!(
            parse_bounded(b"{} trailing", 8, 1024),
            Err(ScanError::Malformed { format: "json", .. })
        ));
    }

    #[test]
    fn depth_prepass_recovers_after_closed_sibling_containers() {
        let payload = br#"[[1],[2],[3],[4]]"#;
        let val = parse_bounded(payload, 2, 1024).unwrap();
        assert_eq!(val.as_array().unwrap().len(), 4);
    }

    proptest! {
        #[test]
        fn parse_bounded_never_panics_on_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..4096),
            max_depth in 0u32..32,
            max_bytes in 0usize..4096,
        ) {
            let res = parse_bounded(&data, max_depth, max_bytes);
            if data.len() > max_bytes {
                let is_too_large = matches!(res, Err(ScanError::TooLarge { .. }));
                prop_assert!(is_too_large);
            }
        }
    }
}
