#![no_main]
use libfuzzer_sys::fuzz_target;
use _core::json_stream::{parse_bounded, DEFAULT_MAX_JSON_BYTES};

fuzz_target!(|data: &[u8]| {
    let _ = parse_bounded(data, 64, DEFAULT_MAX_JSON_BYTES);
});
