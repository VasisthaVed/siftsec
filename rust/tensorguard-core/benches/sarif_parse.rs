use std::time::Instant;
use _tg_core::json_stream::{parse_bounded, DEFAULT_MAX_JSON_BYTES};

fn main() {
    let sample = br#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ModelAudit"}},"results":[{"ruleId":"MA-1","level":"error","message":{"text":"test"}}]}]}"#;
    let start = Instant::now();
    for _ in 0..1_000 {
        let _ = parse_bounded(sample, 64, DEFAULT_MAX_JSON_BYTES).expect("valid sarif");
    }
    let elapsed = start.elapsed();
    println!("Parsed 1,000 SARIF payloads in {:?}", elapsed);
    assert!(elapsed.as_millis() < 500, "SARIF parse regression: {:?}", elapsed);
}
