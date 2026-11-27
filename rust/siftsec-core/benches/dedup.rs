use _core::dedup::{deduplicate, NormalizedFinding};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::BTreeMap;

fn make_200_findings() -> Vec<NormalizedFinding> {
    (0..200)
        .map(|i| NormalizedFinding {
            schema_version: 1,
            source_tool: format!("tool-{}", i % 4),
            rule_id: format!("RULE-{:03}", i % 50),
            severity: if i % 5 == 0 { "CRITICAL" } else { "HIGH" }.to_string(),
            asset_id: format!("asset-{}", i % 40),
            asset_kind: "mcp_server".to_string(),
            component_hash: Some(format!("hash-{:04}", i % 40)),
            location: format!("mcp-{}.json", i % 10),
            message: "bench finding".to_string(),
            evidence: BTreeMap::new(),
            framework_requirements: Vec::new(),
            sources: vec![format!("tool-{}", i % 4)],
        })
        .collect()
}

fn bench_dedup_200(c: &mut Criterion) {
    let payload = make_200_findings();
    c.bench_function("dedup_200_findings", |b| {
        b.iter(|| {
            let out = deduplicate(black_box(payload.clone()));
            black_box(out)
        })
    });
}

criterion_group!(benches, bench_dedup_200);
criterion_main!(benches);
