// SPDX-License-Identifier: Apache-2.0
use _core::graph::{evaluate_payload_json, Edge, EdgeKind, GraphPayload, Node, NodeKind};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn make_1k_node_5k_edge_payload() -> String {
    let mut nodes = Vec::with_capacity(1000);
    for i in 0..1000 {
        let kind = match i % 6 {
            0 => NodeKind::Boundary,
            1 => NodeKind::AiAsset,
            2 => NodeKind::Identity,
            3 => NodeKind::DataStore,
            4 => NodeKind::Skill,
            _ => NodeKind::Model,
        };
        nodes.push(Node {
            id: format!("node-{i:04}"),
            kind,
            sensitive: i % 6 == 3 && i > 900,
            boundary: i % 6 == 0 && i < 30,
            display_name: format!("Node {i}"),
        });
    }

    let mut edges = Vec::with_capacity(5000);
    for i in 0..5000 {
        let src = i % 1000;
        let dst = (i * 7 + 13) % 1000;
        edges.push(Edge {
            source: format!("node-{src:04}"),
            target: format!("node-{dst:04}"),
            kind: if i % 10 == 0 {
                EdgeKind::ModelHandoff
            } else {
                EdgeKind::UsesRole
            },
            confidence: 1.0,
            provenance: "bench".to_string(),
            actions: if i % 20 == 0 {
                vec!["s3:*".to_string()]
            } else {
                vec!["s3:GetObject".to_string()]
            },
        });
    }

    serde_json::to_string(&GraphPayload {
        schema: 1,
        nodes,
        edges,
        max_hops: 8,
    })
    .expect("serialize bench graph")
}

fn bench_graph_1k_5k(c: &mut Criterion) {
    let payload_json = make_1k_node_5k_edge_payload();
    c.bench_function("graph_1k_nodes_5k_edges", |b| {
        b.iter(|| {
            let out = evaluate_payload_json(black_box(&payload_json)).expect("valid graph");
            black_box(out)
        })
    });
}

criterion_group!(benches, bench_graph_1k_5k);
criterion_main!(benches);
