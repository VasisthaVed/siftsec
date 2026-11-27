// SPDX-License-Identifier: Apache-2.0
use crate::graph::reach::Witness;
use crate::graph::{ReachabilityResult, SecurityGraph};

pub fn score_witnesses(sg: &SecurityGraph, witnesses: Vec<Witness>) -> ReachabilityResult {
    if witnesses.is_empty() {
        return ReachabilityResult {
            schema: 1,
            reachable: false,
            witness_path: Vec::new(),
            hops: 0,
            reaches_sensitive: false,
            via_write_permission: false,
            severity: "INFO".to_string(),
            explanation:
                "No reachable path from an internet-exposed boundary to a sensitive data store."
                    .to_string(),
            witnesses: Vec::new(),
        };
    }

    // Prefer a write-capable witness if multiple exist at minimum/comparable depth;
    // witnesses are already deterministically sorted by (hops, start_idx, end_idx).
    let chosen = witnesses
        .iter()
        .find(|w| w.via_write_permission)
        .unwrap_or(&witnesses[0]);

    let witness_path: Vec<String> = chosen
        .path
        .iter()
        .map(|idx| sg.graph[*idx].id.clone())
        .collect();
    let hops = witness_path.len().saturating_sub(1);
    let via_write = chosen.via_write_permission;
    let severity = if via_write { "CRITICAL" } else { "LOW" }.to_string();

    let start_id = witness_path.first().map(String::as_str).unwrap_or("");
    let end_id = witness_path.last().map(String::as_str).unwrap_or("");
    let perm_desc = if via_write {
        "write permission"
    } else {
        "read-only permission"
    };
    let explanation = format!(
        "Reachable in {hops} hops from boundary '{start_id}' to sensitive data_store '{end_id}' via {perm_desc}."
    );

    let all_witness_paths: Vec<Vec<String>> = witnesses
        .iter()
        .map(|w| w.path.iter().map(|idx| sg.graph[*idx].id.clone()).collect())
        .collect();

    ReachabilityResult {
        schema: 1,
        reachable: true,
        witness_path,
        hops,
        reaches_sensitive: true,
        via_write_permission: via_write,
        severity,
        explanation,
        witnesses: all_witness_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, EdgeKind, GraphPayload, Node, NodeKind};

    #[test]
    fn rejects_unknown_schema_version() {
        let payload = GraphPayload {
            schema: 99,
            nodes: vec![],
            edges: vec![],
            max_hops: 8,
        };
        let res = SecurityGraph::build(payload);
        assert!(res.is_err());
    }

    #[test]
    fn write_vs_readonly_scoring_separates_critical_from_low() {
        let mk_payload = |action: &str| GraphPayload {
            schema: 1,
            max_hops: 8,
            nodes: vec![
                Node {
                    id: "nb-1".into(),
                    kind: NodeKind::Boundary,
                    sensitive: false,
                    boundary: true,
                    display_name: "notebook".into(),
                },
                Node {
                    id: "role-1".into(),
                    kind: NodeKind::Identity,
                    sensitive: false,
                    boundary: false,
                    display_name: "role".into(),
                },
                Node {
                    id: "s3-weights".into(),
                    kind: NodeKind::DataStore,
                    sensitive: true,
                    boundary: false,
                    display_name: "weights".into(),
                },
            ],
            edges: vec![
                Edge {
                    source: "nb-1".into(),
                    target: "role-1".into(),
                    kind: EdgeKind::UsesRole,
                    confidence: 1.0,
                    provenance: "test".into(),
                    actions: vec![],
                },
                Edge {
                    source: "role-1".into(),
                    target: "s3-weights".into(),
                    kind: EdgeKind::ReadsBucket,
                    confidence: 1.0,
                    provenance: "test".into(),
                    actions: vec![action.into()],
                },
            ],
        };

        let (sg_w, hops_w) = SecurityGraph::build(mk_payload("s3:*")).unwrap();
        let res_w = score_witnesses(
            &sg_w,
            crate::graph::reach::find_shortest_witnesses(&sg_w, hops_w),
        );
        assert!(res_w.reachable);
        assert!(res_w.via_write_permission);
        assert_eq!(res_w.severity, "CRITICAL");
        assert_eq!(res_w.witness_path.len(), 3);

        let (sg_r, hops_r) = SecurityGraph::build(mk_payload("s3:GetObject")).unwrap();
        let res_r = score_witnesses(
            &sg_r,
            crate::graph::reach::find_shortest_witnesses(&sg_r, hops_r),
        );
        assert!(res_r.reachable);
        assert!(!res_r.via_write_permission);
        assert_eq!(res_r.severity, "LOW");
    }
}
