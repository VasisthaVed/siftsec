use crate::graph::{EdgeKind, NodeKind, SecurityGraph};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct Witness {
    pub path: Vec<NodeIndex<u32>>,
    pub via_write_permission: bool,
}

pub fn is_write_action(action: &str) -> bool {
    let a = action.trim();
    if a == "*" || a.eq_ignore_ascii_case("s3:*") {
        return true;
    }
    let low = a.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "s3:putobject"
            | "s3:deleteobject"
            | "s3:putbucketpolicy"
            | "iam:passrole"
            | "sts:assumerole"
    ) || low.ends_with(":*")
        || low.contains(":put")
        || low.contains(":delete")
        || low.contains(":write")
}

fn edge_grants_write(actions: &[String]) -> bool {
    actions.iter().any(|a| is_write_action(a))
}

/// Checks if a `model` node holds an outgoing write-capable role/bucket edge (up to 2 hops)
/// so `model_handoff` credential inheritance propagates `model_A`'s write scope.
fn node_has_write_creds(sg: &SecurityGraph, start: NodeIndex<u32>) -> bool {
    for e1 in sg.graph.edges(start) {
        if edge_grants_write(&e1.weight().actions) {
            return true;
        }
        let mid = e1.target();
        if sg.graph[mid].kind == NodeKind::Identity {
            for e2 in sg.graph.edges(mid) {
                if edge_grants_write(&e2.weight().actions) {
                    return true;
                }
            }
        }
    }
    false
}

/// Shortest-path BFS from every boundary node to every sensitive `data_store` within `max_hops` (ADR-025).
/// Uses `FxHashMap<u32, u32>` strictly for internal `NodeIndex` predecessor tracking (ADR-026).
pub fn find_shortest_witnesses(sg: &SecurityGraph, max_hops: usize) -> Vec<Witness> {
    let mut boundary_nodes: Vec<NodeIndex<u32>> = sg
        .graph
        .node_indices()
        .filter(|&idx| sg.graph[idx].boundary)
        .collect();
    boundary_nodes.sort_by_key(|idx| idx.index());

    let mut witnesses: Vec<Witness> = Vec::new();

    for start in boundary_nodes {
        let mut pred: FxHashMap<u32, u32> = FxHashMap::default();
        let mut dist: FxHashMap<u32, usize> = FxHashMap::default();
        let mut queue: VecDeque<NodeIndex<u32>> = VecDeque::new();

        dist.insert(start.index() as u32, 0);
        queue.push_back(start);

        let mut targets_found: Vec<NodeIndex<u32>> = Vec::new();

        while let Some(u) = queue.pop_front() {
            let d = dist[&(u.index() as u32)];
            if d >= max_hops {
                continue;
            }

            let mut neighbors: Vec<NodeIndex<u32>> =
                sg.graph.edges(u).map(|e| e.target()).collect();
            neighbors.sort_by_key(|n| n.index());
            neighbors.dedup();

            for v in neighbors {
                let v_key = v.index() as u32;
                if let std::collections::hash_map::Entry::Vacant(e) = dist.entry(v_key) {
                    e.insert(d + 1);
                    pred.insert(v_key, u.index() as u32);
                    let target_node = &sg.graph[v];
                    if target_node.kind == NodeKind::DataStore && target_node.sensitive {
                        targets_found.push(v);
                    }
                    queue.push_back(v);
                }
            }
        }

        for target in targets_found {
            let mut path = Vec::new();
            let mut cur = target.index() as u32;
            path.push(NodeIndex::new(cur as usize));
            while let Some(&p) = pred.get(&cur) {
                path.push(NodeIndex::new(p as usize));
                if p == start.index() as u32 {
                    break;
                }
                cur = p;
            }
            path.reverse();

            let mut via_write = false;
            for win in path.windows(2) {
                let (u, v) = (win[0], win[1]);
                for e in sg.graph.edges_connecting(u, v) {
                    if edge_grants_write(&e.weight().actions) {
                        via_write = true;
                    }
                    if e.weight().kind == EdgeKind::ModelHandoff && node_has_write_creds(sg, u) {
                        via_write = true;
                    }
                }
            }

            witnesses.push(Witness {
                path,
                via_write_permission: via_write,
            });
        }
    }

    // ADR-031: sort witnesses by (hops, start_id_index, end_id_index)
    witnesses.sort_by(|a, b| {
        let a_hops = a.path.len().saturating_sub(1);
        let b_hops = b.path.len().saturating_sub(1);
        let a_start = a.path.first().map(|n| n.index()).unwrap_or(0);
        let b_start = b.path.first().map(|n| n.index()).unwrap_or(0);
        let a_end = a.path.last().map(|n| n.index()).unwrap_or(0);
        let b_end = b.path.last().map(|n| n.index()).unwrap_or(0);
        a_hops
            .cmp(&b_hops)
            .then_with(|| a_start.cmp(&b_start))
            .then_with(|| a_end.cmp(&b_end))
    });

    witnesses
}
