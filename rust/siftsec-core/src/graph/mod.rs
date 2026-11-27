// SPDX-License-Identifier: Apache-2.0
pub mod reach;
pub mod score;

use crate::error::ScanError;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Boundary,
    AiAsset,
    Identity,
    DataStore,
    Skill,
    Model,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    UsesRole,
    ReadsBucket,
    MemberOfSg,
    KbUsesVectorstore,
    AgentUsesGuardrail,
    SkillUsesAgent,
    ModelHandoff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub boundary: bool,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub provenance: String,
    #[serde(default)]
    pub actions: Vec<String>,
}

fn default_confidence() -> f32 {
    1.0
}

fn default_max_hops() -> usize {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPayload {
    pub schema: u8,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReachabilityResult {
    pub schema: u8,
    pub reachable: bool,
    pub witness_path: Vec<String>,
    pub hops: usize,
    pub reaches_sensitive: bool,
    pub via_write_permission: bool,
    pub severity: String,
    pub explanation: String,
    pub witnesses: Vec<Vec<String>>,
}

/// Extract deterministic `(provider, service, id)` sort key from a resource ID/ARN.
fn node_sort_key(id: &str) -> (String, String, String) {
    if let Some(rest) = id.strip_prefix("arn:") {
        let mut parts = rest.splitn(4, ':');
        let provider = parts.next().unwrap_or("").to_string();
        let service = parts.next().unwrap_or("").to_string();
        return (provider, service, id.to_string());
    }
    if let Some((scheme, _)) = id.split_once("://") {
        return (scheme.to_string(), String::new(), id.to_string());
    }
    (String::new(), String::new(), id.to_string())
}

pub struct SecurityGraph {
    pub graph: DiGraph<Node, Edge, u32>,
    /// Primary string-keyed map uses default `HashMap` (SipHash-1-3, ADR-026).
    pub id_to_idx: HashMap<String, NodeIndex<u32>>,
}

impl SecurityGraph {
    pub fn build(payload: GraphPayload) -> Result<(Self, usize), ScanError> {
        if payload.schema != 1 {
            return Err(ScanError::Malformed {
                format: "graph_payload",
                offset: 0,
                reason: format!("unsupported schema version {}", payload.schema),
            });
        }

        let mut nodes = payload.nodes;
        nodes.sort_by_key(|a| node_sort_key(&a.id));
        nodes.dedup_by(|a, b| a.id == b.id);

        let mut edges = payload.edges;
        edges.sort_by(|a, b| {
            a.source
                .cmp(&b.source)
                .then_with(|| a.target.cmp(&b.target))
                .then_with(|| a.kind.cmp(&b.kind))
        });

        let mut graph = DiGraph::<Node, Edge, u32>::with_capacity(nodes.len(), edges.len());
        let mut id_to_idx: HashMap<String, NodeIndex<u32>> = HashMap::with_capacity(nodes.len());

        for node in nodes {
            let id = node.id.clone();
            let idx = graph.add_node(node);
            id_to_idx.insert(id, idx);
        }

        for edge in edges {
            if let (Some(&src), Some(&dst)) =
                (id_to_idx.get(&edge.source), id_to_idx.get(&edge.target))
            {
                graph.add_edge(src, dst, edge);
            }
        }

        Ok((Self { graph, id_to_idx }, payload.max_hops))
    }
}

pub fn evaluate_payload_json(payload_json: &str) -> Result<String, ScanError> {
    let payload: GraphPayload =
        serde_json::from_str(payload_json).map_err(|e| ScanError::Malformed {
            format: "graph_json",
            offset: e.line() as u64,
            reason: e.to_string(),
        })?;
    let (sg, max_hops) = SecurityGraph::build(payload)?;
    let witnesses = reach::find_shortest_witnesses(&sg, max_hops);
    let result = score::score_witnesses(&sg, witnesses);
    serde_json::to_string(&result).map_err(|e| ScanError::Malformed {
        format: "graph_output",
        offset: 0,
        reason: e.to_string(),
    })
}
