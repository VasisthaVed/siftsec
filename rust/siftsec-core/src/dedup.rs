use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedFinding {
    #[serde(rename = "schema", default = "default_schema")]
    pub schema_version: u8,
    pub source_tool: String,
    pub rule_id: String,
    pub severity: String,
    pub asset_id: String,
    #[serde(default = "default_asset_kind")]
    pub asset_kind: String,
    #[serde(default)]
    pub component_hash: Option<String>,
    #[serde(default)]
    pub location: String,
    pub message: String,
    #[serde(default)]
    pub evidence: BTreeMap<String, String>,
    #[serde(default)]
    pub framework_requirements: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}

fn default_schema() -> u8 {
    1
}

fn default_asset_kind() -> String {
    "unknown".to_string()
}

pub fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Deterministic merge key: `sha256(component_hash | rule_or_cwe | location)`.
pub fn compute_merge_key(f: &NormalizedFinding) -> String {
    let comp = f.component_hash.as_deref().unwrap_or(&f.asset_id);
    let rule_or_cwe = f
        .evidence
        .get("cwe")
        .map(String::as_str)
        .unwrap_or(&f.rule_id);
    let mut hasher = Sha256::new();
    hasher.update(comp.as_bytes());
    hasher.update(b"|");
    hasher.update(rule_or_cwe.as_bytes());
    hasher.update(b"|");
    hasher.update(f.location.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

/// Cross-tool finding deduplication index.
///
/// Primary map uses `std::collections::HashMap` (SipHash-1-3) because keys derive from
/// untrusted SARIF input (ADR-026). `FxHashMap` is restricted strictly to internal `u32` IDs.
pub struct FindingIndex {
    buckets: HashMap<String, Vec<NormalizedFinding>>,
    node_map: FxHashMap<u32, usize>,
}

impl Default for FindingIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingIndex {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            node_map: FxHashMap::default(),
        }
    }

    pub fn insert(&mut self, finding: NormalizedFinding) {
        let key = compute_merge_key(&finding);
        let idx = self.buckets.len() as u32;
        self.buckets.entry(key).or_default().push(finding);
        self.node_map.entry(idx).or_insert(idx as usize);
    }

    pub fn into_merged(self) -> Vec<NormalizedFinding> {
        let mut merged = Vec::with_capacity(self.buckets.len());
        for (_key, group) in self.buckets {
            if let Some(first) = group.first().cloned() {
                let mut acc = first;
                if acc.sources.is_empty() {
                    acc.sources.push(acc.source_tool.clone());
                }
                for item in group.into_iter().skip(1) {
                    if severity_rank(&item.severity) > severity_rank(&acc.severity) {
                        acc.severity = item.severity;
                    }
                    let mut incoming_sources = item.sources;
                    if incoming_sources.is_empty() {
                        incoming_sources.push(item.source_tool);
                    }
                    for s in incoming_sources {
                        if !acc.sources.contains(&s) {
                            acc.sources.push(s);
                        }
                    }
                    for req in item.framework_requirements {
                        if !acc.framework_requirements.contains(&req) {
                            acc.framework_requirements.push(req);
                        }
                    }
                    for (k, v) in item.evidence {
                        acc.evidence.entry(k).or_insert(v);
                    }
                }
                merged.push(acc);
            }
        }
        // Deterministic output order: (severity_rank DESC, rule_id ASC, asset_id ASC)
        merged.sort_by(|a, b| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.asset_id.cmp(&b.asset_id))
        });
        merged
    }
}

pub fn deduplicate(findings: Vec<NormalizedFinding>) -> Vec<NormalizedFinding> {
    let mut index = FindingIndex::new();
    for f in findings {
        index.insert(f);
    }
    index.into_merged()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn sample_finding(tool: &str, asset_id: &str, hash: &str) -> NormalizedFinding {
        NormalizedFinding {
            schema_version: 1,
            source_tool: tool.to_string(),
            rule_id: "MCP-001".to_string(),
            severity: "HIGH".to_string(),
            asset_id: asset_id.to_string(),
            asset_kind: "mcp_server".to_string(),
            component_hash: Some(hash.to_string()),
            location: "mcp.json".to_string(),
            message: "test".to_string(),
            evidence: BTreeMap::new(),
            framework_requirements: Vec::new(),
            sources: vec![tool.to_string()],
        }
    }

    #[test]
    fn collapses_duplicate_findings_and_preserves_sources() {
        let f1 = sample_finding("modelaudit", "srv-a", "deadbeef");
        let f2 = sample_finding("trivy", "srv-b", "deadbeef");
        let f3 = sample_finding("agent-bom", "srv-c", "deadbeef");
        let out = deduplicate(vec![f1, f2, f3]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sources, vec!["modelaudit", "trivy", "agent-bom"]);
    }

    #[test]
    fn sorts_deterministically_by_severity_rule_asset() {
        let low = NormalizedFinding {
            severity: "LOW".to_string(),
            rule_id: "R-1".to_string(),
            ..sample_finding("trivy", "b", "h1")
        };
        let crit = NormalizedFinding {
            severity: "CRITICAL".to_string(),
            rule_id: "R-2".to_string(),
            ..sample_finding("modelaudit", "a", "h2")
        };
        let out = deduplicate(vec![low, crit]);
        assert_eq!(out[0].severity, "CRITICAL");
        assert_eq!(out[1].severity, "LOW");
    }

    #[test]
    fn dos_resistance_colliding_keys_linear_time() {
        let build = |n: usize| -> Vec<NormalizedFinding> {
            (0..n)
                .map(|i| {
                    let key = format!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_{i:08}");
                    sample_finding("trivy", &key, &key)
                })
                .collect()
        };

        let items_10k = build(10_000);
        let items_100k = build(100_000);

        let t10 = Instant::now();
        let out10 = deduplicate(items_10k);
        let d10 = t10.elapsed().as_secs_f64().max(1e-6);
        assert_eq!(out10.len(), 10_000);

        let t100 = Instant::now();
        let out100 = deduplicate(items_100k);
        let d100 = t100.elapsed().as_secs_f64();
        assert_eq!(out100.len(), 100_000);

        let ratio = d100 / d10;
        assert!(
            ratio < 15.0,
            "SipHash linear scaling violated: 100k/10k ratio = {ratio:.2} (d10={d10:.4}s, d100={d100:.4}s)"
        );
    }
}
