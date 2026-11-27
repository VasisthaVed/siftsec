#![deny(unsafe_code)]

pub mod dedup;
pub mod error;
pub mod json_stream;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::BTreeMap;

#[allow(unsafe_code)]
#[pyfunction]
#[pyo3(signature = (bytes, max_depth=64, max_bytes=json_stream::DEFAULT_MAX_JSON_BYTES))]
pub fn parse_json_bounded(
    py: Python<'_>,
    bytes: Vec<u8>,
    max_depth: u32,
    max_bytes: usize,
) -> PyResult<String> {
    let val = py.detach(|| json_stream::parse_bounded(&bytes, max_depth, max_bytes))?;
    serde_json::to_string(&val).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

fn extract_finding(obj: &Bound<'_, PyAny>) -> PyResult<dedup::NormalizedFinding> {
    let d = obj.cast::<PyDict>()?;
    let get_str = |key: &str, default: &str| -> PyResult<String> {
        match d.get_item(key)? {
            Some(v) if !v.is_none() => v.extract::<String>(),
            _ => Ok(default.to_string()),
        }
    };
    let schema_version: u8 = match d.get_item("schema")? {
        Some(v) if !v.is_none() => v.extract()?,
        _ => 1,
    };
    let component_hash: Option<String> = match d.get_item("component_hash")? {
        Some(v) if !v.is_none() => Some(v.extract()?),
        _ => None,
    };
    let evidence: BTreeMap<String, String> = match d.get_item("evidence")? {
        Some(v) if !v.is_none() => v.extract()?,
        _ => BTreeMap::new(),
    };
    let framework_requirements: Vec<String> = match d.get_item("framework_requirements")? {
        Some(v) if !v.is_none() => v.extract()?,
        _ => Vec::new(),
    };
    let sources: Vec<String> = match d.get_item("sources")? {
        Some(v) if !v.is_none() => v.extract()?,
        _ => Vec::new(),
    };

    Ok(dedup::NormalizedFinding {
        schema_version,
        source_tool: get_str("source_tool", "")?,
        rule_id: get_str("rule_id", "UNKNOWN")?,
        severity: get_str("severity", "MEDIUM")?,
        asset_id: get_str("asset_id", "")?,
        asset_kind: get_str("asset_kind", "unknown")?,
        component_hash,
        location: get_str("location", "")?,
        message: get_str("message", "")?,
        evidence,
        framework_requirements,
        sources,
    })
}

fn finding_to_py(py: Python<'_>, f: dedup::NormalizedFinding) -> PyResult<Py<PyAny>> {
    let out = PyDict::new(py);
    out.set_item("schema", f.schema_version)?;
    out.set_item("source_tool", f.source_tool)?;
    out.set_item("rule_id", f.rule_id)?;
    out.set_item("severity", f.severity)?;
    out.set_item("asset_id", f.asset_id)?;
    out.set_item("asset_kind", f.asset_kind)?;
    out.set_item("component_hash", f.component_hash)?;
    out.set_item("location", f.location)?;
    out.set_item("message", f.message)?;
    out.set_item("evidence", f.evidence)?;
    out.set_item("framework_requirements", f.framework_requirements)?;
    out.set_item("sources", f.sources)?;
    Ok(out.into_any().unbind())
}

#[allow(unsafe_code)]
#[pyfunction]
pub fn index_findings(py: Python<'_>, findings: Vec<Py<PyAny>>) -> PyResult<Vec<Py<PyAny>>> {
    let mut rust_findings = Vec::with_capacity(findings.len());
    for item in &findings {
        rust_findings.push(extract_finding(item.bind(py))?);
    }
    let merged = py.detach(|| dedup::deduplicate(rust_findings));
    let mut out = Vec::with_capacity(merged.len());
    for item in merged {
        out.push(finding_to_py(py, item)?);
    }
    Ok(out)
}

#[allow(unsafe_code)]
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_json_bounded, m)?)?;
    m.add_function(wrap_pyfunction!(index_findings, m)?)?;
    Ok(())
}

#[cfg(test)]
mod panic_boundary {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn parse_bounded_never_panics_on_deep_input() {
        let deep = "[".repeat(100_000) + &"]".repeat(100_000);
        let result = catch_unwind(AssertUnwindSafe(|| {
            json_stream::parse_bounded(deep.as_bytes(), 64, json_stream::DEFAULT_MAX_JSON_BYTES)
        }));
        assert!(result.is_ok(), "parser panicked on deep input");
        assert!(result.unwrap().is_err(), "deep input must be rejected");
    }
}
