#![deny(unsafe_code)]

pub mod error;
pub mod json_stream;

use pyo3::prelude::*;

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

#[allow(unsafe_code)]
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_json_bounded, m)?)?;
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
