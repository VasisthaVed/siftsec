// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("input exceeds maximum size ({size} > {max} bytes)")]
    TooLarge { size: usize, max: usize },

    #[error("input exceeds maximum nesting depth ({depth} > {max})")]
    TooDeep { depth: u32, max: u32 },

    #[error("input exceeds operation budget ({ops} > {max})")]
    OpBudgetExceeded { ops: u64, max: u64 },

    #[error("malformed {format} at byte {offset}: {reason}")]
    Malformed {
        format: &'static str,
        offset: u64,
        reason: String,
    },

    #[error("truncated {format} stream at byte {offset}")]
    Truncated { format: &'static str, offset: u64 },

    #[error("graph exceeds node cap ({nodes} > {max})")]
    GraphTooLarge { nodes: usize, max: usize },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ScanError> for pyo3::PyErr {
    fn from(err: ScanError) -> Self {
        use pyo3::exceptions::{PyMemoryError, PyOSError, PyValueError};
        match err {
            ScanError::TooLarge { .. } | ScanError::GraphTooLarge { .. } => {
                PyMemoryError::new_err(err.to_string())
            }
            ScanError::TooDeep { .. }
            | ScanError::OpBudgetExceeded { .. }
            | ScanError::Malformed { .. }
            | ScanError::Truncated { .. } => PyValueError::new_err(err.to_string()),
            ScanError::Io(_) => PyOSError::new_err(err.to_string()),
        }
    }
}
