//! Conversion for the VRRP core. Ranges index the bytes that were passed in.
use octetrail::vrrp::{self, Range};
use pyo3::prelude::*;

/// `(addrs, auth)` for the bytes after a VRRP header.
#[pyfunction]
fn _vrrp_layout(count: u8, data: &[u8]) -> (Vec<Range>, Range) {
    let found = vrrp::layout(count, data);
    (found.addrs, found.auth)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_vrrp_layout, module)?)?;
    Ok(())
}
