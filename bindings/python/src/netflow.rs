//! Conversion for the NetFlow record split.
use octetrail::netflow;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// `(count, start of a cut-off record or None)` for `len` bytes of records of
/// `size` bytes.
#[pyfunction]
fn _netflow_records(len: usize, size: usize) -> PyResult<(usize, Option<usize>)> {
    if size == 0 {
        return Err(PyValueError::new_err("record size must not be 0"));
    }
    let found = netflow::records(len, size);
    Ok((found.count, found.tail))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_netflow_records, module)?)?;
    Ok(())
}
