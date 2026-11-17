//! Conversion for the DHCP options core. Ranges index the bytes that were passed in.
use octetrail::dhcp::{self, Range};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
pyo3::create_exception!(_native, DhcpMissingLengthError, PyException);

/// `([(type, (start, end))], rest)` for the bytes after a DHCP header. A
/// missing length byte raises DhcpMissingLengthError with its offset.
#[pyfunction]
fn _dhcp_options(data: &[u8]) -> PyResult<(Vec<(u8, Range)>, usize)> {
    match dhcp::options(data) {
        Ok(found) => Ok((found.opts, found.rest)),
        Err(e) => Err(DhcpMissingLengthError::new_err(e.at)),
    }
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "DhcpMissingLengthError",
        module.py().get_type::<DhcpMissingLengthError>(),
    )?;
    module.add_function(wrap_pyfunction!(_dhcp_options, module)?)?;
    Ok(())
}
