//! Conversion for the RIP core. Offsets index the bytes that were passed in.
use octetrail::rip;
use pyo3::prelude::*;

pyo3::create_exception!(_native, RipShortEntryError, pyo3::exceptions::PyException);

/// `(start, is_auth)` for each RIP entry from `start`. A cut-off last entry
/// raises `RipShortEntryError(have)`.
#[pyfunction]
fn _rip_entries(buf: &[u8], start: usize) -> PyResult<Vec<(usize, bool)>> {
    rip::entries(buf, start).map_err(|short| RipShortEntryError::new_err(short.have))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_rip_entries, module)?)?;
    module.add(
        "RipShortEntryError",
        module.py().get_type::<RipShortEntryError>(),
    )?;
    Ok(())
}
