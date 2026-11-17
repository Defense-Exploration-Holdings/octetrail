//! Conversion for the GRE core. Offsets index the bytes that were passed in.
use octetrail::gre::{self, Error, Range};
use pyo3::prelude::*;

pyo3::create_exception!(_native, GreShortOptionsError, pyo3::exceptions::PyException);
pyo3::create_exception!(_native, GreShortSreError, pyo3::exceptions::PyException);

/// `(options, sres, payload)` for a GRE packet. A short option block raises
/// `GreShortOptionsError` and a short source route entry `GreShortSreError(have)`.
#[pyfunction]
fn _gre_layout(buf: &[u8]) -> PyResult<(Vec<u32>, Vec<Range>, usize)> {
    match gre::layout(buf) {
        Ok(found) => Ok((found.options, found.sres, found.payload)),
        Err(Error::ShortSre { have }) => Err(GreShortSreError::new_err(have)),
        Err(Error::ShortHeader { have }) => Err(super::TruncatedError::new_err(format!(
            "got {have}, {} needed at least",
            gre::HEADER_LEN
        ))),
        Err(Error::ShortOptions) => Err(GreShortOptionsError::new_err(())),
    }
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_gre_layout, module)?)?;
    module.add(
        "GreShortOptionsError",
        module.py().get_type::<GreShortOptionsError>(),
    )?;
    module.add(
        "GreShortSreError",
        module.py().get_type::<GreShortSreError>(),
    )?;
    Ok(())
}
