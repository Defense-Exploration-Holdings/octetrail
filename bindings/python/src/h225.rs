//! Conversion for the H.225.0 element walk. Offsets index the bytes passed in.
use octetrail::h225;
use pyo3::prelude::*;

/// `(spans, cut)`: `(start, end)` of each whole information element, and the
/// start of an element whose length is cut off, if any.
#[pyfunction]
fn _h225_elements(buf: &[u8]) -> (Vec<(usize, usize)>, Option<usize>) {
    let found = h225::elements(buf);
    (found.spans, found.cut)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_h225_elements, module)?)?;
    Ok(())
}
