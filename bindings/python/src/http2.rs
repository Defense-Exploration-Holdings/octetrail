//! Conversion for the HTTP/2 frame walk. Offsets index the bytes passed in.
use octetrail::http2;
use pyo3::prelude::*;

/// `([(start, end)], tail)` for the whole frames from `start`.
#[pyfunction]
fn _http2_frame_spans(data: &[u8], start: usize) -> (Vec<(usize, usize)>, usize) {
    let found = http2::frames(data, start);
    (found.spans, found.tail)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_http2_frame_spans, module)?)?;
    Ok(())
}
