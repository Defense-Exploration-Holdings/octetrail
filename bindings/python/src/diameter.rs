//! Conversion for the Diameter AVP walk. Offsets index the bytes passed in.
use octetrail::diameter;
use pyo3::prelude::*;

/// `([(start, stop or None)], offset of a failing AVP or None)`.
#[pyfunction]
fn _diameter_avp_spans(data: &[u8]) -> (Vec<(usize, Option<usize>)>, Option<usize>) {
    let found = diameter::avps(data);
    let spans = found.spans.into_iter().map(|s| (s.start, s.stop)).collect();
    (spans, found.fails_at)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_diameter_avp_spans, module)?)?;
    Ok(())
}
