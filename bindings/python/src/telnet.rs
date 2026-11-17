//! Conversion for the Telnet core. Offsets index the bytes that were passed in.
use octetrail::telnet;
use pyo3::prelude::*;

type Ranges = Vec<(usize, usize)>;
type Values = Vec<(usize, usize, usize)>;

/// `(lines, options)` as `strip_options` finds them: `(start, end)` for each
/// line and `(name index, start, end)` for each suboption value.
#[pyfunction]
fn _telnet_strip(buf: &[u8]) -> (Ranges, Values) {
    let found = telnet::strip_options(buf);
    (found.lines, found.options)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_telnet_strip, module)?)?;
    Ok(())
}
