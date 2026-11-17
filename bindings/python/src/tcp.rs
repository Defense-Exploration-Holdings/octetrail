//! Python conversion for the TCP core.

use octetrail::tcp::{parse_options, Error, Header};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, TCPHeaderError, PyValueError);

type ParsedOption<'py> = Option<(u8, Bound<'py, PyBytes>)>;

/// Where the options of a segment end and its payload starts, as dpkt 1.9.8
/// slices them: at the data offset, cut to the bytes present.
#[pyfunction]
fn _tcp_layout(bytes: &Bound<'_, PyBytes>) -> PyResult<usize> {
    let raw = bytes.as_bytes();
    match Header::parse(raw) {
        Ok(header) => Ok(header.header_len().min(raw.len())),
        Err(error @ Error::TruncatedHeader { .. }) => {
            Err(crate::TruncatedError::new_err(error.to_string()))
        }
        Err(error) => Err(TCPHeaderError::new_err(error.to_string())),
    }
}

#[pyfunction]
fn _tcp_parse_opts<'py>(py: Python<'py>, bytes: &[u8]) -> Vec<ParsedOption<'py>> {
    parse_options(bytes)
        .into_iter()
        .map(|option| option.map(|(kind, data)| (kind, PyBytes::new(py, data))))
        .collect()
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_tcp_layout, module)?)?;
    module.add_function(wrap_pyfunction!(_tcp_parse_opts, module)?)?;
    module.add("TCPHeaderError", module.py().get_type::<TCPHeaderError>())?;
    Ok(())
}
