//! Python conversion for HTTP/1.x messages parsed the way dpkt does.
use octetrail::http::{self, BodyMode, Headers};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
pyo3::create_exception!(_native, HttpFormatError, PyException);
pyo3::create_exception!(_native, HttpOverflowError, PyException);

fn error(e: http::Error) -> PyErr {
    match e {
        http::Error::NeedData(_) => crate::TruncatedError::new_err(e.to_string()),
        http::Error::Overflow => HttpOverflowError::new_err(e.to_string()),
        _ => HttpFormatError::new_err(e.to_string()),
    }
}

#[pyfunction]
fn _http_parse_headers(raw: &[u8]) -> PyResult<(Headers, usize)> {
    http::parse_headers(raw).map_err(error)
}

/// A chunked body and the number of bytes it used.
#[pyfunction]
fn _http_parse_chunked<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<(Bound<'py, PyBytes>, usize)> {
    let (body, used) = http::parse_body(raw, BodyMode::Chunked).map_err(error)?;
    Ok((PyBytes::new(py, &body), used))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("HttpFormatError", module.py().get_type::<HttpFormatError>())?;
    module.add(
        "HttpOverflowError",
        module.py().get_type::<HttpOverflowError>(),
    )?;
    module.add_function(wrap_pyfunction!(_http_parse_headers, module)?)?;
    module.add_function(wrap_pyfunction!(_http_parse_chunked, module)?)?;
    Ok(())
}
