//! Python conversion for HTTP/1.x messages parsed the way dpkt does.
use octetrail::http::{self, BodyMode, Headers, Int};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
pyo3::create_exception!(_native, HttpFormatError, PyException);

fn error(e: http::Error) -> PyErr {
    match e {
        http::Error::NeedData(_) => crate::TruncatedError::new_err(e.to_string()),
        _ => HttpFormatError::new_err(e.to_string()),
    }
}

#[pyfunction]
fn _http_request_line(raw: &[u8]) -> PyResult<([String; 3], usize)> {
    http::request_line(raw).map_err(error)
}

#[pyfunction]
fn _http_response_line(raw: &[u8]) -> PyResult<([String; 3], usize)> {
    http::response_line(raw).map_err(error)
}

#[pyfunction]
fn _http_body_allowed(status: &str) -> bool {
    http::body_allowed(status)
}

/// The body for the parsed header rows and the bytes after it.
#[pyfunction]
fn _http_body<'py>(
    py: Python<'py>,
    raw: &[u8],
    headers: Headers,
    body_allowed: bool,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (body, rest) = http::body(raw, &headers, body_allowed).map_err(error)?;
    Ok((PyBytes::new(py, &body), PyBytes::new(py, rest)))
}

#[pyfunction]
fn _http_parse_headers(raw: &[u8]) -> PyResult<(Headers, usize)> {
    http::parse_headers(raw).map_err(error)
}

/// `mode` is "chunked", "length", "end" or "empty"; `length` is an int for "length".
#[pyfunction]
fn _http_parse_body<'py>(
    py: Python<'py>,
    raw: &[u8],
    mode: &str,
    length: i128,
) -> PyResult<(Bound<'py, PyBytes>, usize)> {
    let mode = match mode {
        "chunked" => BodyMode::Chunked,
        "length" if length < 0 => BodyMode::Length(Int::Negative),
        "length" => BodyMode::Length(Int::Value(usize::try_from(length).unwrap_or(usize::MAX))),
        "end" => BodyMode::ToEnd,
        _ => BodyMode::Empty,
    };
    let (body, used) = http::parse_body(raw, mode).map_err(error)?;
    Ok((PyBytes::new(py, &body), used))
}

#[pyfunction]
fn _http_pack<'py>(
    py: Python<'py>,
    start: &str,
    headers: &str,
    body: &[u8],
) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &http::pack(start, headers, body))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("HttpFormatError", module.py().get_type::<HttpFormatError>())?;
    module.add_function(wrap_pyfunction!(_http_request_line, module)?)?;
    module.add_function(wrap_pyfunction!(_http_response_line, module)?)?;
    module.add_function(wrap_pyfunction!(_http_body_allowed, module)?)?;
    module.add_function(wrap_pyfunction!(_http_body, module)?)?;
    module.add_function(wrap_pyfunction!(_http_parse_headers, module)?)?;
    module.add_function(wrap_pyfunction!(_http_parse_body, module)?)?;
    module.add_function(wrap_pyfunction!(_http_pack, module)?)?;
    Ok(())
}
