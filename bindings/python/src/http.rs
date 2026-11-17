//! Native HTTP framing with staged head/body parsing for partial Python state.
use octetrail::http::{self, Headers};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
pyo3::create_exception!(_native, HttpFormatError, PyException);
fn error(e: http::Error) -> PyErr {
    match e {
        http::Error::Limit => crate::PacketLimitError::new_err(e.to_string()),
        http::Error::Truncated => crate::TruncatedError::new_err(e.to_string()),
        _ => HttpFormatError::new_err(e.to_string()),
    }
}
#[pyfunction]
fn _http_start(raw: &Bound<'_, PyBytes>, response: bool) -> PyResult<([String; 3], usize)> {
    http::start(raw.as_bytes(), response).map_err(error)
}
#[pyfunction]
fn _http_headers(raw: &Bound<'_, PyBytes>, pos: usize) -> PyResult<(Headers, usize)> {
    http::headers(raw.as_bytes(), pos).map_err(error)
}
type Body<'py> = (Bound<'py, PyBytes>, Bound<'py, PyBytes>);
#[pyfunction]
fn _http_body<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyBytes>,
    pos: usize,
    headers: Headers,
    allowed: bool,
) -> PyResult<Body<'py>> {
    let (body, tail) = http::body(raw.as_bytes(), pos, &headers, allowed).map_err(error)?;
    Ok((PyBytes::new(py, body), PyBytes::new(py, tail)))
}
#[pyfunction]
fn _http_pack<'py>(
    py: Python<'py>,
    head: &Bound<'py, PyBytes>,
    body: &Bound<'py, PyBytes>,
    response: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let packed = http::pack(head.as_bytes(), body.as_bytes(), response).map_err(error)?;
    Ok(PyBytes::new(py, &packed))
}
#[pyfunction]
fn _http_field(name: &str, value: &str) -> PyResult<()> {
    http::validate_field(name, value).map_err(error)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("HttpFormatError", module.py().get_type::<HttpFormatError>())?;
    module.add_function(wrap_pyfunction!(_http_start, module)?)?;
    module.add_function(wrap_pyfunction!(_http_headers, module)?)?;
    module.add_function(wrap_pyfunction!(_http_body, module)?)?;
    module.add_function(wrap_pyfunction!(_http_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_http_field, module)?)?;
    Ok(())
}
