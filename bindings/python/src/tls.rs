//! Explicit passive TLS envelope and metadata bindings.
use octetrail::tls::{self, Handshake, Record, ServerHello};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
pyo3::create_exception!(_native, TlsFormatError, PyException);
fn error(e: tls::Error) -> PyErr {
    match e {
        tls::Error::Limit => crate::PacketLimitError::new_err(e.to_string()),
        tls::Error::Truncated => crate::TruncatedError::new_err(e.to_string()),
        _ => TlsFormatError::new_err(e.to_string()),
    }
}
#[pyfunction]
fn _tls_record<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyBytes>,
) -> PyResult<(u8, u16, Bound<'py, PyBytes>)> {
    let r = Record::parse(raw.as_bytes()).map_err(error)?;
    Ok((r.kind, r.version, PyBytes::new(py, r.data)))
}
type Spans = (Vec<(usize, usize)>, usize);
#[pyfunction]
fn _tls_records(raw: &Bound<'_, PyBytes>) -> PyResult<Spans> {
    tls::records(raw.as_bytes()).map_err(error)
}
#[pyfunction]
fn _tls_record_pack<'py>(
    py: Python<'py>,
    kind: u8,
    version: u16,
    length: u16,
    data: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &tls::record_bytes(kind, version, length, data.as_bytes()).map_err(error)?,
    ))
}
#[pyfunction]
fn _tls_handshake<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyBytes>,
) -> PyResult<(u8, Bound<'py, PyBytes>)> {
    let h = Handshake::parse(raw.as_bytes()).map_err(error)?;
    Ok((h.kind, PyBytes::new(py, h.data)))
}
#[pyfunction]
fn _tls_handshake_pack<'py>(
    py: Python<'py>,
    kind: u8,
    length: u32,
    data: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &tls::handshake_bytes(kind, length, data.as_bytes()).map_err(error)?,
    ))
}
type Extensions<'py> = Option<Vec<(u16, Bound<'py, PyBytes>)>>;
type Hello<'py> = (
    u16,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    u16,
    u8,
    Extensions<'py>,
    Bound<'py, PyBytes>,
);
#[pyfunction]
fn _tls_hello<'py>(py: Python<'py>, raw: &Bound<'py, PyBytes>) -> PyResult<Hello<'py>> {
    let h = ServerHello::parse(raw.as_bytes()).map_err(error)?;
    Ok((
        h.version,
        PyBytes::new(py, h.random),
        PyBytes::new(py, h.session_id),
        h.cipher_code,
        h.compression,
        h.extensions.map(|rows| {
            rows.into_iter()
                .map(|(k, v)| (k, PyBytes::new(py, v)))
                .collect()
        }),
        PyBytes::new(py, h.data),
    ))
}
#[pyfunction]
fn _tls_hello_pack<'py>(
    py: Python<'py>,
    version: u16,
    random: &Bound<'py, PyBytes>,
    data: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &tls::hello_bytes(version, random.as_bytes(), data.as_bytes()).map_err(error)?,
    ))
}
pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("TlsFormatError", module.py().get_type::<TlsFormatError>())?;
    module.add_function(wrap_pyfunction!(_tls_record, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_records, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_record_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_handshake, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_handshake_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_hello, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_hello_pack, module)?)?;
    Ok(())
}
