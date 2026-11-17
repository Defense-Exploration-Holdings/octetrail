//! Conversion for the TLS core. Ranges index the bytes that were passed in.
use octetrail::tls::{self, Error, Hello, Range, HELLO_LEN};
use pyo3::exceptions::{PyException, PyIndexError};
use pyo3::prelude::*;

pyo3::create_exception!(_native, TlsVersionError, PyException);

fn name(error: Option<Error>) -> Option<&'static str> {
    error.map(|e| match e {
        Error::Struct => "struct",
        Error::ShortRecord => "short_record",
        Error::Version(_) => "version",
        Error::Index => "index",
    })
}

type Ext = (u16, usize, usize);
type HelloRow = (
    Option<Range>,
    Option<Vec<u16>>,
    Option<Range>,
    Option<Vec<Ext>>,
    Option<&'static str>,
);

/// The variable part of a hello in `raw`, after its 34 fixed bytes. `raw` is
/// at least 34 bytes long.
#[pyfunction]
fn _tls_hello(raw: &[u8], client: bool) -> HelloRow {
    let body = raw.get(HELLO_LEN..).unwrap_or_default();
    let hello = if client {
        Hello::client(body)
    } else {
        Hello::server(body)
    };
    let h = tls::shift_hello(hello, HELLO_LEN);
    (
        h.session_id,
        h.ciphersuites,
        h.compression,
        h.extensions
            .map(|found| found.into_iter().map(|(k, (a, b))| (k, a, b)).collect()),
        name(h.error),
    )
}

/// `(certificates, error)`. `certificates` is None when the list length is cut short.
#[pyfunction]
fn _tls_certificates(raw: &[u8]) -> (Option<Vec<Range>>, Option<&'static str>) {
    match tls::certificates(raw) {
        Ok((found, error)) => (Some(found), name(error)),
        Err(error) => (None, name(Some(error))),
    }
}

#[pyfunction]
fn _tls_extensions(raw: &[u8]) -> (Vec<Ext>, Option<&'static str>) {
    let (found, error) = tls::extensions(raw, 0);
    (
        found.into_iter().map(|(k, (a, b))| (k, a, b)).collect(),
        name(error),
    )
}

#[pyfunction]
fn _tls_records(raw: &[u8]) -> (Vec<Range>, Option<&'static str>) {
    let (spans, error) = tls::tls_records(raw);
    (spans, name(error))
}

#[pyfunction]
fn _tls_multi_factory(raw: &[u8]) -> PyResult<(Vec<Range>, usize)> {
    tls::multi_factory(raw).map_err(|e| match e {
        Error::Version(at) => TlsVersionError::new_err(at),
        other => PyException::new_err(other.to_string()),
    })
}

/// `(len, msg, pad, rest)` for the bytes after an SSLv2 header.
#[pyfunction]
fn _ssl2(len: u16, data: &[u8]) -> PyResult<(u16, Range, Option<Range>, Range)> {
    let s = tls::ssl2(len, data).map_err(|e| PyIndexError::new_err(e.to_string()))?;
    Ok((s.len, s.msg, s.pad, s.rest))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_tls_hello, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_certificates, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_extensions, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_records, module)?)?;
    module.add_function(wrap_pyfunction!(_tls_multi_factory, module)?)?;
    module.add_function(wrap_pyfunction!(_ssl2, module)?)?;
    module.add("TlsVersionError", module.py().get_type::<TlsVersionError>())?;
    Ok(())
}
