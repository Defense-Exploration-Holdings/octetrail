//! Python conversion for the TCP core.

use octetrail::tcp::{parse_options, Error, Header, Limits, Segment};
use pyo3::exceptions::{PyMemoryError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, TCPHeaderError, PyValueError);

/// sport, dport, seq, ack, _off_flags, win, sum, urp.
type Fields = (u16, u16, u32, u32, u16, u16, u16, u16);

type ParsedOption<'py> = Option<(u8, Bound<'py, PyBytes>)>;

fn python_error(error: Error) -> PyErr {
    match error {
        error @ Error::TruncatedHeader { .. } => crate::TruncatedError::new_err(error.to_string()),
        error @ Error::InvalidDataOffset { .. } => TCPHeaderError::new_err(error.to_string()),
        error @ Error::SegmentLimit { .. } => crate::PacketLimitError::new_err(error.to_string()),
        Error::LengthOverflow => PyValueError::new_err(error.to_string()),
        Error::Allocation => PyMemoryError::new_err(error.to_string()),
    }
}

fn header(fields: Fields) -> Header {
    let (sport, dport, seq, ack, off_flags, win, checksum, urp) = fields;
    Header {
        sport,
        dport,
        seq,
        ack,
        off_flags,
        win,
        checksum,
        urp,
    }
}

#[pyfunction]
fn _tcp_unpack<'py>(
    py: Python<'py>,
    bytes: &Bound<'py, PyBytes>,
) -> PyResult<(Fields, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let segment = Segment::parse(bytes.as_bytes(), Limits::default()).map_err(python_error)?;
    let h = segment.header;
    Ok((
        (
            h.sport,
            h.dport,
            h.seq,
            h.ack,
            h.off_flags,
            h.win,
            h.checksum,
            h.urp,
        ),
        PyBytes::new(py, segment.opts),
        PyBytes::new(py, segment.data),
    ))
}

#[pyfunction]
fn _tcp_header(py: Python<'_>, fields: Fields) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &header(fields).to_bytes())
}

#[pyfunction]
fn _tcp_pack<'py>(
    py: Python<'py>,
    fields: Fields,
    opts: &Bound<'py, PyBytes>,
    payload: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = Segment {
        header: header(fields),
        opts: opts.as_bytes(),
        data: payload.as_bytes(),
    }
    .to_bytes(Limits::default())
    .map_err(python_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn _tcp_parse_opts<'py>(py: Python<'py>, bytes: &[u8]) -> Vec<ParsedOption<'py>> {
    parse_options(bytes)
        .into_iter()
        .map(|option| option.map(|(kind, data)| (kind, PyBytes::new(py, data))))
        .collect()
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_tcp_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_tcp_header, module)?)?;
    module.add_function(wrap_pyfunction!(_tcp_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_tcp_parse_opts, module)?)?;
    module.add("TCPHeaderError", module.py().get_type::<TCPHeaderError>())?;
    Ok(())
}
