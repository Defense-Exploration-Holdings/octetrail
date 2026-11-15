//! Python conversion for the independent fixed-header TCP core.

use octetrail::tcp::{Error, Header, Limits, Segment};
use pyo3::exceptions::{PyMemoryError, PyNotImplementedError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, TCPHeaderError, PyValueError);

type Fields = (u16, u16, u32, u32, u8, u8, u16, u16, u16);

fn python_error(error: Error) -> PyErr {
    match error {
        error @ Error::TruncatedHeader { .. } => crate::TruncatedError::new_err(error.to_string()),
        error @ Error::InvalidDataOffset { .. } => TCPHeaderError::new_err(error.to_string()),
        error @ (Error::OptionsUnsupported { .. } | Error::ReservedBitsUnsupported { .. }) => {
            PyNotImplementedError::new_err(error.to_string())
        }
        error @ Error::SegmentLimit { .. } => crate::PacketLimitError::new_err(error.to_string()),
        Error::LengthOverflow => PyValueError::new_err(error.to_string()),
        Error::Allocation => PyMemoryError::new_err(error.to_string()),
    }
}

fn header(fields: Fields) -> Header {
    let (sport, dport, seq, ack, off, flags, win, checksum, urp) = fields;
    Header {
        sport,
        dport,
        seq,
        ack,
        off,
        flags,
        win,
        checksum,
        urp,
    }
}

#[pyfunction]
fn _tcp_unpack<'py>(
    py: Python<'py>,
    bytes: &Bound<'py, PyBytes>,
) -> PyResult<(Fields, Bound<'py, PyBytes>)> {
    let segment = Segment::parse(bytes.as_bytes(), Limits::default()).map_err(python_error)?;
    let h = segment.header;
    Ok((
        (
            h.sport, h.dport, h.seq, h.ack, h.off, h.flags, h.win, h.checksum, h.urp,
        ),
        PyBytes::new(py, segment.data),
    ))
}

#[pyfunction]
fn _tcp_header(py: Python<'_>, fields: Fields) -> PyResult<Bound<'_, PyBytes>> {
    let bytes = header(fields).to_bytes().map_err(python_error)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn _tcp_pack<'py>(
    py: Python<'py>,
    fields: Fields,
    payload: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = Segment {
        header: header(fields),
        data: payload.as_bytes(),
    }
    .to_bytes(Limits::default())
    .map_err(python_error)?;
    Ok(PyBytes::new(py, &bytes))
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_tcp_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_tcp_header, module)?)?;
    module.add_function(wrap_pyfunction!(_tcp_pack, module)?)?;
    module.add("TCPHeaderError", module.py().get_type::<TCPHeaderError>())?;
    Ok(())
}
