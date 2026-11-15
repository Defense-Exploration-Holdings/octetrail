//! Conversion for the independent offline UDP core.

use octetrail::udp::{Datagram, Error, Header, Limits};
use pyo3::exceptions::{PyMemoryError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

type Fields = (u16, u16, u16, u16);

fn python_error(error: Error) -> PyErr {
    match error {
        error @ Error::TruncatedHeader { .. } => crate::TruncatedError::new_err(error.to_string()),
        error @ Error::DatagramLimit { .. } => crate::PacketLimitError::new_err(error.to_string()),
        Error::LengthOverflow => PyValueError::new_err(error.to_string()),
        Error::Allocation => PyMemoryError::new_err(error.to_string()),
    }
}

fn header((sport, dport, ulen, checksum): Fields) -> Header {
    Header {
        sport,
        dport,
        ulen,
        checksum,
    }
}

#[pyfunction]
fn _udp_unpack<'py>(
    py: Python<'py>,
    bytes: &Bound<'py, PyBytes>,
) -> PyResult<(Fields, Bound<'py, PyBytes>)> {
    let datagram = Datagram::parse(bytes.as_bytes(), Limits::default()).map_err(python_error)?;
    let h = datagram.header;
    Ok((
        (h.sport, h.dport, h.ulen, h.checksum),
        PyBytes::new(py, datagram.data),
    ))
}

#[pyfunction]
fn _udp_header(py: Python<'_>, fields: Fields) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &header(fields).to_bytes())
}

#[pyfunction]
fn _udp_pack<'py>(
    py: Python<'py>,
    fields: Fields,
    payload: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = Datagram {
        header: header(fields),
        data: payload.as_bytes(),
    }
    .to_bytes(Limits::default())
    .map_err(python_error)?;
    Ok(PyBytes::new(py, &bytes))
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_udp_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_udp_header, module)?)?;
    module.add_function(wrap_pyfunction!(_udp_pack, module)?)?;
    Ok(())
}
