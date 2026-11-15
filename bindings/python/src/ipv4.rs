use pyo3::exceptions::{PyException, PyMemoryError, PyNotImplementedError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, Ipv4UnpackError, PyException);

type Fields<'py> = (
    u8,
    u8,
    u16,
    u16,
    u16,
    u8,
    u8,
    u16,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
);

fn error(error: octetrail::ipv4::Error) -> PyErr {
    use octetrail::ipv4::Error;
    match error {
        error @ Error::Truncated { .. } => super::TruncatedError::new_err(error.to_string()),
        Error::InvalidHeaderLength => Ipv4UnpackError::new_err(error.to_string()),
        error @ (Error::UnsupportedVersion(_)
        | Error::OptionsUnsupported
        | Error::OffloadLengthUnsupported) => PyNotImplementedError::new_err(error.to_string()),
        Error::Allocation => PyMemoryError::new_err(error.to_string()),
        error => PyValueError::new_err(error.to_string()),
    }
}

fn header(fields: Fields<'_>) -> octetrail::ipv4::Header {
    fn address(bytes: &[u8]) -> [u8; 4] {
        let mut output = [0; 4];
        let n = bytes.len().min(4);
        output[..n].copy_from_slice(&bytes[..n]);
        output
    }
    octetrail::ipv4::Header {
        version_ihl: fields.0,
        tos: fields.1,
        total_length: fields.2,
        id: fields.3,
        flags_offset: fields.4,
        ttl: fields.5,
        protocol: fields.6,
        checksum: fields.7,
        src: address(fields.8.as_bytes()),
        dst: address(fields.9.as_bytes()),
    }
}

#[pyfunction]
fn _ipv4_unpack<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyBytes>,
) -> PyResult<(Fields<'py>, Bound<'py, PyBytes>)> {
    let packet = octetrail::ipv4::Packet::parse(raw.as_bytes()).map_err(error)?;
    let h = packet.header;
    Ok((
        (
            h.version_ihl,
            h.tos,
            h.total_length,
            h.id,
            h.flags_offset,
            h.ttl,
            h.protocol,
            h.checksum,
            PyBytes::new(py, &h.src),
            PyBytes::new(py, &h.dst),
        ),
        PyBytes::new(py, packet.data),
    ))
}

#[pyfunction]
fn _ipv4_header<'py>(py: Python<'py>, fields: Fields<'py>) -> PyResult<Bound<'py, PyBytes>> {
    let raw = header(fields).to_bytes().map_err(error)?;
    Ok(PyBytes::new(py, &raw))
}

#[pyfunction]
fn _ipv4_pack<'py>(
    py: Python<'py>,
    fields: Fields<'py>,
    data: &Bound<'py, PyBytes>,
) -> PyResult<(Bound<'py, PyBytes>, u16, u16)> {
    let mut packet = octetrail::ipv4::Packet {
        header: header(fields),
        data: data.as_bytes(),
    };
    let raw = packet.to_bytes().map_err(error)?;
    Ok((
        PyBytes::new(py, &raw),
        packet.header.total_length,
        packet.header.checksum,
    ))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_ipv4_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv4_header, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv4_pack, module)?)?;
    module.add("Ipv4UnpackError", module.py().get_type::<Ipv4UnpackError>())?;
    Ok(())
}
