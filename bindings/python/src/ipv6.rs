//! Conversion for the bounded IPv6 core.
use octetrail::ipv6::{self, Extension, Header, Limits};
use pyo3::exceptions::{PyException, PyMemoryError, PyNotImplementedError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, Ipv6PackError, PyException);
type Fields<'py> = (u32, u16, u8, u8, Bound<'py, PyBytes>, Bound<'py, PyBytes>);
type Extensions<'py> = Vec<(u8, Bound<'py, PyBytes>)>;
type Unpacked<'py> = (
    Fields<'py>,
    Extensions<'py>,
    Bound<'py, PyBytes>,
    u8,
    bool,
    &'static str,
);

fn error(failure: ipv6::Error) -> PyErr {
    match failure {
        ipv6::Error::TruncatedHeader => crate::TruncatedError::new_err(failure.to_string()),
        ipv6::Error::UnsupportedVersion(_) => PyNotImplementedError::new_err(failure.to_string()),
        ipv6::Error::Limit => crate::PacketLimitError::new_err(failure.to_string()),
        ipv6::Error::Allocation => PyMemoryError::new_err(failure.to_string()),
        ipv6::Error::InvalidExtension => Ipv6PackError::new_err(failure.to_string()),
    }
}

fn header(fields: Fields<'_>) -> Header {
    fn address(bytes: &[u8]) -> [u8; 16] {
        let mut out = [0; 16];
        let n = bytes.len().min(16);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }
    Header {
        version_class_flow: fields.0,
        payload_length: fields.1,
        next_header: fields.2,
        hop_limit: fields.3,
        src: address(fields.4.as_bytes()),
        dst: address(fields.5.as_bytes()),
    }
}

#[pyfunction]
fn _ipv6_unpack<'py>(py: Python<'py>, raw: &Bound<'py, PyBytes>) -> PyResult<Unpacked<'py>> {
    let packet = ipv6::Packet::parse(raw.as_bytes(), Limits::default()).map_err(error)?;
    let h = packet.header;
    Ok((
        (
            h.version_class_flow,
            h.payload_length,
            h.next_header,
            h.hop_limit,
            PyBytes::new(py, &h.src),
            PyBytes::new(py, &h.dst),
        ),
        packet
            .extensions
            .iter()
            .map(|e| (e.kind, PyBytes::new(py, e.bytes)))
            .collect(),
        PyBytes::new(py, packet.data),
        packet.protocol,
        packet.fragmented,
        packet.status,
    ))
}

#[pyfunction]
fn _ipv6_pack<'py>(
    py: Python<'py>,
    fields: Fields<'py>,
    extensions: Extensions<'py>,
    payload: &Bound<'py, PyBytes>,
) -> PyResult<(Bound<'py, PyBytes>, u8, bool, bool)> {
    let extensions: Vec<_> = extensions
        .iter()
        .map(|(kind, bytes)| Extension {
            kind: *kind,
            bytes: bytes.as_bytes(),
        })
        .collect();
    let (raw, protocol, fragmented, checksum_supported) = ipv6::encode(
        header(fields),
        &extensions,
        payload.as_bytes(),
        Limits::default(),
    )
    .map_err(error)?;
    Ok((
        PyBytes::new(py, &raw),
        protocol,
        fragmented,
        checksum_supported,
    ))
}

#[pyfunction]
fn _ipv6_header<'py>(py: Python<'py>, fields: Fields<'py>) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &header(fields).to_bytes().map_err(error)?))
}

#[pyfunction]
fn _ipv6_checksum(fields: Fields<'_>, protocol: u8, payload: &Bound<'_, PyBytes>) -> PyResult<u16> {
    let h = header(fields);
    ipv6::transport_checksum(h.src, h.dst, protocol, payload.as_bytes()).map_err(error)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_ipv6_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv6_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv6_header, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv6_checksum, module)?)?;
    module.add("Ipv6PackError", module.py().get_type::<Ipv6PackError>())?;
    Ok(())
}
