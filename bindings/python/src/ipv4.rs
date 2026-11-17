use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, Ipv4UnpackError, PyException);

/// Where the payload of a datagram starts and ends, as dpkt 1.9.8 slices it. The
/// options run from the end of the fixed header to the payload start.
#[pyfunction]
fn _ipv4_layout(raw: &Bound<'_, PyBytes>) -> PyResult<(usize, usize)> {
    use octetrail::ipv4::{Error, Packet, HEADER_LEN};
    match Packet::parse(raw.as_bytes()) {
        Ok(packet) => {
            let start = HEADER_LEN + packet.opts.len();
            Ok((start, start + packet.data.len()))
        }
        Err(error @ Error::Truncated { .. }) => {
            Err(super::TruncatedError::new_err(error.to_string()))
        }
        Err(error) => Err(Ipv4UnpackError::new_err(error.to_string())),
    }
}

/// Internet checksum of a buffer, in network byte order.
#[pyfunction]
fn _inet_checksum(raw: &Bound<'_, PyBytes>) -> u16 {
    octetrail::ipv4::checksum(raw.as_bytes())
}

/// TCP or UDP checksum over a packed pseudoheader and the transport bytes.
#[pyfunction]
fn _ipv4_transport_checksum(
    pseudo: &Bound<'_, PyBytes>,
    data: &Bound<'_, PyBytes>,
) -> PyResult<u16> {
    let pseudo: &[u8; 12] = pseudo
        .as_bytes()
        .try_into()
        .map_err(|_| PyValueError::new_err("pseudoheader must be 12 bytes"))?;
    Ok(octetrail::ipv4::pseudo_checksum(pseudo, data.as_bytes()))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_ipv4_layout, module)?)?;
    module.add_function(wrap_pyfunction!(_inet_checksum, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv4_transport_checksum, module)?)?;
    module.add("Ipv4UnpackError", module.py().get_type::<Ipv4UnpackError>())?;
    Ok(())
}
