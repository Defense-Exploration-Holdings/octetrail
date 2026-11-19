//! Conversion for the IPv6 core. Ranges index the bytes that were passed in.
use octetrail::ipv6::{self, Body, Extension, Packet};
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};

pyo3::create_exception!(_native, Ipv6ShortError, PyException);
pyo3::create_exception!(_native, Ipv6OptionsError, PyException);
pyo3::create_exception!(_native, Ipv6OptionLengthError, PyException);

type Range = (usize, usize);
type Fields<'py> = (u32, u16, u8, u8, Bound<'py, PyBytes>, Bound<'py, PyBytes>);

fn error(failure: ipv6::Error) -> PyErr {
    match failure {
        ipv6::Error::Short(have, need) => Ipv6ShortError::new_err((have, need)),
        ipv6::Error::Options => Ipv6OptionsError::new_err(()),
        ipv6::Error::OptionLength => Ipv6OptionLengthError::new_err(()),
        ipv6::Error::NotExtension(_) => PyValueError::new_err("not an IPv6 extension header"),
    }
}

/// (kind, fields, data range, length, extra), where extra is a list of
/// (type, length, start, end) options, a list of address ranges, the
/// auth_data range, or None.
fn extension<'py>(py: Python<'py>, ext: &Extension) -> PyResult<Bound<'py, PyTuple>> {
    let extra = match &ext.body {
        Body::Options(found) => PyList::new(
            py,
            found.iter().map(|o| (o.kind, o.length, o.data.0, o.data.1)),
        )?
        .into_any(),
        Body::Routing(slots) => PyList::new(py, slots)?.into_any(),
        Body::Ah(auth) => auth.into_pyobject(py)?.into_any(),
        Body::Fragment | Body::Esp => py.None().into_bound(py),
    };
    (ext.kind, ext.fields.clone(), ext.data, ext.length, extra).into_pyobject(py)
}

#[pyfunction]
fn _ipv6_extension<'py>(py: Python<'py>, kind: u8, raw: &[u8]) -> PyResult<Bound<'py, PyTuple>> {
    extension(py, &Extension::parse(kind, raw).map_err(error)?)
}

type Unpacked<'py> = (
    Fields<'py>,
    Vec<Bound<'py, PyTuple>>,
    Range,
    Option<u8>,
    Option<PyErr>,
);

#[pyfunction]
fn _ipv6_unpack<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Unpacked<'py>> {
    let packet = Packet::parse(raw).map_err(error)?;
    let h = packet.header;
    let extensions = packet
        .extensions
        .iter()
        .map(|e| extension(py, e))
        .collect::<PyResult<_>>()?;
    Ok((
        (
            h.v_fc_flow,
            h.plen,
            h.nxt,
            h.hlim,
            PyBytes::new(py, &h.src),
            PyBytes::new(py, &h.dst),
        ),
        extensions,
        packet.rest,
        packet.next,
        packet.error.map(error),
    ))
}

#[pyfunction]
fn _ipv6_checksum(pseudo: &[u8], payload: &[u8]) -> PyResult<u16> {
    if pseudo.len() % 2 != 0 {
        return Err(PyValueError::new_err(
            "the pseudo-header must have an even length",
        ));
    }
    Ok(ipv6::checksum(&[pseudo, payload]))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_ipv6_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv6_extension, module)?)?;
    module.add_function(wrap_pyfunction!(_ipv6_checksum, module)?)?;
    module.add("Ipv6ShortError", module.py().get_type::<Ipv6ShortError>())?;
    module.add(
        "Ipv6OptionsError",
        module.py().get_type::<Ipv6OptionsError>(),
    )?;
    module.add(
        "Ipv6OptionLengthError",
        module.py().get_type::<Ipv6OptionLengthError>(),
    )?;
    Ok(())
}
