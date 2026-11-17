//! Conversion for the Ethernet core. Offsets index the bytes that were passed in.
use octetrail::ethernet::{self, Error, Frame, Kind, Llc, Range, Stack};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

pyo3::create_exception!(_native, EthernetShortError, PyException);
pyo3::create_exception!(_native, EthernetStructError, PyException);
pyo3::create_exception!(_native, EthernetIndexError, PyException);

fn error(e: Error) -> PyErr {
    match e {
        Error::Short { have, need } => EthernetShortError::new_err((have, need)),
        Error::Struct => EthernetStructError::new_err(e.to_string()),
        Error::Index => EthernetIndexError::new_err(e.to_string()),
    }
}

type FrameRow = (
    Option<usize>,
    usize,
    u16,
    &'static str,
    Option<Range>,
    Option<Range>,
    Option<u32>,
    Option<Range>,
);

/// `(isl, header, type, kind, llc, padding, fcs, trailer)`.
#[pyfunction]
fn _ethernet_frame(raw: &[u8]) -> PyResult<FrameRow> {
    let f = Frame::parse(raw).map_err(error)?;
    let (kind, llc, padding, fcs, trailer) = match f.kind {
        Kind::Typed => ("typed", None, None, None, None),
        Kind::Novell => ("novell", None, None, None, None),
        Kind::Unknown => ("unknown", None, None, None, None),
        Kind::Llc {
            llc,
            padding,
            fcs,
            trailer,
        } => ("llc", Some(llc), padding, fcs, trailer),
    };
    Ok((
        f.isl,
        f.header,
        f.ethertype,
        kind,
        llc,
        padding,
        fcs,
        trailer,
    ))
}

/// `(tags, labels, next, payload)` for the stack that `next` announces.
#[pyfunction]
fn _ethernet_stack(raw: &[u8], next: u16) -> PyResult<(Vec<usize>, Vec<usize>, u16, usize)> {
    let s = Stack::parse(raw, next).map_err(error)?;
    Ok((s.tags, s.labels, s.next, s.payload))
}

type LlcRow = (u8, u8, u8, Option<(u32, u16)>, usize);

/// `(dsap, ssap, ctl, snap, payload)`, with `snap` as `(oui, type)`.
#[pyfunction]
fn _llc(raw: &[u8]) -> PyResult<LlcRow> {
    let l = Llc::parse(raw).map_err(error)?;
    Ok((l.dsap, l.ssap, l.ctl, l.snap, l.payload))
}

#[pyfunction]
fn _crc32(raw: &[u8]) -> u32 {
    ethernet::crc32(raw)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_ethernet_frame, module)?)?;
    module.add_function(wrap_pyfunction!(_ethernet_stack, module)?)?;
    module.add_function(wrap_pyfunction!(_llc, module)?)?;
    module.add_function(wrap_pyfunction!(_crc32, module)?)?;
    let py = module.py();
    module.add("EthernetShortError", py.get_type::<EthernetShortError>())?;
    module.add("EthernetStructError", py.get_type::<EthernetStructError>())?;
    module.add("EthernetIndexError", py.get_type::<EthernetIndexError>())?;
    Ok(())
}
