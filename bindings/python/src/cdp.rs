//! Conversion for the CDP and DTP cores. Offsets index the bytes that were
//! passed in.
use octetrail::{cdp, dtp};
use pyo3::prelude::*;

pyo3::create_exception!(_native, CdpShortTlvError, pyo3::exceptions::PyException);
pyo3::create_exception!(_native, DtpShortTlvError, pyo3::exceptions::PyException);

type CdpRow = (u16, u16, Option<u32>, usize, usize);

/// `(type, len, addresses, data_start, data_end)` for each CDP entry from
/// `start`. A cut-off entry header raises `CdpShortTlvError(have, need)`.
#[pyfunction]
fn _cdp_tlvs(buf: &[u8], start: usize) -> PyResult<Vec<CdpRow>> {
    let found = cdp::tlvs(buf, start)
        .map_err(|short| CdpShortTlvError::new_err((short.have, short.need)))?;
    Ok(found
        .iter()
        .map(|t| (t.kind, t.len, t.addresses, t.data.0, t.data.1))
        .collect())
}

/// `(type, value_start, value_end)` for each DTP entry from `start`. A cut-off
/// entry header raises `DtpShortTlvError(have)`.
#[pyfunction]
fn _dtp_tlvs(buf: &[u8], start: usize) -> PyResult<Vec<(u16, usize, usize)>> {
    let found = dtp::tlvs(buf, start).map_err(|short| DtpShortTlvError::new_err(short.have))?;
    Ok(found.iter().map(|(t, (s, e))| (*t, *s, *e)).collect())
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_cdp_tlvs, module)?)?;
    module.add_function(wrap_pyfunction!(_dtp_tlvs, module)?)?;
    module.add(
        "CdpShortTlvError",
        module.py().get_type::<CdpShortTlvError>(),
    )?;
    module.add(
        "DtpShortTlvError",
        module.py().get_type::<DtpShortTlvError>(),
    )?;
    Ok(())
}
