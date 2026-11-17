//! Conversion for the RADIUS and STUN attribute cores. Offsets index the
//! bytes that were passed in.
use octetrail::{radius, stun};
use pyo3::prelude::*;

pyo3::create_exception!(_native, RadiusShortAttrError, pyo3::exceptions::PyException);
pyo3::create_exception!(_native, StunShortAttrError, pyo3::exceptions::PyException);

/// `(type, start, end)` for each RADIUS attribute. A single byte left at the
/// end raises `RadiusShortAttrError(at)`.
#[pyfunction]
fn _radius_attrs(buf: &[u8]) -> PyResult<Vec<(u8, usize, usize)>> {
    radius::attrs(buf).map_err(|short| RadiusShortAttrError::new_err(short.at))
}

/// `(type, length, start, end)` for each STUN attribute. A cut-off attribute
/// header raises `StunShortAttrError(at)`.
#[pyfunction]
fn _stun_attrs(buf: &[u8]) -> PyResult<Vec<(u16, u16, usize, usize)>> {
    stun::attrs(buf).map_err(|short| StunShortAttrError::new_err(short.at))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_radius_attrs, module)?)?;
    module.add_function(wrap_pyfunction!(_stun_attrs, module)?)?;
    module.add(
        "RadiusShortAttrError",
        module.py().get_type::<RadiusShortAttrError>(),
    )?;
    module.add(
        "StunShortAttrError",
        module.py().get_type::<StunShortAttrError>(),
    )?;
    Ok(())
}
