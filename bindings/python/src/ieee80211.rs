//! Conversion for the IEEE 802.11 and radiotap walks. Offsets index the bytes that were passed in.
use octetrail::ieee80211;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
pyo3::create_exception!(_native, RadiotapPresentError, PyException);

/// The start of each information element in `data`.
#[pyfunction]
fn _ieee80211_ie_starts(data: &[u8]) -> Vec<usize> {
    ieee80211::ie_starts(data)
}

/// The length of the radiotap present flags at the start of `data`. When the
/// bytes end first, RadiotapPresentError carries the flag byte dpkt reads.
#[pyfunction]
fn _radiotap_present_len(data: &[u8]) -> PyResult<usize> {
    ieee80211::present_len(data).map_err(|e| RadiotapPresentError::new_err(e.index))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "RadiotapPresentError",
        module.py().get_type::<RadiotapPresentError>(),
    )?;
    module.add_function(wrap_pyfunction!(_ieee80211_ie_starts, module)?)?;
    module.add_function(wrap_pyfunction!(_radiotap_present_len, module)?)?;
    Ok(())
}
