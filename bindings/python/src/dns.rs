//! Python conversion for DNS names. The messages are walked in Python, as
//! in dpkt, so that subclasses can replace each step.
use octetrail::dns;
use pyo3::exceptions::{PyException, PyMemoryError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

pyo3::create_exception!(_native, DnsFormatError, PyException);
pyo3::create_exception!(_native, DnsLabelError, PyException);
pyo3::create_exception!(_native, DnsPointerError, PyException);

fn error(failure: dns::Error) -> PyErr {
    match failure {
        dns::Error::NeedData => crate::TruncatedError::new_err(failure.to_string()),
        dns::Error::Limit => crate::PacketLimitError::new_err(failure.to_string()),
        dns::Error::Allocation => PyMemoryError::new_err(failure.to_string()),
        _ => DnsFormatError::new_err(failure.to_string()),
    }
}

/// `pack_name` over the UTF-8 name, looking suffixes up in `label_ptrs` and
/// adding the new ones. A label over 255 bytes raises
/// `DnsLabelError(length)` and a pointer over 16 bits `DnsPointerError(value)`.
#[pyfunction]
fn _dns_pack_name<'py>(
    py: Python<'py>,
    name: &[u8],
    offset: usize,
    pointers: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyBytes>> {
    let found = dns::pack_name_with(
        name,
        offset,
        |key| match pointers.get_item(PyBytes::new(py, key))? {
            Some(value) => value.extract::<usize>().map(Some),
            None => Ok(None),
        },
        |key, at| pointers.set_item(PyBytes::new(py, &key), at),
    );
    match found {
        Ok(raw) => Ok(PyBytes::new(py, &raw)),
        Err(dns::PackNameError::Label(n)) => Err(DnsLabelError::new_err(n)),
        Err(dns::PackNameError::Pointer(n)) => Err(DnsPointerError::new_err(n)),
        Err(dns::PackNameError::Lookup(error)) => Err(error),
    }
}

/// `unpack_name` without the UTF-8 decoding: `(labels joined by dots, next
/// offset, steps left, bytes left)`, charging the budget passed in.
#[pyfunction]
fn _dns_unpack_name<'py>(
    py: Python<'py>,
    buf: &[u8],
    offset: usize,
    steps: usize,
    bytes: usize,
) -> PyResult<(Bound<'py, PyBytes>, usize, usize, usize)> {
    let mut budget = dns::Budget { steps, bytes };
    let (raw, next) = dns::unpack_name_raw(buf, offset, &mut budget).map_err(error)?;
    Ok((PyBytes::new(py, &raw), next, budget.steps, budget.bytes))
}

/// `(start, end)` of each TXT or HINFO character string.
#[pyfunction]
fn _dns_text(raw: &[u8]) -> Vec<(usize, usize)> {
    dns::text_ranges(raw)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_dns_pack_name, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_unpack_name, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_text, module)?)?;
    module.add("DnsFormatError", module.py().get_type::<DnsFormatError>())?;
    module.add("DnsLabelError", module.py().get_type::<DnsLabelError>())?;
    module.add("DnsPointerError", module.py().get_type::<DnsPointerError>())?;
    Ok(())
}
