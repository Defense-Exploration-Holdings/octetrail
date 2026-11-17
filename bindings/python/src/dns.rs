//! Python conversion for explicitly selected bounded DNS messages.
use octetrail::dns::{self, Message, Question, Record};
use pyo3::exceptions::{PyException, PyMemoryError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, DnsFormatError, PyException);
type Q = (String, u16, u16);
type RR = (
    String,
    u16,
    u16,
    u32,
    Vec<u8>,
    Vec<String>,
    Vec<u32>,
    Vec<String>,
);
type Unpacked<'py> = (u16, u16, Vec<Q>, Vec<Vec<RR>>, Bound<'py, PyBytes>);

fn error(failure: dns::Error) -> PyErr {
    match failure {
        dns::Error::Truncated => crate::TruncatedError::new_err(failure.to_string()),
        dns::Error::Limit => crate::PacketLimitError::new_err(failure.to_string()),
        dns::Error::Allocation => PyMemoryError::new_err(failure.to_string()),
        _ => DnsFormatError::new_err(failure.to_string()),
    }
}

#[pyfunction]
fn _dns_unpack<'py>(py: Python<'py>, raw: &Bound<'py, PyBytes>) -> PyResult<Unpacked<'py>> {
    let message = Message::parse(raw.as_bytes()).map_err(error)?;
    let questions = message
        .questions
        .into_iter()
        .map(|q| (q.name, q.kind, q.class))
        .collect();
    let sections = message
        .sections
        .into_iter()
        .map(|rows| {
            rows.into_iter()
                .map(|r| {
                    (
                        r.name,
                        r.kind,
                        r.class,
                        r.ttl,
                        r.raw.to_vec(),
                        r.names,
                        r.numbers,
                        r.text,
                    )
                })
                .collect()
        })
        .collect();
    Ok((
        message.id,
        message.flags,
        questions,
        sections,
        PyBytes::new(py, message.trailing),
    ))
}

#[pyfunction]
fn _dns_pack<'py>(
    py: Python<'py>,
    id: u16,
    flags: u16,
    questions: Vec<Q>,
    sections: Vec<Vec<RR>>,
    trailing: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    if sections.len() != 3 {
        return Err(DnsFormatError::new_err(
            "DNS requires three resource sections",
        ));
    }
    let questions: Vec<_> = questions
        .into_iter()
        .map(|(name, kind, class)| Question { name, kind, class })
        .collect();
    let records: Vec<Vec<_>> = sections
        .iter()
        .map(|rows| {
            rows.iter()
                .map(|r| Record {
                    name: r.0.clone(),
                    kind: r.1,
                    class: r.2,
                    ttl: r.3,
                    raw: &r.4,
                    names: r.5.clone(),
                    numbers: r.6.clone(),
                    text: r.7.clone(),
                })
                .collect()
        })
        .collect();
    let raw = dns::encode(
        id,
        flags,
        &questions,
        [&records[0], &records[1], &records[2]],
        trailing.as_bytes(),
    )
    .map_err(error)?;
    Ok(PyBytes::new(py, &raw))
}

#[pyfunction]
fn _dns_header(
    py: Python<'_>,
    id: u16,
    flags: u16,
    counts: [usize; 4],
) -> PyResult<Bound<'_, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &dns::header(id, flags, counts).map_err(error)?,
    ))
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_dns_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_header, module)?)?;
    module.add("DnsFormatError", module.py().get_type::<DnsFormatError>())?;
    Ok(())
}
