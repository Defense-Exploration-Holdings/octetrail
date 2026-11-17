//! Python conversion for DNS messages.
use octetrail::dns::{self, Entry, Message, Question, Rdata};
use pyo3::exceptions::{PyException, PyMemoryError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;

pyo3::create_exception!(_native, DnsFormatError, PyException);
pyo3::create_exception!(_native, DnsPackError, PyException);
type Q = (String, u16, u16);
type RR<'py> = (
    String,
    u16,
    u16,
    u32,
    u16,
    Bound<'py, PyBytes>,
    Vec<String>,
    Vec<u32>,
    Vec<String>,
);
type Unpacked<'py> = (u16, u16, Vec<Q>, Vec<Vec<RR<'py>>>);
/// (name, type, class, ttl, kind of rdata, raw bytes, names, numbers, text).
/// The kind is "raw", "name", "soa", "mx", "srv" or "text".
type PackedRR = (
    String,
    u16,
    u16,
    u32,
    String,
    Vec<u8>,
    Vec<String>,
    Vec<u32>,
    Vec<Vec<u8>>,
);

fn error(failure: dns::Error) -> PyErr {
    match failure {
        dns::Error::NeedData => crate::TruncatedError::new_err(failure.to_string()),
        dns::Error::Limit => crate::PacketLimitError::new_err(failure.to_string()),
        dns::Error::Allocation => PyMemoryError::new_err(failure.to_string()),
        dns::Error::Pack(_) => DnsPackError::new_err(failure.to_string()),
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
                        r.rlen,
                        PyBytes::new(py, r.raw),
                        r.names,
                        r.numbers,
                        r.text,
                    )
                })
                .collect()
        })
        .collect();
    Ok((message.id, message.flags, questions, sections))
}

fn pack_error(reason: &'static str) -> PyErr {
    DnsPackError::new_err(reason)
}

fn entry(r: &PackedRR) -> PyResult<Entry<'_>> {
    let (name, kind, class, ttl, form, raw, names, numbers, text) = r;
    let one = |i: usize| -> PyResult<String> {
        names
            .get(i)
            .cloned()
            .ok_or_else(|| pack_error("missing DNS name"))
    };
    let small = |n: u32| u16::try_from(n).map_err(|_| pack_error("DNS field out of range"));
    let rdata = match form.as_str() {
        "raw" => Rdata::Raw(raw),
        "name" => Rdata::Name(one(0)?),
        "soa" => Rdata::Soa {
            mname: one(0)?,
            rname: one(1)?,
            numbers: numbers
                .as_slice()
                .try_into()
                .map_err(|_| pack_error("SOA needs five numbers"))?,
        },
        "mx" => Rdata::Mx {
            preference: small(
                *numbers
                    .first()
                    .ok_or_else(|| pack_error("missing preference"))?,
            )?,
            name: one(0)?,
        },
        "srv" => {
            if numbers.len() != 3 {
                return Err(pack_error("SRV needs three numbers"));
            }
            Rdata::Srv {
                numbers: [small(numbers[0])?, small(numbers[1])?, small(numbers[2])?],
                name: one(0)?,
            }
        }
        "text" => Rdata::Text(text.clone()),
        _ => return Err(pack_error("unknown DNS rdata form")),
    };
    Ok(Entry {
        name: name.clone(),
        kind: *kind,
        class: *class,
        ttl: *ttl,
        rdata,
    })
}

#[pyfunction]
fn _dns_pack(
    py: Python<'_>,
    id: u16,
    flags: u16,
    questions: Vec<Q>,
    sections: Vec<Vec<PackedRR>>,
) -> PyResult<Bound<'_, PyBytes>> {
    if sections.len() != 3 {
        return Err(pack_error("DNS requires three resource sections"));
    }
    let questions: Vec<_> = questions
        .into_iter()
        .map(|(name, kind, class)| Question { name, kind, class })
        .collect();
    let records = sections
        .iter()
        .map(|rows| rows.iter().map(entry).collect::<PyResult<Vec<_>>>())
        .collect::<PyResult<Vec<_>>>()?;
    let raw = dns::encode(
        id,
        flags,
        &questions,
        [&records[0], &records[1], &records[2]],
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

/// `pack_name(name, off, label_ptrs)`: the dictionary maps upper-cased suffix
/// bytes to offsets and gains the suffixes this name adds.
#[pyfunction]
fn _dns_pack_name<'py>(
    py: Python<'py>,
    name: &str,
    offset: usize,
    pointers: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut known = HashMap::new();
    for (key, value) in pointers.iter() {
        if let (Ok(key), Ok(value)) = (key.extract::<Vec<u8>>(), value.extract::<usize>()) {
            known.insert(key, value);
        }
    }
    let before = known.clone();
    let raw = dns::pack_name(name, offset, &mut known).map_err(error)?;
    for (key, value) in known {
        if !before.contains_key(&key) {
            pointers.set_item(PyBytes::new(py, &key), value)?;
        }
    }
    Ok(PyBytes::new(py, &raw))
}

#[pyfunction]
fn _dns_unpack_name(buf: &[u8], offset: usize) -> PyResult<(String, usize)> {
    dns::unpack_name(buf, offset).map_err(error)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_dns_unpack, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_pack, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_header, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_pack_name, module)?)?;
    module.add_function(wrap_pyfunction!(_dns_unpack_name, module)?)?;
    module.add("DnsFormatError", module.py().get_type::<DnsFormatError>())?;
    module.add("DnsPackError", module.py().get_type::<DnsPackError>())?;
    Ok(())
}
