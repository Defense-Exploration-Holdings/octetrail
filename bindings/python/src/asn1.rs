//! Conversion for the ASN.1 walk. Offsets index the bytes that were passed in.
use octetrail::asn1::{self, Event, Stop};
use pyo3::prelude::*;

type Events = Vec<(u8, u8, u64, usize)>;

/// `(events, stop)` for `asn1.decode`. Each event is `(kind, identifier, a, b)`:
/// kind 0 starts a nested list, 1 ends it, 2 is an INTEGER with value `a`,
/// 3 a UTCTime and 4 other bytes, both `buf[a:b]`. `stop` is `None` or
/// `(kind, a, b)`: 0 IndexError at `a`, 1 a short `b`-byte unpack at `a`,
/// 2 a long-form length octet `a`, 3 an INTEGER length `a`, 4 the element
/// limit and 5 the depth limit.
#[pyfunction]
fn _asn1_decode(buf: &[u8]) -> (Events, Option<(u8, u64, u64)>) {
    let found = asn1::decode(buf);
    let events = found
        .events
        .into_iter()
        .map(|event| match event {
            Event::Begin(t) => (0, t, 0, 0),
            Event::End => (1, 0, 0, 0),
            Event::Integer(t, n) => (2, t, u64::from(n), 0),
            Event::UtcTime(t, start, end) => (3, t, start as u64, end),
            Event::Bytes(t, start, end) => (4, t, start as u64, end),
        })
        .collect();
    let stop = found.stop.map(|stop| match stop {
        Stop::Index(at) => (0, at as u64, 0),
        Stop::Short { start, width } => (1, start as u64, width as u64),
        Stop::LongLength(first) => (2, u64::from(first), 0),
        Stop::IntegerLength(length) => (3, length, 0),
        Stop::Elements => (4, asn1::MAX_ELEMENTS as u64, 0),
        Stop::Depth => (5, asn1::MAX_DEPTH as u64, 0),
    });
    (events, stop)
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_asn1_decode, module)?)?;
    Ok(())
}
