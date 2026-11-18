#![no_main]
//! ASN.1 walk for any buffer: bounded output, offsets inside the buffer and
//! balanced nesting when the decode finishes.
use libfuzzer_sys::fuzz_target;
use octetrail::asn1::{decode, Event, MAX_DEPTH, MAX_ELEMENTS};

fuzz_target!(|data: &[u8]| {
    let found = decode(data);
    let mut depth = 0usize;
    let mut elements = 0usize;
    for event in &found.events {
        match *event {
            Event::Begin(_) => {
                depth += 1;
                elements += 1;
                assert!(depth <= MAX_DEPTH);
            }
            Event::End => depth = depth.checked_sub(1).expect("End without Begin"),
            Event::Integer(..) => elements += 1,
            Event::UtcTime(_, start, end) | Event::Bytes(_, start, end) => {
                elements += 1;
                assert!(start <= end && end <= data.len());
            }
        }
    }
    assert!(elements <= MAX_ELEMENTS);
    if found.stop.is_none() {
        assert_eq!(depth, 0);
    }
});
