#![no_main]
//! H.225.0 element walk for any buffer: spans tile the buffer in order.
use libfuzzer_sys::fuzz_target;
use octetrail::h225::elements;

fuzz_target!(|data: &[u8]| {
    let found = elements(data);
    let mut at = 0usize;
    for &(start, end) in &found.spans {
        assert_eq!(start, at);
        assert!(start < end && end <= data.len());
        at = end;
    }
    match found.cut {
        Some(cut) => assert_eq!(cut, at),
        None => assert_eq!(at, data.len()),
    }
});
