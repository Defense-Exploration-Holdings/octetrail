#![no_main]
//! HTTP/2 frame boundaries from any start offset.
use libfuzzer_sys::fuzz_target;
use octetrail::http2::frames;

fuzz_target!(|data: &[u8]| {
    let start = data.first().map_or(0, |&b| usize::from(b) % 32);
    let found = frames(data, start);
    assert!(found.tail <= data.len());
    for &(begin, end) in &found.spans {
        assert!(begin < end && end <= found.tail);
    }
});
