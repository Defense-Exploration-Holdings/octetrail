#![no_main]
//! Diameter AVPs after the message header.
use libfuzzer_sys::fuzz_target;
use octetrail::diameter::avps;

fuzz_target!(|data: &[u8]| {
    let found = avps(data);
    let mut last = None;
    for span in &found.spans {
        assert!(span.start < data.len());
        assert!(last.map_or(true, |at| span.start > at));
        last = Some(span.start);
    }
});
