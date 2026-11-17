#![no_main]
//! DNS messages, including name compression loops.
use libfuzzer_sys::fuzz_target;
use octetrail::dns::Message;

fuzz_target!(|data: &[u8]| {
    let _ = Message::parse(data);
});
