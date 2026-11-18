#![no_main]
//! IEEE 802.11 information elements and radiotap present words.
use libfuzzer_sys::fuzz_target;
use octetrail::ieee80211::{ie_starts, present_len};

fuzz_target!(|data: &[u8]| {
    let _ = ie_starts(data);
    let _ = present_len(data);
});
