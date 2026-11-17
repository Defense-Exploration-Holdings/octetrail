#![no_main]
//! DHCP options after the fixed header.
use libfuzzer_sys::fuzz_target;
use octetrail::dhcp::options;

fuzz_target!(|data: &[u8]| {
    let _ = options(data);
});
