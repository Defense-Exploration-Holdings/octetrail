#![no_main]
//! HTTP/1.x start line, header and body framing for requests and responses.
use libfuzzer_sys::fuzz_target;
use octetrail::http;

fuzz_target!(|data: &[u8]| {
    for response in [false, true] {
        if let Ok((_, pos)) = http::start(data, response) {
            if let Ok((headers, pos)) = http::headers(data, pos) {
                let _ = http::body(data, pos, &headers, true);
            }
        }
    }
});
