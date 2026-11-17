#![no_main]
//! HTTP/1.x requests and responses, including chunked bodies.
use libfuzzer_sys::fuzz_target;
use octetrail::http;

fuzz_target!(|data: &[u8]| {
    let _ = http::Request::parse(data);
    let _ = http::Response::parse(data);
    let _ = http::message(data, true);
});
