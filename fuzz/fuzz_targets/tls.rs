#![no_main]
//! TLS record framing, hellos, certificate lists and SSLv2 splitting.
use libfuzzer_sys::fuzz_target;
use octetrail::tls;

fuzz_target!(|data: &[u8]| {
    let _ = tls::multi_factory(data);
    let _ = tls::tls_records(data);
    let _ = tls::Hello::client(data);
    let _ = tls::Hello::server(data);
    let _ = tls::certificates(data);
    let _ = tls::extensions(data, 0);
    if let [a, b, rest @ ..] = data {
        let _ = tls::ssl2(u16::from_be_bytes([*a, *b]), rest);
    }
});
