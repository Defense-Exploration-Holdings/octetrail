#![no_main]
//! Passive TLS record framing, handshake headers and ServerHello metadata.
use libfuzzer_sys::fuzz_target;
use octetrail::tls;

fuzz_target!(|data: &[u8]| {
    if let Ok((spans, _)) = tls::records(data) {
        for (start, end) in spans {
            if let Some(raw) = data.get(start..end) {
                if let Ok(record) = tls::Record::parse(raw) {
                    let _ = tls::Handshake::parse(record.data);
                }
            }
        }
    }
    let _ = tls::Handshake::parse(data);
    let _ = tls::ServerHello::parse(data);
});
