#![no_main]
//! PCAPNG reader: arbitrary files must end in Ok or Err, never a panic.
use libfuzzer_sys::fuzz_target;
use octetrail::pcapng::{Limits, Reader};

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_packet_bytes: 1 << 20,
        max_block_bytes: 1 << 20,
        max_interfaces: 64,
        max_blocks_per_read: 256,
    };
    if let Ok(reader) = Reader::new(data, limits) {
        for packet in reader {
            if packet.is_err() {
                break;
            }
        }
    }
});
