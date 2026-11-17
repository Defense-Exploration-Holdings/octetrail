#![no_main]
//! DNS messages, including name compression loops.
use libfuzzer_sys::fuzz_target;
use octetrail::dns::{self, Budget, Message};

fuzz_target!(|data: &[u8]| {
    let _ = Message::parse(data);
    // The Python facade reads one name at a time, sharing one budget.
    let mut budget = Budget::new();
    let mut offset = 12;
    while let Ok((_, next)) = dns::unpack_name_raw(data, offset, &mut budget) {
        if next <= offset {
            break;
        }
        offset = next;
    }
    for (start, end) in dns::text_ranges(data) {
        let _ = &data[start..end];
    }
});
