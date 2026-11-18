#![no_main]
//! NetFlow record split for any length and nonzero record size.
use libfuzzer_sys::fuzz_target;
use octetrail::netflow::records;

fuzz_target!(|data: &[u8]| {
    if let [size, rest @ ..] = data {
        let size = usize::from(*size).max(1);
        let found = records(rest.len(), size);
        assert!(found.count * size <= rest.len());
    }
});
