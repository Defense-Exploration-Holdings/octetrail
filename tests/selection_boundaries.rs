//! Cursor and error boundaries used by the thin Python format-selection factory.

use octetrail::{pcapng, Error, Limits, Reader};
use std::io::{Cursor, Seek, SeekFrom};

fn literal(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .flat_map(|word| {
            word.as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn failed_classic_probe_can_be_rewound_into_native_pcapng_reader() {
    let data = literal(include_str!("fixtures/pcapng-little.hex"));
    let mut input = Cursor::new(data);
    assert!(matches!(
        Reader::new(&mut input, Limits::default()),
        Err(Error::UnsupportedMagic([0x0a, 0x0d, 0x0d, 0x0a]))
    ));
    assert_eq!(input.position(), 24);
    input.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = pcapng::Reader::new(&mut input, pcapng::Limits::default()).unwrap();
    assert_eq!(reader.first_interface().snaplen, 64);
    let packet = reader.next().unwrap().unwrap();
    assert_eq!(packet.timestamp.ticks, 1_250_000);
    assert_eq!(packet.data, b"abc");
    assert!(reader.next().is_none());
}

#[test]
fn classic_reader_starts_at_current_position_without_seeking() {
    let mut data = b"prefix".to_vec();
    data.extend(literal(include_str!("fixtures/big-nano.hex")));
    let mut input = Cursor::new(data);
    input.set_position(6);
    let mut reader = Reader::new(&mut input, Limits::default()).unwrap();
    let packet = reader.next().unwrap().unwrap();
    assert_eq!(packet.timestamp.seconds, 1_700_000_000);
    assert_eq!(packet.timestamp.fraction, 123_456_789);
    assert_eq!(packet.data, b"rail");
    assert!(reader.next().is_none());
}

#[test]
fn incomplete_initial_probe_is_truncation_after_consuming_available_bytes() {
    let full = literal(include_str!("fixtures/pcapng-little.hex"));
    for length in [0, 3, 23] {
        let mut input = Cursor::new(&full[..length]);
        assert!(matches!(
            Reader::new(&mut input, Limits::default()),
            Err(Error::Truncated("global header"))
        ));
        assert_eq!(input.position(), length as u64);
    }
}
