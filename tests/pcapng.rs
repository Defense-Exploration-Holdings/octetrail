use octetrail::pcapng::{Limits, Reader, Resolution};
use octetrail::Error;
use std::io::{self, Cursor, Read};

fn literal(text: &str) -> Vec<u8> {
    let hex: String = text.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> Vec<u8> {
    literal(include_str!("fixtures/pcapng-little.hex"))
}
fn word(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}
fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    assert_eq!(body.len() % 4, 0);
    let length = (body.len() + 12) as u32;
    [word(kind), word(length), body.to_vec(), word(length)].concat()
}
fn section(length: i64) -> Vec<u8> {
    block(
        0x0a0d0d0a,
        &[
            word(0x1a2b3c4d),
            vec![1, 0, 0, 0],
            length.to_le_bytes().to_vec(),
        ]
        .concat(),
    )
}
fn interface(snaplen: u32, options: &[u8]) -> Vec<u8> {
    block(
        1,
        &[vec![147, 0, 0, 0], word(snaplen), options.to_vec()].concat(),
    )
}
fn packet(id: u32, ticks: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = payload.to_vec();
    data.resize((data.len() + 3) & !3, 0);
    block(
        6,
        &[
            word(id),
            word((ticks >> 32) as u32),
            word(ticks as u32),
            word(payload.len() as u32),
            word(payload.len() as u32),
            data,
        ]
        .concat(),
    )
}
fn option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut value = [
        code.to_le_bytes().to_vec(),
        (data.len() as u16).to_le_bytes().to_vec(),
        data.to_vec(),
    ]
    .concat();
    value.resize((value.len() + 3) & !3, 0);
    value
}
fn reader(bytes: Vec<u8>) -> Reader<Cursor<Vec<u8>>> {
    Reader::new(Cursor::new(bytes), Limits::default()).unwrap()
}

#[test]
fn literal_default_microseconds_and_original_length() {
    let mut capture = reader(fixture());
    assert_eq!(capture.first_interface().linktype, 147);
    assert_eq!(capture.first_interface().snaplen, 64);
    assert_eq!(capture.get_ref().position(), 48);
    let record = capture.next().unwrap().unwrap();
    assert_eq!(record.data, b"abc");
    assert_eq!(record.original_len, 5);
    assert_eq!(record.timestamp.ticks, 1_250_000);
    assert_eq!(record.timestamp.resolution, Resolution::Decimal(6));
    assert_eq!(record.timestamp.offset_seconds, 0);
    assert_eq!((record.section_index, record.interface_id), (0, 0));
    assert!(capture.next().is_none());
    assert!(capture.next().is_none());
}

#[test]
fn literal_big_endian_nanoseconds_and_negative_offset() {
    let record = reader(literal(include_str!("fixtures/pcapng-big-nano.hex")))
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.data, b"rail");
    assert_eq!(record.timestamp.ticks, 1_250_000_000);
    assert_eq!(record.timestamp.resolution, Resolution::Decimal(9));
    assert_eq!(record.timestamp.offset_seconds, -2);
}

#[test]
fn section_local_interfaces_and_byte_orders() {
    let timing = [
        option(9, &[0x8a]),
        option(14, &(-5_i64).to_le_bytes()),
        option(0, &[]),
    ]
    .concat();
    let bytes = [
        section(-1),
        interface(64, &[]),
        interface(0, &timing),
        packet(1, 1024, b"one"),
        literal(include_str!("fixtures/pcapng-big-nano.hex")),
    ]
    .concat();
    let mut capture = reader(bytes);
    let first = capture.next().unwrap().unwrap();
    assert_eq!((first.section_index, first.interface_id), (0, 1));
    assert_eq!(first.timestamp.resolution, Resolution::Binary(10));
    assert_eq!(first.timestamp.offset_seconds, -5);
    let second = capture.next().unwrap().unwrap();
    assert_eq!((second.section_index, second.interface_id), (1, 0));
    assert_eq!(second.timestamp.resolution, Resolution::Decimal(9));
    assert!(capture.next().is_none());
    assert_eq!(capture.first_interface().snaplen, 64);
}

#[test]
fn empty_capture_and_zero_length_packet_with_unlimited_snaplen() {
    let empty = [section(-1), interface(0, &[])].concat();
    assert!(reader(empty.clone()).next().is_none());
    assert!(reader([empty, packet(0, 0, b"")].concat())
        .next()
        .unwrap()
        .unwrap()
        .data
        .is_empty());
}

#[test]
fn unknown_blocks_options_and_padding_are_skipped_within_bounds() {
    let options = [option(65000, b"ordinary"), option(0, &[])].concat();
    let mut epb = packet(0, 1, b"abc");
    epb[31] = 0x11; // Packet padding is not returned as payload.
    let bytes = [
        section(-1),
        block(0x1234, &[]),
        interface(64, &options),
        block(4, &[0; 4]),
        epb,
    ]
    .concat();
    assert_eq!(reader(bytes).next().unwrap().unwrap().data, b"abc");
}

#[test]
fn block_budget_is_checked_before_body_allocation_or_read() {
    let mut capture = Reader::new(
        Cursor::new(fixture()),
        Limits {
            max_block_bytes: 32,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        capture.next(),
        Some(Err(Error::BlockLimit {
            declared: 36,
            limit: 32
        }))
    ));
    assert!(capture.next().is_none());
    assert_eq!(capture.into_inner().position(), 56);
}

#[test]
fn packet_and_interface_budgets_are_terminal() {
    let mut capture = Reader::new(
        Cursor::new(fixture()),
        Limits {
            max_packet_bytes: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        capture.next(),
        Some(Err(Error::PacketLimit {
            captured: 3,
            limit: 2
        }))
    ));
    assert!(capture.next().is_none());
    let bytes = [section(-1), interface(64, &[]), interface(64, &[])].concat();
    let mut capture = Reader::new(
        Cursor::new(bytes),
        Limits {
            max_interfaces: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        capture.next(),
        Some(Err(Error::ResourceLimit {
            resource: "pcapng interfaces",
            limit: 1
        }))
    ));
    assert!(capture.next().is_none());
}

#[test]
fn metadata_scan_budget_applies_to_constructor_and_iteration() {
    let limits = Limits {
        max_blocks_per_read: 1,
        ..Limits::default()
    };
    let bytes = [section(-1), block(4, &[]), interface(64, &[])].concat();
    assert!(matches!(
        Reader::new(Cursor::new(bytes), limits),
        Err(Error::ResourceLimit { .. })
    ));
    let bytes = [
        section(-1),
        interface(64, &[]),
        block(4, &[]),
        packet(0, 0, b"abc"),
    ]
    .concat();
    let mut capture = Reader::new(Cursor::new(bytes), limits).unwrap();
    assert!(matches!(
        capture.next(),
        Some(Err(Error::ResourceLimit { .. }))
    ));
    assert!(capture.next().is_none());
}

#[test]
fn block_length_alignment_and_repeated_length_are_checked() {
    let mut bytes = fixture();
    bytes[52..56].copy_from_slice(&14_u32.to_le_bytes());
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField("pcapng block length or alignment")))
    ));
    let mut bytes = fixture();
    let length = bytes.len();
    bytes[length - 4..].copy_from_slice(&40_u32.to_le_bytes());
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField("pcapng repeated block length")))
    ));
}

#[test]
fn incomplete_block_prefixes_are_errors_and_not_eof() {
    let bytes = fixture();
    for length in 0..48 {
        assert!(Reader::new(Cursor::new(&bytes[..length]), Limits::default()).is_err());
    }
    assert!(reader(bytes[..48].to_vec()).next().is_none());
    for length in 49..bytes.len() {
        let mut capture = reader(bytes[..length].to_vec());
        assert!(matches!(capture.next(), Some(Err(Error::Truncated(_)))));
        assert!(capture.next().is_none());
    }
}

#[test]
fn interface_ids_and_packet_length_relationships_are_checked() {
    let bytes = [section(-1), interface(64, &[]), packet(1, 1, b"abc")].concat();
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField("pcapng interface id")))
    ));
    let bytes = [section(-1), interface(2, &[]), packet(0, 1, b"abc")].concat();
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField("pcapng captured length")))
    ));
    let mut bytes = fixture();
    bytes[72..76].copy_from_slice(&2_u32.to_le_bytes());
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField("pcapng captured length")))
    ));
    let mut bytes = fixture();
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField("pcapng packet length or padding")))
    ));
}

#[test]
fn options_require_lengths_padding_and_an_end_marker() {
    for options in [
        option(9, &[6]),
        [option(9, &[6, 7]), option(0, &[])].concat(),
        [option(14, &[0; 4]), option(0, &[])].concat(),
        [option(9, &[6]), option(9, &[9]), option(0, &[])].concat(),
        [option(14, &[0; 8]), option(14, &[0; 8]), option(0, &[])].concat(),
        vec![1, 0, 5, 0],
        option(0, &[0; 4]),
    ] {
        let bytes = [section(-1), interface(64, &options)].concat();
        assert!(matches!(
            Reader::new(Cursor::new(bytes), Limits::default()),
            Err(Error::InvalidField(_))
        ));
    }
}

#[test]
fn known_section_lengths_are_enforced_and_interfaces_reset() {
    let body = [interface(64, &[]), packet(0, 0, b"abc")].concat();
    let bytes = [
        section(body.len() as i64),
        body.clone(),
        section(-1),
        interface(64, &[]),
        packet(0, 0, b"tail"),
    ]
    .concat();
    let records = reader(bytes).collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].section_index, 1);
    let bytes = [section(body.len() as i64 + 4), body.clone()].concat();
    let mut capture = reader(bytes);
    capture.next().unwrap().unwrap();
    assert!(matches!(
        capture.next(),
        Some(Err(Error::Truncated("pcapng section")))
    ));
    assert!(matches!(
        reader([section(20), body].concat()).next(),
        Some(Err(Error::InvalidField("pcapng section length boundary")))
    ));
    assert!(
        reader([section(0), section(-1), interface(64, &[])].concat())
            .next()
            .is_none()
    );
}

#[test]
fn unsupported_packet_blocks_are_explicit() {
    for kind in [2, 3] {
        let mut capture = reader([section(-1), interface(64, &[]), block(kind, &[])].concat());
        assert!(
            matches!(capture.next(), Some(Err(Error::UnsupportedBlock(value))) if value == kind)
        );
        assert!(capture.next().is_none());
    }
}

#[test]
fn version_byte_order_and_section_length_validation() {
    for (offset, replacement) in [
        (8, vec![0; 4]),
        (14, vec![1, 0]),
        (16, (-2_i64).to_le_bytes().to_vec()),
    ] {
        let mut bytes = fixture();
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        assert!(matches!(
            Reader::new(Cursor::new(bytes), Limits::default()),
            Err(Error::InvalidField(_))
        ));
    }
}

struct Partial {
    input: Cursor<Vec<u8>>,
    interrupted: bool,
}
impl Read for Partial {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.interrupted = !self.interrupted;
        if self.interrupted {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = bytes.len().min(2);
        self.input.read(&mut bytes[..length])
    }
}

#[test]
fn nonseekable_short_and_interrupted_reads_work() {
    let input = Partial {
        input: Cursor::new(fixture()),
        interrupted: false,
    };
    let records = Reader::new(input, Limits::default())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records[0].data, b"abc");
}
