use octetrail::{ByteOrder, Error, Limits, Reader, Resolution, Timestamp};
use std::io::{self, Cursor, Read};

fn decode(hex: &str) -> Vec<u8> {
    let compact: String = hex.split_whitespace().collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture() -> Vec<u8> {
    decode(include_str!("fixtures/little-micro.hex"))
}

fn reader(bytes: Vec<u8>) -> Reader<Cursor<Vec<u8>>> {
    Reader::new(Cursor::new(bytes), Limits::default()).unwrap()
}

#[test]
fn literal_little_micro_preserves_metadata_time_and_bytes() {
    let mut capture = reader(fixture());
    let header = capture.header();
    assert_eq!(header.byte_order, ByteOrder::Little);
    assert_eq!(header.resolution, Resolution::Microseconds);
    assert_eq!((header.snaplen, header.linktype), (64, 147));
    assert_eq!((header.reserved1, header.reserved2), (0, 0));
    let packet = capture.next().unwrap().unwrap();
    assert_eq!(packet.data, b"abc");
    assert_eq!(packet.original_len, 5);
    assert_eq!(
        packet.timestamp,
        Timestamp {
            seconds: 1,
            fraction: 250000,
            resolution: Resolution::Microseconds,
        }
    );
    let empty = capture.next().unwrap().unwrap();
    assert_eq!((empty.timestamp.seconds, empty.timestamp.fraction), (2, 0));
    assert_eq!(empty.original_len, 0);
    assert!(empty.data.is_empty());
    assert!(capture.next().is_none());
    assert!(capture.next().is_none());
}

#[test]
fn literal_big_nano_preserves_precision() {
    let mut capture = reader(decode(include_str!("fixtures/big-nano.hex")));
    assert_eq!(capture.header().byte_order, ByteOrder::Big);
    let packet = capture.next().unwrap().unwrap();
    assert_eq!(packet.timestamp.seconds, 1_700_000_000);
    assert_eq!(packet.timestamp.fraction, 123_456_789);
    assert_eq!(packet.timestamp.resolution, Resolution::Nanoseconds);
    assert_eq!(packet.data, b"rail");
    assert!(capture.next().is_none());
}

#[test]
fn empty_capture_is_fused() {
    let mut capture = reader(fixture()[..24].to_vec());
    assert!(capture.next().is_none());
    assert!(capture.next().is_none());
}

#[test]
fn incomplete_global_headers_are_truncated() {
    for length in 0..24 {
        assert!(matches!(
            Reader::new(Cursor::new(&fixture()[..length]), Limits::default()),
            Err(Error::Truncated("global header"))
        ));
    }
}

#[test]
fn incomplete_record_headers_are_truncated_and_terminal() {
    for length in 25..40 {
        let mut capture = reader(fixture()[..length].to_vec());
        assert!(matches!(
            capture.next(),
            Some(Err(Error::Truncated("record header")))
        ));
        assert!(capture.next().is_none());
    }
}

#[test]
fn incomplete_payloads_are_truncated_and_terminal() {
    for length in 40..43 {
        let mut capture = reader(fixture()[..length].to_vec());
        assert!(matches!(
            capture.next(),
            Some(Err(Error::Truncated("packet payload")))
        ));
        assert!(capture.next().is_none());
    }
}

#[test]
fn unknown_magic_and_version_are_distinct() {
    let mut bytes = fixture();
    bytes[..4].copy_from_slice(b"none");
    assert!(matches!(
        Reader::new(Cursor::new(bytes), Limits::default()),
        Err(Error::UnsupportedMagic(_))
    ));
    let mut bytes = fixture();
    bytes[6..8].copy_from_slice(&3_u16.to_le_bytes());
    assert!(matches!(
        Reader::new(Cursor::new(bytes), Limits::default()),
        Err(Error::UnsupportedVersion { major: 2, minor: 3 })
    ));
}

#[test]
fn zero_snaplen_is_rejected() {
    let mut bytes = fixture();
    bytes[16..20].fill(0);
    assert!(matches!(
        Reader::new(Cursor::new(bytes), Limits::default()),
        Err(Error::InvalidField("zero snap length"))
    ));
}

#[test]
fn fractional_ticks_must_fit_the_resolution() {
    for (mut bytes, offset, ticks, order) in [
        (fixture(), 28, 1_000_000_u32, ByteOrder::Little),
        (
            decode(include_str!("fixtures/big-nano.hex")),
            28,
            1_000_000_000_u32,
            ByteOrder::Big,
        ),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&match order {
            ByteOrder::Little => ticks.to_le_bytes(),
            ByteOrder::Big => ticks.to_be_bytes(),
        });
        let mut capture = reader(bytes);
        assert!(matches!(
            capture.next(),
            Some(Err(Error::InvalidField("timestamp fraction")))
        ));
        assert!(capture.next().is_none());
    }
}

#[test]
fn length_relationships_are_checked() {
    let mut bytes = fixture();
    bytes[16..20].copy_from_slice(&2_u32.to_le_bytes());
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField(
            "captured length exceeds snap length"
        )))
    ));
    let mut bytes = fixture();
    bytes[36..40].copy_from_slice(&2_u32.to_le_bytes());
    assert!(matches!(
        reader(bytes).next(),
        Some(Err(Error::InvalidField(
            "captured length exceeds original length"
        )))
    ));
}

#[test]
fn configured_limit_is_checked_before_payload_reads() {
    // Only the headers are present. The limit must win over payload truncation.
    let mut capture = Reader::new(
        Cursor::new(fixture()[..40].to_vec()),
        Limits {
            max_packet_bytes: 2,
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
    assert_eq!(capture.into_inner().position(), 40);
}

#[test]
fn limit_boundary_and_zero_limit_are_useful() {
    let mut capture = Reader::new(
        Cursor::new(fixture()),
        Limits {
            max_packet_bytes: 3,
        },
    )
    .unwrap();
    assert_eq!(capture.next().unwrap().unwrap().data, b"abc");
    let mut bytes = fixture()[..24].to_vec();
    bytes.extend_from_slice(&fixture()[43..]);
    let mut capture = Reader::new(
        Cursor::new(bytes),
        Limits {
            max_packet_bytes: 0,
        },
    )
    .unwrap();
    assert!(capture.next().unwrap().unwrap().data.is_empty());
    assert!(capture.next().is_none());
}

#[test]
fn construction_and_early_stop_leave_input_at_expected_cursor() {
    let capture = reader(fixture());
    assert_eq!(capture.into_inner().position(), 24);
    let mut capture = reader(fixture());
    capture.next().unwrap().unwrap();
    assert_eq!(capture.into_inner().position(), 43);
}

struct ShortReads {
    input: Cursor<Vec<u8>>,
    interrupt: bool,
}

impl Read for ShortReads {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = buf.len().min(2);
        self.input.read(&mut buf[..length])
    }
}

#[test]
fn short_reads_and_interrupts_work_without_seek() {
    let source = ShortReads {
        input: Cursor::new(fixture()),
        interrupt: false,
    };
    let capture = Reader::new(source, Limits::default()).unwrap();
    let records = capture.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].data, b"abc");
}

struct FailsAfter {
    input: Cursor<Vec<u8>>,
    at: u64,
}

impl Read for FailsAfter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.at.saturating_sub(self.input.position());
        if remaining == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let length = buf.len().min(remaining as usize);
        self.input.read(&mut buf[..length])
    }
}

#[test]
fn io_errors_are_preserved_at_each_read_boundary() {
    for at in [0, 10, 24, 29, 41] {
        let result = Reader::new(
            FailsAfter {
                input: Cursor::new(fixture()),
                at,
            },
            Limits::default(),
        );
        let error = match result {
            Err(error) => error,
            Ok(mut capture) => {
                let error = capture.next().unwrap().unwrap_err();
                assert!(capture.next().is_none());
                error
            }
        };
        assert!(
            matches!(error, Error::Io(ref source) if source.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[test]
fn reserved_header_fields_are_retained() {
    let mut bytes = fixture();
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[12..16].copy_from_slice(&7_u32.to_le_bytes());
    let header = reader(bytes).header();
    assert_eq!(header.reserved1, u32::MAX);
    assert_eq!(header.reserved2, 7);
}
