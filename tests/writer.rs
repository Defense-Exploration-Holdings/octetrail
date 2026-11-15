use octetrail::writer::Options;
use octetrail::{ByteOrder, Error, Limits, Resolution, Timestamp, Writer};
use std::io::{self, Write};

fn literal(text: &str) -> Vec<u8> {
    let hex: String = text.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn options() -> Options {
    Options {
        byte_order: ByteOrder::Little,
        snaplen: 64,
        linktype: 147,
        ..Options::default()
    }
}

fn time(seconds: u32, fraction: u32) -> Timestamp {
    Timestamp {
        seconds,
        fraction,
        resolution: Resolution::Microseconds,
    }
}

#[test]
fn little_micro_output_matches_reviewed_literal_not_our_reader() {
    let mut writer = Writer::new(Vec::new(), options(), Limits::default()).unwrap();
    writer.write_packet(time(1, 250_000), 5, b"abc").unwrap();
    writer.write_packet(time(2, 0), 0, b"").unwrap();
    assert_eq!(
        writer.into_inner(),
        literal(include_str!("fixtures/little-micro.hex"))
    );
}

#[test]
fn big_nano_output_matches_reviewed_literal() {
    let config = Options {
        byte_order: ByteOrder::Big,
        resolution: Resolution::Nanoseconds,
        ..options()
    };
    let mut writer = Writer::new(Vec::new(), config, Limits::default()).unwrap();
    let timestamp = Timestamp {
        seconds: 1_700_000_000,
        fraction: 123_456_789,
        resolution: Resolution::Nanoseconds,
    };
    writer.write_packet(timestamp, 4, b"rail").unwrap();
    assert_eq!(
        writer.into_inner(),
        literal(include_str!("fixtures/big-nano.hex"))
    );
}

#[test]
fn all_magic_byte_orders_and_resolutions_have_explicit_wire_bytes() {
    for (order, resolution, magic) in [
        (
            ByteOrder::Little,
            Resolution::Microseconds,
            [0xd4, 0xc3, 0xb2, 0xa1],
        ),
        (
            ByteOrder::Big,
            Resolution::Microseconds,
            [0xa1, 0xb2, 0xc3, 0xd4],
        ),
        (
            ByteOrder::Little,
            Resolution::Nanoseconds,
            [0x4d, 0x3c, 0xb2, 0xa1],
        ),
        (
            ByteOrder::Big,
            Resolution::Nanoseconds,
            [0xa1, 0xb2, 0x3c, 0x4d],
        ),
    ] {
        let config = Options {
            byte_order: order,
            resolution,
            ..options()
        };
        let mut writer = Writer::new(Vec::new(), config, Limits::default()).unwrap();
        writer
            .write_packet(
                Timestamp {
                    seconds: 0x01020304,
                    fraction: 7,
                    resolution,
                },
                5,
                b"abc",
            )
            .unwrap();
        let bytes = writer.into_inner();
        assert_eq!(&bytes[..4], &magic);
        assert_eq!(&bytes[8..16], &[0; 8]);
        assert_eq!(
            &bytes[24..28],
            if order == ByteOrder::Little {
                &[4, 3, 2, 1]
            } else {
                &[1, 2, 3, 4]
            }
        );
        assert_eq!(&bytes[40..], b"abc");
        assert_eq!(bytes.len(), 43);
    }
}

#[test]
fn invalid_header_emits_nothing() {
    let mut bytes = Vec::new();
    assert!(matches!(
        Writer::new(
            &mut bytes,
            Options {
                snaplen: 0,
                ..options()
            },
            Limits::default()
        ),
        Err(Error::InvalidField("zero snap length"))
    ));
    assert!(bytes.is_empty());
}

#[test]
fn record_validation_emits_nothing_and_can_be_retried() {
    let mut writer = Writer::new(
        Vec::new(),
        Options {
            snaplen: 2,
            ..options()
        },
        Limits {
            max_packet_bytes: 3,
        },
    )
    .unwrap();
    for (timestamp, original, data) in [
        (time(1, 1_000_000), 0, b"".as_slice()),
        (
            Timestamp {
                resolution: Resolution::Nanoseconds,
                ..time(1, 0)
            },
            0,
            b"".as_slice(),
        ),
        (time(1, 0), 1, b"ab".as_slice()),
        (time(1, 0), 3, b"abc".as_slice()),
        (time(1, 0), 4, b"abcd".as_slice()),
    ] {
        assert!(writer.write_packet(timestamp, original, data).is_err());
        assert_eq!(writer.get_ref().len(), 24);
        assert!(!writer.is_failed());
    }
    writer.write_packet(time(1, 0), 2, b"ab").unwrap();
    assert_eq!(writer.get_ref().len(), 42);
}

#[test]
fn empty_packets_and_policy_boundary() {
    let mut writer = Writer::new(
        Vec::new(),
        options(),
        Limits {
            max_packet_bytes: 0,
        },
    )
    .unwrap();
    writer.write_packet(time(0, 0), 0, b"").unwrap();
    assert_eq!(writer.into_inner().len(), 40);
    let mut writer = Writer::new(
        Vec::new(),
        Options {
            snaplen: 3,
            ..options()
        },
        Limits {
            max_packet_bytes: 3,
        },
    )
    .unwrap();
    writer
        .write_packet(time(u32::MAX, 999_999), 3, b"abc")
        .unwrap();
    assert_eq!(writer.into_inner().len(), 43);
}

struct Partial {
    bytes: Vec<u8>,
    interrupt: bool,
    flushes: usize,
}

impl Write for Partial {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = bytes.len().min(2);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn short_writes_and_rust_interrupts_are_completed() {
    let sink = Partial {
        bytes: Vec::new(),
        interrupt: false,
        flushes: 0,
    };
    let mut writer = Writer::new(sink, options(), Limits::default()).unwrap();
    writer.write_packet(time(1, 250_000), 5, b"abc").unwrap();
    writer.flush().unwrap();
    let sink = writer.into_inner();
    assert_eq!(sink.flushes, 1);
    assert_eq!(
        sink.bytes,
        literal(include_str!("fixtures/little-micro.hex"))[..43]
    );
}

struct Failing {
    bytes: Vec<u8>,
    at: usize,
    zero: bool,
    fail_flush: bool,
}

impl Write for Failing {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len() == self.at {
            return if self.zero {
                Ok(0)
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            };
        }
        let count = bytes.len().min(self.at - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn output_errors_preserve_kind_and_make_record_writes_terminal() {
    for at in [24, 28, 41] {
        let sink = Failing {
            bytes: Vec::new(),
            at,
            zero: false,
            fail_flush: false,
        };
        let mut writer = Writer::new(sink, options(), Limits::default()).unwrap();
        assert!(
            matches!(writer.write_packet(time(1, 0), 3, b"abc"), Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(writer.is_failed());
        assert!(matches!(
            writer.write_packet(time(1, 0), 0, b""),
            Err(Error::WriterFailed)
        ));
        assert!(matches!(writer.flush(), Err(Error::WriterFailed)));
        assert_eq!(writer.into_inner().bytes.len(), at);
    }
}

#[test]
fn global_header_failure_can_leave_only_a_prefix() {
    for at in [0, 10] {
        let mut sink = Failing {
            bytes: Vec::new(),
            at,
            zero: false,
            fail_flush: false,
        };
        assert!(matches!(
            Writer::new(&mut sink, options(), Limits::default()),
            Err(Error::Io(_))
        ));
        assert_eq!(sink.bytes.len(), at);
    }
}

#[test]
fn zero_progress_is_a_terminal_write_zero_error() {
    let sink = Failing {
        bytes: Vec::new(),
        at: 24,
        zero: true,
        fail_flush: false,
    };
    let mut writer = Writer::new(sink, options(), Limits::default()).unwrap();
    assert!(
        matches!(writer.write_packet(time(1, 0), 0, b""), Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::WriteZero)
    );
    assert!(writer.is_failed());
    assert_eq!(writer.get_ref().bytes.len(), 24);
}

#[test]
fn flush_failure_is_terminal_and_into_inner_does_not_flush() {
    let sink = Failing {
        bytes: Vec::new(),
        at: usize::MAX,
        zero: false,
        fail_flush: true,
    };
    let mut writer = Writer::new(sink, options(), Limits::default()).unwrap();
    assert!(
        matches!(writer.flush(), Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(matches!(
        writer.write_packet(time(0, 0), 0, b""),
        Err(Error::WriterFailed)
    ));
    let sink = Partial {
        bytes: Vec::new(),
        interrupt: false,
        flushes: 0,
    };
    let writer = Writer::new(sink, options(), Limits::default()).unwrap();
    assert_eq!(writer.into_inner().flushes, 0);
}
