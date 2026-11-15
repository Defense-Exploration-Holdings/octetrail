use octetrail::pcapng::Resolution;
use octetrail::pcapng_writer::{Limits, Options, Writer};
use octetrail::{ByteOrder, Error};
use std::io::{self, Write};

fn literal(text: &str) -> Vec<u8> {
    let hex: String = text.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn options() -> Options<'static> {
    Options {
        byte_order: ByteOrder::Little,
        snaplen: 64,
        linktype: 147,
        ..Options::default()
    }
}

#[test]
fn little_output_matches_existing_literal_without_a_reader() {
    let mut writer = Writer::new(Vec::new(), options(), Limits::default()).unwrap();
    writer.write_packet(1_250_000, 5, b"abc").unwrap();
    assert_eq!(
        writer.into_inner(),
        literal(include_str!("fixtures/pcapng-little.hex"))
    );
}

#[test]
fn big_nano_and_offset_match_existing_literal() {
    let config = Options {
        byte_order: ByteOrder::Big,
        timestamp_resolution: Some(Resolution::Decimal(9)),
        timestamp_offset: Some(-2),
        ..options()
    };
    let mut writer = Writer::new(Vec::new(), config, Limits::default()).unwrap();
    writer.write_packet(1_250_000_000, 4, b"rail").unwrap();
    assert_eq!(
        writer.into_inner(),
        literal(include_str!("fixtures/pcapng-big-nano.hex"))
    );
}

#[test]
fn section_interface_clock_and_padding_match_new_literal() {
    let config = Options {
        section_comment: Some(b"lab"),
        interface_name: Some(b"if0"),
        timestamp_resolution: Some(Resolution::Binary(10)),
        timestamp_offset: Some(-2),
        ..options()
    };
    let mut writer = Writer::new(Vec::new(), config, Limits::default()).unwrap();
    writer.write_packet(1024, 3, b"abc").unwrap();
    assert_eq!(
        writer.into_inner(),
        literal(include_str!("fixtures/pcapng-options-little.hex"))
    );
}

#[test]
fn both_orders_preserve_full_tick_bits_and_packet_lengths() {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut writer = Writer::new(
            Vec::new(),
            Options {
                byte_order: order,
                ..options()
            },
            Limits::default(),
        )
        .unwrap();
        writer.write_packet(u64::MAX, 7, b"abc").unwrap();
        let bytes = writer.into_inner();
        assert_eq!(&bytes[60..68], &[0xff; 8]);
        assert_eq!(&bytes[76..80], b"abc\0");
        let length = if order == ByteOrder::Little {
            [36, 0, 0, 0]
        } else {
            [0, 0, 0, 36]
        };
        assert_eq!(&bytes[52..56], &length);
        assert_eq!(&bytes[80..84], &length);
    }
}

#[test]
fn all_metadata_and_both_initial_blocks_are_validated_before_output() {
    let too_long = vec![b'a'; 65536];
    for config in [
        Options {
            section_comment: Some(&too_long),
            ..options()
        },
        Options {
            interface_name: Some(b"\xff"),
            ..options()
        },
        Options {
            timestamp_resolution: Some(Resolution::Decimal(128)),
            ..options()
        },
    ] {
        let mut sink = Vec::new();
        assert!(Writer::new(&mut sink, config, Limits::default()).is_err());
        assert!(sink.is_empty());
    }
    let mut sink = Vec::new();
    let config = Options {
        timestamp_resolution: Some(Resolution::Decimal(6)),
        ..options()
    };
    assert!(matches!(
        Writer::new(
            &mut sink,
            config,
            Limits {
                max_block_bytes: 28,
                ..Limits::default()
            }
        ),
        Err(Error::BlockLimit {
            declared: 32,
            limit: 28
        })
    ));
    assert!(sink.is_empty());
}

#[test]
fn metadata_boundary_and_explicit_zero_options_are_retained() {
    let name = vec![b'a'; 65535];
    let config = Options {
        interface_name: Some(&name),
        timestamp_resolution: Some(Resolution::Binary(127)),
        timestamp_offset: Some(0),
        ..options()
    };
    let writer = Writer::new(Vec::new(), config, Limits::default()).unwrap();
    assert_eq!(writer.interface().resolution, Resolution::Binary(127));
    assert_eq!(writer.interface().offset_seconds, 0);
    assert_eq!(&writer.get_ref()[46..48], &[0xff, 0xff]);
}

#[test]
fn packet_validation_is_nonemitting_and_recoverable() {
    let mut writer = Writer::new(
        Vec::new(),
        Options {
            snaplen: 2,
            ..options()
        },
        Limits {
            max_packet_bytes: 3,
            ..Limits::default()
        },
    )
    .unwrap();
    for (original, data) in [
        (1, b"ab".as_slice()),
        (3, b"abc".as_slice()),
        (4, b"abcd".as_slice()),
    ] {
        assert!(writer.write_packet(0, original, data).is_err());
        assert_eq!(writer.get_ref().len(), 48);
        assert!(!writer.is_failed());
    }
    writer.write_packet(0, 2, b"ab").unwrap();
    assert_eq!(writer.get_ref().len(), 84);
}

#[test]
fn block_limit_and_unlimited_snap_length_have_separate_policy() {
    let mut writer = Writer::new(
        Vec::new(),
        Options {
            snaplen: 0,
            ..options()
        },
        Limits {
            max_block_bytes: 32,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        writer.write_packet(0, 1, b"a"),
        Err(Error::BlockLimit {
            declared: 36,
            limit: 32
        })
    ));
    assert_eq!(writer.get_ref().len(), 48);
    writer.write_packet(0, 0, b"").unwrap();
    assert_eq!(writer.get_ref().len(), 80);
    let mut writer = Writer::new(
        Vec::new(),
        Options {
            snaplen: 0,
            ..options()
        },
        Limits {
            max_packet_bytes: 3,
            ..Limits::default()
        },
    )
    .unwrap();
    writer.write_packet(0, 5, b"abc").unwrap();
}

struct Sink {
    bytes: Vec<u8>,
    fail_at: usize,
    zero: bool,
    short: bool,
    interrupt: bool,
    flushes: usize,
    flush_error: bool,
}
impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.bytes.len() == self.fail_at {
            return if self.zero {
                Ok(0)
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            };
        }
        if self.short {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
        }
        let count = data
            .len()
            .min(self.fail_at - self.bytes.len())
            .min(if self.short { 2 } else { usize::MAX });
        self.bytes.extend_from_slice(&data[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flush_error {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}
fn sink() -> Sink {
    Sink {
        bytes: Vec::new(),
        fail_at: usize::MAX,
        zero: false,
        short: false,
        interrupt: false,
        flushes: 0,
        flush_error: false,
    }
}

#[test]
fn short_and_interrupted_writes_complete_the_literal() {
    let mut writer = Writer::new(
        Sink {
            short: true,
            ..sink()
        },
        options(),
        Limits::default(),
    )
    .unwrap();
    writer.write_packet(1_250_000, 5, b"abc").unwrap();
    writer.flush().unwrap();
    let output = writer.into_inner();
    assert_eq!(output.flushes, 1);
    assert_eq!(
        output.bytes,
        literal(include_str!("fixtures/pcapng-little.hex"))
    );
}

#[test]
fn initial_io_failures_leave_only_a_prefix() {
    for at in [0, 10, 28, 35, 47] {
        let mut output = Sink {
            fail_at: at,
            ..sink()
        };
        assert!(matches!(
            Writer::new(&mut output, options(), Limits::default()),
            Err(Error::Io(_))
        ));
        assert_eq!(output.bytes.len(), at);
    }
}

#[test]
fn record_header_payload_padding_and_trailer_errors_are_terminal() {
    for at in [48, 52, 77, 79, 82] {
        let mut writer = Writer::new(
            Sink {
                fail_at: at,
                ..sink()
            },
            options(),
            Limits::default(),
        )
        .unwrap();
        assert!(
            matches!(writer.write_packet(0, 3, b"abc"), Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(writer.is_failed());
        assert!(matches!(
            writer.write_packet(0, 0, b""),
            Err(Error::WriterFailed)
        ));
        assert!(matches!(writer.flush(), Err(Error::WriterFailed)));
        assert_eq!(writer.get_ref().bytes.len(), at);
    }
}

#[test]
fn zero_progress_and_flush_errors_are_terminal_without_implicit_flush() {
    let mut writer = Writer::new(
        Sink {
            fail_at: 48,
            zero: true,
            ..sink()
        },
        options(),
        Limits::default(),
    )
    .unwrap();
    assert!(
        matches!(writer.write_packet(0, 0, b""), Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::WriteZero)
    );
    assert!(writer.is_failed());
    let mut writer = Writer::new(
        Sink {
            flush_error: true,
            ..sink()
        },
        options(),
        Limits::default(),
    )
    .unwrap();
    assert!(
        matches!(writer.flush(), Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(matches!(
        writer.write_packet(0, 0, b""),
        Err(Error::WriterFailed)
    ));
    let writer = Writer::new(sink(), options(), Limits::default()).unwrap();
    assert_eq!(writer.into_inner().flushes, 0);
}
