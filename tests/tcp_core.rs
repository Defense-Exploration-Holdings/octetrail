use octetrail::tcp::{Error, Header, Limits, Segment, HEADER_LEN};

// Independently assembled offline fields and the opaque ASCII payload "rail".
const LITERAL: &[u8] = &[
    0x30, 0x39, 0, 0x50, 0x89, 0xab, 0xcd, 0xef, 0x87, 0x65, 0x43, 0x21, 0x50, 0x10, 0x10, 0, 0x12,
    0x34, 0, 0, b'r', b'a', b'i', b'l',
];

#[test]
fn literal_fields_and_borrowed_payload_are_exact() {
    let segment = Segment::parse(LITERAL, Limits::default()).unwrap();
    assert_eq!(segment.header.sport, 12345);
    assert_eq!(segment.header.dport, 80);
    assert_eq!(segment.header.seq, 0x89abcdef);
    assert_eq!(segment.header.ack, 0x87654321);
    assert_eq!(segment.header.off, 5);
    assert_eq!(segment.header.flags, 0x10);
    assert_eq!(segment.header.win, 4096);
    assert_eq!(segment.header.checksum, 0x1234);
    assert_eq!(segment.header.urp, 0);
    assert_eq!(segment.data, b"rail");
    assert_eq!(segment.data.as_ptr(), LITERAL[HEADER_LEN..].as_ptr());
    assert_eq!(segment.to_bytes(Limits::default()).unwrap(), LITERAL);
}

#[test]
fn defaults_match_explicit_reference_bytes() {
    assert_eq!(
        Header::default().to_bytes().unwrap(),
        [0xde, 0xad, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0x50, 2, 0xff, 0xff, 0, 0, 0, 0]
    );
}

#[test]
fn unsigned_fields_and_network_order_cover_high_bits() {
    let header = Header {
        sport: 0xffff,
        dport: 0x8000,
        seq: 0xffffffff,
        ack: 0x80000000,
        off: 5,
        flags: 0x80,
        win: 0x8000,
        checksum: 0xffff,
        urp: 0xffff,
    };
    let raw = [
        0xff, 0xff, 0x80, 0, 0xff, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0x50, 0x80, 0x80, 0, 0xff,
        0xff, 0xff, 0xff,
    ];
    assert_eq!(header.to_bytes().unwrap(), raw);
    assert_eq!(Header::parse(&raw).unwrap(), header);
}

#[test]
fn empty_payload_needs_exactly_twenty_bytes() {
    let raw = Header::default().to_bytes().unwrap();
    let segment = Segment::parse(&raw, Limits::default()).unwrap();
    assert!(segment.data.is_empty());
    assert_eq!(segment.to_bytes(Limits::default()).unwrap().len(), 20);
}

#[test]
fn every_short_header_length_is_truncation() {
    for available in 0..HEADER_LEN {
        assert_eq!(
            Segment::parse(&LITERAL[..available], Limits::default()).unwrap_err(),
            Error::TruncatedHeader { available }
        );
    }
}

#[test]
fn offsets_below_five_are_invalid() {
    for words in 0..5 {
        let mut raw = LITERAL.to_vec();
        raw[12] = words << 4;
        assert_eq!(
            Segment::parse(&raw, Limits::default()).unwrap_err(),
            Error::InvalidDataOffset { words }
        );
    }
}

#[test]
fn options_are_explicitly_unsupported() {
    let mut raw = LITERAL.to_vec();
    raw[12] = 6 << 4;
    raw.splice(20..20, [1, 1, 1, 1]); // Ordinary NOP options, never interpreted.
    assert_eq!(
        Segment::parse(&raw, Limits::default()).unwrap_err(),
        Error::OptionsUnsupported { words: 6 }
    );
    let header = Header {
        off: 6,
        ..Header::default()
    };
    assert_eq!(
        header.to_bytes().unwrap_err(),
        Error::OptionsUnsupported { words: 6 }
    );
}

#[test]
fn nonce_and_reserved_bits_are_explicitly_unsupported() {
    for bits in [1, 2, 4, 8] {
        let mut raw = LITERAL.to_vec();
        raw[12] |= bits;
        assert_eq!(
            Segment::parse(&raw, Limits::default()).unwrap_err(),
            Error::ReservedBitsUnsupported { bits }
        );
    }
}

#[test]
fn checksum_zero_and_nonzero_are_never_recomputed() {
    for checksum in [0, 0x8000, 0xffff] {
        let segment = Segment {
            header: Header {
                checksum,
                ..Header::default()
            },
            data: b"changed opaque data",
        };
        let raw = segment.to_bytes(Limits::default()).unwrap();
        assert_eq!(&raw[16..18], &checksum.to_be_bytes());
        assert_eq!(segment.header.checksum, checksum);
    }
}

#[test]
fn complete_segment_limit_includes_header() {
    let exact = Limits {
        max_segment_bytes: LITERAL.len() as u32,
    };
    let smaller = Limits {
        max_segment_bytes: exact.max_segment_bytes - 1,
    };
    let segment = Segment::parse(LITERAL, exact).unwrap();
    let error = Error::SegmentLimit {
        length: LITERAL.len(),
        limit: smaller.max_segment_bytes,
    };
    assert_eq!(Segment::parse(LITERAL, smaller).unwrap_err(), error);
    assert_eq!(segment.to_bytes(smaller).unwrap_err(), error);
    assert_eq!(segment.to_bytes(exact).unwrap(), LITERAL);
    assert!(matches!(
        segment.to_bytes(Limits {
            max_segment_bytes: 0
        }),
        Err(Error::SegmentLimit { .. })
    ));
}

#[test]
fn mutation_replaces_fields_and_preserves_the_original_input() {
    let mut segment = Segment::parse(LITERAL, Limits::default()).unwrap();
    segment.header.sport = 0x8000;
    segment.header.seq = 0xffffffff;
    segment.header.flags = 0x18;
    segment.data = b"new";
    let raw = segment.to_bytes(Limits::default()).unwrap();
    assert_eq!(&raw[..2], &[0x80, 0]);
    assert_eq!(&raw[4..8], &[0xff; 4]);
    assert_eq!(raw[13], 0x18);
    assert_eq!(&raw[16..18], &[0x12, 0x34]);
    assert_eq!(&raw[20..], b"new");
    assert_eq!(&LITERAL[20..], b"rail");
}

#[test]
fn binary_payload_and_repeated_serialization_are_exact() {
    let payload: Vec<u8> = (0..=255).chain([0, 0]).collect();
    let segment = Segment {
        header: Header::default(),
        data: &payload,
    };
    let first = segment.to_bytes(Limits::default()).unwrap();
    assert_eq!(&first[20..], payload);
    assert_eq!(segment.to_bytes(Limits::default()).unwrap(), first);
    assert_eq!(
        Segment::parse(&first, Limits::default()).unwrap().data,
        payload
    );
}
