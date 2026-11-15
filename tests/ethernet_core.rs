use octetrail::ethernet::{Error, Frame, Header, Limits, HEADER_LEN};

// Hand-assembled header followed by opaque user bytes, not protocol traffic.
const LITERAL: &[u8] = &[
    0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x88, 0xb5, b'a', b'b', b'c', 0, 0,
];

#[test]
fn literal_fields_and_borrowed_payload_are_exact() {
    let frame = Frame::parse(LITERAL, Limits::default()).unwrap();
    assert_eq!(frame.header.dst, [2, 0, 0, 0, 0, 1]);
    assert_eq!(frame.header.src, [2, 0, 0, 0, 0, 2]);
    assert_eq!(frame.header.ethertype, 0x88b5);
    assert_eq!(frame.data, b"abc\0\0");
    assert_eq!(frame.data.as_ptr(), LITERAL[HEADER_LEN..].as_ptr());
    assert_eq!(frame.to_bytes(Limits::default()).unwrap(), LITERAL);
}

#[test]
fn header_address_padding_truncation_and_network_order_are_explicit() {
    let header = Header::new(b"a", b"12345678", 0x88b5).unwrap();
    assert_eq!(
        header.to_bytes().unwrap(),
        [b'a', 0, 0, 0, 0, 0, b'1', b'2', b'3', b'4', b'5', b'6', 0x88, 0xb5]
    );
}

#[test]
fn all_short_header_lengths_are_truncation() {
    for length in 0..HEADER_LEN {
        assert_eq!(
            Frame::parse(&LITERAL[..length], Limits::default()).unwrap_err(),
            Error::TruncatedHeader { available: length }
        );
    }
    assert_eq!(
        Error::TruncatedHeader { available: 3 }.to_string(),
        "got 3, 14 needed at least"
    );
}

#[test]
fn length_reserved_and_link_encapsulation_types_are_explicitly_unsupported() {
    for ethertype in (0u16..0x0600).chain([0x8100, 0x88a8, 0x9100, 0x9200, 0x8847, 0x8848]) {
        let mut bytes = LITERAL.to_vec();
        bytes[12..14].copy_from_slice(&ethertype.to_be_bytes());
        assert_eq!(
            Frame::parse(&bytes, Limits::default()).unwrap_err(),
            Error::UnsupportedFraming { ethertype }
        );
        assert_eq!(
            Header::new(b"", b"", ethertype).unwrap_err(),
            Error::UnsupportedFraming { ethertype }
        );
    }
}

#[test]
fn network_types_do_not_trigger_payload_decoding() {
    for ethertype in [0x0600u16, 0x0800, 0x0806, 0x86dd, 0x88b5, 0xffff] {
        let mut bytes = LITERAL.to_vec();
        bytes[12..14].copy_from_slice(&ethertype.to_be_bytes());
        let frame = Frame::parse(&bytes, Limits::default()).unwrap();
        assert_eq!(frame.header.ethertype, ethertype);
        assert_eq!(frame.data, b"abc\0\0");
        assert_eq!(frame.to_bytes(Limits::default()).unwrap(), bytes);
    }
}

#[test]
fn complete_frame_limit_includes_header_for_parse_and_serialization() {
    let exact = Limits {
        max_frame_bytes: LITERAL.len() as u32,
    };
    let smaller = Limits {
        max_frame_bytes: LITERAL.len() as u32 - 1,
    };
    let frame = Frame::parse(LITERAL, exact).unwrap();
    assert_eq!(frame.to_bytes(exact).unwrap(), LITERAL);
    let expected = Error::FrameLimit {
        length: LITERAL.len(),
        limit: smaller.max_frame_bytes,
    };
    assert_eq!(Frame::parse(LITERAL, smaller).unwrap_err(), expected);
    assert_eq!(frame.to_bytes(smaller).unwrap_err(), expected);
    assert!(matches!(
        frame.to_bytes(Limits { max_frame_bytes: 0 }),
        Err(Error::FrameLimit { .. })
    ));
}

#[test]
fn mutation_serializes_new_fields_without_mutating_input() {
    let mut frame = Frame::parse(LITERAL, Limits::default()).unwrap();
    frame.header.dst = [1, 2, 3, 4, 5, 6];
    frame.header.ethertype = 0x88b6;
    frame.data = b"rail";
    assert_eq!(
        frame.to_bytes(Limits::default()).unwrap(),
        [1, 2, 3, 4, 5, 6, 2, 0, 0, 0, 0, 2, 0x88, 0xb6, b'r', b'a', b'i', b'l']
    );
    assert_eq!(LITERAL[0], 2);
    assert_eq!(&LITERAL[14..], b"abc\0\0");
}

#[test]
fn unsupported_mutated_header_is_rejected_before_serialization() {
    let mut frame = Frame::parse(LITERAL, Limits::default()).unwrap();
    frame.header.ethertype = 0x8100;
    assert_eq!(
        frame.to_bytes(Limits::default()).unwrap_err(),
        Error::UnsupportedFraming { ethertype: 0x8100 }
    );
}

#[test]
fn empty_payload_has_no_implicit_padding_or_fcs() {
    let frame = Frame {
        header: Header::new(b"", b"", 0x0800).unwrap(),
        data: b"",
    };
    assert_eq!(
        frame.to_bytes(Limits::default()).unwrap(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0]
    );
}
