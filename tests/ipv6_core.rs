use octetrail::ipv6::{encode, transport_checksum, Error, Extension, Header, Limits, Packet};

fn literal(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; 40];
    raw[0] = 0x60;
    raw[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    raw[6] = next;
    raw[7] = 32;
    raw.extend_from_slice(payload);
    raw
}

#[test]
fn every_short_base_header_is_need_data() {
    for size in 0..40 {
        assert_eq!(Header::parse(&vec![0; size]), Err(Error::TruncatedHeader));
    }
}

#[test]
fn fixed_fields_payload_borrow_and_trailing_padding() {
    let mut raw = literal(253, b"note");
    raw.extend_from_slice(b"padding");
    let packet = Packet::parse(&raw, Limits::default()).unwrap();
    assert_eq!(packet.data, b"note");
    assert_eq!(packet.data.as_ptr(), raw[40..].as_ptr());
    assert_eq!(packet.header.payload_length, 4);
    assert_eq!(packet.header.hop_limit, 32);
    assert_eq!(packet.protocol, 253);
    assert_eq!(packet.status, "complete");
    assert_eq!(
        encode(packet.header, &[], packet.data, Limits::default())
            .unwrap()
            .0,
        raw[..44]
    );
}

#[test]
fn ordered_duplicate_extensions_are_borrowed() {
    let data = [60, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, b'x'];
    let raw = literal(60, &data);
    let packet = Packet::parse(&raw, Limits::default()).unwrap();
    assert_eq!(packet.extensions.len(), 2);
    assert_eq!(packet.extensions[0].bytes.as_ptr(), raw[40..].as_ptr());
    assert_eq!(packet.data, b"x");
    assert_eq!(packet.protocol, 253);
    assert_eq!(
        encode(
            packet.header,
            &packet.extensions,
            packet.data,
            Limits::default()
        )
        .unwrap()
        .0,
        raw
    );
}

#[test]
fn any_non_atomic_fragment_stops_extension_traversal() {
    for (field, fragmented) in [(0u16, false), (1, true), (8, true), (9, true)] {
        let mut body = vec![253, 0];
        body.extend_from_slice(&field.to_be_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(b"notes");
        let raw = literal(44, &body);
        let packet = Packet::parse(&raw, Limits::default()).unwrap();
        assert_eq!(packet.fragmented, fragmented);
        assert_eq!(packet.data, b"notes");
    }
    let raw = literal(44, &[60, 0, 0, 1, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0]);
    let p = Packet::parse(&raw, Limits::default()).unwrap();
    assert!(p.fragmented);
    assert_eq!(p.extensions.len(), 1);
    assert_eq!(p.protocol, 60);
}

#[test]
fn incomplete_data_is_preserved_without_decoding() {
    let mut raw = literal(6, b"note");
    raw[5] = 12;
    let packet = Packet::parse(&raw, Limits::default()).unwrap();
    assert_eq!(packet.status, "truncated_payload");
    assert_eq!(packet.data, b"note");
    let raw = literal(0, &[6, 0, 0, 0]);
    let packet = Packet::parse(&raw, Limits::default()).unwrap();
    assert_eq!(packet.status, "incomplete_extension");
    assert!(packet.extensions.is_empty());
    assert_eq!(packet.data, &[6, 0, 0, 0]);
    let mut raw = literal(6, b"note");
    raw[5] = 0;
    assert_eq!(
        Packet::parse(&raw, Limits::default()).unwrap().status,
        "unsupported_zero_length"
    );
}

#[test]
fn extension_and_packet_limits_are_explicit() {
    let mut body = Vec::new();
    for index in 0..17 {
        body.extend_from_slice(&[if index == 16 { 253 } else { 60 }, 0, 0, 0, 0, 0, 0, 0]);
    }
    let raw = literal(60, &body);
    assert!(matches!(
        Packet::parse(&raw, Limits::default()),
        Err(Error::Limit)
    ));
    let raw = literal(60, &[253, 0, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(
        Packet::parse(
            &raw,
            Limits {
                max_extension_bytes: 7,
                ..Limits::default()
            }
        ),
        Err(Error::Limit)
    ));
    assert!(matches!(
        Packet::parse(&vec![0; 65576], Limits::default()),
        Err(Error::Limit)
    ));
}

#[test]
fn encoding_checks_chain_and_preserves_length() {
    let header = Header {
        next_header: 6,
        ..Header::default()
    };
    let (raw, protocol, _, _) = encode(header, &[], b"note", Limits::default()).unwrap();
    assert_eq!(raw[4..6], [0, 0]);
    assert_eq!(protocol, 6);
    let ext = Extension {
        kind: 60,
        bytes: &[6, 0, 0, 0, 0, 0, 0, 0],
    };
    assert_eq!(
        encode(header, &[ext], b"", Limits::default()).unwrap_err(),
        Error::InvalidExtension
    );
    assert_eq!(
        encode(header, &[], &vec![0; 65536], Limits::default()).unwrap_err(),
        Error::Limit
    );
    let header = Header {
        next_header: 43,
        ..header
    };
    let ext = Extension {
        kind: 43,
        bytes: &[6, 0, 0, 1, 0, 0, 0, 0],
    };
    assert!(!encode(header, &[ext], b"", Limits::default()).unwrap().3);
}

#[test]
fn independent_udp_pseudoheader_word_sums() {
    assert_eq!(
        transport_checksum([0; 16], [0; 16], 17, &[0, 1, 0, 2, 0, 8, 0, 0]).unwrap(),
        0xffdb
    );
    assert_eq!(
        transport_checksum([0; 16], [0; 16], 17, &[0, 1, 0, 2, 0, 10, 0, 0, 0xff, 0xd7]).unwrap(),
        0xffff
    );
}
