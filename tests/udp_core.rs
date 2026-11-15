use octetrail::udp::{Datagram, Error, Header, Limits, HEADER_LEN};

// Independent wire fields: 12345, 54321, 12, 0x1234, then opaque ASCII.
const LITERAL: &[u8] = &[
    0x30, 0x39, 0xd4, 0x31, 0, 12, 0x12, 0x34, b'r', b'a', b'i', b'l',
];

#[test]
fn literal_fields_network_order_and_borrowed_payload() {
    let packet = Datagram::parse(LITERAL, Limits::default()).unwrap();
    assert_eq!(
        packet.header,
        Header {
            sport: 12345,
            dport: 54321,
            ulen: 12,
            checksum: 0x1234
        }
    );
    assert_eq!(packet.data, b"rail");
    assert_eq!(packet.data.as_ptr(), LITERAL[HEADER_LEN..].as_ptr());
    assert_eq!(packet.to_bytes(Limits::default()).unwrap(), LITERAL);
}

#[test]
fn defaults_and_unsigned_wire_fields_have_independent_bytes() {
    assert_eq!(Header::default().to_bytes(), [0xde, 0xad, 0, 0, 0, 8, 0, 0]);
    let header = Header {
        sport: 65535,
        dport: 32768,
        ulen: 0,
        checksum: 65535,
    };
    let raw = [255, 255, 128, 0, 0, 0, 255, 255];
    assert_eq!(header.to_bytes(), raw);
    assert_eq!(Header::parse(&raw).unwrap(), header);
}

#[test]
fn every_incomplete_header_is_truncation() {
    for available in 0..HEADER_LEN {
        let error = Error::TruncatedHeader { available };
        assert_eq!(Header::parse(&LITERAL[..available]).unwrap_err(), error);
        assert_eq!(
            Datagram::parse(&LITERAL[..available], Limits::default()).unwrap_err(),
            error
        );
    }
}

#[test]
fn empty_payload_is_an_eight_byte_datagram() {
    let raw = [0xde, 0xad, 0, 0, 0, 8, 0, 0];
    let packet = Datagram::parse(&raw, Limits::default()).unwrap();
    assert!(packet.data.is_empty());
    assert_eq!(packet.to_bytes(Limits::default()).unwrap(), raw);
}

#[test]
fn declared_length_does_not_trim_or_extend_the_supplied_payload() {
    for ulen in [0_u16, 7, 8, 12, 65535] {
        let mut raw = LITERAL.to_vec();
        raw[4..6].copy_from_slice(&ulen.to_be_bytes());
        let packet = Datagram::parse(&raw, Limits::default()).unwrap();
        assert_eq!(packet.header.ulen, ulen);
        assert_eq!(packet.data, b"rail");
        assert_eq!(packet.to_bytes(Limits::default()).unwrap(), raw);
    }
}

#[test]
fn payload_mutations_preserve_caller_length_and_checksum_including_zero() {
    for checksum in [0, 0x8000, 0xffff] {
        let mut packet = Datagram {
            header: Header {
                checksum,
                ..Header::default()
            },
            data: b"rail",
        };
        packet.data = b"ordinary changed payload";
        let raw = packet.to_bytes(Limits::default()).unwrap();
        assert_eq!(&raw[4..8], &[0, 8, (checksum >> 8) as u8, checksum as u8]);
        assert_eq!(&raw[8..], b"ordinary changed payload");
        assert_eq!(packet.header.ulen, 8);
        assert_eq!(packet.header.checksum, checksum);
    }
}

#[test]
fn mutation_is_exact_and_does_not_change_input() {
    let mut packet = Datagram::parse(LITERAL, Limits::default()).unwrap();
    packet.header.sport = 65535;
    packet.header.ulen = 11;
    packet.data = b"new";
    assert_eq!(
        packet.to_bytes(Limits::default()).unwrap(),
        [255, 255, 0xd4, 0x31, 0, 11, 0x12, 0x34, b'n', b'e', b'w']
    );
    assert_eq!(&LITERAL[8..], b"rail");
}

#[test]
fn complete_buffer_budget_is_independent_of_stored_length() {
    let packet = Datagram::parse(LITERAL, Limits::default()).unwrap();
    for limit in [0, 7, 11] {
        let limits = Limits {
            max_datagram_bytes: limit,
        };
        let error = Error::DatagramLimit { length: 12, limit };
        assert_eq!(Datagram::parse(LITERAL, limits).unwrap_err(), error);
        assert_eq!(packet.to_bytes(limits).unwrap_err(), error);
    }
    assert_eq!(
        packet
            .to_bytes(Limits {
                max_datagram_bytes: 12
            })
            .unwrap(),
        LITERAL
    );
}

#[test]
fn default_budget_boundary_is_checked_before_serialization_allocation() {
    let payload = vec![b'x'; 65527];
    let packet = Datagram {
        header: Header::default(),
        data: &payload,
    };
    let raw = packet.to_bytes(Limits::default()).unwrap();
    assert_eq!(raw.len(), 65535);
    assert_eq!(&raw[..8], &[0xde, 0xad, 0, 0, 0, 8, 0, 0]);
    assert_eq!(
        Datagram::parse(&raw, Limits::default()).unwrap().data.len(),
        65527
    );
    let too_large = vec![b'x'; 65536];
    assert!(matches!(
        Datagram::parse(&too_large, Limits::default()),
        Err(Error::DatagramLimit {
            length: 65536,
            limit: 65535
        })
    ));
    let packet = Datagram {
        header: Header::default(),
        data: &too_large[8..],
    };
    assert!(matches!(
        packet.to_bytes(Limits::default()),
        Err(Error::DatagramLimit {
            length: 65536,
            limit: 65535
        })
    ));
}
