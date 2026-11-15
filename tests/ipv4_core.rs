use octetrail::ipv4::{checksum, Error, Header, Packet};

const HEADER: [u8; 20] = [
    0x45, 0, 0, 24, 0x12, 0x34, 0x40, 0, 64, 253, 0x3b, 0x7e, 192, 0, 2, 1, 198, 51, 100, 2,
];

fn literal() -> Vec<u8> {
    [HEADER.as_slice(), b"rail"].concat()
}

#[test]
fn literal_header_fields_and_borrowed_payload() {
    let raw = literal();
    let p = Packet::parse(&raw).unwrap();
    assert_eq!(p.header.src, [192, 0, 2, 1]);
    assert_eq!(p.header.dst, [198, 51, 100, 2]);
    assert_eq!(
        (p.header.total_length, p.header.id, p.header.flags_offset),
        (24, 0x1234, 0x4000)
    );
    assert_eq!(
        (p.header.ttl, p.header.protocol, p.header.checksum),
        (64, 253, 0x3b7e)
    );
    assert_eq!(p.data, b"rail");
    assert_eq!(p.data.as_ptr(), raw[20..].as_ptr());
}

#[test]
fn checksum_known_words_odd_byte_and_empty_input() {
    let mut zeroed = HEADER;
    zeroed[10..12].fill(0);
    assert_eq!(checksum(&zeroed), 0x3b7e);
    assert_eq!(checksum(&HEADER), 0);
    assert_eq!(checksum(&[1, 2, 3]), 0xfbfd);
    assert_eq!(checksum(&[]), 0xffff);
}

#[test]
fn zero_sum_updates_length_checksum_and_emits_literal() {
    let mut p = Packet {
        header: Header {
            checksum: 0,
            total_length: 20,
            ..Header::parse(&HEADER).unwrap()
        },
        data: b"rail",
    };
    assert_eq!(p.to_bytes().unwrap(), literal());
    assert_eq!((p.header.total_length, p.header.checksum), (24, 0x3b7e));
    assert_eq!(p.to_bytes().unwrap(), literal());
}

#[test]
fn nonzero_sum_retains_explicit_fields_until_reset() {
    let raw = literal();
    let mut p = Packet::parse(&raw).unwrap();
    p.data = b"other";
    let bytes = p.to_bytes().unwrap();
    assert_eq!(&bytes[..20], &HEADER);
    assert_eq!(&bytes[20..], b"other");
    p.header.checksum = 0;
    let refreshed = p.to_bytes().unwrap();
    assert_eq!(p.header.total_length, 25);
    assert_eq!(checksum(&refreshed[..20]), 0);
}

#[test]
fn all_short_header_lengths_are_truncation() {
    for n in 0..20 {
        assert_eq!(
            Packet::parse(&HEADER[..n]).unwrap_err(),
            Error::Truncated {
                available: n,
                required: 20
            }
        );
    }
}

#[test]
fn options_version_and_too_small_ihl_are_distinct() {
    for (first, error) in [
        (0x46, Error::OptionsUnsupported),
        (0x65, Error::UnsupportedVersion(6)),
        (0x44, Error::InvalidHeaderLength),
    ] {
        let mut raw = literal();
        raw[0] = first;
        assert_eq!(Packet::parse(&raw).unwrap_err(), error);
    }
}

#[test]
fn declared_payload_is_complete_and_trailing_bytes_are_ignored() {
    assert_eq!(
        Packet::parse(&literal()[..23]).unwrap_err(),
        Error::Truncated {
            available: 23,
            required: 24
        }
    );
    let mut raw = literal();
    raw.extend_from_slice(b"padding");
    assert_eq!(Packet::parse(&raw).unwrap().data, b"rail");
    for length in [0u16, 19] {
        let mut bytes = literal();
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            Packet::parse(&bytes).unwrap_err(),
            if length == 0 {
                Error::OffloadLengthUnsupported
            } else {
                Error::InvalidTotalLength(length)
            }
        );
    }
}

#[test]
fn checksum_is_not_implicitly_validated_on_parse() {
    let mut raw = literal();
    raw[10..12].copy_from_slice(&1u16.to_be_bytes());
    let mut p = Packet::parse(&raw).unwrap();
    assert_eq!(p.header.checksum, 1);
    assert_eq!(p.to_bytes().unwrap(), raw);
}

#[test]
fn default_header_and_valid_zero_checksum_are_stable() {
    let mut p = Packet {
        header: Header::default(),
        data: b"",
    };
    assert_eq!(
        p.to_bytes().unwrap(),
        [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0x7a, 0xeb, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    p.header.id = 0x7aeb;
    p.header.checksum = 0;
    let raw = p.to_bytes().unwrap();
    assert_eq!(p.header.checksum, 0);
    assert_eq!(checksum(&raw), 0);
    assert_eq!(p.to_bytes().unwrap(), raw);
}

#[test]
fn maximum_datagram_bound_is_enforced_before_output_allocation() {
    let payload = vec![b'x'; 65515];
    let mut p = Packet {
        header: Header::default(),
        data: &payload,
    };
    assert_eq!(p.to_bytes().unwrap().len(), 65535);
    assert_eq!(p.header.total_length, 65535);
    let too_large = vec![b'x'; 65516];
    p.data = &too_large;
    assert_eq!(p.to_bytes().unwrap_err(), Error::TooLarge);
}
