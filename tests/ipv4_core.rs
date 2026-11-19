#![cfg(feature = "protocols")]
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
        opts: &[],
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
fn any_version_is_accepted_and_only_small_ihl_is_rejected() {
    for first in [0x05, 0x65, 0xf5] {
        let mut raw = literal();
        raw[0] = first;
        let p = Packet::parse(&raw).unwrap();
        assert_eq!((p.header.version_ihl, p.data), (first, b"rail".as_slice()));
    }
    for ihl in 0..5 {
        let mut raw = literal();
        raw[0] = 0x40 | ihl;
        assert_eq!(Packet::parse(&raw).unwrap_err(), Error::InvalidHeaderLength);
    }
}

#[test]
fn payload_is_sliced_like_dpkt() {
    let raw = literal();
    // A payload cut off by the buffer is kept as found.
    assert_eq!(Packet::parse(&raw[..23]).unwrap().data, b"rai");
    assert_eq!(Packet::parse(&raw[..20]).unwrap().data, b"");
    // Bytes beyond the declared length are dropped.
    let padded = [raw.as_slice(), b"padding"].concat();
    assert_eq!(Packet::parse(&padded).unwrap().data, b"rail");
    // A zero length keeps the rest of the buffer (segmentation offload).
    let mut offload = padded.clone();
    offload[2..4].fill(0);
    assert_eq!(Packet::parse(&offload).unwrap().data, b"railpadding");
    // A length inside the header leaves an empty payload.
    for length in [1u16, 19, 20] {
        let mut bytes = raw.clone();
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!((p.opts, p.data), (b"".as_slice(), b"".as_slice()));
    }
}

#[test]
fn short_options_are_kept_as_found() {
    let mut raw = literal();
    raw[0] = 0x4f;
    let p = Packet::parse(&raw).unwrap();
    assert_eq!((p.opts, p.data), (b"rail".as_slice(), b"".as_slice()));
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
        opts: &[],
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
        opts: &[],
        data: &payload,
    };
    assert_eq!(p.to_bytes().unwrap().len(), 65535);
    assert_eq!(p.header.total_length, 65535);
    let too_large = vec![b'x'; 65516];
    p.data = &too_large;
    p.header.checksum = 0;
    assert_eq!(p.to_bytes().unwrap_err(), Error::TooLarge);
    // An explicit checksum packs as assigned, so no length is computed.
    p.header.checksum = 1;
    assert_eq!(p.to_bytes().unwrap().len(), 65536);
}

#[test]
fn options_are_borrowed_checked_and_included_in_checksum() {
    let mut p = Packet {
        header: Header {
            version_ihl: 0x46,
            ..Header::default()
        },
        opts: &[1, 1, 1, 1],
        data: b"rail",
    };
    let raw = p.to_bytes().unwrap();
    assert_eq!(raw.len(), 28);
    assert_eq!(checksum(&raw[..24]), 0);
    let parsed = Packet::parse(&raw).unwrap();
    assert_eq!(parsed.opts, &[1, 1, 1, 1]);
    assert_eq!(parsed.opts.as_ptr(), raw[20..].as_ptr());
    assert_eq!(parsed.data, b"rail");
    assert_eq!(Packet::parse(&raw[..23]).unwrap().opts, &[1, 1, 1]);
    // Options are packed as assigned, whatever the IHL says.
    p.opts = &[];
    p.header.checksum = 0;
    assert_eq!(p.to_bytes().unwrap().len(), 24);
}

#[test]
fn pseudoheader_known_udp_words_and_length_bound() {
    // Independent network-word sum of the pseudoheader, UDP fields and "ok".
    let data = [0x12, 0x34, 0x56, 0x78, 0, 10, 0, 0, b'o', b'k'];
    assert_eq!(
        octetrail::ipv4::transport_checksum([192, 0, 2, 1], [198, 51, 100, 2], 17, &data).unwrap(),
        0x3b8b
    );
    assert_eq!(
        octetrail::ipv4::transport_checksum([0; 4], [0; 4], 6, &vec![0; 65536]).unwrap_err(),
        Error::TooLarge
    );
}

#[test]
fn packed_pseudoheader_matches_field_form_and_maps_udp_zero() {
    let src = [192, 0, 2, 1];
    let dst = [198, 51, 100, 2];
    let data = b"\x00\x6f\x00\xde\x00\x0e\x00\x00foobar";
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&src);
    pseudo[4..8].copy_from_slice(&dst);
    pseudo[9] = 17;
    pseudo[10..].copy_from_slice(&(data.len() as u16).to_be_bytes());
    assert_eq!(
        octetrail::ipv4::pseudo_checksum(&pseudo, data),
        octetrail::ipv4::transport_checksum(src, dst, 17, data).unwrap()
    );
    // A pseudoheader and payload whose sum folds to zero.
    let zero = [0xff; 12];
    let mut udp = zero;
    udp[9] = 17;
    let complement = !checksum(&udp);
    let fill = (!complement).to_be_bytes();
    assert_eq!(octetrail::ipv4::pseudo_checksum(&udp, &fill), u16::MAX);
}
