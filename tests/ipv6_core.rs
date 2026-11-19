#![cfg(feature = "protocols")]
use octetrail::ipv6::{checksum, Body, Error, Extension, Header, Packet};

fn literal(plen: u16, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; 40];
    raw[0] = 0x60;
    raw[4..6].copy_from_slice(&plen.to_be_bytes());
    raw[6] = next;
    raw[7] = 32;
    raw.extend_from_slice(payload);
    raw
}

#[test]
fn short_headers_and_any_version() {
    for size in 0..40 {
        assert_eq!(Header::parse(&vec![0; size]), Err(Error::Short(size, 40)));
    }
    let mut raw = literal(0, 6, b"");
    raw[0] = 0x40;
    let h = Header::parse(&raw).unwrap();
    assert_eq!(h.v_fc_flow >> 28, 4);
    assert_eq!(h.to_bytes()[..], raw[..]);
}

#[test]
fn payload_is_plen_bytes_or_everything() {
    let p = Packet::parse(&literal(4, 6, b"notepadding")).unwrap();
    assert_eq!((p.rest, p.next, p.error), ((40, 44), Some(6), None));
    let p = Packet::parse(&literal(0, 6, b"all of it")).unwrap();
    assert_eq!(p.rest, (40, 49));
    let p = Packet::parse(&literal(100, 6, b"cut")).unwrap();
    assert_eq!(p.rest, (40, 43));
}

#[test]
fn chain_of_every_extension() {
    let mut payload = vec![43, 0, 1, 0, 0, 5, 1, 9]; // hop-by-hop: PadN, Pad1, option 5
    payload.extend([44, 2, 0, 1, 0, 0, 0, 0]); // routing with one address
    payload.extend([0x20; 16]);
    payload.extend([51, 0, 0x00, 0x09, 0, 0, 0, 7]); // fragment, offset 1, more
    payload.extend([60, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2]); // AH, 24 bytes
    payload.extend([b'a'; 12]);
    payload.extend([50, 0, 0, 0, 0, 0, 0, 0]); // destination options, 8 bytes
    payload.extend(b"espdata!");
    let raw = literal(0, 0, &payload);
    let p = Packet::parse(&raw).unwrap();
    let kinds: Vec<u8> = p.extensions.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [0, 43, 44, 51, 60, 50]);
    assert_eq!(
        (p.next, p.rest, p.error),
        (None, (raw.len(), raw.len()), None)
    );
    let routing = &p.extensions[1];
    assert_eq!(routing.body, Body::Routing(vec![(56, 72)]));
    assert_eq!(routing.length, 24);
    assert_eq!(p.extensions[2].fields, [51, 0, 9, 7]);
    let ah = &p.extensions[3];
    assert_eq!((ah.length, ah.data.1), (24, raw.len()));
    assert_eq!(ah.body, Body::Ah((92, 104)));
    let esp = &p.extensions[5];
    assert_eq!(
        (esp.fields.clone(), esp.data),
        (vec![0x6573_7064, 0x6174_6121], (raw.len(), raw.len()))
    );
}

#[test]
fn a_short_extension_keeps_the_ones_before_it() {
    let raw = literal(0, 44, &[0, 0, 0, 0, 0, 0, 0, 0, 59]);
    let p = Packet::parse(&raw).unwrap();
    assert_eq!(p.extensions.len(), 1);
    assert_eq!(p.error, Some(Error::Short(1, 2)));
}

#[test]
fn ah_with_zero_length_has_no_auth_data() {
    let ext =
        Extension::parse(51, &[59, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(
        (ext.length, ext.data, ext.body),
        (8, (12, 18), Body::Ah((12, 12)))
    );
}

#[test]
fn checksum_pads_an_odd_tail() {
    assert_eq!(checksum(&[b"\x01"]), !0x0100);
    assert_eq!(checksum(&[b"\x00\x01", b"\xf2\x03"]), !0xf204);
}
