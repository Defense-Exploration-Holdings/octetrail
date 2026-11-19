#![cfg(feature = "protocols")]
use octetrail::ethernet::{crc32, Error, Frame, Kind, Llc, Stack, HEADER_LEN, ISL_LEN};

fn header(kind: u16) -> Vec<u8> {
    let mut out = vec![2; 12];
    out.extend_from_slice(&kind.to_be_bytes());
    out
}

fn isl() -> Vec<u8> {
    let mut tag = vec![0x01, 0, 0x0c, 0, 0, 3, 2, 2, 2, 2, 2, 2, 0, 0x26];
    tag.resize(ISL_LEN, 0);
    tag
}

#[test]
fn short_headers_report_what_they_found() {
    for length in 0..HEADER_LEN {
        let err = Frame::parse(&vec![0; length]).unwrap_err();
        assert_eq!(
            err,
            Error::Short {
                have: length,
                need: HEADER_LEN
            }
        );
    }
    let mut raw = isl();
    raw.truncate(20);
    assert_eq!(
        Frame::parse(&raw).unwrap_err(),
        Error::Short {
            have: 20,
            need: ISL_LEN
        }
    );
    let mut raw = isl();
    raw.extend_from_slice(&[0; 5]);
    assert_eq!(Frame::parse(&raw).unwrap_err(), Error::Struct);
}

#[test]
fn frame_kinds_follow_the_type_and_payload() {
    assert_eq!(Frame::parse(&header(0x86dd)).unwrap().kind, Kind::Typed);
    assert_eq!(Frame::parse(&header(0)).unwrap().kind, Kind::Unknown);
    let mut novell = header(40);
    novell.extend_from_slice(&[0xff, 0xff, 0]);
    assert_eq!(Frame::parse(&novell).unwrap().kind, Kind::Novell);
}

#[test]
fn llc_tail_is_split_into_padding_fcs_and_trailer() {
    let mut raw = header(7);
    raw.extend_from_slice(b"\xf0\xf0\x03note");
    raw.extend_from_slice(&[0; 39]);
    raw.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    raw.extend_from_slice(b"tr");
    let Kind::Llc {
        llc,
        padding,
        fcs,
        trailer,
    } = Frame::parse(&raw).unwrap().kind
    else {
        panic!("not an 802.3 frame");
    };
    assert_eq!(llc, (14, 21));
    assert_eq!(padding, Some((21, 60)));
    assert_eq!(fcs, Some(0x1234_5678));
    assert_eq!(trailer, Some((64, 66)));
}

#[test]
fn stacks_stop_where_dpkt_stops() {
    let tags = [0, 5, 0x81, 0, 0, 6, 0x81, 0, 0, 7, 0x86, 0xdd];
    let stack = Stack::parse(&tags, 0x88a8).unwrap();
    assert_eq!(
        (stack.tags, stack.next, stack.payload),
        (vec![0, 4], 0x8100, 8)
    );
    let labels = [0, 1, 0, 64, 0, 1, 1, 64, 0x45];
    let stack = Stack::parse(&labels, 0x8847).unwrap();
    assert_eq!(
        (stack.labels, stack.next, stack.payload),
        (vec![0, 4], 0x0800, 8)
    );
    assert_eq!(
        Stack::parse(&labels[..8], 0x8847).unwrap_err(),
        Error::Index
    );
    assert_eq!(
        Stack::parse(&labels[..2], 0x8847).unwrap_err(),
        Error::Short { have: 2, need: 4 }
    );
    let mut ecw = vec![0, 1, 1, 64, 0, 0, 0, 0];
    ecw.extend_from_slice(&header(0x88b5));
    let stack = Stack::parse(&ecw, 0x8847).unwrap();
    assert_eq!((stack.next, stack.payload), (0x6558, 8));
}

#[test]
fn llc_snap_needs_five_more_bytes() {
    let snap = Llc::parse(b"\xaa\xaa\x03\x00\x00\x0c\x20\x00rest").unwrap();
    assert_eq!((snap.snap, snap.payload), (Some((0x0c, 0x2000)), 8));
    assert_eq!(Llc::parse(b"\xaa\xaa\x03\x00").unwrap_err(), Error::Struct);
    assert_eq!(
        Llc::parse(b"\x42").unwrap_err(),
        Error::Short { have: 1, need: 3 }
    );
    assert_eq!(Llc::parse(b"\x42\x42\x03").unwrap().snap, None);
}

#[test]
fn long_inputs_parse_in_one_pass() {
    let mut raw: Vec<u8> = std::iter::repeat_n(isl(), 50_000).flatten().collect();
    raw.extend_from_slice(&header(0x88b5));
    let frame = Frame::parse(&raw).unwrap();
    assert_eq!(frame.header, 50_000 * ISL_LEN);
    assert_eq!(crc32(&raw[..0]), 0);
}
