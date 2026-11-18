//! Diameter AVP boundaries as dpkt 1.9.8 walks them. Offsets index the bytes
//! after the Diameter header that dpkt keeps.

/// Header bytes of one AVP: code, flags and a 24-bit length.
pub const AVP_HEADER_LEN: usize = 8;
const VENDOR_LEN: usize = 4;

/// Where one AVP starts, and where the bytes it reads end. `stop` is `None`
/// when a length below the header makes dpkt read to the end of the buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub stop: Option<usize>,
}

/// The AVPs read before the walk stops, and the offset of an AVP that fails:
/// one shorter than its header, or a vendor AVP with no room for the vendor id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Avps {
    pub spans: Vec<Span>,
    pub fails_at: Option<usize>,
}

/// The length of Python's `buf[start:stop]` for a buffer of `len` bytes.
fn slice_len(len: usize, start: usize, stop: i64) -> usize {
    let start = start.min(len);
    let stop = if stop >= 0 {
        usize::try_from(stop).map_or(len, |s| s.min(len))
    } else {
        len.saturating_sub(usize::try_from(stop.unsigned_abs()).unwrap_or(usize::MAX))
    };
    stop.saturating_sub(start)
}

/// Walk the AVPs the way dpkt does: each one moves past its header, its vendor
/// id when the vendor flag is set, and the data its length selects.
pub fn avps(data: &[u8]) -> Avps {
    let mut spans = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let rest = data.len() - at;
        if rest < AVP_HEADER_LEN {
            return Avps {
                spans,
                fails_at: Some(at),
            };
        }
        let vendor = data[at + 4] & 0x80 != 0;
        let length = u32::from_be_bytes([0, data[at + 5], data[at + 6], data[at + 7]]);
        let body = rest - AVP_HEADER_LEN;
        if vendor && body < VENDOR_LEN {
            return Avps {
                spans,
                fails_at: Some(at),
            };
        }
        let end = i64::from(length) - AVP_HEADER_LEN as i64;
        let size = if vendor {
            AVP_HEADER_LEN + VENDOR_LEN + slice_len(body, VENDOR_LEN, end)
        } else {
            AVP_HEADER_LEN + slice_len(body, 0, end)
        };
        let stop = (end >= 0).then_some(at + size);
        spans.push(Span { start: at, stop });
        at += size;
    }
    Avps {
        spans,
        fails_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avp(flags: u8, length: u32, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0, 1, 8, flags];
        out.extend_from_slice(&length.to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn plain_and_vendor() {
        let mut data = avp(0x40, 12, b"h002");
        data.extend(avp(0xc0, 16, b"\xde\xad\xbe\xefh002"));
        let found = avps(&data);
        assert_eq!(found.fails_at, None);
        assert_eq!(
            found.spans,
            vec![
                Span {
                    start: 0,
                    stop: Some(12)
                },
                Span {
                    start: 12,
                    stop: Some(28)
                }
            ]
        );
    }

    #[test]
    fn short_length_reads_to_the_end() {
        let data = avp(0, 4, b"abcdefgh");
        let found = avps(&data);
        assert_eq!(
            found.spans,
            vec![Span {
                start: 0,
                stop: None
            }]
        );
        assert_eq!(found.fails_at, Some(12));
    }

    #[test]
    fn failures() {
        assert_eq!(avps(b"\0\0\0").fails_at, Some(0));
        assert_eq!(avps(&avp(0x80, 12, b"ab")).fails_at, Some(0));
        let long = avp(0, 99, b"ab");
        assert_eq!(
            avps(&long).spans,
            vec![Span {
                start: 0,
                stop: Some(10)
            }]
        );
    }

    #[test]
    fn python_slices() {
        assert_eq!(slice_len(10, 0, -4), 6);
        assert_eq!(slice_len(10, 4, -8), 0);
        assert_eq!(slice_len(10, 4, 20), 6);
        assert_eq!(slice_len(3, 4, 2), 0);
    }
}
