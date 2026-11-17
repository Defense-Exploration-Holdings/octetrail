//! DTP type-length-value entries as dpkt 1.9.8 reads them.
//! Offsets index the whole packet, starting at the one-byte version.

pub type Range = (usize, usize);

pub const HEADER_LEN: usize = 1;

/// An entry header is cut off; `have` bytes were left.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortTlv {
    pub have: usize,
}

/// `(type, value)` for each entry from `buf[start..]`. A value is cut to the
/// bytes present.
pub fn tlvs(buf: &[u8], start: usize) -> Result<Vec<(u16, Range)>, ShortTlv> {
    let n = buf.len();
    let mut at = start.min(n);
    let mut found = Vec::new();
    while at < n {
        if n - at < 4 {
            return Err(ShortTlv { have: n - at });
        }
        let kind = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let len = usize::from(u16::from_be_bytes([buf[at + 2], buf[at + 3]]));
        let end = (at + 4 + len).min(n);
        found.push((kind, (at + 4, end)));
        at = end;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_cut_to_the_buffer() {
        let found = tlvs(b"\x01\x00\x01\x00\x02ab\x00\x04\x00\x09mac", 1).unwrap();
        assert_eq!(found, vec![(1, (5, 7)), (4, (11, 14))]);
        assert_eq!(tlvs(b"\x01\x00\x01", 1).unwrap_err(), ShortTlv { have: 2 });
    }
}
