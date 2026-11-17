//! STUN attributes as dpkt 1.9.8 reads them.
//! Offsets index the buffer that was passed in.

pub const ATTR_HEADER_LEN: usize = 4;

/// Fewer than four bytes are left for an attribute header; it starts at `at`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortAttr {
    pub at: usize,
}

/// `(type, length, value_start, value_end)` for each attribute in `buf`.
///
/// As in dpkt, a value is cut to the bytes present and each attribute is
/// padded to a multiple of four bytes.
pub fn attrs(buf: &[u8]) -> Result<Vec<(u16, u16, usize, usize)>, ShortAttr> {
    let n = buf.len();
    let mut at = 0;
    let mut found = Vec::new();
    while at < n {
        if n - at < ATTR_HEADER_LEN {
            return Err(ShortAttr { at });
        }
        let kind = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let length = u16::from_be_bytes([buf[at + 2], buf[at + 3]]);
        let start = at + ATTR_HEADER_LEN;
        let end = (start + usize::from(length)).min(n);
        found.push((kind, length, start, end));
        let padded = usize::from(length).div_ceil(ATTR_HEADER_LEN) * ATTR_HEADER_LEN;
        at = start + padded;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_padded_to_four_bytes() {
        let buf = b"\x00\x06\x00\x03abc\x00\x80\x28\x00\x04wxyz";
        assert_eq!(attrs(buf).unwrap(), vec![(6, 3, 4, 7), (0x8028, 4, 12, 16)]);
        assert_eq!(attrs(b"\x00\x01\x00\x09ab").unwrap(), vec![(1, 9, 4, 6)]);
    }

    #[test]
    fn a_short_header_is_an_error() {
        assert_eq!(
            attrs(b"\x00\x01\x00\x00\x00\x02").unwrap_err(),
            ShortAttr { at: 4 }
        );
    }
}
