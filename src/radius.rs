//! RADIUS attributes as dpkt 1.9.8 reads them.
//! Offsets index the buffer that was passed in.

/// One byte is left where an attribute needs at least two; it starts at `at`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortAttr {
    pub at: usize,
}

/// `(type, value_start, value_end)` for each attribute in `buf`.
///
/// As in dpkt, a length below 2 ends the list, a value is cut to the bytes
/// present, and an attribute moves past `length` bytes.
pub fn attrs(buf: &[u8]) -> Result<Vec<(u8, usize, usize)>, ShortAttr> {
    let n = buf.len();
    let mut at = 0;
    let mut found = Vec::new();
    while at < n {
        if n - at < 2 {
            return Err(ShortAttr { at });
        }
        let length = usize::from(buf[at + 1]);
        if length < 2 {
            break;
        }
        let start = (at + 2).min(n);
        let end = (at + length).min(n);
        found.push((buf[at], start, end));
        at += length;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_stop_at_a_short_length() {
        let buf = b"\x01\x06user\x02\x0apassword\x00\x00";
        assert_eq!(attrs(buf).unwrap(), vec![(1, 2, 6), (2, 8, 16)]);
        assert_eq!(attrs(b"\x01\x09ab").unwrap(), vec![(1, 2, 4)]);
        assert_eq!(attrs(b"").unwrap(), vec![]);
    }

    #[test]
    fn one_byte_left_is_an_error() {
        assert_eq!(attrs(b"\x01\x03a\x05").unwrap_err(), ShortAttr { at: 3 });
        assert_eq!(attrs(b"\x07").unwrap_err(), ShortAttr { at: 0 });
    }
}
