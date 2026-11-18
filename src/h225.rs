//! H.225.0 information element boundaries as dpkt 1.9.8 walks them.
//! Offsets index the buffer that was passed in.

/// The information element type whose length takes two bytes.
pub const USER_TO_USER: u8 = 126;

/// The elements found in a buffer of information elements.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Elements {
    /// `(start, end)` of each whole element. `end` is clamped to the buffer,
    /// so an element whose length runs past the end ends there, as dpkt's
    /// slice does.
    pub spans: Vec<(usize, usize)>,
    /// Where an element starts whose length bytes are cut off. dpkt fails on
    /// it, and nothing follows it.
    pub cut: Option<usize>,
}

/// Split `buf` into elements the way dpkt's `H225.unpack` loop does: a type
/// byte with the high bit set has no length or value, type 126 has a 2-byte
/// length and every other type a 1-byte length.
pub fn elements(buf: &[u8]) -> Elements {
    let mut found = Elements::default();
    let mut pos = 0usize;
    while pos < buf.len() {
        let t = buf[pos];
        let (header, len) = if t & 0x80 != 0 {
            (1, 0)
        } else if t == USER_TO_USER {
            match buf.get(pos + 1..pos + 3) {
                Some(&[hi, lo]) => (3, usize::from(u16::from_be_bytes([hi, lo]))),
                _ => {
                    found.cut = Some(pos);
                    return found;
                }
            }
        } else {
            match buf.get(pos + 1) {
                Some(&n) => (2, usize::from(n)),
                None => {
                    found.cut = Some(pos);
                    return found;
                }
            }
        };
        let end = (pos + header + len).min(buf.len());
        found.spans.push((pos, end));
        pos = end;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_by_type() {
        let found = elements(b"\xa1\x04\x02ab\x7e\x00\x01x\x28\x00");
        assert_eq!(found.spans, [(0, 1), (1, 5), (5, 9), (9, 11)]);
        assert_eq!(found.cut, None);
    }

    #[test]
    fn long_and_cut_elements() {
        assert_eq!(
            elements(b"\x28\x09abc"),
            Elements {
                spans: vec![(0, 5)],
                cut: None
            }
        );
        assert_eq!(
            elements(b"\xa1\x28"),
            Elements {
                spans: vec![(0, 1)],
                cut: Some(1)
            }
        );
        assert_eq!(elements(b"\x7e\x00").cut, Some(0));
    }
}
