//! VRRP address lists as dpkt 1.9.8 reads them. Ranges index the bytes after
//! the eight-byte header, and are cut to the bytes present.

pub type Range = (usize, usize);

pub const HEADER_LEN: usize = 8;

/// The addresses and authentication data after a VRRP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    pub addrs: Vec<Range>,
    pub auth: Range,
}

/// Split `data` into `count` four-byte addresses and the authentication data.
/// As in dpkt, the authentication data starts four bytes after the last
/// address offset, so a count of zero skips four bytes.
pub fn layout(count: u8, data: &[u8]) -> Layout {
    let clamp = |at: usize| at.min(data.len());
    let mut addrs = Vec::with_capacity(usize::from(count));
    let mut off = 0;
    for n in 0..usize::from(count) {
        off = 4 * n;
        addrs.push((clamp(off), clamp(off + 4)));
    }
    Layout {
        addrs,
        auth: (clamp(off + 4), data.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_count_skips_four_bytes() {
        assert_eq!(
            layout(0, b"abcdefg"),
            Layout {
                addrs: vec![],
                auth: (4, 7)
            }
        );
    }

    #[test]
    fn short_data_cuts_addresses() {
        let found = layout(3, b"abcdef");
        assert_eq!(found.addrs, vec![(0, 4), (4, 6), (6, 6)]);
        assert_eq!(found.auth, (6, 6));
    }
}
