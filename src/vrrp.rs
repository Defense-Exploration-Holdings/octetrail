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
/// The authentication data starts right after the last address. dpkt starts it
/// four bytes later when `count` is zero.
pub fn layout(count: u8, data: &[u8]) -> Layout {
    let clamp = |at: usize| at.min(data.len());
    let addrs = (0..usize::from(count))
        .map(|n| (clamp(4 * n), clamp(4 * n + 4)))
        .collect();
    Layout {
        addrs,
        auth: (clamp(4 * usize::from(count)), data.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_count_starts_auth_at_zero() {
        assert_eq!(
            layout(0, b"abcdefg"),
            Layout {
                addrs: vec![],
                auth: (0, 7)
            }
        );
    }

    #[test]
    fn auth_follows_the_last_address() {
        let found = layout(2, b"aaaabbbbcc");
        assert_eq!(found.addrs, vec![(0, 4), (4, 8)]);
        assert_eq!(found.auth, (8, 10));
    }

    #[test]
    fn short_data_cuts_addresses() {
        let found = layout(3, b"abcdef");
        assert_eq!(found.addrs, vec![(0, 4), (4, 6), (6, 6)]);
        assert_eq!(found.auth, (6, 6));
    }
}
