//! RIP route entries as dpkt 1.9.8 reads them.
//! Offsets index the whole packet, starting at the four-byte RIP header.

pub const HEADER_LEN: usize = 4;
pub const ENTRY_LEN: usize = 20;
/// The address family that marks an authentication entry.
pub const AUTH_FAMILY: u16 = 0xFFFF;

/// The last entry is cut off; `have` bytes were left.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortEntry {
    pub have: usize,
}

/// `(start, is_auth)` for each 20-byte entry from `buf[start..]`.
pub fn entries(buf: &[u8], start: usize) -> Result<Vec<(usize, bool)>, ShortEntry> {
    let n = buf.len();
    let mut at = start.min(n);
    let mut found = Vec::with_capacity((n - at) / ENTRY_LEN);
    while at < n {
        if n - at < ENTRY_LEN {
            return Err(ShortEntry { have: n - at });
        }
        let family = u16::from_be_bytes([buf[at], buf[at + 1]]);
        found.push((at, family == AUTH_FAMILY));
        at += ENTRY_LEN;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_twenty_bytes() {
        let mut buf = vec![2, 2, 0, 0, 0xff, 0xff];
        buf.extend_from_slice(&[0; 18]);
        buf.extend_from_slice(&[0, 2]);
        buf.extend_from_slice(&[0; 18]);
        assert_eq!(
            entries(&buf, HEADER_LEN).unwrap(),
            vec![(4, true), (24, false)]
        );
        buf.push(0);
        assert_eq!(
            entries(&buf, HEADER_LEN).unwrap_err(),
            ShortEntry { have: 1 }
        );
    }
}
