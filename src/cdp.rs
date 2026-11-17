//! CDP type-length-value entries as dpkt 1.9.8 reads them.
//! Offsets index the whole packet, starting at the four-byte CDP header.

pub type Range = (usize, usize);

pub const HEADER_LEN: usize = 4;
pub const TLV_HEADER_LEN: usize = 4;
/// The address list entry has a four-byte address count after its header.
pub const ADDRESSES_HEADER_LEN: usize = 8;
pub const ADDRESS: u16 = 2;

/// An entry header is cut off: `have` bytes were left and `need` are read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortTlv {
    pub have: usize,
    pub need: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tlv {
    pub kind: u16,
    pub len: u16,
    /// The address count, for an address list entry.
    pub addresses: Option<u32>,
    /// The entry value. A nonzero `len` shorter than the header cuts that
    /// many bytes short of the header length from the end of the packet, as
    /// dpkt's slice does; a zero `len` takes the rest of the packet.
    pub data: Range,
}

/// Read entries from `buf[start..]` to the end. Each entry starts where the
/// previous entry's value ends, so every step is at least four bytes.
pub fn tlvs(buf: &[u8], start: usize) -> Result<Vec<Tlv>, ShortTlv> {
    let n = buf.len();
    let mut at = start.min(n);
    let mut found = Vec::new();
    while at < n {
        let have = n - at;
        if have < TLV_HEADER_LEN {
            return Err(ShortTlv {
                have,
                need: TLV_HEADER_LEN,
            });
        }
        let kind = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let header = if kind == ADDRESS {
            ADDRESSES_HEADER_LEN
        } else {
            TLV_HEADER_LEN
        };
        if have < header {
            return Err(ShortTlv { have, need: header });
        }
        let len = u16::from_be_bytes([buf[at + 2], buf[at + 3]]);
        let addresses = (kind == ADDRESS)
            .then(|| u32::from_be_bytes([buf[at + 4], buf[at + 5], buf[at + 6], buf[at + 7]]));
        let data_start = at + header;
        let declared = usize::from(len);
        let data_end = if declared == 0 {
            n
        } else if declared >= header {
            (data_start + declared - header).min(n)
        } else {
            n.saturating_sub(header - declared).max(data_start)
        };
        found.push(Tlv {
            kind,
            len,
            addresses,
            data: (data_start, data_end),
        });
        at = data_end.max(data_start);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_follow_their_lengths() {
        let buf = b"\x02\xb4\x00\x00\x00\x01\x00\x06ab\x00\x02\x00\x0c\x00\x00\x00\x01xyzw";
        let found = tlvs(buf, HEADER_LEN).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].data, (8, 10));
        assert_eq!(found[1].addresses, Some(1));
        assert_eq!(found[1].data, (18, 22));
    }

    #[test]
    fn zero_and_short_lengths_reach_the_end() {
        let found = tlvs(b"\x00\x05\x00\x00rest", 0).unwrap();
        assert_eq!(found[0].data, (4, 8));
        let found = tlvs(b"\x00\x05\x00\x01", 0).unwrap();
        assert_eq!(found[0].data, (4, 4));
        assert_eq!(
            tlvs(b"\x00\x05\x00\x01restxyz", 0).unwrap_err(),
            ShortTlv { have: 3, need: 4 }
        );
        assert_eq!(
            tlvs(b"\x00\x05\x00\x01ab\x00", 0).unwrap_err(),
            ShortTlv { have: 3, need: 4 }
        );
        assert_eq!(
            tlvs(b"\x00\x02\x00\x08\x00", 0).unwrap_err(),
            ShortTlv { have: 5, need: 8 }
        );
    }
}
