//! GRE option fields and source route entries as dpkt 1.9.8 reads them.
//! Offsets index the whole packet, starting at the four-byte GRE header.

pub type Range = (usize, usize);

pub const HEADER_LEN: usize = 4;
pub const SRE_HEADER_LEN: usize = 4;

pub const CP: u16 = 0x8000;
pub const RP: u16 = 0x4000;
pub const KP: u16 = 0x2000;
pub const SP: u16 = 0x1000;
pub const AP: u16 = 0x0080;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The header is shorter than four bytes.
    ShortHeader { have: usize },
    /// The option fields that the flags select are cut off.
    ShortOptions,
    /// A source route entry header is cut off; `have` bytes were left.
    ShortSre { have: usize },
}

/// The option fields, source route entries and payload of a GRE packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    /// Option field values in wire order, as unsigned integers.
    pub options: Vec<u32>,
    /// Each source route entry from its header to the end of its data, which
    /// is cut to the bytes present.
    pub sres: Vec<Range>,
    /// Where the payload starts.
    pub payload: usize,
}

/// Widths in bytes of the option fields that `flags` selects, in wire order.
/// Version 0 may carry sum and offset, key, sequence and acknowledgment.
/// Other versions carry payload length and call ID, then sequence and
/// acknowledgment.
pub fn option_widths(flags: u16) -> Vec<usize> {
    let mut widths = Vec::new();
    if flags & 0x7 == 0 {
        if flags & (CP | RP) != 0 {
            widths.extend([2, 2]);
        }
        if flags & KP != 0 {
            widths.push(4);
        }
    } else {
        widths.extend([2, 2]);
    }
    if flags & SP != 0 {
        widths.push(4);
    }
    if flags & AP != 0 {
        widths.push(4);
    }
    widths
}

/// Read the option fields and, with the routing flag, source route entries
/// until one with a zero length.
pub fn layout(buf: &[u8]) -> Result<Layout, Error> {
    if buf.len() < HEADER_LEN {
        return Err(Error::ShortHeader { have: buf.len() });
    }
    let flags = u16::from_be_bytes([buf[0], buf[1]]);
    let mut at = HEADER_LEN;
    let mut options = Vec::new();
    for width in option_widths(flags) {
        let field = buf.get(at..at + width).ok_or(Error::ShortOptions)?;
        options.push(field.iter().fold(0u32, |v, b| (v << 8) | u32::from(*b)));
        at += width;
    }
    let mut sres = Vec::new();
    if flags & RP != 0 {
        loop {
            let rest = &buf[at..];
            if rest.len() < SRE_HEADER_LEN {
                return Err(Error::ShortSre { have: rest.len() });
            }
            let len = usize::from(rest[3]);
            let end = (SRE_HEADER_LEN + len).min(rest.len());
            sres.push((at, at + end));
            at += end;
            if len == 0 {
                break;
            }
        }
    }
    Ok(Layout {
        options,
        sres,
        payload: at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_reads_length_call_id_and_sequence() {
        let buf = b"\x30\x81\x88\x0a\x00\x67\x17\x80\x00\x06\x8f\xb1\x00\x08\x3a\x76A";
        let found = layout(buf).unwrap();
        assert_eq!(found.options, vec![103, 6016, 430001, 539254]);
        assert_eq!(found.payload, 16);
    }

    #[test]
    fn routing_entries_end_at_zero_length() {
        let buf = b"\x40\x00\x08\x00\x00\x01\x00\x02\x00\x00\x00\x02ab\x00\x00\x00\x00rest";
        let found = layout(buf).unwrap();
        assert_eq!(found.sres, vec![(8, 14), (14, 18)]);
        assert_eq!(found.payload, 18);
    }

    #[test]
    fn short_parts_are_errors() {
        assert_eq!(layout(b"\x80\x00\x08\x00\x00"), Err(Error::ShortOptions));
        assert_eq!(
            layout(b"\x40\x00\x08\x00\x00\x00\x00\x00\x00"),
            Err(Error::ShortSre { have: 1 })
        );
        assert_eq!(layout(b"\x00"), Err(Error::ShortHeader { have: 1 }));
    }
}
