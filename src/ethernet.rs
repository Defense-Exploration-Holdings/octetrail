//! Ethernet framing as dpkt 1.9.8 reads it: Ethernet II, Cisco ISL, Novell raw
//! 802.3 and IEEE 802.3 with LLC, and the 802.1Q and MPLS stacks that follow an
//! Ethernet II header. Every range indexes the buffer that was passed in, and
//! every walk is a single pass.

use std::fmt;

pub type Range = (usize, usize);

pub const HEADER_LEN: usize = 14;
pub const VLAN_LEN: usize = 4;
pub const MPLS_LEN: usize = 4;
pub const ISL_LEN: usize = 26;
pub const LLC_LEN: usize = 3;

pub const TYPE_IP: u16 = 0x0800;
pub const TYPE_IP6: u16 = 0x86dd;
pub const TYPE_8021Q: u16 = 0x8100;
pub const TYPE_8021AD: u16 = 0x88a8;
pub const TYPE_QINQ1: u16 = 0x9100;
pub const TYPE_QINQ2: u16 = 0x9200;
pub const TYPE_MPLS: u16 = 0x8847;
pub const TYPE_MPLS_MCAST: u16 = 0x8848;
pub const TYPE_TEB: u16 = 0x6558;

/// The most MPLS labels read before the payload, as in dpkt.
pub const MAX_LABELS: usize = 24;
/// The most 802.1Q tags read before the payload, as in dpkt.
pub const MAX_TAGS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A header that needs `need` bytes found `have`.
    Short { have: usize, need: usize },
    /// The Ethernet header after an ISL tag is shorter than 14 bytes.
    Struct,
    /// No byte follows the MPLS label stack.
    Index,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { have, need } => write!(f, "got {have}, {need} needed at least"),
            Self::Struct => write!(f, "unpack requires a buffer of {HEADER_LEN} bytes"),
            Self::Index => write!(f, "index out of range"),
        }
    }
}

impl std::error::Error for Error {}

fn be16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn is_isl(dst: &[u8]) -> bool {
    dst.starts_with(&[0x01, 0, 0x0c, 0, 0]) || dst.starts_with(&[0x03, 0, 0x0c, 0, 0])
}

/// What follows the Ethernet header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    /// The type is above 1500: an Ethernet II payload.
    Typed,
    /// The payload starts with `ff ff`: IPX after those two bytes.
    Novell,
    /// The type is 0.
    Unknown,
    /// IEEE 802.3: `type` is the LLC length, and the rest is split by
    /// Wireshark's heuristic into padding, a frame check sequence and a trailer.
    Llc {
        llc: Range,
        padding: Option<Range>,
        fcs: Option<u32>,
        trailer: Option<Range>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// The last ISL tag read. dpkt keeps only the innermost one.
    pub isl: Option<usize>,
    /// Where the final 14-byte Ethernet header starts.
    pub header: usize,
    pub ethertype: u16,
    pub kind: Kind,
}

impl Frame {
    /// Walk ISL tags and classify the frame. The payload starts at
    /// `header + 14`.
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        let mut at = 0;
        let mut isl = None;
        loop {
            let level = &buf[at..];
            if level.len() < HEADER_LEN {
                return Err(if at == 0 {
                    Error::Short {
                        have: level.len(),
                        need: HEADER_LEN,
                    }
                } else {
                    Error::Struct
                });
            }
            let ethertype = be16(level, 12);
            let data = &level[HEADER_LEN..];
            let kind = if ethertype > 1500 {
                Kind::Typed
            } else if is_isl(&level[..6]) {
                if level.len() < ISL_LEN {
                    return Err(Error::Short {
                        have: level.len(),
                        need: ISL_LEN,
                    });
                }
                isl = Some(at);
                at += ISL_LEN;
                continue;
            } else if data.starts_with(&[0xff, 0xff]) {
                Kind::Novell
            } else if ethertype == 0 {
                Kind::Unknown
            } else {
                llc(at + HEADER_LEN, data, usize::from(ethertype))
            };
            return Ok(Self {
                isl,
                header: at,
                ethertype,
                kind,
            });
        }
    }
}

fn llc(start: usize, data: &[u8], length: usize) -> Kind {
    let mut padding = None;
    let mut fcs = None;
    let mut trailer = None;
    if data.len() > length {
        let mut tail = length;
        if data.len() - tail > 4 && length < 46 {
            let end = (tail + 46 - length).min(data.len());
            if end - tail == 46 - length && data[tail..end].iter().all(|&b| b == 0) {
                padding = Some((start + tail, start + end));
                tail = end;
            }
        }
        if data.len() - tail >= 4 {
            let word = [data[tail], data[tail + 1], data[tail + 2], data[tail + 3]];
            fcs = Some(u32::from_be_bytes(word));
            tail += 4;
        }
        if tail < data.len() {
            trailer = Some((start + tail, start + data.len()));
        }
    }
    Kind::Llc {
        llc: (start, start + length.min(data.len())),
        padding,
        fcs,
        trailer,
    }
}

/// The 802.1Q tags or MPLS labels at the start of an Ethernet II payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stack {
    pub tags: Vec<usize>,
    pub labels: Vec<usize>,
    /// The type that selects the payload class.
    pub next: u16,
    /// Where the payload starts.
    pub payload: usize,
}

impl Stack {
    /// Read the stack that `next` announces. Other types read nothing.
    pub fn parse(buf: &[u8], next: u16) -> Result<Self, Error> {
        let mut stack = Self {
            next,
            ..Self::default()
        };
        let short = |at: usize| Error::Short {
            have: buf.len() - at,
            need: VLAN_LEN,
        };
        let mut at = 0;
        if matches!(next, TYPE_8021Q | TYPE_8021AD | TYPE_QINQ1 | TYPE_QINQ2) {
            for _ in 0..MAX_TAGS {
                if buf.len() - at < VLAN_LEN {
                    return Err(short(at));
                }
                stack.tags.push(at);
                stack.next = be16(buf, at + 2);
                at += VLAN_LEN;
                if stack.next != TYPE_8021Q {
                    break;
                }
            }
        } else if matches!(next, TYPE_MPLS | TYPE_MPLS_MCAST) {
            for _ in 0..MAX_LABELS {
                if buf.len() - at < MPLS_LEN {
                    return Err(short(at));
                }
                stack.labels.push(at);
                let bottom = buf[at + 2] & 1 == 1;
                at += MPLS_LEN;
                if bottom {
                    break;
                }
            }
            let first = *buf.get(at).ok_or(Error::Index)?;
            if first == 0x45 {
                stack.next = TYPE_IP;
            } else if first & 0xf0 == 0x60 {
                stack.next = TYPE_IP6;
            } else if buf.len() - at >= HEADER_LEN {
                if buf[at..at + 2] == [0, 0] {
                    at += 4;
                }
                stack.next = TYPE_TEB;
            }
        }
        stack.payload = at;
        Ok(stack)
    }
}

/// The LLC header and its SNAP extension when DSAP and SSAP are both 0xaa.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Llc {
    pub dsap: u8,
    pub ssap: u8,
    pub ctl: u8,
    /// `(oui, type)` of a SNAP header.
    pub snap: Option<(u32, u16)>,
    /// Where the LLC payload starts.
    pub payload: usize,
}

impl Llc {
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < LLC_LEN {
            return Err(Error::Short {
                have: buf.len(),
                need: LLC_LEN,
            });
        }
        let (dsap, ssap, ctl) = (buf[0], buf[1], buf[2]);
        if dsap == 0xaa && ssap == 0xaa {
            if buf.len() < LLC_LEN + 5 {
                return Err(Error::Struct);
            }
            let oui = u32::from_be_bytes([0, buf[3], buf[4], buf[5]]);
            return Ok(Self {
                dsap,
                ssap,
                ctl,
                snap: Some((oui, be16(buf, 6))),
                payload: LLC_LEN + 5,
            });
        }
        Ok(Self {
            dsap,
            ssap,
            ctl,
            snap: None,
            payload: LLC_LEN,
        })
    }
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

/// The IEEE CRC-32 that zlib computes.
pub fn crc32(buf: &[u8]) -> u32 {
    !buf.iter().fold(!0u32, |c, &b| {
        CRC_TABLE[usize::from((c as u8) ^ b)] ^ (c >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn isl_chain_keeps_the_innermost_tag() {
        let mut isl = vec![0x01, 0, 0x0c, 0, 0];
        isl.resize(ISL_LEN, 0);
        let mut frame = [isl.clone(), isl].concat();
        frame.extend_from_slice(&[2; 12]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let parsed = Frame::parse(&frame).unwrap();
        assert_eq!((parsed.isl, parsed.header), (Some(ISL_LEN), 2 * ISL_LEN));
        assert_eq!(parsed.kind, Kind::Typed);
    }
}
