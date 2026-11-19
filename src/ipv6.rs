//! IPv6 base headers and the extension headers dpkt 1.9.8 walks.
//!
//! Parsing follows `dpkt.ip6`: the payload is `plen` bytes (all of them when
//! `plen` is zero), and hop-by-hop, routing, fragment, AH, ESP and destination
//! options headers are read in a chain until another protocol follows. Nothing
//! is reassembled or validated beyond what dpkt reads.

use std::fmt;

pub const HEADER_LEN: usize = 40;
/// Extension header protocol numbers, in dpkt's `EXT_HDRS` order.
pub const EXTENSIONS: [u8; 6] = [0, 43, 44, 51, 50, 60];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A fixed header needs more bytes: (available, needed).
    Short(usize, usize),
    /// An option type or length byte is past the end of the buffer.
    Options,
    /// An option runs past the header's declared length.
    OptionLength,
    /// The protocol number is not an IPv6 extension header.
    NotExtension(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short(have, need) => write!(f, "got {have}, {need} needed at least"),
            Self::Options => write!(f, "IPv6 option runs past the end"),
            Self::OptionLength => write!(f, "IPv6 option runs past the header length"),
            Self::NotExtension(kind) => write!(f, "{kind} is not an IPv6 extension header"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub v_fc_flow: u32,
    pub plen: u16,
    pub nxt: u8,
    pub hlim: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            v_fc_flow: 0x6000_0000,
            plen: 0,
            nxt: 0,
            hlim: 0,
            src: [0; 16],
            dst: [0; 16],
        }
    }
}

impl Header {
    /// Any version is accepted, as in dpkt.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < HEADER_LEN {
            return Err(Error::Short(raw.len(), HEADER_LEN));
        }
        Ok(Self {
            v_fc_flow: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            plen: u16::from_be_bytes([raw[4], raw[5]]),
            nxt: raw[6],
            hlim: raw[7],
            src: raw[8..24].try_into().expect("fixed source field"),
            dst: raw[24..40].try_into().expect("fixed destination field"),
        })
    }

    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut raw = [0; HEADER_LEN];
        raw[..4].copy_from_slice(&self.v_fc_flow.to_be_bytes());
        raw[4..6].copy_from_slice(&self.plen.to_be_bytes());
        raw[6] = self.nxt;
        raw[7] = self.hlim;
        raw[8..24].copy_from_slice(&self.src);
        raw[24..].copy_from_slice(&self.dst);
        raw
    }
}

/// One option of a hop-by-hop or destination options header. Pad1 and PadN
/// are skipped, as in dpkt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opt {
    pub kind: u8,
    pub length: u8,
    /// The option data, as a range of the buffer the header was read from.
    pub data: (usize, usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    Options(Vec<Opt>),
    /// Ranges of the 16-byte address slots, cut to the bytes present.
    Routing(Vec<(usize, usize)>),
    Fragment,
    /// The range of `auth_data`.
    Ah((usize, usize)),
    Esp,
}

/// One extension header, with every range relative to the buffer it was read from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extension {
    pub kind: u8,
    /// The header fields in `__hdr__` order.
    pub fields: Vec<u32>,
    /// dpkt's `data` attribute.
    pub data: (usize, usize),
    /// dpkt's `length` attribute: the bytes the chain moves past.
    pub length: usize,
    pub body: Body,
}

fn be(raw: &[u8]) -> u32 {
    raw.iter().fold(0, |n, b| (n << 8) | u32::from(*b))
}

fn fixed(buf: &[u8], widths: &[usize]) -> Result<Vec<u32>, Error> {
    let need = widths.iter().sum();
    if buf.len() < need {
        return Err(Error::Short(buf.len(), need));
    }
    let mut at = 0;
    Ok(widths
        .iter()
        .map(|w| {
            at += w;
            be(&buf[at - w..at])
        })
        .collect())
}

fn options(buf: &[u8], length: usize) -> Result<Vec<Opt>, Error> {
    // Options fill the declared header after its two fixed bytes. An option that
    // runs past the declared length is an error; dpkt reads on into the payload.
    // A capture cut short inside the header keeps the options that are there.
    let area = length - 2;
    let data = &buf[2..length.min(buf.len())];
    let mut found = Vec::new();
    let mut index = 0;
    while index < data.len() {
        let kind = data[index];
        if kind == 0 {
            index += 1;
            continue;
        }
        let size = *data.get(index + 1).ok_or(Error::Options)?;
        let end = index + 2 + usize::from(size);
        if end > area {
            return Err(Error::OptionLength);
        }
        if kind != 1 {
            found.push(Opt {
                kind,
                length: size,
                data: (2 + index + 2, 2 + end.min(data.len())),
            });
        }
        index = end;
    }
    if index < area && data.len() < area {
        // The capture ends inside the option list.
        return Err(Error::Options);
    }
    Ok(found)
}

impl Extension {
    /// Read the extension header `kind` from the start of `buf`.
    pub fn parse(kind: u8, buf: &[u8]) -> Result<Self, Error> {
        let n = buf.len();
        let clamp = |start: usize, end: usize| (start.min(n), end.min(n));
        Ok(match kind {
            0 | 60 => {
                let fields = fixed(buf, &[1, 1])?;
                let length = (fields[1] as usize + 1) * 8;
                Self {
                    kind,
                    body: Body::Options(options(buf, length)?),
                    fields,
                    data: clamp(2, length),
                    length,
                }
            }
            43 => {
                let fields = fixed(buf, &[1, 1, 1, 1, 4])?;
                let count = fields[1] as usize / 2;
                let data = clamp(8, 8 + count * 16);
                let addresses = (0..count)
                    .map(|i| clamp(data.0 + i * 16, data.0 + i * 16 + 16))
                    .map(|(a, b)| (a.min(data.1), b.min(data.1)))
                    .collect();
                Self {
                    kind,
                    length: fields[1] as usize * 8 + 8,
                    fields,
                    data,
                    body: Body::Routing(addresses),
                }
            }
            44 => Self {
                kind,
                fields: fixed(buf, &[1, 1, 2, 4])?,
                data: (n.min(8), n.min(8)),
                length: 8,
                body: Body::Fragment,
            },
            51 => {
                let fields = fixed(buf, &[1, 1, 2, 4, 4])?;
                let rest = n - 12;
                // The ICV is (len - 1) * 4 bytes. dpkt's slice turns a zero length into
                // "all but the last four bytes"; here it is empty, as in the IPv4 AH class.
                let auth = (fields[1] as usize).saturating_sub(1) * 4;
                let auth = auth.min(rest);
                Self {
                    kind,
                    length: (fields[1] as usize + 2) * 4,
                    fields,
                    data: (12, n),
                    body: Body::Ah((12, 12 + auth)),
                }
            }
            50 => Self {
                kind,
                fields: fixed(buf, &[4, 4])?,
                data: (8, n),
                length: n,
                body: Body::Esp,
            },
            _ => return Err(Error::NotExtension(kind)),
        })
    }

    /// The next header, or `None` after ESP, whose header has no such field.
    pub fn next(&self) -> Option<u8> {
        (self.kind != 50).then(|| self.fields[0] as u8)
    }

    fn shift(mut self, by: usize) -> Self {
        let move_range = |r: &mut (usize, usize)| *r = (r.0 + by, r.1 + by);
        move_range(&mut self.data);
        match &mut self.body {
            Body::Options(found) => found.iter_mut().for_each(|o| move_range(&mut o.data)),
            Body::Routing(slots) => slots.iter_mut().for_each(move_range),
            Body::Ah(auth) => move_range(auth),
            Body::Fragment | Body::Esp => {}
        }
        self
    }
}

/// A parsed packet. Ranges are relative to the whole input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub header: Header,
    /// The extension headers read, in order.
    pub extensions: Vec<Extension>,
    /// What follows the last extension header: the bytes dpkt dispatches.
    pub rest: (usize, usize),
    /// The protocol of `rest`, or `None` after ESP.
    pub next: Option<u8>,
    /// Set when an extension header could not be read. `extensions` then
    /// holds the headers before it, which dpkt has already stored.
    pub error: Option<Error>,
}

impl Packet {
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let header = Header::parse(raw)?;
        let end = match usize::from(header.plen) {
            0 => raw.len(),
            plen => (HEADER_LEN + plen).min(raw.len()),
        };
        let mut packet = Self {
            header,
            extensions: Vec::new(),
            rest: (HEADER_LEN, end),
            next: Some(header.nxt),
            error: None,
        };
        let mut at = HEADER_LEN;
        while let Some(kind) = packet.next.filter(|k| EXTENSIONS.contains(k)) {
            match Extension::parse(kind, &raw[at..end]) {
                Ok(ext) => {
                    let ext = ext.shift(at);
                    at = at.saturating_add(ext.length).min(end);
                    packet.next = ext.next();
                    packet.extensions.push(ext);
                }
                Err(error) => {
                    packet.error = Some(error);
                    break;
                }
            }
        }
        packet.rest = (at, end);
        Ok(packet)
    }
}

/// The Internet checksum of the concatenated parts, in network order, as
/// dpkt's `in_cksum_done(in_cksum_add(...))` computes it. Every part but the
/// last must have an even length.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    for part in parts {
        let mut words = part.chunks_exact(2);
        for w in &mut words {
            sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
        }
        if let [last] = words.remainder() {
            sum += u64::from(*last) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_dpkt() {
        let data: Vec<u8> = (0..15).collect();
        // dpkt.in_cksum(bytes(range(15))) is 51150.
        assert_eq!(checksum(&[&data]), 51150);
        assert_eq!(checksum(&[&data[..2], &data[2..]]), 51150);
        assert_eq!(checksum(&[]), 0xffff);
    }

    #[test]
    fn unknown_extension_kind_is_an_error() {
        let buf = [0u8; 16];
        for kind in (0..=u8::MAX).filter(|k| !EXTENSIONS.contains(k)) {
            assert_eq!(
                Extension::parse(kind, &buf).unwrap_err(),
                Error::NotExtension(kind)
            );
        }
    }

    #[test]
    fn options_stay_inside_the_declared_length() {
        // len 0 means 8 bytes: PadN of 2, then an option of 2 bytes of data.
        let buf = [59, 0, 1, 0, 5, 2, 7, 8, 99, 99];
        let ext = Extension::parse(0, &buf).unwrap();
        assert_eq!(ext.data, (2, 8));
        let Body::Options(found) = ext.body else {
            panic!()
        };
        assert_eq!(
            found,
            [Opt {
                kind: 5,
                length: 2,
                data: (6, 8)
            }]
        );
        // An option whose data runs past byte 8 is an error, even with bytes after it.
        let past = [59, 0, 1, 0, 0, 0, 5, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(Extension::parse(0, &past), Err(Error::OptionLength));
        assert_eq!(Extension::parse(0, &[59, 0, 7]), Err(Error::Options));
        // Cut short inside an option's data: the option keeps the bytes present.
        let Body::Options(cut) = Extension::parse(0, &[59, 0, 5, 4, 1]).unwrap().body else {
            panic!()
        };
        assert_eq!(
            cut,
            [Opt {
                kind: 5,
                length: 4,
                data: (4, 5)
            }]
        );
    }
}
