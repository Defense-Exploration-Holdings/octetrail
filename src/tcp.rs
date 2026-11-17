//! TCP headers, opaque options and payloads, parsed and packed as dpkt 1.9.8 does.

use std::fmt;

pub const HEADER_LEN: usize = 20;
pub const DEFAULT_MAX_SEGMENT_BYTES: u32 = 16 * 1024 * 1024;

/// Option kinds 0 (end of list) and 1 (no operation) have no length byte.
pub const OPT_EOL: u8 = 0;
pub const OPT_NOP: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete offline segment, including the fixed 20-byte header.
    pub max_segment_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    TruncatedHeader { available: usize },
    InvalidDataOffset { words: u8 },
    SegmentLimit { length: usize, limit: u32 },
    LengthOverflow,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { available } => {
                write!(f, "got {available}, {HEADER_LEN} needed at least")
            }
            Self::InvalidDataOffset { .. } => write!(f, "invalid header length"),
            Self::SegmentLimit { length, limit } => {
                write!(f, "TCP segment length {length} exceeds limit {limit}")
            }
            Self::LengthOverflow => write!(f, "TCP segment length overflow"),
            Self::Allocation => write!(f, "cannot allocate TCP segment"),
        }
    }
}

impl std::error::Error for Error {}

fn check_length(length: usize, limits: Limits) -> Result<(), Error> {
    if length > limits.max_segment_bytes as usize {
        Err(Error::SegmentLimit {
            length,
            limit: limits.max_segment_bytes,
        })
    } else {
        Ok(())
    }
}

/// Unsigned wire fields; the checksum is preserved exactly as supplied.
///
/// `off_flags` holds the data offset (4 bits), the reserved bits (3 bits) and the nine
/// flag bits, including the nonce bit 0x100, as one 16-bit word like dpkt's `_off_flags`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub off_flags: u16,
    pub win: u16,
    pub checksum: u16,
    pub urp: u16,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            sport: 0xdead,
            dport: 0,
            seq: 0xdeadbeef,
            ack: 0,
            off_flags: (5 << 12) | 2,
            win: 0xffff,
            checksum: 0,
            urp: 0,
        }
    }
}

impl Header {
    /// Data offset in 32-bit words.
    pub fn off(self) -> u8 {
        (self.off_flags >> 12) as u8
    }

    /// The three reserved bits between the offset and the flags.
    pub fn reserved(self) -> u8 {
        ((self.off_flags >> 9) & 7) as u8
    }

    /// The nine flag bits, including the nonce bit 0x100.
    pub fn flags(self) -> u16 {
        self.off_flags & 0x1ff
    }

    /// Header length in bytes that the data offset declares.
    pub fn header_len(self) -> usize {
        usize::from(self.off()) * 4
    }

    /// Reads the 20-byte base header. Only a data offset below five words is an error.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader {
                available: bytes.len(),
            });
        }
        let header = Self {
            sport: u16::from_be_bytes([bytes[0], bytes[1]]),
            dport: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            off_flags: u16::from_be_bytes([bytes[12], bytes[13]]),
            win: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            urp: u16::from_be_bytes([bytes[18], bytes[19]]),
        };
        let words = header.off();
        if words < 5 {
            return Err(Error::InvalidDataOffset { words });
        }
        Ok(header)
    }

    /// Writes the fields exactly as stored; the offset is not checked against the options.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut output = [0; HEADER_LEN];
        output[..2].copy_from_slice(&self.sport.to_be_bytes());
        output[2..4].copy_from_slice(&self.dport.to_be_bytes());
        output[4..8].copy_from_slice(&self.seq.to_be_bytes());
        output[8..12].copy_from_slice(&self.ack.to_be_bytes());
        output[12..14].copy_from_slice(&self.off_flags.to_be_bytes());
        output[14..16].copy_from_slice(&self.win.to_be_bytes());
        output[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        output[18..20].copy_from_slice(&self.urp.to_be_bytes());
        output
    }
}

/// A borrowed view; no protocol interpretation or checksum validation is done.
#[derive(Debug, Eq, PartialEq)]
pub struct Segment<'a> {
    pub header: Header,
    pub opts: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Options are the bytes up to the declared offset that are present, so a short
    /// buffer gives short options and no data, as in dpkt.
    pub fn parse(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader {
                available: bytes.len(),
            });
        }
        check_length(bytes.len(), limits)?;
        let header = Header::parse(bytes)?;
        let end = header.header_len().min(bytes.len());
        Ok(Self {
            header,
            opts: &bytes[HEADER_LEN..end],
            data: &bytes[end..],
        })
    }

    /// Header, options and data concatenated; options need not match the offset.
    pub fn to_bytes(&self, limits: Limits) -> Result<Vec<u8>, Error> {
        let length = HEADER_LEN
            .checked_add(self.opts.len())
            .and_then(|n| n.checked_add(self.data.len()))
            .ok_or(Error::LengthOverflow)?;
        check_length(length, limits)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        output.extend_from_slice(&self.header.to_bytes());
        output.extend_from_slice(self.opts);
        output.extend_from_slice(self.data);
        Ok(output)
    }
}

/// Splits an option buffer like dpkt's `parse_opts`.
///
/// Kinds 0 and 1 are single bytes. Other kinds read a length byte, treated as at least
/// two, and take the bytes after it up to that length or the end of the buffer. A kind
/// with no length byte ends the list with `None`.
pub fn parse_options(mut bytes: &[u8]) -> Vec<Option<(u8, &[u8])>> {
    let mut options = Vec::new();
    while let Some(&kind) = bytes.first() {
        if kind > OPT_NOP {
            let Some(&length) = bytes.get(1) else {
                options.push(None);
                break;
            };
            let length = usize::from(length.max(2)).min(bytes.len());
            options.push(Some((kind, &bytes[2..length])));
            bytes = &bytes[length..];
        } else {
            options.push(Some((kind, &bytes[..0])));
            bytes = &bytes[1..];
        }
    }
    options
}
