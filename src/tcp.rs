//! Bounded TCP headers with opaque options and payloads.

use std::fmt;

pub const HEADER_LEN: usize = 20;
pub const DEFAULT_MAX_SEGMENT_BYTES: u32 = 16 * 1024 * 1024;

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
    InvalidOptionsLength,
    TruncatedOptions { available: usize, required: usize },
    ReservedBitsUnsupported { bits: u8 },
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
            Self::InvalidOptionsLength => write!(f, "TCP options do not match data offset"),
            Self::TruncatedOptions {
                available,
                required,
            } => write!(f, "got {available}, {required} needed at least"),
            Self::ReservedBitsUnsupported { bits } => {
                write!(f, "TCP reserved/nonce bits are unsupported (0x{bits:x})")
            }
            Self::SegmentLimit { length, limit } => {
                write!(f, "TCP segment length {length} exceeds limit {limit}")
            }
            Self::LengthOverflow => write!(f, "TCP segment length overflow"),
            Self::Allocation => write!(f, "cannot allocate TCP segment"),
        }
    }
}

impl std::error::Error for Error {}

fn check_offset(words: u8) -> Result<(), Error> {
    if !(5..=15).contains(&words) {
        Err(Error::InvalidDataOffset { words })
    } else {
        Ok(())
    }
}

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub off: u8,
    pub flags: u8,
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
            off: 5,
            flags: 2,
            win: 0xffff,
            checksum: 0,
            urp: 0,
        }
    }
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader {
                available: bytes.len(),
            });
        }
        let off = bytes[12] >> 4;
        check_offset(off)?;
        let bits = bytes[12] & 0x0f;
        if bits != 0 {
            return Err(Error::ReservedBitsUnsupported { bits });
        }
        Ok(Self {
            sport: u16::from_be_bytes([bytes[0], bytes[1]]),
            dport: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            off,
            flags: bytes[13],
            win: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            urp: u16::from_be_bytes([bytes[18], bytes[19]]),
        })
    }

    pub fn to_bytes(self) -> Result<[u8; HEADER_LEN], Error> {
        check_offset(self.off)?;
        let mut output = [0; HEADER_LEN];
        output[..2].copy_from_slice(&self.sport.to_be_bytes());
        output[2..4].copy_from_slice(&self.dport.to_be_bytes());
        output[4..8].copy_from_slice(&self.seq.to_be_bytes());
        output[8..12].copy_from_slice(&self.ack.to_be_bytes());
        output[12] = self.off << 4;
        output[13] = self.flags;
        output[14..16].copy_from_slice(&self.win.to_be_bytes());
        output[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        output[18..20].copy_from_slice(&self.urp.to_be_bytes());
        Ok(output)
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
    pub fn parse(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader {
                available: bytes.len(),
            });
        }
        check_length(bytes.len(), limits)?;
        let header = Header::parse(bytes)?;
        let header_len = usize::from(header.off) * 4;
        if bytes.len() < header_len {
            return Err(Error::TruncatedOptions {
                available: bytes.len(),
                required: header_len,
            });
        }
        Ok(Self {
            header,
            opts: &bytes[HEADER_LEN..header_len],
            data: &bytes[header_len..],
        })
    }

    pub fn to_bytes(&self, limits: Limits) -> Result<Vec<u8>, Error> {
        let header = self.header.to_bytes()?;
        if self.opts.len() != usize::from(self.header.off) * 4 - HEADER_LEN {
            return Err(Error::InvalidOptionsLength);
        }
        let length = HEADER_LEN
            .checked_add(self.opts.len())
            .and_then(|n| n.checked_add(self.data.len()))
            .ok_or(Error::LengthOverflow)?;
        check_length(length, limits)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        output.extend_from_slice(&header);
        output.extend_from_slice(self.opts);
        output.extend_from_slice(self.data);
        Ok(output)
    }
}
