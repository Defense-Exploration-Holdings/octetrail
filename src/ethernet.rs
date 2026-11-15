//! Bounded, opaque Ethernet II frames without higher-layer dispatch.

use std::fmt;

pub const HEADER_LEN: usize = 14;
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete frame, including its 14-byte header.
    pub max_frame_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    TruncatedHeader { available: usize },
    UnsupportedFraming { ethertype: u16 },
    FrameLimit { length: usize, limit: u32 },
    LengthOverflow,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { available } => {
                write!(f, "got {available}, {HEADER_LEN} needed at least")
            }
            Self::UnsupportedFraming { ethertype } => {
                write!(f, "unsupported Ethernet framing type 0x{ethertype:04x}")
            }
            Self::FrameLimit { length, limit } => {
                write!(f, "Ethernet frame length {length} exceeds limit {limit}")
            }
            Self::LengthOverflow => write!(f, "Ethernet frame length overflow"),
            Self::Allocation => write!(f, "cannot allocate Ethernet frame"),
        }
    }
}

impl std::error::Error for Error {}

fn check_type(ethertype: u16) -> Result<(), Error> {
    // 802.3 length/reserved values and link-layer encapsulations are outside
    // this plain Ethernet II subset. Network-layer types remain opaque.
    if ethertype < 0x0600
        || matches!(
            ethertype,
            0x8100 | 0x88a8 | 0x9100 | 0x9200 | 0x8847 | 0x8848
        )
    {
        return Err(Error::UnsupportedFraming { ethertype });
    }
    Ok(())
}

fn check_length(length: usize, limits: Limits) -> Result<(), Error> {
    if length > limits.max_frame_bytes as usize {
        return Err(Error::FrameLimit {
            length,
            limit: limits.max_frame_bytes,
        });
    }
    Ok(())
}

/// Fixed network-order fields. No payload type is inferred from an EtherType.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl Header {
    /// Normalize addresses with dpkt's fixed-width byte-string packing rule.
    pub fn new(dst: &[u8], src: &[u8], ethertype: u16) -> Result<Self, Error> {
        check_type(ethertype)?;
        let mut header = Self {
            dst: [0; 6],
            src: [0; 6],
            ethertype,
        };
        let dst_len = dst.len().min(6);
        let src_len = src.len().min(6);
        header.dst[..dst_len].copy_from_slice(&dst[..dst_len]);
        header.src[..src_len].copy_from_slice(&src[..src_len]);
        Ok(header)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader {
                available: bytes.len(),
            });
        }
        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        Self::new(&bytes[..6], &bytes[6..12], ethertype)
    }

    pub fn to_bytes(self) -> Result<[u8; HEADER_LEN], Error> {
        check_type(self.ethertype)?;
        let mut output = [0; HEADER_LEN];
        output[..6].copy_from_slice(&self.dst);
        output[6..12].copy_from_slice(&self.src);
        output[12..].copy_from_slice(&self.ethertype.to_be_bytes());
        Ok(output)
    }
}

/// A zero-copy payload view. All bytes after the header remain payload bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub header: Header,
    pub data: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader {
                available: bytes.len(),
            });
        }
        check_length(bytes.len(), limits)?;
        let header = Header::parse(bytes)?;
        Ok(Self {
            header,
            data: &bytes[HEADER_LEN..],
        })
    }

    /// Validate before allocating. No minimum-size padding or FCS is added.
    pub fn to_bytes(&self, limits: Limits) -> Result<Vec<u8>, Error> {
        let header = self.header.to_bytes()?;
        let length = HEADER_LEN
            .checked_add(self.data.len())
            .ok_or(Error::LengthOverflow)?;
        check_length(length, limits)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        output.extend_from_slice(&header);
        output.extend_from_slice(self.data);
        Ok(output)
    }
}
