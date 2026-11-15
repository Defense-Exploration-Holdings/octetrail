//! Fixed eight-byte UDP headers and opaque bytes without checksum automation.

use std::fmt;

pub const HEADER_LEN: usize = 8;
pub const DEFAULT_MAX_DATAGRAM_BYTES: u32 = 65535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete supplied buffer, independent of the stored UDP length field.
    pub max_datagram_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    TruncatedHeader { available: usize },
    DatagramLimit { length: usize, limit: u32 },
    LengthOverflow,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { available } => {
                write!(f, "got {available}, {HEADER_LEN} needed at least")
            }
            Self::DatagramLimit { length, limit } => {
                write!(f, "UDP buffer length {length} exceeds limit {limit}")
            }
            Self::LengthOverflow => write!(f, "UDP buffer length overflow"),
            Self::Allocation => write!(f, "cannot allocate UDP buffer"),
        }
    }
}

impl std::error::Error for Error {}

fn check_length(length: usize, limits: Limits) -> Result<(), Error> {
    if length > limits.max_datagram_bytes as usize {
        Err(Error::DatagramLimit {
            length,
            limit: limits.max_datagram_bytes,
        })
    } else {
        Ok(())
    }
}

/// Unsigned wire fields. Neither length nor checksum is rewritten implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub sport: u16,
    pub dport: u16,
    pub ulen: u16,
    pub checksum: u16,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            sport: 0xdead,
            dport: 0,
            ulen: HEADER_LEN as u16,
            checksum: 0,
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
        Ok(Self {
            sport: u16::from_be_bytes([bytes[0], bytes[1]]),
            dport: u16::from_be_bytes([bytes[2], bytes[3]]),
            ulen: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }

    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..2].copy_from_slice(&self.sport.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dport.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.ulen.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        bytes
    }
}

/// A borrowed offline view. All supplied bytes after the header remain payload.
#[derive(Debug, Eq, PartialEq)]
pub struct Datagram<'a> {
    pub header: Header,
    pub data: &'a [u8],
}

impl<'a> Datagram<'a> {
    pub fn parse(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        let header = Header::parse(bytes)?;
        check_length(bytes.len(), limits)?;
        Ok(Self {
            header,
            data: &bytes[HEADER_LEN..],
        })
    }

    pub fn to_bytes(&self, limits: Limits) -> Result<Vec<u8>, Error> {
        let length = HEADER_LEN
            .checked_add(self.data.len())
            .ok_or(Error::LengthOverflow)?;
        check_length(length, limits)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(self.data);
        Ok(bytes)
    }
}
