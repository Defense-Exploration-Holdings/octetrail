//! Fixed IPv4 headers and opaque datagram payloads, without protocol dispatch.

use std::fmt;

pub const HEADER_LEN: usize = 20;
pub const MAX_TOTAL_LEN: usize = u16::MAX as usize;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Truncated { available: usize, required: usize },
    InvalidHeaderLength,
    UnsupportedVersion(u8),
    OptionsUnsupported,
    OffloadLengthUnsupported,
    InvalidTotalLength(u16),
    TooLarge,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                available,
                required,
            } => {
                write!(f, "got {available}, {required} needed at least")
            }
            Self::InvalidHeaderLength => write!(f, "invalid header length"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported IPv4 version {v}"),
            Self::OptionsUnsupported => write!(f, "IPv4 options are not supported"),
            Self::OffloadLengthUnsupported => write!(f, "zero IPv4 total length is unsupported"),
            Self::InvalidTotalLength(n) => write!(f, "IPv4 total length {n} is below 20"),
            Self::TooLarge => write!(f, "IPv4 datagram exceeds 65535 bytes"),
            Self::Allocation => write!(f, "cannot allocate IPv4 datagram"),
        }
    }
}
impl std::error::Error for Error {}

/// Internet checksum in network byte order. An odd last byte is zero-padded.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            version_ihl: 0x45,
            tos: 0,
            total_length: 20,
            id: 0,
            flags_offset: 0,
            ttl: 64,
            protocol: 0,
            checksum: 0,
            src: [0; 4],
            dst: [0; 4],
        }
    }
}

impl Header {
    fn validate_layout(self) -> Result<(), Error> {
        if self.version_ihl >> 4 != 4 {
            return Err(Error::UnsupportedVersion(self.version_ihl >> 4));
        }
        match self.version_ihl & 15 {
            0..=4 => Err(Error::InvalidHeaderLength),
            5 => Ok(()),
            _ => Err(Error::OptionsUnsupported),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated {
                available: bytes.len(),
                required: HEADER_LEN,
            });
        }
        let half = |offset| u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let header = Self {
            version_ihl: bytes[0],
            tos: bytes[1],
            total_length: half(2),
            id: half(4),
            flags_offset: half(6),
            ttl: bytes[8],
            protocol: bytes[9],
            checksum: half(10),
            src: bytes[12..16].try_into().expect("fixed header source slice"),
            dst: bytes[16..20]
                .try_into()
                .expect("fixed header destination slice"),
        };
        header.validate_layout()?;
        Ok(header)
    }

    /// Encode fields as assigned, without checksum validation or recalculation.
    pub fn to_bytes(self) -> Result<[u8; HEADER_LEN], Error> {
        self.validate_layout()?;
        let mut output = [0; HEADER_LEN];
        output[0] = self.version_ihl;
        output[1] = self.tos;
        output[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        output[4..6].copy_from_slice(&self.id.to_be_bytes());
        output[6..8].copy_from_slice(&self.flags_offset.to_be_bytes());
        output[8] = self.ttl;
        output[9] = self.protocol;
        output[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        output[12..16].copy_from_slice(&self.src);
        output[16..20].copy_from_slice(&self.dst);
        Ok(output)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    pub header: Header,
    pub data: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Retain the declared datagram and ignore any trailing enclosing-frame bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(bytes)?;
        let length = usize::from(header.total_length);
        if length == 0 {
            return Err(Error::OffloadLengthUnsupported);
        }
        if length < HEADER_LEN {
            return Err(Error::InvalidTotalLength(header.total_length));
        }
        if length > bytes.len() {
            return Err(Error::Truncated {
                available: bytes.len(),
                required: length,
            });
        }
        Ok(Self {
            header,
            data: &bytes[HEADER_LEN..length],
        })
    }

    /// Follow dpkt 1.9.8's zero-checksum update rule, preserving explicit sums.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let length = HEADER_LEN
            .checked_add(self.data.len())
            .ok_or(Error::TooLarge)?;
        if length > MAX_TOTAL_LEN {
            return Err(Error::TooLarge);
        }
        self.header.validate_layout()?;
        if self.header.checksum == 0 {
            self.header.total_length = length as u16;
            self.header.checksum = checksum(&self.header.to_bytes()?);
        }
        let raw = self.header.to_bytes()?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        output.extend_from_slice(&raw);
        output.extend_from_slice(self.data);
        Ok(output)
    }
}
