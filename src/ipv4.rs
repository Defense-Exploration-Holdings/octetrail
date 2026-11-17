//! IPv4 headers, opaque options and native checksum operations.
//!
//! Parsing follows dpkt 1.9.8: any version is accepted, options and payload are sliced
//! from what is present, and a zero total length means the rest of the buffer.

use std::fmt;

pub const HEADER_LEN: usize = 20;
pub const MAX_TOTAL_LEN: usize = u16::MAX as usize;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Truncated { available: usize, required: usize },
    InvalidHeaderLength,
    UnsupportedTransport(u8),
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
            Self::UnsupportedTransport(p) => write!(f, "unsupported checksum protocol {p}"),
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
    /// Header length in bytes as declared by the IHL field.
    pub fn header_len(self) -> usize {
        usize::from(self.version_ihl & 15) * 4
    }

    /// Read the fixed 20 bytes. Version and IHL are returned as found.
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
        Ok(header)
    }

    /// Encode fields as assigned, without layout checks or checksum recalculation.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
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
        output
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    pub header: Header,
    pub opts: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Slice options and payload the way dpkt 1.9.8 does. Only a buffer shorter than the
    /// fixed header or an IHL below 5 is an error. Short options and a payload cut off by
    /// the buffer are kept as found, bytes beyond a nonzero total length are dropped, and
    /// a zero total length (segmentation offload) keeps the rest of the buffer.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(bytes)?;
        let header_len = header.header_len();
        if header_len < HEADER_LEN {
            return Err(Error::InvalidHeaderLength);
        }
        let start = header_len.min(bytes.len());
        let end = match usize::from(header.total_length) {
            0 => bytes.len(),
            length => length.min(bytes.len()).max(start),
        };
        Ok(Self {
            header,
            opts: &bytes[HEADER_LEN..start],
            data: &bytes[start..end],
        })
    }

    /// Byte length of the encoded datagram: header, options and payload as assigned.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.opts.len() + self.data.len()
    }

    /// Follow dpkt 1.9.8: a zero checksum sets the total length and computes the header
    /// checksum; an explicit checksum leaves every field as assigned.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let length = self.encoded_len();
        if self.header.checksum == 0 {
            self.header.total_length = u16::try_from(length).map_err(|_| Error::TooLarge)?;
            let sum =
                u32::from(!checksum(&self.header.to_bytes())) + u32::from(!checksum(self.opts));
            self.header.checksum = finish_checksum(sum);
        }
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

/// Combine even-aligned checksum components without allocating a joined buffer.
fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 TCP/UDP pseudoheader checksum. Caller supplies a zeroed transport sum.
/// Fragment selection and the zero-IP-checksum update policy belong to the facade.
pub fn transport_checksum(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    data: &[u8],
) -> Result<u16, Error> {
    if !matches!(protocol, 6 | 17) {
        return Err(Error::UnsupportedTransport(protocol));
    }
    let length = u16::try_from(data.len()).map_err(|_| Error::TooLarge)?;
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&src);
    pseudo[4..8].copy_from_slice(&dst);
    pseudo[9] = protocol;
    pseudo[10..].copy_from_slice(&length.to_be_bytes());
    Ok(pseudo_checksum(&pseudo, data))
}

/// Checksum over an already packed 12-byte pseudoheader and the transport bytes,
/// as dpkt 1.9.8 computes it. A UDP result of zero (protocol 17 in byte 9) is sent
/// as all ones.
pub fn pseudo_checksum(pseudo: &[u8; 12], data: &[u8]) -> u16 {
    let sum = finish_checksum(u32::from(!checksum(pseudo)) + u32::from(!checksum(data)));
    if pseudo[9] == 17 && sum == 0 {
        u16::MAX
    } else {
        sum
    }
}
