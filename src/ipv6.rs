//! Bounded IPv6 base headers and opaque extension framing. No reassembly.

use std::fmt;

pub const HEADER_LEN: usize = 40;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_extensions: usize,
    pub max_extension_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_extensions: 16,
            max_extension_bytes: 2048,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    TruncatedHeader,
    UnsupportedVersion(u8),
    Limit,
    InvalidExtension,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "IPv6 requires a complete 40-byte base header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported IPv6 version {v}"),
            Self::Limit => write!(f, "IPv6 packet or extension limit exceeded"),
            Self::InvalidExtension => write!(f, "IPv6 extension framing or chain is inconsistent"),
            Self::Allocation => write!(f, "cannot allocate IPv6 output"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub version_class_flow: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            version_class_flow: 0x60000000,
            payload_length: 0,
            next_header: 0,
            hop_limit: 0,
            src: [0; 16],
            dst: [0; 16],
        }
    }
}

impl Header {
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader);
        }
        let h = Self {
            version_class_flow: u32::from_be_bytes(raw[..4].try_into().expect("fixed base field")),
            payload_length: u16::from_be_bytes([raw[4], raw[5]]),
            next_header: raw[6],
            hop_limit: raw[7],
            src: raw[8..24].try_into().expect("fixed source field"),
            dst: raw[24..40].try_into().expect("fixed destination field"),
        };
        h.validate()?;
        Ok(h)
    }

    fn validate(self) -> Result<(), Error> {
        let v = (self.version_class_flow >> 28) as u8;
        if v != 6 {
            return Err(Error::UnsupportedVersion(v));
        }
        Ok(())
    }

    pub fn to_bytes(self) -> Result<[u8; HEADER_LEN], Error> {
        self.validate()?;
        let mut raw = [0; HEADER_LEN];
        raw[..4].copy_from_slice(&self.version_class_flow.to_be_bytes());
        raw[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        raw[6] = self.next_header;
        raw[7] = self.hop_limit;
        raw[8..24].copy_from_slice(&self.src);
        raw[24..].copy_from_slice(&self.dst);
        Ok(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extension<'a> {
    pub kind: u8,
    pub bytes: &'a [u8],
}

fn extension_length(kind: u8, raw: &[u8]) -> Option<usize> {
    if raw.len() < 2 {
        return None;
    }
    match kind {
        0 | 43 | 60 => Some((usize::from(raw[1]) + 1) * 8),
        44 => Some(8),
        51 if raw[1] >= 1 => Some((usize::from(raw[1]) + 2) * 4),
        _ => None,
    }
}

fn supported_extension(kind: u8) -> bool {
    matches!(kind, 0 | 43 | 44 | 51 | 60)
}

fn non_atomic(ext: Extension<'_>) -> bool {
    ext.kind == 44 && u16::from_be_bytes([ext.bytes[2], ext.bytes[3]]) & 0xfff9 != 0
}

#[derive(Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub extensions: Vec<Extension<'a>>,
    pub data: &'a [u8],
    pub protocol: u8,
    pub fragmented: bool,
    pub status: &'static str,
}

impl<'a> Packet<'a> {
    pub fn parse(raw: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if raw.len() > HEADER_LEN + MAX_PAYLOAD_LEN {
            return Err(Error::Limit);
        }
        let header = Header::parse(raw)?;
        let available = &raw[HEADER_LEN..];
        let length = usize::from(header.payload_length);
        let mut packet = Self {
            header,
            extensions: Vec::new(),
            data: &available[..length.min(available.len())],
            protocol: header.next_header,
            fragmented: false,
            status: "complete",
        };
        if length > available.len() {
            packet.status = "truncated_payload";
            return Ok(packet);
        }
        if length == 0 && !available.is_empty() {
            packet.data = available;
            packet.status = "unsupported_zero_length";
            return Ok(packet);
        }
        let mut used = 0usize;
        while supported_extension(packet.protocol) {
            if packet.extensions.len() >= limits.max_extensions {
                return Err(Error::Limit);
            }
            let Some(size) = extension_length(packet.protocol, packet.data) else {
                packet.status = "incomplete_extension";
                break;
            };
            used = used.checked_add(size).ok_or(Error::Limit)?;
            if used > limits.max_extension_bytes {
                return Err(Error::Limit);
            }
            if packet.data.len() < size {
                packet.status = "incomplete_extension";
                break;
            }
            let ext = Extension {
                kind: packet.protocol,
                bytes: &packet.data[..size],
            };
            packet
                .extensions
                .try_reserve(1)
                .map_err(|_| Error::Allocation)?;
            packet.extensions.push(ext);
            packet.protocol = ext.bytes[0];
            packet.data = &packet.data[size..];
            if non_atomic(ext) {
                packet.fragmented = true;
                break;
            }
        }
        Ok(packet)
    }
}

/// Serialize assigned fields. Payload length remains caller-owned, as in dpkt.
/// Returns wire bytes, final protocol, fragment state and checksum eligibility.
pub fn encode(
    header: Header,
    extensions: &[Extension<'_>],
    data: &[u8],
    limits: Limits,
) -> Result<(Vec<u8>, u8, bool, bool), Error> {
    let fixed = header.to_bytes()?;
    if extensions.len() > limits.max_extensions {
        return Err(Error::Limit);
    }
    let mut used = 0usize;
    let mut protocol = header.next_header;
    let mut fragmented = false;
    let mut checksum_supported = true;
    for ext in extensions {
        if fragmented
            || ext.kind != protocol
            || extension_length(ext.kind, ext.bytes) != Some(ext.bytes.len())
        {
            return Err(Error::InvalidExtension);
        }
        used = used.checked_add(ext.bytes.len()).ok_or(Error::Limit)?;
        if used > limits.max_extension_bytes {
            return Err(Error::Limit);
        }
        fragmented = non_atomic(*ext);
        if ext.kind == 43 && ext.bytes[3] != 0 {
            checksum_supported = false;
        }
        protocol = ext.bytes[0];
    }
    let payload_len = used.checked_add(data.len()).ok_or(Error::Limit)?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(Error::Limit);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(HEADER_LEN + payload_len)
        .map_err(|_| Error::Allocation)?;
    output.extend_from_slice(&fixed);
    for ext in extensions {
        output.extend_from_slice(ext.bytes);
    }
    output.extend_from_slice(data);
    Ok((output, protocol, fragmented, checksum_supported))
}

pub fn transport_checksum(
    src: [u8; 16],
    dst: [u8; 16],
    protocol: u8,
    data: &[u8],
) -> Result<u16, Error> {
    if data.len() > MAX_PAYLOAD_LEN || !matches!(protocol, 6 | 17) {
        return Err(Error::Limit);
    }
    let mut pseudo = [0; 40];
    pseudo[..16].copy_from_slice(&src);
    pseudo[16..32].copy_from_slice(&dst);
    pseudo[32..36].copy_from_slice(&(data.len() as u32).to_be_bytes());
    pseudo[39] = protocol;
    let mut sum =
        u32::from(!crate::ipv4::checksum(&pseudo)) + u32::from(!crate::ipv4::checksum(data));
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    Ok(if protocol == 17 && checksum == 0 {
        0xffff
    } else {
        checksum
    })
}
