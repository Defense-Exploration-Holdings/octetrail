//! Bounded sequential reading of ordinary classic pcap 2.4 captures.
//!
//! This native API is deliberately stricter than dpkt on incomplete records.
//! It does not claim Python API compatibility. See docs/compatibility.md.
//! The separate [`pcapng`] module reads a bounded Enhanced Packet Block subset.
//! The [`writer`] module emits validated classic-pcap records to a provided sink.
//! The [`pcapng_writer`] module emits a bounded single-interface EPB subset.

use std::fmt;
use std::io::{self, Read};
use std::iter::FusedIterator;

pub mod dns;
pub mod ethernet;
pub mod gre;
pub mod http;
pub mod ipv4;
pub mod ipv6;
pub mod pcapng;
pub mod pcapng_writer;
pub mod writer;
pub use writer::Writer;

pub mod tcp;
pub mod tls;
pub mod udp;
pub mod vrrp;

/// Default maximum captured packet size, independent of capture snap length.
pub const DEFAULT_MAX_PACKET_BYTES: u32 = 16 * 1024 * 1024;

/// Capture byte order. Packet contents are never byte-swapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    Microseconds,
    Nanoseconds,
}

impl Resolution {
    pub const fn ticks_per_second(self) -> u32 {
        match self {
            Self::Microseconds => 1_000_000,
            Self::Nanoseconds => 1_000_000_000,
        }
    }
}

/// Exact wire timestamp. No floating-point conversion occurs in the parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: u32,
    pub fraction: u32,
    pub resolution: Resolution,
}

/// Raw global header values. Reserved fields are retained without interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub byte_order: ByteOrder,
    pub resolution: Resolution,
    pub snaplen: u32,
    pub linktype: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_packet_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
        }
    }
}

/// One captured record. `data.len()` is the captured length.
#[derive(Debug, Eq, PartialEq)]
pub struct Packet {
    pub timestamp: Timestamp,
    pub original_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Truncated(&'static str),
    UnsupportedMagic([u8; 4]),
    UnsupportedVersion { major: u16, minor: u16 },
    InvalidField(&'static str),
    PacketLimit { captured: u32, limit: u32 },
    BlockLimit { declared: u32, limit: u32 },
    ResourceLimit { resource: &'static str, limit: u32 },
    UnsupportedBlock(u32),
    WriterFailed,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "capture I/O: {error}"),
            Self::Truncated(part) => write!(f, "truncated {part}"),
            Self::UnsupportedMagic(magic) => write!(f, "unsupported capture magic {magic:02x?}"),
            Self::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported pcap version {major}.{minor}")
            }
            Self::InvalidField(field) => write!(f, "invalid {field}"),
            Self::PacketLimit { captured, limit } => {
                write!(f, "captured length {captured} exceeds packet limit {limit}")
            }
            Self::BlockLimit { declared, limit } => {
                write!(f, "block length {declared} exceeds block limit {limit}")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(f, "{resource} exceeds limit {limit}")
            }
            Self::UnsupportedBlock(kind) => write!(f, "unsupported packet block type {kind}"),
            Self::WriterFailed => write!(f, "capture writer is unusable after I/O failure"),
            Self::Allocation => write!(f, "cannot allocate packet buffer"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8], part: &'static str) -> Result<(), Error> {
    reader.read_exact(buf).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::Truncated(part)
        } else {
            Error::Io(error)
        }
    })
}

/// Owns the input reader, reading only the global header at construction.
///
/// Each `next` consumes at most one record. EOF and all record errors are
/// terminal. Dropping the reader drops its input; `into_inner` returns it at
/// its current position. No seeking or protocol parsing occurs.
pub struct Reader<R> {
    input: R,
    header: Header,
    limits: Limits,
    ended: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(mut input: R, limits: Limits) -> Result<Self, Error> {
        let mut raw = [0; 24];
        read_exact(&mut input, &mut raw, "global header")?;
        let magic = [raw[0], raw[1], raw[2], raw[3]];
        let (byte_order, resolution) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (ByteOrder::Little, Resolution::Microseconds),
            [0xa1, 0xb2, 0xc3, 0xd4] => (ByteOrder::Big, Resolution::Microseconds),
            [0x4d, 0x3c, 0xb2, 0xa1] => (ByteOrder::Little, Resolution::Nanoseconds),
            [0xa1, 0xb2, 0x3c, 0x4d] => (ByteOrder::Big, Resolution::Nanoseconds),
            _ => return Err(Error::UnsupportedMagic(magic)),
        };
        let major = byte_order.u16([raw[4], raw[5]]);
        let minor = byte_order.u16([raw[6], raw[7]]);
        if (major, minor) != (2, 4) {
            return Err(Error::UnsupportedVersion { major, minor });
        }
        let snaplen = byte_order.u32([raw[16], raw[17], raw[18], raw[19]]);
        if snaplen == 0 {
            return Err(Error::InvalidField("zero snap length"));
        }
        let header = Header {
            byte_order,
            resolution,
            snaplen,
            linktype: byte_order.u32([raw[20], raw[21], raw[22], raw[23]]),
            reserved1: byte_order.u32([raw[8], raw[9], raw[10], raw[11]]),
            reserved2: byte_order.u32([raw[12], raw[13], raw[14], raw[15]]),
        };
        Ok(Self {
            input,
            header,
            limits,
            ended: false,
        })
    }

    pub fn header(&self) -> Header {
        self.header
    }

    /// Borrow the underlying input without changing its cursor.
    pub fn get_ref(&self) -> &R {
        &self.input
    }

    pub fn into_inner(self) -> R {
        self.input
    }

    fn read_packet(&mut self) -> Result<Option<Packet>, Error> {
        let mut raw = [0; 16];
        // Only an EOF before the first record byte is a clean end of capture.
        loop {
            match self.input.read(&mut raw[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(Error::Io(error)),
            }
        }
        read_exact(&mut self.input, &mut raw[1..], "record header")?;
        let order = self.header.byte_order;
        let seconds = order.u32([raw[0], raw[1], raw[2], raw[3]]);
        let fraction = order.u32([raw[4], raw[5], raw[6], raw[7]]);
        let captured = order.u32([raw[8], raw[9], raw[10], raw[11]]);
        let original_len = order.u32([raw[12], raw[13], raw[14], raw[15]]);
        if fraction >= self.header.resolution.ticks_per_second() {
            return Err(Error::InvalidField("timestamp fraction"));
        }
        if captured > self.limits.max_packet_bytes {
            return Err(Error::PacketLimit {
                captured,
                limit: self.limits.max_packet_bytes,
            });
        }
        if captured > self.header.snaplen {
            return Err(Error::InvalidField("captured length exceeds snap length"));
        }
        if captured > original_len {
            return Err(Error::InvalidField(
                "captured length exceeds original length",
            ));
        }
        let size = usize::try_from(captured).map_err(|_| Error::Allocation)?;
        let mut data = Vec::new();
        data.try_reserve_exact(size)
            .map_err(|_| Error::Allocation)?;
        data.resize(size, 0);
        read_exact(&mut self.input, &mut data, "packet payload")?;
        Ok(Some(Packet {
            timestamp: Timestamp {
                seconds,
                fraction,
                resolution: self.header.resolution,
            },
            original_len,
            data,
        }))
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Packet, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        match self.read_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => {
                self.ended = true;
                None
            }
            Err(error) => {
                self.ended = true;
                Some(Err(error))
            }
        }
    }
}

impl<R: Read> FusedIterator for Reader<R> {}
