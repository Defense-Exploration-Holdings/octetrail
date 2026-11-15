//! A bounded offline pcapng 1.0 reader for Enhanced Packet Blocks.
//!
//! Section-local interfaces and exact timestamp components are preserved.
//! Deprecated Packet Blocks and timestamp-less Simple Packet Blocks are explicit
//! errors. Other blocks are skipped only after their framing has been validated.

use crate::{read_exact, ByteOrder, Error};
use std::io::{self, Read};
use std::iter::FusedIterator;

const SHB: u32 = 0x0a0d0d0a;
const IDB: u32 = 1;
const EPB: u32 = 6;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_packet_bytes: u32,
    pub max_block_bytes: u32,
    pub max_interfaces: u32,
    pub max_blocks_per_read: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packet_bytes: crate::DEFAULT_MAX_PACKET_BYTES,
            max_block_bytes: 32 * 1024 * 1024,
            max_interfaces: 1024,
            max_blocks_per_read: 4096,
        }
    }
}

/// The wire option encodes a negative power of ten or two. No rounding occurs
/// here, even for resolutions too fine to represent as an integer denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    Decimal(u8),
    Binary(u8),
}

impl Resolution {
    pub const fn components(self) -> (u32, u8) {
        match self {
            Self::Decimal(exponent) => (10, exponent),
            Self::Binary(exponent) => (2, exponent),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interface {
    pub linktype: u16,
    /// Zero means unlimited in pcapng, unlike classic pcap.
    pub snaplen: u32,
    pub resolution: Resolution,
    pub offset_seconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub ticks: u64,
    pub resolution: Resolution,
    pub offset_seconds: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Packet {
    pub section_index: u64,
    pub interface_id: u32,
    pub interface: Interface,
    pub timestamp: Timestamp,
    pub original_len: u32,
    pub data: Vec<u8>,
}

struct Block {
    kind: u32,
    order: ByteOrder,
    body: Vec<u8>,
}

fn word(bytes: &[u8], offset: usize, order: ByteOrder) -> u32 {
    order.u32([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn signed64(bytes: &[u8], order: ByteOrder) -> i64 {
    let raw = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];
    match order {
        ByteOrder::Little => i64::from_le_bytes(raw),
        ByteOrder::Big => i64::from_be_bytes(raw),
    }
}

fn options(
    bytes: &[u8],
    order: ByteOrder,
    mut visit: impl FnMut(u16, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    if bytes.is_empty() {
        return Ok(());
    }
    let mut position = 0;
    while bytes.len() - position >= 4 {
        let code = order.u16([bytes[position], bytes[position + 1]]);
        let length = usize::from(order.u16([bytes[position + 2], bytes[position + 3]]));
        position += 4;
        if code == 0 {
            return if length == 0 && position == bytes.len() {
                Ok(())
            } else {
                Err(Error::InvalidField("pcapng option terminator"))
            };
        }
        let padded = (length + 3) & !3;
        if padded > bytes.len() - position {
            return Err(Error::InvalidField("pcapng option length or padding"));
        }
        visit(code, &bytes[position..position + length])?;
        position += padded;
    }
    Err(Error::InvalidField("missing pcapng option terminator"))
}

/// Owns its input and scans to the first Interface Description Block at
/// construction. Iteration is terminal after EOF or an error. Section lengths,
/// block framing and option boundaries are validated. Packet buffers are owned.
pub struct Reader<R> {
    input: R,
    limits: Limits,
    order: Option<ByteOrder>,
    remaining: Option<u64>,
    section_index: u64,
    interfaces: Vec<Interface>,
    first_interface: Interface,
    ended: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(input: R, limits: Limits) -> Result<Self, Error> {
        let mut reader = Self {
            input,
            limits,
            order: None,
            remaining: None,
            section_index: 0,
            interfaces: Vec::new(),
            first_interface: Interface {
                linktype: 0,
                snaplen: 0,
                resolution: Resolution::Decimal(6),
                offset_seconds: 0,
            },
            ended: false,
        };
        let block = reader
            .block()?
            .ok_or(Error::Truncated("pcapng section header"))?;
        if block.kind != SHB {
            return Err(Error::InvalidField(
                "pcapng first block is not a section header",
            ));
        }
        reader.section(block)?;
        for _ in 0..limits.max_blocks_per_read {
            let Some(block) = reader.block()? else {
                return Err(Error::InvalidField("pcapng interface not found"));
            };
            match block.kind {
                SHB => reader.section(block)?,
                IDB => {
                    reader.interface(block)?;
                    reader.first_interface = reader.interfaces[0];
                    return Ok(reader);
                }
                EPB | 2 | 3 => return Err(Error::InvalidField("pcapng packet before interface")),
                _ => {}
            }
        }
        Err(reader.scan_limit())
    }

    pub fn first_interface(&self) -> Interface {
        self.first_interface
    }

    pub fn get_ref(&self) -> &R {
        &self.input
    }

    pub fn into_inner(self) -> R {
        self.input
    }

    fn scan_limit(&self) -> Error {
        Error::ResourceLimit {
            resource: "pcapng blocks per read",
            limit: self.limits.max_blocks_per_read,
        }
    }

    fn block(&mut self) -> Result<Option<Block>, Error> {
        let mut header = [0; 8];
        loop {
            match self.input.read(&mut header[..1]) {
                Ok(0) => {
                    if self.remaining.is_some_and(|remaining| remaining != 0) {
                        return Err(Error::Truncated("pcapng section"));
                    }
                    return Ok(None);
                }
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(Error::Io(error)),
            }
        }
        read_exact(&mut self.input, &mut header[1..], "pcapng block header")?;
        let section = header[..4] == SHB.to_be_bytes();
        let mut bom = [0; 4];
        let order = if section {
            if self.remaining.is_some_and(|remaining| remaining != 0) {
                return Err(Error::InvalidField("pcapng section length boundary"));
            }
            read_exact(&mut self.input, &mut bom, "pcapng byte order magic")?;
            match bom {
                [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::Big,
                _ => return Err(Error::InvalidField("pcapng byte order magic")),
            }
        } else {
            self.order.ok_or(Error::InvalidField(
                "pcapng first block is not a section header",
            ))?
        };
        let kind = word(&header, 0, order);
        let length = word(&header, 4, order);
        if length < if section { 28 } else { 12 } || length % 4 != 0 {
            return Err(Error::InvalidField("pcapng block length or alignment"));
        }
        if length > self.limits.max_block_bytes {
            return Err(Error::BlockLimit {
                declared: length,
                limit: self.limits.max_block_bytes,
            });
        }
        if !section {
            if let Some(remaining) = self.remaining.as_mut() {
                *remaining = remaining
                    .checked_sub(u64::from(length))
                    .ok_or(Error::InvalidField("pcapng section length boundary"))?;
            }
        }
        let size = usize::try_from(length - 12).map_err(|_| Error::Allocation)?;
        let mut body = Vec::new();
        body.try_reserve_exact(size)
            .map_err(|_| Error::Allocation)?;
        body.resize(size, 0);
        if section {
            body[..4].copy_from_slice(&bom);
            read_exact(&mut self.input, &mut body[4..], "pcapng block body")?;
        } else {
            read_exact(&mut self.input, &mut body, "pcapng block body")?;
        }
        let mut trailer = [0; 4];
        read_exact(&mut self.input, &mut trailer, "pcapng block trailer")?;
        if order.u32(trailer) != length {
            return Err(Error::InvalidField("pcapng repeated block length"));
        }
        Ok(Some(Block { kind, order, body }))
    }

    fn section(&mut self, block: Block) -> Result<(), Error> {
        let body = block.body;
        // The framing minimum guarantees the fixed 16-byte section body.
        if block.order.u16([body[4], body[5]]) != 1 || block.order.u16([body[6], body[7]]) != 0 {
            return Err(Error::InvalidField("unsupported pcapng section version"));
        }
        let length = signed64(&body[8..16], block.order);
        if length < -1 || (length >= 0 && length % 4 != 0) {
            return Err(Error::InvalidField("pcapng section length"));
        }
        options(&body[16..], block.order, |_, _| Ok(()))?;
        if self.order.is_some() {
            self.section_index = self
                .section_index
                .checked_add(1)
                .ok_or(Error::InvalidField("pcapng section count overflow"))?;
        }
        self.order = Some(block.order);
        self.remaining = (length >= 0).then_some(length as u64);
        self.interfaces.clear();
        Ok(())
    }

    fn interface(&mut self, block: Block) -> Result<(), Error> {
        if block.body.len() < 8 {
            return Err(Error::InvalidField("pcapng interface body"));
        }
        if self.interfaces.len() >= self.limits.max_interfaces as usize {
            return Err(Error::ResourceLimit {
                resource: "pcapng interfaces",
                limit: self.limits.max_interfaces,
            });
        }
        let body = block.body;
        let mut interface = Interface {
            linktype: block.order.u16([body[0], body[1]]),
            snaplen: word(&body, 4, block.order),
            resolution: Resolution::Decimal(6),
            offset_seconds: 0,
        };
        let (mut seen_resolution, mut seen_offset) = (false, false);
        options(&body[8..], block.order, |code, value| {
            match code {
                9 => {
                    if value.len() != 1 || seen_resolution {
                        return Err(Error::InvalidField("pcapng timestamp resolution option"));
                    }
                    interface.resolution = if value[0] & 0x80 == 0 {
                        Resolution::Decimal(value[0])
                    } else {
                        Resolution::Binary(value[0] & 0x7f)
                    };
                    seen_resolution = true;
                }
                14 => {
                    if value.len() != 8 || seen_offset {
                        return Err(Error::InvalidField("pcapng timestamp offset option"));
                    }
                    interface.offset_seconds = signed64(value, block.order);
                    seen_offset = true;
                }
                _ => {}
            }
            Ok(())
        })?;
        self.interfaces
            .try_reserve(1)
            .map_err(|_| Error::Allocation)?;
        self.interfaces.push(interface);
        Ok(())
    }

    fn packet(&self, block: Block) -> Result<Packet, Error> {
        let body = block.body;
        if body.len() < 20 {
            return Err(Error::InvalidField("pcapng enhanced packet body"));
        }
        let interface_id = word(&body, 0, block.order);
        let index = usize::try_from(interface_id)
            .map_err(|_| Error::InvalidField("pcapng interface id"))?;
        let interface = *self
            .interfaces
            .get(index)
            .ok_or(Error::InvalidField("pcapng interface id"))?;
        let ticks =
            (u64::from(word(&body, 4, block.order)) << 32) | u64::from(word(&body, 8, block.order));
        let captured = word(&body, 12, block.order);
        let original_len = word(&body, 16, block.order);
        if captured > self.limits.max_packet_bytes {
            return Err(Error::PacketLimit {
                captured,
                limit: self.limits.max_packet_bytes,
            });
        }
        if captured > original_len || (interface.snaplen != 0 && captured > interface.snaplen) {
            return Err(Error::InvalidField("pcapng captured length"));
        }
        let size = usize::try_from(captured).map_err(|_| Error::Allocation)?;
        let end = 20_usize
            .checked_add(size)
            .ok_or(Error::InvalidField("pcapng captured length"))?;
        let padded = end
            .checked_add(3)
            .ok_or(Error::InvalidField("pcapng packet padding"))?
            & !3;
        if padded > body.len() {
            return Err(Error::InvalidField("pcapng packet length or padding"));
        }
        options(&body[padded..], block.order, |_, _| Ok(()))?;
        let mut data = Vec::new();
        data.try_reserve_exact(size)
            .map_err(|_| Error::Allocation)?;
        data.extend_from_slice(&body[20..end]);
        Ok(Packet {
            section_index: self.section_index,
            interface_id,
            interface,
            timestamp: Timestamp {
                ticks,
                resolution: interface.resolution,
                offset_seconds: interface.offset_seconds,
            },
            original_len,
            data,
        })
    }

    fn read_packet(&mut self) -> Result<Option<Packet>, Error> {
        for _ in 0..self.limits.max_blocks_per_read {
            let Some(block) = self.block()? else {
                return Ok(None);
            };
            match block.kind {
                SHB => self.section(block)?,
                IDB => self.interface(block)?,
                EPB => return self.packet(block).map(Some),
                2 | 3 => return Err(Error::UnsupportedBlock(block.kind)),
                _ => {}
            }
        }
        Err(self.scan_limit())
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
