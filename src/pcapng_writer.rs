//! Bounded single-section, single-interface offline pcapng output.
//!
//! Timestamps are exact ticks. Optional clock metadata does not change those
//! ticks implicitly. Packet and metadata validation precede their output.

use crate::pcapng::{Interface, Resolution};
use crate::writer::{half, word};
use crate::{ByteOrder, Error};
use std::io::{self, Write};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_packet_bytes: u32,
    pub max_block_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packet_bytes: crate::DEFAULT_MAX_PACKET_BYTES,
            max_block_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options<'a> {
    pub byte_order: ByteOrder,
    pub snaplen: u32,
    pub linktype: u16,
    pub timestamp_resolution: Option<Resolution>,
    pub timestamp_offset: Option<i64>,
    pub section_comment: Option<&'a [u8]>,
    pub interface_name: Option<&'a [u8]>,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            byte_order: if cfg!(target_endian = "little") {
                ByteOrder::Little
            } else {
                ByteOrder::Big
            },
            snaplen: 1500,
            linktype: 1,
            timestamp_resolution: None,
            timestamp_offset: None,
            section_comment: None,
            interface_name: None,
        }
    }
}

fn text_length(value: Option<&[u8]>) -> Result<u32, Error> {
    match value {
        None => Ok(0),
        Some(bytes) => {
            let size = u16::try_from(bytes.len())
                .map_err(|_| Error::InvalidField("pcapng option exceeds 16 bits"))?;
            std::str::from_utf8(bytes)
                .map_err(|_| Error::InvalidField("pcapng text option must be UTF-8"))?;
            Ok(4 + ((u32::from(size) + 3) & !3))
        }
    }
}

fn check_block(length: u32, limit: u32) -> Result<(), Error> {
    if length > limit {
        Err(Error::BlockLimit {
            declared: length,
            limit,
        })
    } else {
        Ok(())
    }
}

fn option(output: &mut impl Write, order: ByteOrder, code: u16, bytes: &[u8]) -> io::Result<()> {
    // Callers validate the 16-bit length before emitting the enclosing block.
    let mut header = [0; 4];
    header[..2].copy_from_slice(&half(order, code));
    header[2..].copy_from_slice(&half(order, bytes.len() as u16));
    output.write_all(&header)?;
    output.write_all(bytes)?;
    output.write_all(&[0; 3][..(4 - bytes.len() % 4) % 4])
}

/// Emits one pcapng 1.0 section of unknown length, one interface and only EPBs.
/// Header options are borrowed during construction and not retained. No packet
/// serialization buffer is allocated. I/O failure is terminal and may leave a
/// prefix; explicit flush reports sink errors but does not promise durability.
pub struct Writer<W> {
    output: W,
    order: ByteOrder,
    interface: Interface,
    limits: Limits,
    failed: bool,
}

impl<W: Write> Writer<W> {
    pub fn new(mut output: W, options: Options<'_>, limits: Limits) -> Result<Self, Error> {
        let comment_length = text_length(options.section_comment)?;
        let name_length = text_length(options.interface_name)?;
        let encoded_resolution = match options.timestamp_resolution {
            None => None,
            Some(Resolution::Decimal(exponent)) if exponent <= 127 => Some(exponent),
            Some(Resolution::Binary(exponent)) if exponent <= 127 => Some(exponent | 0x80),
            _ => {
                return Err(Error::InvalidField(
                    "pcapng resolution exponent exceeds 127",
                ))
            }
        };
        let interface_options = options.interface_name.is_some()
            || encoded_resolution.is_some()
            || options.timestamp_offset.is_some();
        let section_length = 28
            + comment_length
            + if options.section_comment.is_some() {
                4
            } else {
                0
            };
        let interface_length = 20
            + name_length
            + if encoded_resolution.is_some() { 8 } else { 0 }
            + if options.timestamp_offset.is_some() {
                12
            } else {
                0
            }
            + if interface_options { 4 } else { 0 };
        // Validate both initial blocks before any part of the section is emitted.
        check_block(section_length, limits.max_block_bytes)?;
        check_block(interface_length, limits.max_block_bytes)?;
        let order = options.byte_order;
        let mut shb = [0; 24];
        shb[..4].copy_from_slice(&word(order, 0x0a0d0d0a));
        shb[4..8].copy_from_slice(&word(order, section_length));
        shb[8..12].copy_from_slice(&word(order, 0x1a2b3c4d));
        shb[12..14].copy_from_slice(&half(order, 1));
        shb[16..24].fill(0xff);
        output.write_all(&shb).map_err(Error::Io)?;
        if let Some(comment) = options.section_comment {
            option(&mut output, order, 1, comment).map_err(Error::Io)?;
            output.write_all(&[0; 4]).map_err(Error::Io)?;
        }
        output
            .write_all(&word(order, section_length))
            .map_err(Error::Io)?;
        let mut idb = [0; 16];
        idb[..4].copy_from_slice(&word(order, 1));
        idb[4..8].copy_from_slice(&word(order, interface_length));
        idb[8..10].copy_from_slice(&half(order, options.linktype));
        idb[12..16].copy_from_slice(&word(order, options.snaplen));
        output.write_all(&idb).map_err(Error::Io)?;
        if let Some(name) = options.interface_name {
            option(&mut output, order, 2, name).map_err(Error::Io)?;
        }
        if let Some(resolution) = encoded_resolution {
            option(&mut output, order, 9, &[resolution]).map_err(Error::Io)?;
        }
        if let Some(offset) = options.timestamp_offset {
            let bytes = match order {
                ByteOrder::Little => offset.to_le_bytes(),
                ByteOrder::Big => offset.to_be_bytes(),
            };
            option(&mut output, order, 14, &bytes).map_err(Error::Io)?;
        }
        if interface_options {
            output.write_all(&[0; 4]).map_err(Error::Io)?;
        }
        output
            .write_all(&word(order, interface_length))
            .map_err(Error::Io)?;
        Ok(Self {
            output,
            order,
            limits,
            failed: false,
            interface: Interface {
                linktype: options.linktype,
                snaplen: options.snaplen,
                resolution: options
                    .timestamp_resolution
                    .unwrap_or(Resolution::Decimal(6)),
                offset_seconds: options.timestamp_offset.unwrap_or(0),
            },
        })
    }

    pub fn write_packet(
        &mut self,
        ticks: u64,
        original_len: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::WriterFailed);
        }
        let captured = u32::try_from(data.len())
            .map_err(|_| Error::InvalidField("pcapng captured length exceeds 32 bits"))?;
        if captured > self.limits.max_packet_bytes {
            return Err(Error::PacketLimit {
                captured,
                limit: self.limits.max_packet_bytes,
            });
        }
        if captured > original_len
            || (self.interface.snaplen != 0 && captured > self.interface.snaplen)
        {
            return Err(Error::InvalidField("pcapng captured length"));
        }
        let padded = captured
            .checked_add(3)
            .ok_or(Error::InvalidField("pcapng packet length overflow"))?
            & !3;
        let length = padded
            .checked_add(32)
            .ok_or(Error::InvalidField("pcapng packet block length overflow"))?;
        check_block(length, self.limits.max_block_bytes)?;
        let mut header = [0; 28];
        for (field, value) in header.chunks_exact_mut(4).zip([
            6,
            length,
            0,
            (ticks >> 32) as u32,
            ticks as u32,
            captured,
            original_len,
        ]) {
            field.copy_from_slice(&word(self.order, value));
        }
        let result = self
            .output
            .write_all(&header)
            .and_then(|()| self.output.write_all(data))
            .and_then(|()| {
                self.output
                    .write_all(&[0; 3][..(padded - captured) as usize])
            })
            .and_then(|()| self.output.write_all(&word(self.order, length)));
        if let Err(error) = result {
            self.failed = true;
            return Err(Error::Io(error));
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::WriterFailed);
        }
        if let Err(error) = self.output.flush() {
            self.failed = true;
            return Err(Error::Io(error));
        }
        Ok(())
    }

    pub fn get_ref(&self) -> &W {
        &self.output
    }
    pub fn interface(&self) -> Interface {
        self.interface
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }
    pub fn into_inner(self) -> W {
        self.output
    }
}
