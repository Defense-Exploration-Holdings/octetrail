//! Offline classic-pcap 2.4 output to a caller-provided synchronous sink.
//!
//! Native timestamps are exact wire components. Validation never emits a partial
//! record. I/O can emit a prefix before failing, after which the writer is terminal.

use crate::{ByteOrder, Error, Limits, Resolution, Timestamp};
use std::io::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    pub byte_order: ByteOrder,
    pub resolution: Resolution,
    pub snaplen: u32,
    pub linktype: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            byte_order: if cfg!(target_endian = "little") {
                ByteOrder::Little
            } else {
                ByteOrder::Big
            },
            resolution: Resolution::Microseconds,
            snaplen: 1500,
            linktype: 1,
        }
    }
}

pub(crate) fn word(order: ByteOrder, value: u32) -> [u8; 4] {
    match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    }
}

pub(crate) fn half(order: ByteOrder, value: u16) -> [u8; 2] {
    match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    }
}

/// Emits a global header at construction, then one header and borrowed payload
/// per call. No packet buffer is allocated. Call `flush` explicitly to observe
/// flush errors. This wrapper does not flush on drop or `into_inner`; the sink's
/// own drop behavior still applies.
pub struct Writer<W> {
    output: W,
    options: Options,
    limits: Limits,
    failed: bool,
}

impl<W: Write> Writer<W> {
    pub fn new(mut output: W, options: Options, limits: Limits) -> Result<Self, Error> {
        if options.snaplen == 0 {
            return Err(Error::InvalidField("zero snap length"));
        }
        let mut header = [0; 24];
        let magic = match options.resolution {
            Resolution::Microseconds => 0xa1b2c3d4,
            Resolution::Nanoseconds => 0xa1b23c4d,
        };
        header[..4].copy_from_slice(&word(options.byte_order, magic));
        header[4..6].copy_from_slice(&half(options.byte_order, 2));
        header[6..8].copy_from_slice(&half(options.byte_order, 4));
        // Reserved timezone and accuracy fields remain zero.
        header[16..20].copy_from_slice(&word(options.byte_order, options.snaplen));
        header[20..24].copy_from_slice(&word(options.byte_order, options.linktype));
        output.write_all(&header).map_err(Error::Io)?;
        Ok(Self {
            output,
            options,
            limits,
            failed: false,
        })
    }

    /// The native API can preserve a larger original wire length. Python's
    /// dpkt-style methods instead set original and captured lengths identically.
    pub fn write_packet(
        &mut self,
        timestamp: Timestamp,
        original_len: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::WriterFailed);
        }
        if timestamp.resolution != self.options.resolution {
            return Err(Error::InvalidField(
                "timestamp resolution does not match writer",
            ));
        }
        if timestamp.fraction >= self.options.resolution.ticks_per_second() {
            return Err(Error::InvalidField("timestamp fraction"));
        }
        let captured = u32::try_from(data.len())
            .map_err(|_| Error::InvalidField("captured length exceeds 32 bits"))?;
        if captured > self.limits.max_packet_bytes {
            return Err(Error::PacketLimit {
                captured,
                limit: self.limits.max_packet_bytes,
            });
        }
        if captured > self.options.snaplen {
            return Err(Error::InvalidField("captured length exceeds snap length"));
        }
        if captured > original_len {
            return Err(Error::InvalidField(
                "captured length exceeds original length",
            ));
        }
        let mut header = [0; 16];
        for (field, value) in header.chunks_exact_mut(4).zip([
            timestamp.seconds,
            timestamp.fraction,
            captured,
            original_len,
        ]) {
            field.copy_from_slice(&word(self.options.byte_order, value));
        }
        let result = self
            .output
            .write_all(&header)
            .and_then(|()| self.output.write_all(data));
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

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub fn into_inner(self) -> W {
        self.output
    }
}
