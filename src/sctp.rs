//! SCTP chunks as dpkt 1.9.8 reads them, and the CRC-32C checksum.
//! Offsets index the whole packet, starting at the 12-byte common header.

pub type Range = (usize, usize);

pub const HEADER_LEN: usize = 12;
pub const CHUNK_HEADER_LEN: usize = 4;
pub const DATA: u8 = 0;

/// A chunk header is cut off; `have` bytes were left.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortChunk {
    pub have: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chunk {
    pub kind: u8,
    pub flags: u8,
    pub len: u16,
    /// The chunk data. A length below four drops that many bytes short of
    /// four from the end of the packet, as dpkt's slice does.
    pub data: Range,
    /// Padding after a DATA chunk whose length is not a multiple of four.
    pub padding: Range,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    pub chunks: Vec<Chunk>,
    /// True when a chunk of length zero ended the list, which leaves the
    /// rest of the packet unread.
    pub stopped: bool,
}

/// Read chunks from `buf[start..]` until the end, or until one whose length
/// and padding are both zero. Each chunk starts `len` plus padding bytes
/// after the previous one, so a length below four makes chunks overlap.
pub fn chunks(buf: &[u8], start: usize) -> Result<Layout, ShortChunk> {
    let n = buf.len();
    let mut at = start.min(n);
    let mut found = Vec::new();
    while at < n {
        if n - at < CHUNK_HEADER_LEN {
            return Err(ShortChunk { have: n - at });
        }
        let kind = buf[at];
        let len = u16::from_be_bytes([buf[at + 2], buf[at + 3]]);
        let data_start = at + CHUNK_HEADER_LEN;
        let declared = usize::from(len);
        let data_end = if declared >= CHUNK_HEADER_LEN {
            (data_start + declared - CHUNK_HEADER_LEN).min(n)
        } else {
            n.saturating_sub(CHUNK_HEADER_LEN - declared)
                .max(data_start)
        };
        let padding_end = if kind == DATA && declared % 4 != 0 {
            (data_end + 4 - declared % 4).min(n)
        } else {
            data_end
        };
        found.push(Chunk {
            kind,
            flags: buf[at + 1],
            len,
            data: (data_start, data_end),
            padding: (data_end, padding_end),
        });
        let step = declared + (padding_end - data_end);
        if step == 0 {
            return Ok(Layout {
                chunks: found,
                stopped: true,
            });
        }
        at = at.saturating_add(step);
    }
    Ok(Layout {
        chunks: found,
        stopped: false,
    })
}

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// The reflected CRC-32C table that dpkt's `crc32c_table` lists.
pub const CRC32C_TABLE: [u32; 256] = crc32c_table();

/// Add `buf` to the running CRC `crc`, as dpkt's `crc32c.add` does.
pub fn crc32c_add(mut crc: u32, buf: &[u8]) -> u32 {
    for b in buf {
        crc = (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(*b)) & 0xff) as usize];
    }
    crc
}

/// Finish a running CRC, inverted and byte-swapped as dpkt's `crc32c.done` does.
pub fn crc32c_done(crc: u32) -> u32 {
    (!crc).swap_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_the_catalogue_check_value() {
        assert_eq!(crc32c_done(crc32c_add(0xffff_ffff, b"")), 0);
        assert_eq!(
            crc32c_done(crc32c_add(0xffff_ffff, b"123456789")),
            0xe306_9283u32.swap_bytes()
        );
        assert_eq!(CRC32C_TABLE[1], 0xF26B_8303);
    }

    #[test]
    fn data_chunks_take_their_padding() {
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(b"\x00\x03\x00\x05x\x00\x00\x00\x0b\x00\x00\x04");
        let found = chunks(&buf, HEADER_LEN).unwrap();
        assert!(!found.stopped);
        assert_eq!(found.chunks.len(), 2);
        assert_eq!(found.chunks[0].data, (16, 17));
        assert_eq!(found.chunks[0].padding, (17, 20));
        assert_eq!(found.chunks[1].data, (24, 24));
    }

    #[test]
    fn short_lengths_overlap_and_zero_stops() {
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(b"\x0b\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        let found = chunks(&buf, HEADER_LEN).unwrap();
        assert!(found.stopped);
        assert_eq!(found.chunks[1].data, (20, 22));
        let short = [0u8, 0, 0, 0, 0x0b, 0, 0, 4, 0, 0];
        assert_eq!(chunks(&short, 4).unwrap_err(), ShortChunk { have: 2 });
        let found = chunks(&[0x0b, 0, 0, 1, 7, 7, 7, 7, 7], 0).unwrap();
        assert_eq!(found.chunks[0].data, (4, 6));
        assert_eq!(found.chunks[1].len, 0x0107);
    }
}
