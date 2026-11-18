//! IEEE 802.11 information elements and radiotap present words, read the way
//! dpkt 1.9.8 walks them. Offsets index the bytes that were passed in.

/// dpkt stops reading information elements when four or fewer bytes are left,
/// the length of a frame check sequence.
pub const FCS_LEN: usize = 4;

/// The start of each information element. Each one is two bytes of type and
/// length and then its data; the next starts after the stated length, and the
/// walk ends when no more than four bytes are left.
pub fn ie_starts(data: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut at = 0;
    while data.len().saturating_sub(at) > FCS_LEN {
        starts.push(at);
        at += 2 + usize::from(data[at + 1]);
    }
    starts
}

/// A radiotap present word whose extension bit cannot be read because the
/// bytes end first. dpkt fails here with `IndexError`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortPresent {
    /// The byte of the present flags that dpkt reads.
    pub index: usize,
}

/// The number of present-flag bytes after the four-byte radiotap header: one
/// 32-bit word, and another for each word whose bit 31 is set.
pub fn present_len(data: &[u8]) -> Result<usize, ShortPresent> {
    let mut words = 1;
    loop {
        let index = 4 * words - 1;
        let have = (4 * words).min(data.len());
        if index >= have {
            return Err(ShortPresent { index });
        }
        if data[index] & 0x80 == 0 {
            return Ok(4 * words);
        }
        words += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements() {
        assert_eq!(
            ie_starts(b"\x00\x03abc\x01\x01x\x00\x00\x00\x00"),
            vec![0, 5]
        );
        assert_eq!(ie_starts(b"\x00\x09ab"), Vec::<usize>::new());
        assert_eq!(ie_starts(b"\x00\x09abcdef"), vec![0]);
    }

    #[test]
    fn present_words() {
        assert_eq!(present_len(b"\x00\x00\x00\x00"), Ok(4));
        assert_eq!(present_len(b"\x00\x00\x00\x80\x01\x00\x00\x00"), Ok(8));
        assert_eq!(
            present_len(b"\x00\x00\x00\x80\x01"),
            Err(ShortPresent { index: 7 })
        );
        assert_eq!(present_len(b"\x00\x00"), Err(ShortPresent { index: 3 }));
    }
}
