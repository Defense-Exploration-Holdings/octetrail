//! DHCP options as dpkt 1.9.8 reads them. Ranges index the bytes after the
//! fixed header, and are cut to the bytes present.

pub type Range = (usize, usize);

/// The options and where the bytes after them start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub opts: Vec<(u8, Range)>,
    pub rest: usize,
}

/// An option type in the last byte, with no length byte after it. dpkt fails
/// here with `IndexError`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingLength {
    pub at: usize,
}

/// Read options until an end option (255) or the end of `data`. Pad options
/// (0) are skipped. An option's data is cut short when `data` ends early, and
/// reading continues after its full stated length.
pub fn options(data: &[u8]) -> Result<Options, MissingLength> {
    let mut opts = Vec::new();
    let mut at = 0;
    while at < data.len() {
        match data[at] {
            0xff => {
                at += 1;
                break;
            }
            0 => at += 1,
            t => {
                let n = *data.get(at + 1).ok_or(MissingLength { at })?;
                let start = (at + 2).min(data.len());
                let end = (at + 2 + usize::from(n)).min(data.len());
                opts.push((t, (start, end)));
                at = end;
            }
        }
    }
    Ok(Options { opts, rest: at })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_end_and_rest() {
        let found = options(b"\x00\x35\x01\x05\x00\x32\x04abcd\xffTAIL").unwrap();
        assert_eq!(found.opts, vec![(0x35, (3, 4)), (0x32, (7, 11))]);
        assert_eq!(found.rest, 12);
    }

    #[test]
    fn short_data_is_cut() {
        let found = options(b"\x0c\x09ab").unwrap();
        assert_eq!(found.opts, vec![(0x0c, (2, 4))]);
        assert_eq!(found.rest, 4);
    }

    #[test]
    fn missing_length() {
        assert_eq!(options(b"\x00\x0c"), Err(MissingLength { at: 1 }));
        assert_eq!(
            options(b""),
            Ok(Options {
                opts: vec![],
                rest: 0
            })
        );
    }
}
