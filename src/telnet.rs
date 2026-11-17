//! Telnet option stripping as dpkt 1.9.8's `strip_options` does it.
//! Offsets index the buffer that was passed in.

pub const IAC: u8 = 255;
pub const SB: u8 = 250;
pub const SE: u8 = 240;

/// The suboption names dpkt looks for, in its order.
pub const SUBOPTIONS: [&[u8]; 3] = [b"USER", b"DISPLAY", b"TERM"];

/// The lines and suboption values found in a buffer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stripped {
    /// `(start, end)` of each line, in order.
    pub lines: Vec<(usize, usize)>,
    /// `(index into SUBOPTIONS, start, end)` of each value, in the order dpkt
    /// assigns them; a later value replaces an earlier one with the same name.
    pub options: Vec<(usize, usize, usize)>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split `buf[start..end]` into lines the way dpkt does: NUL bytes become line
/// breaks, then `bytes.splitlines()` runs and one trailing empty line is dropped.
fn lines(buf: &[u8], start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    let first = out.len();
    let mut at = start;
    let mut line = start;
    while at < end {
        match buf[at] {
            b'\n' | 0 => {
                out.push((line, at));
                at += 1;
                line = at;
            }
            b'\r' => {
                out.push((line, at));
                at += 1;
                if at < end && matches!(buf[at], b'\n' | 0) {
                    at += 1;
                }
                line = at;
            }
            _ => at += 1,
        }
    }
    if line < end {
        out.push((line, end));
    }
    if out.len() > first {
        let (s, e) = out[out.len() - 1];
        if s == e {
            out.pop();
        }
    }
}

/// dpkt's `strip_options`: split on IAC, drop command bytes and suboption
/// negotiation, read the USER, DISPLAY and TERM suboption values, and return
/// the remaining text as lines.
pub fn strip_options(buf: &[u8]) -> Stripped {
    let mut found = Stripped::default();
    let mut subopt = false;
    let mut start = 0;
    let n = buf.len();
    while start <= n {
        let end = buf[start..]
            .iter()
            .position(|&b| b == IAC)
            .map_or(n, |p| start + p);
        let mut piece = (start, end);
        start = end + 1;
        if piece.0 == piece.1 {
            continue;
        }
        let o = buf[piece.0];
        let keep = if o > SB {
            piece.0 = (piece.0 + 2).min(piece.1);
            true
        } else if o == SE {
            piece.0 += 1;
            subopt = false;
            true
        } else if o == SB {
            subopt = true;
            let w = &buf[piece.0..piece.1];
            for (index, name) in SUBOPTIONS.iter().enumerate() {
                let mut key = name.to_vec();
                key.push(1);
                if let Some(p) = find(w, &key) {
                    let value = piece.0 + p + key.len();
                    let stop = buf[value..piece.1]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(piece.1, |q| value + q);
                    found.options.push((index, value, stop));
                }
            }
            false
        } else {
            !subopt
        };
        if keep && piece.0 < piece.1 {
            lines(buf, piece.0, piece.1, &mut found.lines);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text<'a>(buf: &'a [u8], found: &Stripped) -> Vec<&'a [u8]> {
        found.lines.iter().map(|&(s, e)| &buf[s..e]).collect()
    }

    #[test]
    fn options_and_lines() {
        let buf = b"\xff\xfb\x18\xff\xfa\x27\x00USER\x01bob\x00\xff\xf0login\r\x00pw\r\x00";
        let found = strip_options(buf);
        assert_eq!(text(buf, &found), vec![&b"login"[..], b"pw"]);
        let (index, s, e) = found.options[0];
        assert_eq!((SUBOPTIONS[index], &buf[s..e]), (&b"USER"[..], &b"bob"[..]));
    }

    #[test]
    fn trailing_null() {
        let buf = b"\x01\x00\x02\x00\x00";
        assert_eq!(text(buf, &strip_options(buf)), vec![&b"\x01"[..], b"\x02"]);
    }
}
