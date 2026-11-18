//! The BER walk of dpkt 1.9.8's `asn1.decode`, without recursion.
//!
//! dpkt decodes the contents of a constructed element by decoding everything
//! from the end of its header to the end of the buffer, then skips the
//! element's length and carries on. This walk visits elements in the same
//! order and reports what dpkt would append, as events with offsets into the
//! buffer. The element count and nesting depth are bounded, because the
//! output of that scheme can grow exponentially with the input.

/// The constructed bit of an identifier octet.
pub const CONSTRUCTED: u8 = 0x20;
/// The tag bits of an identifier octet.
pub const TAGMASK: u8 = 0x1f;
/// Universal INTEGER.
pub const INTEGER: u8 = 2;
/// Universal UTCTime.
pub const UTC_TIME: u8 = 23;

/// Most elements one decode may produce.
pub const MAX_ELEMENTS: usize = 1 << 18;
/// Deepest nesting of constructed elements one decode may produce.
pub const MAX_DEPTH: usize = 512;

/// One step of the decode, in dpkt's order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// A constructed element with this identifier octet starts a nested list.
    Begin(u8),
    /// The innermost nested list ends.
    End,
    /// An INTEGER with its value.
    Integer(u8, u32),
    /// A UTCTime whose text is `buf[start..end]`.
    UtcTime(u8, usize, usize),
    /// Any other primitive element whose value is `buf[start..end]`.
    Bytes(u8, usize, usize),
}

/// Why a decode stopped. Offsets index the buffer that was passed in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    /// dpkt indexes `buf[at]`, past the end, and raises IndexError.
    Index(usize),
    /// dpkt unpacks a 2-byte (`width` 2) or 4-byte (`width` 4) big-endian
    /// value from `buf[start..]`, which is too short, and raises struct.error.
    Short { start: usize, width: usize },
    /// A long-form length with this first octet: dpkt's UnpackError.
    LongLength(u8),
    /// An INTEGER longer than 4 bytes: dpkt's UnpackError.
    IntegerLength(u64),
    /// More than [`MAX_ELEMENTS`] elements.
    Elements,
    /// Deeper than [`MAX_DEPTH`].
    Depth,
}

/// The events of a decode and, if it failed, why. The events are complete
/// up to the failure.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Decoded {
    pub events: Vec<Event>,
    pub stop: Option<Stop>,
}

fn byte(buf: &[u8], at: usize) -> Result<u8, Stop> {
    buf.get(at).copied().ok_or(Stop::Index(at))
}

fn be(buf: &[u8], start: usize, width: usize) -> Result<u32, Stop> {
    let bytes = buf
        .get(start..)
        .and_then(|rest| rest.get(..width))
        .ok_or(Stop::Short { start, width })?;
    Ok(bytes.iter().fold(0, |n, &b| (n << 8) | u32::from(b)))
}

/// What a frame does when the decode it started returns.
#[derive(Clone, Copy, Debug)]
enum Then {
    /// Carry on at this offset.
    Resume(usize),
    /// Decode again from `again` as another element with identifier `t`
    /// (dpkt's indefinite-length case), then carry on at `resume`.
    Twice { t: u8, again: usize, resume: usize },
}

/// Decode `buf` the way dpkt's `asn1.decode(buf)` does.
pub fn decode(buf: &[u8]) -> Decoded {
    let mut out = Decoded::default();
    if let Err(stop) = walk(buf, &mut out.events) {
        out.stop = Some(stop);
    }
    out
}

fn walk(buf: &[u8], events: &mut Vec<Event>) -> Result<(), Stop> {
    let len = buf.len();
    let mut elements = 0usize;
    // Each entry is a decode in progress: what its parent does next.
    let mut frames: Vec<Then> = Vec::new();
    let mut pos = 0usize;
    let mut count = |events: &mut Vec<Event>, event: Event| {
        elements += 1;
        if elements > MAX_ELEMENTS {
            return Err(Stop::Elements);
        }
        events.push(event);
        Ok(())
    };
    let enter = |frames: &mut Vec<Then>, then: Then| {
        if frames.len() >= MAX_DEPTH {
            return Err(Stop::Depth);
        }
        frames.push(then);
        Ok(())
    };
    loop {
        if pos >= len {
            // This decode is done; return to the decode that started it.
            match frames.pop() {
                None => return Ok(()),
                Some(Then::Resume(next)) => {
                    events.push(Event::End);
                    pos = next;
                }
                Some(Then::Twice { t, again, resume }) => {
                    events.push(Event::End);
                    count(events, Event::Begin(t))?;
                    enter(&mut frames, Then::Resume(resume))?;
                    pos = again;
                }
            }
            continue;
        }
        let t = buf[pos];
        let constructed = t & CONSTRUCTED != 0;
        let tag = t & TAGMASK;
        let first = byte(buf, pos + 1)?;
        let mut length = u64::from(first);
        let mut c = 0usize;
        if constructed && first == 128 {
            // dpkt appends decode(buf[2:]) here, then again below.
            let content = pos + 2;
            count(events, Event::Begin(t))?;
            enter(
                &mut frames,
                Then::Twice {
                    t,
                    again: content,
                    resume: content.saturating_add(128),
                },
            )?;
            pos = content;
            continue;
        } else if first >= 128 {
            c = usize::from(first & 127);
            length = match c {
                1 => u64::from(byte(buf, pos + 2)?),
                2 => u64::from(be(buf, pos + 2, 2)?),
                3 => {
                    // dpkt reads from the length octet itself and keeps 12 bits.
                    let n = be(buf, pos + 1, 4)? & 0xfff;
                    c = 2;
                    u64::from(n)
                }
                4 => u64::from(be(buf, pos + 2, 4)?),
                _ => return Err(Stop::LongLength(first)),
            };
        }
        let content = pos + 2 + c;
        let next = usize::try_from(length)
            .ok()
            .and_then(|n| content.checked_add(n))
            .unwrap_or(usize::MAX);
        if constructed {
            count(events, Event::Begin(t))?;
            enter(&mut frames, Then::Resume(next))?;
            pos = content;
            continue;
        }
        let end = next.min(len).max(content.min(len));
        let start = content.min(len);
        let event = if tag == INTEGER {
            let n = match length {
                0 => 0,
                1 => u32::from(byte(buf, content)?),
                2 => be(buf, content, 2)?,
                3 => be(buf, content, 4)? >> 8,
                4 => be(buf, content, 4)?,
                _ => return Err(Stop::IntegerLength(length)),
            };
            Event::Integer(t, n)
        } else if tag == UTC_TIME {
            Event::UtcTime(t, start, end)
        } else {
            Event::Bytes(t, start, end)
        };
        count(events, event)?;
        pos = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(buf: &[u8]) -> Vec<Event> {
        let found = decode(buf);
        assert_eq!(found.stop, None);
        found.events
    }

    #[test]
    fn primitive_and_integer() {
        assert_eq!(
            events(b"\x02\x01\x05\x04\x02ab"),
            [Event::Integer(2, 5), Event::Bytes(4, 5, 7)]
        );
        // A 3-byte INTEGER reads 4 bytes; the next element starts at the 4th.
        let found = decode(b"\x02\x03\x01\x02\x03\x04");
        assert_eq!(found.events, [Event::Integer(2, 0x010203)]);
        assert_eq!(found.stop, Some(Stop::Index(6)));
    }

    #[test]
    fn constructed_contents_run_to_the_end() {
        // dpkt: [(48, [(2, 5), (4, b'x')]), (4, b'x')]
        assert_eq!(
            events(b"\x30\x03\x02\x01\x05\x04\x01x"),
            [
                Event::Begin(0x30),
                Event::Integer(2, 5),
                Event::Bytes(4, 7, 8),
                Event::End,
                Event::Bytes(4, 7, 8),
            ]
        );
    }

    #[test]
    fn indefinite_length_is_decoded_twice() {
        assert_eq!(
            events(b"\x30\x80\x02\x01\x05"),
            [
                Event::Begin(0x30),
                Event::Integer(2, 5),
                Event::End,
                Event::Begin(0x30),
                Event::Integer(2, 5),
                Event::End,
            ]
        );
    }

    #[test]
    fn long_form_lengths() {
        assert_eq!(events(b"\x04\x81\x01a"), [Event::Bytes(4, 3, 4)]);
        assert_eq!(
            events(b"\x04\x84\x00\x00\x00\x02ab"),
            [Event::Bytes(4, 6, 8)]
        );
        assert_eq!(decode(b"\x04\x85").stop, Some(Stop::LongLength(0x85)));
        assert_eq!(decode(b"\x04\x80ab").stop, Some(Stop::LongLength(0x80)));
        assert_eq!(decode(b"\x04\x81").stop, Some(Stop::Index(2)));
        assert_eq!(
            decode(b"\x04\x82\x00").stop,
            Some(Stop::Short { start: 2, width: 2 })
        );
    }

    #[test]
    fn short_integers_fail_like_dpkt() {
        assert_eq!(decode(b"\x02").stop, Some(Stop::Index(1)));
        assert_eq!(decode(b"\x02\x01").stop, Some(Stop::Index(2)));
        assert_eq!(
            decode(b"\x02\x03\x01\x02\x03").stop,
            Some(Stop::Short { start: 2, width: 4 })
        );
        assert_eq!(decode(b"\x02\x05").stop, Some(Stop::IntegerLength(5)));
    }

    #[test]
    fn huge_lengths_do_not_overflow() {
        assert_eq!(
            events(b"\x04\x84\xff\xff\xff\xffab"),
            [Event::Bytes(4, 6, 8)]
        );
    }

    #[test]
    fn exponential_output_is_bounded() {
        let buf = b"\x30\x00".repeat(40);
        assert_eq!(decode(&buf).stop, Some(Stop::Elements));
        let deep: Vec<u8> = (0..MAX_DEPTH + 1).flat_map(|_| [0x30u8, 0x80]).collect();
        assert_eq!(decode(&deep).stop, Some(Stop::Depth));
    }
}
