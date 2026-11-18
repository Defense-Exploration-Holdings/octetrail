//! HTTP/2 frame boundaries as dpkt 1.9.8's `frame_multi_factory` finds them.

/// Bytes in a frame header: a 24-bit length, the type, the flags and the
/// stream id.
pub const FRAME_HEADER_LEN: usize = 9;

/// The whole frames found from a start offset, as `(start, end)` pairs, and
/// where the bytes that do not hold a whole frame begin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frames {
    pub spans: Vec<(usize, usize)>,
    pub tail: usize,
}

/// Find each whole frame from `start`: a header and the payload its length
/// gives. The walk stops at the first frame that is cut off.
pub fn frames(data: &[u8], start: usize) -> Frames {
    let mut spans = Vec::new();
    let mut at = start.min(data.len());
    while data.len() - at >= FRAME_HEADER_LEN {
        let length = u32::from_be_bytes([0, data[at], data[at + 1], data[at + 2]]);
        let Some(end) = usize::try_from(length)
            .ok()
            .and_then(|n| (at + FRAME_HEADER_LEN).checked_add(n))
            .filter(|&end| end <= data.len())
        else {
            break;
        };
        spans.push((at, end));
        at = end;
    }
    Frames { spans, tail: at }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes()[1..].to_vec();
        out.extend_from_slice(&[4, 0, 0, 0, 0, 0]);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn whole_frames_then_tail() {
        let mut data = frame(b"");
        data.extend(frame(b"abcdef"));
        data.extend(&frame(b"cut")[..10]);
        assert_eq!(
            frames(&data, 0),
            Frames {
                spans: vec![(0, 9), (9, 24)],
                tail: 24
            }
        );
    }

    #[test]
    fn start_offset_and_short_header() {
        let mut data = b"preface".to_vec();
        data.extend(frame(b"x"));
        data.extend(b"\0\0");
        assert_eq!(
            frames(&data, 7),
            Frames {
                spans: vec![(7, 17)],
                tail: 17
            }
        );
        assert_eq!(
            frames(b"ab", 5),
            Frames {
                spans: vec![],
                tail: 2
            }
        );
    }
}
