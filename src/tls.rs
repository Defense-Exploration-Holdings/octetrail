//! TLS and SSLv2 framing and hello parsing, following `dpkt.ssl` in dpkt 1.9.8.
//!
//! Every function returns ranges into the buffer it was given. Where dpkt's
//! code would hit a `struct.error`, these functions return [`Error::Struct`],
//! together with whatever dpkt had already stored. No cryptography.

use std::fmt;

/// The record versions `tls_multi_factory` and `SSLFactory` recognize.
pub const SSL3_VERSIONS: [u16; 4] = [0x0300, 0x0301, 0x0302, 0x0303];

pub type Range = (usize, usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// dpkt would raise `struct.error` here: a fixed-size field is cut short.
    Struct,
    /// A record says it is longer than the bytes present.
    ShortRecord,
    /// `tls_multi_factory` found a record whose version is not SSL 3 or TLS.
    Version(usize),
    /// An SSLv2 record has no padding-length byte.
    Index,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Struct => f.write_str("a fixed-size TLS field is cut short"),
            Self::ShortRecord => f.write_str("TLSRecord data was too short."),
            Self::Version(at) => write!(f, "bad TLS version at offset {at}"),
            Self::Index => f.write_str("index out of range"),
        }
    }
}
impl std::error::Error for Error {}

fn clamp(buf: &[u8], start: usize, end: usize) -> Range {
    (start.min(buf.len()), end.min(buf.len()))
}

fn shift((a, b): Range, by: usize) -> Range {
    (a + by, b + by)
}

/// `parse_variable_array(buf[at:], lenbytes)`: the data range, cut to the
/// bytes present, and the declared size plus the length bytes.
pub fn variable_array(buf: &[u8], at: usize, lenbytes: usize) -> Result<(Range, usize), Error> {
    let start = at.saturating_add(lenbytes);
    let field = buf
        .get(at.min(buf.len())..start.min(buf.len()))
        .unwrap_or_default();
    if field.len() != lenbytes {
        return Err(Error::Struct);
    }
    let size = field.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b));
    Ok((
        clamp(buf, start, start.saturating_add(size)),
        size + lenbytes,
    ))
}

fn u16_at(buf: &[u8], at: usize) -> Result<u16, Error> {
    match buf.get(at..at.saturating_add(2)) {
        Some([a, b]) => Ok(u16::from_be_bytes([*a, *b])),
        _ => Err(Error::Struct),
    }
}

/// `parse_extensions(buf[at:])`. On an error, the extensions read so far are
/// returned with it.
pub fn extensions(buf: &[u8], at: usize) -> (Vec<(u16, Range)>, Option<Error>) {
    let mut found = Vec::new();
    let Ok(total) = u16_at(buf, at) else {
        return (found, Some(Error::Struct));
    };
    let mut pointer = 2usize;
    while pointer < usize::from(total) {
        let kind = match u16_at(buf, at.saturating_add(pointer)) {
            Ok(kind) => kind,
            Err(e) => return (found, Some(e)),
        };
        pointer += 2;
        match variable_array(buf, at.saturating_add(pointer), 2) {
            Ok((data, parsed)) => {
                found.push((kind, data));
                pointer += parsed;
            }
            Err(e) => return (found, Some(e)),
        }
    }
    (found, None)
}

/// The variable part of a ClientHello or ServerHello, as dpkt stores it. A
/// field is `None` when dpkt did not reach it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Hello {
    pub session_id: Option<Range>,
    /// ClientHello cipher suite codes, or the one ServerHello code.
    pub ciphersuites: Option<Vec<u16>>,
    /// ClientHello compression methods, or the one ServerHello method.
    pub compression: Option<Range>,
    pub extensions: Option<Vec<(u16, Range)>>,
    pub error: Option<Error>,
}

/// The fixed ClientHello and ServerHello header: version and random.
pub const HELLO_LEN: usize = 34;

impl Hello {
    fn extensions_at(&mut self, body: &[u8], at: usize) {
        // dpkt parses extensions only when at least six bytes follow.
        if body.len().saturating_sub(at) >= 6 {
            let (found, error) = extensions(body, at);
            if error.is_none() {
                self.extensions = Some(found);
            }
            self.error = error;
        }
    }

    /// `TLSClientHello.unpack` after its fixed header, on `body = buf[34:]`.
    pub fn client(body: &[u8]) -> Self {
        let mut hello = Self::default();
        let run = |hello: &mut Self| -> Result<(), Error> {
            let (session, mut pointer) = variable_array(body, 0, 1)?;
            hello.session_id = Some(session);
            let (suites, parsed) = variable_array(body, pointer, 2)?;
            pointer += parsed;
            let raw = &body[suites.0..suites.1];
            if raw.len() % 2 != 0 {
                return Err(Error::Struct);
            }
            hello.ciphersuites = Some(
                raw.chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect(),
            );
            let (methods, parsed) = variable_array(body, pointer, 1)?;
            pointer += parsed;
            hello.compression = Some(methods);
            hello.extensions_at(body, pointer);
            Ok(())
        };
        if let Err(e) = run(&mut hello) {
            hello.error = Some(e);
        }
        hello
    }

    /// `TLSServerHello.unpack` after its fixed header, on `body = buf[34:]`.
    pub fn server(body: &[u8]) -> Self {
        let mut hello = Self::default();
        let run = |hello: &mut Self| -> Result<(), Error> {
            let (session, mut pointer) = variable_array(body, 0, 1)?;
            hello.session_id = Some(session);
            hello.ciphersuites = Some(vec![u16_at(body, pointer)?]);
            pointer += 2;
            if pointer >= body.len() {
                return Err(Error::Struct);
            }
            hello.compression = Some((pointer, pointer + 1));
            pointer += 1;
            hello.extensions_at(body, pointer);
            Ok(())
        };
        if let Err(e) = run(&mut hello) {
            hello.error = Some(e);
        }
        hello
    }
}

/// `TLSCertificate.unpack`. The outer error means the list length itself is
/// cut short. Otherwise the certificates read are returned with the error that
/// stopped the loop, if any.
pub fn certificates(body: &[u8]) -> Result<(Vec<Range>, Option<Error>), Error> {
    let (_, total) = variable_array(body, 0, 3)?;
    let mut found = Vec::new();
    let mut pointer = 3;
    while pointer < total {
        match variable_array(body, pointer, 3) {
            Ok((cert, parsed)) => {
                found.push(cert);
                pointer += parsed;
            }
            Err(e) => return Ok((found, Some(e))),
        }
    }
    Ok((found, None))
}

/// One TLS record header and its data range, as `TLSRecord.unpack` reads it.
/// `buf` holds at least five bytes.
fn record(buf: &[u8], at: usize) -> Result<Range, Error> {
    let length = usize::from(u16_at(buf, at + 3)?);
    let data = clamp(buf, at + 5, at + 5 + length);
    if data.1 - data.0 != length {
        return Err(Error::ShortRecord);
    }
    Ok(data)
}

/// `TLS.unpack`: the record spans read and the error that stopped it, if any.
/// The first span starts at 0, so it includes the five header bytes `TLS`
/// itself unpacked, as in dpkt.
pub fn tls_records(buf: &[u8]) -> (Vec<Range>, Option<Error>) {
    let mut spans = Vec::new();
    let mut pointer = 0usize;
    while pointer < buf.len().saturating_sub(5) {
        let Ok(length) = u16_at(buf, pointer + 3) else {
            return (spans, Some(Error::Struct));
        };
        let end = pointer + 5 + usize::from(length);
        // TLSRecord(buf[pointer:end]) needs its declared data within the slice.
        if end > buf.len() {
            return (spans, Some(Error::ShortRecord));
        }
        spans.push((pointer, end));
        pointer = end;
    }
    (spans, None)
}

/// `tls_multi_factory`: the complete record spans and the bytes they use.
pub fn multi_factory(buf: &[u8]) -> Result<(Vec<Range>, usize), Error> {
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i + 5 <= buf.len() {
        let version = u16::from_be_bytes([buf[i + 1], buf[i + 2]]);
        if !SSL3_VERSIONS.contains(&version) {
            return Err(Error::Version(i));
        }
        match record(buf, i) {
            Ok((_, end)) => {
                spans.push((i, end));
                i = end;
            }
            Err(_) => break,
        }
    }
    Ok((spans, i))
}

/// The pieces of an SSLv2 record after its two-byte header, as `SSL2.unpack`
/// splits `data = buf[2:]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ssl2 {
    pub len: u16,
    pub msg: Range,
    pub pad: Option<Range>,
    pub rest: Range,
}

pub fn ssl2(len: u16, data: &[u8]) -> Result<Ssl2, Error> {
    if len & 0x8000 != 0 {
        let n = usize::from(len & 0x7fff);
        let msg = clamp(data, 0, n);
        return Ok(Ssl2 {
            len: len & 0x7fff,
            msg,
            pad: None,
            rest: (msg.1, data.len()),
        });
    }
    let n = usize::from(len & 0x3fff);
    let padlen = usize::from(*data.first().ok_or(Error::Index)?);
    let msg = clamp(data, 1, 1 + n);
    let pad = clamp(data, 1 + n, 1 + n + padlen);
    Ok(Ssl2 {
        len: len & 0x3fff,
        msg,
        pad: Some(pad),
        rest: (pad.1, data.len()),
    })
}

/// Move every range of a hello by `by` bytes.
pub fn shift_hello(mut hello: Hello, by: usize) -> Hello {
    hello.session_id = hello.session_id.map(|r| shift(r, by));
    hello.compression = hello.compression.map(|r| shift(r, by));
    if let Some(found) = &mut hello.extensions {
        found.iter_mut().for_each(|(_, r)| *r = shift(*r, by));
    }
    hello
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_arrays_report_the_declared_size() {
        assert_eq!(variable_array(b"\x05ab", 0, 1), Ok(((1, 3), 6)));
        assert_eq!(variable_array(b"\x00\x00\x02xyz", 0, 3), Ok(((3, 5), 5)));
        assert_eq!(variable_array(b"\x00", 0, 2), Err(Error::Struct));
        assert_eq!(variable_array(b"", 7, 1), Err(Error::Struct));
    }

    #[test]
    fn extensions_stop_at_the_declared_total() {
        // The loop compares the pointer with the total, not total + 2.
        let buf = b"\x00\x04\x00\x0a\x00\x00\xff\xff";
        assert_eq!(extensions(buf, 0), (vec![(10, (6, 6))], None));
        assert_eq!(
            extensions(b"\x00\x09\x00\x0a\x00", 0).1,
            Some(Error::Struct)
        );
    }

    #[test]
    fn records_and_factory() {
        let rec = b"\x16\x03\x01\x00\x02hi";
        let mut two = rec.to_vec();
        two.extend_from_slice(b"\x17\x03\x03\x00\x05ab");
        assert_eq!(multi_factory(&two), Ok((vec![(0, 7)], 7)));
        assert_eq!(
            multi_factory(b"\x16\x09\x09\x00\x00"),
            Err(Error::Version(0))
        );
        assert_eq!(tls_records(rec), (vec![(0, 7)], None));
        assert_eq!(tls_records(&two).1, Some(Error::ShortRecord));
    }

    #[test]
    fn ssl2_split() {
        let s = ssl2(0x8003, b"abcdef").unwrap();
        assert_eq!((s.len, s.msg, s.rest), (3, (0, 3), (3, 6)));
        let s = ssl2(0x0002, b"\x01abpz").unwrap();
        assert_eq!((s.msg, s.pad, s.rest), ((1, 3), Some((3, 4)), (4, 5)));
        assert_eq!(ssl2(0x0002, b""), Err(Error::Index));
    }
}
