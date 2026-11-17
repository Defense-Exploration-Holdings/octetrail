//! Bounded passive TLS envelopes and ServerHello metadata. No cryptography.
use std::fmt;
pub const MAX_MESSAGE: usize = 1024 * 1024;
pub const MAX_RECORD_DATA: usize = 65535;
pub const MAX_RECORDS: usize = 1024;
pub const MAX_EXTENSIONS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Format,
    Version,
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "incomplete TLS envelope or ServerHello",
            Self::Format => "invalid TLS ServerHello framing in supported subset",
            Self::Version => "unrecognized TLS record version",
            Self::Limit => "TLS byte or extension limit exceeded",
        })
    }
}
impl std::error::Error for Error {}
fn budget(raw: &[u8]) -> Result<(), Error> {
    if raw.len() > MAX_MESSAGE {
        Err(Error::Limit)
    } else {
        Ok(())
    }
}
fn u16_at(raw: &[u8], pos: usize) -> Result<u16, Error> {
    let bytes = raw
        .get(pos..pos.checked_add(2).ok_or(Error::Limit)?)
        .ok_or(Error::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
#[derive(Debug, Eq, PartialEq)]
pub struct Record<'a> {
    pub kind: u8,
    pub version: u16,
    pub data: &'a [u8],
}
impl<'a> Record<'a> {
    /// Parse one envelope. Supplied bytes beyond its length are not consumed.
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        // Only the framed record is read; trailing input is not copied or charged.
        if raw.len() < 5 {
            return Err(Error::Truncated);
        }
        let length = u16_at(raw, 3)? as usize;
        let data = raw.get(5..5 + length).ok_or(Error::Truncated)?;
        Ok(Self {
            kind: raw[0],
            version: u16_at(raw, 1)?,
            data,
        })
    }
}
/// Frame complete records with known legacy versions, leaving a partial tail.
pub fn records(raw: &[u8]) -> Result<(Vec<(usize, usize)>, usize), Error> {
    let mut spans = Vec::new();
    let mut pos = 0;
    while raw.len() - pos >= 5 {
        if spans.len() == MAX_RECORDS || MAX_MESSAGE - pos < 5 {
            break;
        }
        let end = pos + 5 + u16_at(raw, pos + 3)? as usize;
        if end > MAX_MESSAGE {
            break;
        }
        let version = u16_at(raw, pos + 1)?;
        if !(0x0300..=0x0303).contains(&version) {
            return Err(Error::Version);
        }
        if end > raw.len() {
            break;
        }
        spans.push((pos, end));
        pos = end;
    }
    Ok((spans, pos))
}
pub fn record_bytes(kind: u8, version: u16, length: u16, data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() > MAX_RECORD_DATA {
        return Err(Error::Limit);
    }
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(kind);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}
#[derive(Debug, Eq, PartialEq)]
pub struct Handshake<'a> {
    pub kind: u8,
    pub data: &'a [u8],
}
impl<'a> Handshake<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() < 4 {
            return Err(Error::Truncated);
        }
        let length = ((raw[1] as usize) << 16) | ((raw[2] as usize) << 8) | raw[3] as usize;
        // A declared length does not consume memory. Report missing bytes first.
        let data = raw.get(4..4 + length).ok_or(Error::Truncated)?;
        if length > MAX_MESSAGE - 4 {
            return Err(Error::Limit);
        }
        Ok(Self { kind: raw[0], data })
    }
}
pub fn handshake_bytes(kind: u8, length: u32, data: &[u8]) -> Result<Vec<u8>, Error> {
    if length as usize > MAX_MESSAGE - 4 || data.len() > MAX_MESSAGE - 4 {
        return Err(Error::Limit);
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.push(kind);
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.extend_from_slice(data);
    Ok(out)
}
#[derive(Debug, Eq, PartialEq)]
pub struct ServerHello<'a> {
    pub version: u16,
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_code: u16,
    pub compression: u8,
    pub extensions: Option<Vec<(u16, &'a [u8])>>,
    /// Entire variable tail, retained as the authoritative serialization input.
    pub data: &'a [u8],
}
impl<'a> ServerHello<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        budget(raw)?;
        if raw.len() < 35 {
            return Err(Error::Truncated);
        }
        let session_len = raw[34] as usize;
        if session_len > 32 {
            return Err(Error::Format);
        }
        let session_end = 35 + session_len;
        let session_id = raw.get(35..session_end).ok_or(Error::Truncated)?;
        let cipher_code = u16_at(raw, session_end)?;
        let compression = *raw.get(session_end + 2).ok_or(Error::Truncated)?;
        let mut pos = session_end + 3;
        let extensions = if pos == raw.len() {
            None
        } else {
            let n = u16_at(raw, pos)? as usize;
            pos += 2;
            if n > raw.len() - pos {
                return Err(Error::Truncated);
            }
            if n != raw.len() - pos {
                return Err(Error::Format);
            }
            let mut rows = Vec::new();
            while pos < raw.len() {
                if rows.len() == MAX_EXTENSIONS {
                    return Err(Error::Limit);
                }
                let kind = u16_at(raw, pos)?;
                let length = u16_at(raw, pos + 2)? as usize;
                pos += 4;
                let payload = raw.get(pos..pos + length).ok_or(Error::Truncated)?;
                rows.push((kind, payload));
                pos += length;
            }
            Some(rows)
        };
        Ok(Self {
            version: u16_at(raw, 0)?,
            // The complete 35-byte prefix was validated before reading session_len.
            random: &raw[2..34],
            session_id,
            cipher_code,
            compression,
            extensions,
            data: &raw[34..],
        })
    }
}
pub fn hello_bytes(version: u16, random: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if random.len() != 32 {
        return Err(Error::Format);
    }
    if data.len() > MAX_MESSAGE - 34 {
        return Err(Error::Limit);
    }
    let mut out = Vec::with_capacity(34 + data.len());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(random);
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello() -> Vec<u8> {
        let mut out = vec![3, 3];
        out.extend(0..32);
        out.extend_from_slice(&[4, b'n', b'o', b't', b'e', 0, 0x2f, 0]);
        out
    }
    #[test]
    fn ordinary_record_and_incremental_tail() {
        let raw = [23, 3, 3, 0, 4, b'n', b'o', b't', b'e'];
        let r = Record::parse(&raw).unwrap();
        assert_eq!(r.kind, 23);
        assert_eq!(r.version, 0x303);
        assert_eq!(r.data, b"note");
        assert_eq!(record_bytes(23, 0x303, 4, b"note").unwrap(), raw);
        let mut joined = raw.to_vec();
        joined.extend_from_slice(&[22, 3, 3, 0, 4, 2]);
        assert_eq!(records(&joined).unwrap(), (vec![(0, 9)], 9));
        assert_eq!(Record::parse(&joined[9..]), Err(Error::Truncated));
    }
    #[test]
    fn unknown_handshake_stays_opaque() {
        let raw = [99, 0, 0, 4, 0, 255, b'n', b'o'];
        let h = Handshake::parse(&raw).unwrap();
        assert_eq!(h.kind, 99);
        assert_eq!(h.data, &[0, 255, b'n', b'o']);
        assert_eq!(handshake_bytes(h.kind, 4, h.data).unwrap(), raw);
    }
    #[test]
    fn independent_hello_and_opaque_extensions() {
        let mut raw = hello();
        raw.extend_from_slice(&[0, 8, 0xfd, 0xe8, 0, 4, b'n', b'o', b't', b'e']);
        let h = ServerHello::parse(&raw).unwrap();
        assert_eq!(h.session_id, b"note");
        assert_eq!(h.random, &(0..32).collect::<Vec<u8>>());
        assert_eq!(h.cipher_code, 0x2f);
        assert_eq!(h.compression, 0);
        assert_eq!(h.extensions, Some(vec![(65000, &b"note"[..])]));
        assert_eq!(hello_bytes(h.version, h.random, h.data).unwrap(), raw);
    }
    #[test]
    fn finite_limits_and_ordinary_partial_messages() {
        assert_eq!(Record::parse(&[23, 3, 3, 0]), Err(Error::Truncated));
        assert_eq!(Handshake::parse(&[2, 0, 0, 4, 3]), Err(Error::Truncated));
        assert_eq!(ServerHello::parse(&hello()[..36]), Err(Error::Truncated));
        assert_eq!(records(&[23, 3, 4, 0, 0]), Err(Error::Version));
        assert!(records(&[23, 3, 3, 0, 0].repeat(MAX_RECORDS)).is_ok());
        let input = [23, 3, 3, 0, 0].repeat(MAX_RECORDS + 1);
        let (spans, used) = records(&input).unwrap();
        assert_eq!((spans.len(), used), (MAX_RECORDS, 5 * MAX_RECORDS));
        assert_eq!(records(&input[used..]).unwrap(), (vec![(0, 5)], 5));
        assert_eq!(
            record_bytes(23, 0x303, 0, &vec![0; MAX_RECORD_DATA + 1]),
            Err(Error::Limit)
        );
        let mut h = hello();
        let ext = [0xfd, 0xe8, 0, 0].repeat(MAX_EXTENSIONS);
        h.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        h.extend_from_slice(&ext);
        assert!(ServerHello::parse(&h).is_ok());
        let ext = [0xfd, 0xe8, 0, 0].repeat(MAX_EXTENSIONS + 1);
        let mut h = hello();
        h.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        h.extend_from_slice(&ext);
        assert_eq!(ServerHello::parse(&h), Err(Error::Limit));
    }
    #[test]
    fn large_backing_buffers_only_charge_framed_bytes() {
        let frame = record_bytes(23, 0x303, 60000, &vec![b'n'; 60000]).unwrap();
        let input = frame.repeat(20);
        assert!(input.len() > MAX_MESSAGE);
        let first = Record::parse(&input).unwrap();
        assert_eq!(first.data.len(), 60000);
        assert_eq!(first.data.as_ptr(), input[5..].as_ptr());
        let (spans, used) = records(&input).unwrap();
        assert_eq!(spans.len(), MAX_MESSAGE / frame.len());
        assert_eq!(used, spans.len() * frame.len());
        assert_eq!(records(&input[used..]).unwrap().1, input.len() - used);
        let mut raw = vec![20, 0, 0, 4, b'n', b'o', b't', b'e'];
        raw.resize(MAX_MESSAGE + 32, 0);
        assert_eq!(Handshake::parse(&raw).unwrap().data, b"note");
    }
    #[test]
    fn length_precedence_format_and_retained_pack_fields() {
        let length = MAX_MESSAGE as u32;
        let mut raw = vec![20];
        raw.extend_from_slice(&length.to_be_bytes()[1..]);
        assert_eq!(Handshake::parse(&raw), Err(Error::Truncated));
        raw.resize(4 + MAX_MESSAGE, 0);
        assert_eq!(Handshake::parse(&raw), Err(Error::Limit));
        let mut h = hello();
        h[34] = 33;
        assert_eq!(ServerHello::parse(&h), Err(Error::Format));
        assert_eq!(
            record_bytes(23, 0x303, 4, b"ok").unwrap(),
            b"\x17\x03\x03\0\x04ok"
        );
        assert_eq!(handshake_bytes(20, 4, b"ok").unwrap(), b"\x14\0\0\x04ok");
    }
}
