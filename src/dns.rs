//! Offline DNS messages, names and common resource records, parsed and packed the
//! way dpkt 1.9.8 does. No transport I/O.

use std::collections::HashMap;
use std::fmt;

/// Name loop iterations, records and text chunks one parse may take. Compression
/// pointers must point strictly backwards, so every name ends, but a crafted
/// message can still chain thousands of pointers per name.
pub const MAX_STEPS: usize = 1 << 24;
/// Decoded name and text bytes one parse may produce.
pub const MAX_WORK_BYTES: usize = 64 * 1024 * 1024;

pub const DNS_A: u16 = 1;
pub const DNS_NS: u16 = 2;
pub const DNS_CNAME: u16 = 5;
pub const DNS_SOA: u16 = 6;
pub const DNS_NULL: u16 = 10;
pub const DNS_PTR: u16 = 12;
pub const DNS_HINFO: u16 = 13;
pub const DNS_MX: u16 = 15;
pub const DNS_TXT: u16 = 16;
pub const DNS_AAAA: u16 = 28;
pub const DNS_SRV: u16 = 33;
pub const DNS_OPT: u16 = 41;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The header is shorter than twelve bytes, or a name runs past the end.
    NeedData,
    /// A fixed-size field is cut short (a `struct.error` in dpkt).
    ShortField,
    /// A compression pointer does not point before the current name.
    Pointer,
    /// The labels of a name add up to more than 255 bytes.
    NameLength,
    /// A label length byte uses the reserved 0x40 or 0x80 forms.
    LabelType(u8),
    /// A name or text string is not UTF-8.
    Encoding,
    /// The record type has no decoder in dpkt.
    UnsupportedType(u16),
    /// A packing input cannot be represented.
    Pack(&'static str),
    Limit,
    Allocation,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedData => write!(f, "incomplete DNS message"),
            Self::ShortField => write!(f, "invalid DNS: truncated field"),
            Self::Pointer => write!(f, "Invalid label compression pointer"),
            Self::NameLength => write!(f, "name longer than 255 bytes"),
            Self::LabelType(n) => write!(f, "Invalid label length {n:02x}"),
            Self::Encoding => write!(f, "DNS textual field requires UTF-8"),
            Self::UnsupportedType(kind) => write!(f, "RR type {kind} is not supported"),
            Self::Pack(reason) => write!(f, "{reason}"),
            Self::Limit => write!(f, "DNS work limit exceeded"),
            Self::Allocation => write!(f, "cannot allocate DNS output"),
        }
    }
}
impl std::error::Error for Error {}

/// The work a parse may still do: name steps and decoded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    pub steps: usize,
    pub bytes: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}
impl Budget {
    pub fn new() -> Self {
        Self {
            steps: MAX_STEPS,
            bytes: MAX_WORK_BYTES,
        }
    }
    fn charge(&mut self, bytes: usize) -> Result<(), Error> {
        self.steps = self.steps.checked_sub(1).ok_or(Error::Limit)?;
        self.bytes = self.bytes.checked_sub(bytes).ok_or(Error::Limit)?;
        Ok(())
    }
}

/// `n` bytes at `offset`, or `ShortField` when fewer remain.
fn fixed(data: &[u8], offset: usize, n: usize) -> Result<&[u8], Error> {
    match offset.checked_add(n) {
        Some(end) if end <= data.len() => Ok(&data[offset..end]),
        _ => Err(Error::ShortField),
    }
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
/// `data[start..start + n]`, clamped to the bytes present like a Python slice.
fn slice(data: &[u8], start: usize, n: usize) -> &[u8] {
    let start = start.min(data.len());
    &data[start..start.saturating_add(n).min(data.len())]
}

/// Decode a possibly compressed name at `offset`, as dpkt's `unpack_name` does.
/// Returns the name and the offset just past it in the original position.
pub fn unpack_name(data: &[u8], offset: usize) -> Result<(String, usize), Error> {
    name(data, offset, &mut Budget::new())
}

fn name(data: &[u8], offset: usize, budget: &mut Budget) -> Result<(String, usize), Error> {
    let (raw, next) = unpack_name_raw(data, offset, budget)?;
    let name = String::from_utf8(raw).map_err(|_| Error::Encoding)?;
    Ok((name, next))
}

/// [`unpack_name`] without the UTF-8 check, charging `budget`. The labels are
/// joined with dots.
pub fn unpack_name_raw(
    data: &[u8],
    mut offset: usize,
    budget: &mut Budget,
) -> Result<(Vec<u8>, usize), Error> {
    let mut out = Vec::new();
    let mut saved = None;
    let mut start = offset;
    let mut length = 0usize;
    let mut labels = 0usize;
    loop {
        budget.charge(0)?;
        let Some(&n) = data.get(offset) else {
            return Err(Error::NeedData);
        };
        if n == 0 {
            offset += 1;
            break;
        }
        match n & 0xc0 {
            0xc0 => {
                let target = usize::from(be16(fixed(data, offset, 2)?) & 0x3fff);
                if target >= start {
                    return Err(Error::Pointer);
                }
                offset += 2;
                saved.get_or_insert(offset);
                start = target;
                offset = target;
            }
            0 => {
                offset += 1;
                let label = slice(data, offset, usize::from(n));
                length += usize::from(n) + 1;
                if length > 255 {
                    return Err(Error::NameLength);
                }
                budget.charge(label.len() + 1)?;
                if labels > 0 {
                    out.push(b'.');
                }
                out.extend_from_slice(label);
                labels += 1;
                offset += usize::from(n);
            }
            _ => return Err(Error::LabelType(n)),
        }
    }
    Ok((out, saved.unwrap_or(offset)))
}

/// `(start, end)` of each TXT or HINFO character string in `raw`, cut to the
/// bytes present, as dpkt's loop reads them.
pub fn text_ranges(raw: &[u8]) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        let start = at + 1;
        let end = (start + usize::from(raw[at])).min(raw.len());
        found.push((start.min(end), end));
        at = start + usize::from(raw[at]);
    }
    found
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}

/// A parsed resource record. `raw` is the RDATA slice, clamped to the message
/// like dpkt's `rdata`; `rlen` is the declared length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub rlen: u16,
    pub raw: &'a [u8],
    /// Decoded names: NS, CNAME, PTR and MX one, SOA two, SRV one.
    pub names: Vec<String>,
    /// MX preference; SOA serial, refresh, retry, expire, minimum; SRV priority,
    /// weight, port.
    pub numbers: Vec<u32>,
    /// TXT and HINFO character strings.
    pub text: Vec<String>,
}

#[derive(Debug)]
pub struct Message<'a> {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub sections: [Vec<Record<'a>>; 3],
}

fn record<'a>(
    data: &'a [u8],
    offset: &mut usize,
    budget: &mut Budget,
) -> Result<Record<'a>, Error> {
    let (owner, next) = name(data, *offset, budget)?;
    let fields = fixed(data, next, 10)?;
    let kind = be16(&fields[..2]);
    let start = next + 10;
    let rlen = be16(&fields[8..]);
    let raw = slice(data, start, usize::from(rlen));
    let mut rr = Record {
        name: owner,
        kind,
        class: be16(&fields[2..4]),
        ttl: be32(&fields[4..8]),
        rlen,
        raw,
        names: Vec::new(),
        numbers: Vec::new(),
        text: Vec::new(),
    };
    match kind {
        DNS_A | DNS_AAAA | DNS_NULL | DNS_OPT => {}
        DNS_NS | DNS_CNAME | DNS_PTR => rr.names.push(name(data, start, budget)?.0),
        DNS_SOA => {
            let (mname, at) = name(data, start, budget)?;
            let (rname, at) = name(data, at, budget)?;
            rr.names = vec![mname, rname];
            let numbers = fixed(data, at, 20)?;
            rr.numbers = numbers.chunks_exact(4).map(be32).collect();
        }
        DNS_MX => {
            rr.numbers.push(u32::from(be16(fixed(raw, 0, 2)?)));
            rr.names.push(name(data, start + 2, budget)?.0);
        }
        DNS_SRV => {
            let numbers = fixed(raw, 0, 6)?;
            rr.numbers = numbers
                .chunks_exact(2)
                .map(|b| u32::from(be16(b)))
                .collect();
            rr.names.push(name(data, start + 6, budget)?.0);
        }
        DNS_TXT | DNS_HINFO => {
            let mut rest = raw;
            while let Some(&n) = rest.first() {
                let chunk = slice(rest, 1, usize::from(n));
                budget.charge(chunk.len())?;
                let text = std::str::from_utf8(chunk).map_err(|_| Error::Encoding)?;
                rr.text.push(text.to_owned());
                rest = slice(rest, 1 + usize::from(n), usize::MAX);
            }
        }
        _ => return Err(Error::UnsupportedType(kind)),
    }
    *offset = start + usize::from(rlen);
    Ok(rr)
}

impl<'a> Message<'a> {
    /// Parse a message. Trailing bytes after the declared sections are ignored,
    /// as in dpkt.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = data.get(..12).ok_or(Error::NeedData)?;
        let count = |i: usize| usize::from(be16(&header[4 + 2 * i..]));
        let mut budget = Budget::new();
        let mut offset = 12;
        // Each question takes at least five bytes and each record eleven, so the
        // lists only grow with input that is present.
        let mut questions = Vec::new();
        for _ in 0..count(0) {
            budget.charge(0)?;
            let (name, next) = name(data, offset, &mut budget)?;
            let fields = fixed(data, next, 4)?;
            questions.push(Question {
                name,
                kind: be16(&fields[..2]),
                class: be16(&fields[2..]),
            });
            offset = next + 4;
        }
        let mut sections: [Vec<Record<'a>>; 3] = std::array::from_fn(|_| Vec::new());
        for (index, section) in sections.iter_mut().enumerate() {
            for _ in 0..count(index + 1) {
                budget.charge(0)?;
                section.push(record(data, &mut offset, &mut budget)?);
            }
        }
        Ok(Self {
            id: be16(header),
            flags: be16(&header[2..]),
            questions,
            sections,
        })
    }
}

/// Resource data to pack for one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rdata<'a> {
    /// Bytes copied as they are: a nonempty `rdata`, an address or OPT's empty data.
    Raw(&'a [u8]),
    /// NS, CNAME or PTR.
    Name(String),
    Soa {
        mname: String,
        rname: String,
        numbers: [u32; 5],
    },
    Mx {
        preference: u16,
        name: String,
    },
    Srv {
        numbers: [u16; 3],
        name: String,
    },
    /// TXT or HINFO character strings.
    Text(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Rdata<'a>,
}

/// dpkt's `pack_name`: split on dots, compress with ASCII case-folded suffixes
/// found in `pointers`, and remember new suffixes that start below 0xc000.
/// `offset` is where the name will be written in the message.
pub fn pack_name(
    value: &str,
    offset: usize,
    pointers: &mut HashMap<Vec<u8>, usize>,
) -> Result<Vec<u8>, Error> {
    let table = std::cell::RefCell::new(pointers);
    let found = pack_name_with(
        value.as_bytes(),
        offset,
        |key| Ok::<_, ()>(table.borrow().get(key).copied()),
        |key, at| {
            table.borrow_mut().insert(key, at);
            Ok(())
        },
    );
    match found {
        Ok(raw) => Ok(raw),
        Err(PackNameError::Pointer(_)) => Err(Error::Pack("DNS compression pointer out of range")),
        Err(PackNameError::Label(_)) => Err(Error::Pack("DNS label exceeds 255 bytes")),
        Err(PackNameError::Lookup(())) => unreachable!("a HashMap lookup cannot fail"),
    }
}

/// Why [`pack_name_with`] stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackNameError<E> {
    /// `0xc000 | pointer` does not fit 16 bits; the value is that sum.
    Pointer(usize),
    /// A label is longer than 255 bytes; the value is its length.
    Label(usize),
    /// The caller's lookup or insert failed.
    Lookup(E),
}

/// [`pack_name`] over the encoded name, with the suffix table behind `get`
/// and `put`, so that a caller can keep it in its own map.
pub fn pack_name_with<E>(
    value: &[u8],
    offset: usize,
    mut get: impl FnMut(&[u8]) -> Result<Option<usize>, E>,
    mut put: impl FnMut(Vec<u8>, usize) -> Result<(), E>,
) -> Result<Vec<u8>, PackNameError<E>> {
    let mut labels: Vec<&[u8]> = if value.is_empty() {
        Vec::new()
    } else {
        value.split(|b| *b == b'.').collect()
    };
    labels.push(b"");
    let mut out = Vec::new();
    for index in 0..labels.len() {
        let key = labels[index..].join(&b'.').to_ascii_uppercase();
        if let Some(pointer) = get(&key).map_err(PackNameError::Lookup)? {
            let pointer = 0xc000 | pointer;
            let pointer = u16::try_from(pointer).map_err(|_| PackNameError::Pointer(pointer))?;
            out.extend_from_slice(&pointer.to_be_bytes());
            return Ok(out);
        }
        let at = offset + out.len();
        if key.len() > 1 && at < 0xc000 {
            put(key, at).map_err(PackNameError::Lookup)?;
        }
        let label = labels[index];
        let n = u8::try_from(label.len()).map_err(|_| PackNameError::Label(label.len()))?;
        out.push(n);
        out.extend_from_slice(label);
    }
    Ok(out)
}

struct Writer {
    out: Vec<u8>,
    pointers: HashMap<Vec<u8>, usize>,
}
impl Writer {
    fn append(&mut self, raw: &[u8]) -> Result<(), Error> {
        self.out
            .try_reserve(raw.len())
            .map_err(|_| Error::Allocation)?;
        self.out.extend_from_slice(raw);
        Ok(())
    }
    fn name(&mut self, value: &str) -> Result<(), Error> {
        let raw = pack_name(value, self.out.len(), &mut self.pointers)?;
        self.append(&raw)
    }
    fn record(&mut self, rr: &Entry<'_>) -> Result<(), Error> {
        self.name(&rr.name)?;
        self.append(&rr.kind.to_be_bytes())?;
        self.append(&rr.class.to_be_bytes())?;
        self.append(&rr.ttl.to_be_bytes())?;
        let length_at = self.out.len();
        self.append(&[0, 0])?;
        let start = self.out.len();
        match &rr.rdata {
            Rdata::Raw(raw) => self.append(raw)?,
            Rdata::Name(name) => self.name(name)?,
            Rdata::Soa {
                mname,
                rname,
                numbers,
            } => {
                self.name(mname)?;
                self.name(rname)?;
                for n in numbers {
                    self.append(&n.to_be_bytes())?
                }
            }
            Rdata::Mx { preference, name } => {
                self.append(&preference.to_be_bytes())?;
                self.name(name)?
            }
            Rdata::Srv { numbers, name } => {
                for n in numbers {
                    self.append(&n.to_be_bytes())?
                }
                self.name(name)?
            }
            Rdata::Text(chunks) => {
                for chunk in chunks {
                    let n = u8::try_from(chunk.len())
                        .map_err(|_| Error::Pack("DNS text string exceeds 255 bytes"))?;
                    self.append(&[n])?;
                    self.append(chunk)?
                }
            }
        }
        let n = u16::try_from(self.out.len() - start)
            .map_err(|_| Error::Pack("DNS rdata exceeds 65535 bytes"))?;
        self.out[length_at..length_at + 2].copy_from_slice(&n.to_be_bytes());
        Ok(())
    }
}

pub fn header(id: u16, flags: u16, counts: [usize; 4]) -> Result<[u8; 12], Error> {
    let mut out = [0; 12];
    out[..2].copy_from_slice(&id.to_be_bytes());
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    for (index, n) in counts.iter().enumerate() {
        let n = u16::try_from(*n).map_err(|_| Error::Pack("DNS section has over 65535 entries"))?;
        out[4 + index * 2..6 + index * 2].copy_from_slice(&n.to_be_bytes())
    }
    Ok(out)
}

/// Pack a message as dpkt's `DNS.__bytes__` does. The pointer dictionary is
/// rebuilt from the names written here; raw RDATA is copied without adding to it.
pub fn encode(
    id: u16,
    flags: u16,
    questions: &[Question],
    sections: [&[Entry<'_>]; 3],
) -> Result<Vec<u8>, Error> {
    let fixed = header(
        id,
        flags,
        [
            questions.len(),
            sections[0].len(),
            sections[1].len(),
            sections[2].len(),
        ],
    )?;
    let mut writer = Writer {
        out: Vec::new(),
        pointers: HashMap::new(),
    };
    writer.append(&fixed)?;
    for q in questions {
        writer.name(&q.name)?;
        writer.append(&q.kind.to_be_bytes())?;
        writer.append(&q.class.to_be_bytes())?
    }
    for section in sections {
        for rr in section {
            writer.record(rr)?
        }
    }
    Ok(writer.out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_work_budget_rejects_before_consumption() {
        let mut empty_steps = Budget {
            steps: 0,
            bytes: 100,
        };
        assert_eq!(empty_steps.charge(1), Err(Error::Limit));
        let mut empty_bytes = Budget {
            steps: 100,
            bytes: 0,
        };
        assert_eq!(empty_bytes.charge(1), Err(Error::Limit));
    }

    #[test]
    fn text_strings_are_cut_to_the_bytes_present() {
        assert_eq!(
            text_ranges(b"\x02ab\x00\x05xy"),
            vec![(1, 3), (4, 4), (5, 7)]
        );
        assert_eq!(text_ranges(b""), vec![]);
    }

    #[test]
    fn raw_names_skip_the_utf8_check() {
        let mut budget = Budget::new();
        let (name, next) = unpack_name_raw(b"\x02\xff\xfe\0", 0, &mut budget).unwrap();
        assert_eq!((name, next), (vec![0xff, 0xfe], 4));
        assert_eq!(budget.steps, MAX_STEPS - 3);
    }
}
