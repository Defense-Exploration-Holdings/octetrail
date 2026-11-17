//! Bounded offline DNS messages, names and common resource records. No transport I/O.

use std::collections::HashMap;
use std::fmt;

pub const MAX_MESSAGE: usize = 65535;
pub const MAX_RECORDS: usize = 1024;
// A name has at most 127 one-byte labels (two charges each), one root
// and MAX_POINTERS pointer charges. Three names per record cover SOA;
// one extra charge per record and one per possible text byte cover the rest.
pub const MAX_STEPS: usize = MAX_RECORDS * (3 * (255 + MAX_POINTERS) + 1) + MAX_MESSAGE;
pub const MAX_WORK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_POINTERS: usize = 128;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Name,
    Rdata,
    Encoding,
    Limit,
    Allocation,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Truncated => "incomplete DNS message field",
                Self::Name => "unsupported or inconsistent DNS name",
                Self::Rdata => "inconsistent DNS resource data",
                Self::Encoding => "DNS textual field requires UTF-8",
                Self::Limit => "DNS size or work limit exceeded",
                Self::Allocation => "cannot allocate DNS output",
            }
        )
    }
}
impl std::error::Error for Error {}

struct Budget {
    steps: usize,
    bytes: usize,
}
impl Budget {
    fn new() -> Self {
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

fn take<'a>(data: &'a [u8], offset: &mut usize, n: usize, end: usize) -> Result<&'a [u8], Error> {
    let next = offset.checked_add(n).ok_or(Error::Limit)?;
    if next > end || next > data.len() {
        return Err(Error::Truncated);
    }
    let out = &data[*offset..next];
    *offset = next;
    Ok(out)
}
fn u16_at(data: &[u8], offset: &mut usize, end: usize) -> Result<u16, Error> {
    let b = take(data, offset, 2, end)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn u32_at(data: &[u8], offset: &mut usize, end: usize) -> Result<u32, Error> {
    let b = take(data, offset, 4, end)?;
    Ok(u32::from_be_bytes(b.try_into().expect("fixed field")))
}

fn name(data: &[u8], offset: &mut usize, end: usize, budget: &mut Budget) -> Result<String, Error> {
    let mut position = *offset;
    let mut ceiling = *offset;
    let mut resume = None;
    let mut hops = 0;
    let mut out = Vec::new();
    let mut wire_len = 1usize;
    loop {
        budget.charge(1)?;
        let boundary = if resume.is_some() { data.len() } else { end };
        let head = take(data, &mut position, 1, boundary)?[0];
        if head == 0 {
            if resume.is_none() {
                *offset = position
            }
            break;
        }
        if head & 0xc0 == 0xc0 {
            let low = take(data, &mut position, 1, boundary)?[0];
            let target = (usize::from(head & 63) << 8) | usize::from(low);
            if target >= ceiling {
                return Err(Error::Name);
            }
            hops += 1;
            if hops > MAX_POINTERS {
                return Err(Error::Limit);
            }
            if resume.is_none() {
                resume = Some(position);
                *offset = position
            }
            ceiling = target;
            position = target;
            continue;
        }
        if head & 0xc0 != 0 {
            return Err(Error::Name);
        }
        let label = take(data, &mut position, usize::from(head), boundary)?;
        wire_len += label.len() + 1;
        if wire_len > 255 || label.contains(&b'.') {
            return Err(Error::Name);
        }
        budget.charge(label.len())?;
        if !out.is_empty() {
            out.push(b'.')
        }
        out.extend_from_slice(label);
    }
    String::from_utf8(out).map_err(|_| Error::Encoding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub raw: &'a [u8],
    pub names: Vec<String>,
    pub numbers: Vec<u32>,
    pub text: Vec<String>,
}

#[derive(Debug)]
pub struct Message<'a> {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub sections: [Vec<Record<'a>>; 3],
    pub trailing: &'a [u8],
}

fn record<'a>(
    data: &'a [u8],
    offset: &mut usize,
    budget: &mut Budget,
) -> Result<Record<'a>, Error> {
    let owner = name(data, offset, data.len(), budget)?;
    let kind = u16_at(data, offset, data.len())?;
    let class = u16_at(data, offset, data.len())?;
    let ttl = u32_at(data, offset, data.len())?;
    let size = usize::from(u16_at(data, offset, data.len())?);
    let start = *offset;
    let raw = take(data, offset, size, data.len())?;
    let end = *offset;
    let mut position = start;
    let mut rr = Record {
        name: owner,
        kind,
        class,
        ttl,
        raw,
        names: Vec::new(),
        numbers: Vec::new(),
        text: Vec::new(),
    };
    match kind {
        1 if size != 4 => return Err(Error::Rdata),
        28 if size != 16 => return Err(Error::Rdata),
        2 | 5 | 12 => rr.names.push(name(data, &mut position, end, budget)?),
        15 => {
            rr.numbers
                .push(u32::from(u16_at(data, &mut position, end)?));
            rr.names.push(name(data, &mut position, end, budget)?)
        }
        6 => {
            rr.names.push(name(data, &mut position, end, budget)?);
            rr.names.push(name(data, &mut position, end, budget)?);
            for _ in 0..5 {
                rr.numbers.push(u32_at(data, &mut position, end)?)
            }
        }
        33 => {
            for _ in 0..3 {
                rr.numbers
                    .push(u32::from(u16_at(data, &mut position, end)?))
            }
            rr.names.push(name(data, &mut position, end, budget)?)
        }
        13 | 16 => {
            while position < end {
                let n = usize::from(take(data, &mut position, 1, end)?[0]);
                budget.charge(n + 1)?;
                let bytes = take(data, &mut position, n, end)?;
                rr.text
                    .push(String::from_utf8(bytes.to_vec()).map_err(|_| Error::Encoding)?);
            }
            if kind == 13 && rr.text.len() != 2 {
                return Err(Error::Rdata);
            }
        }
        _ => position = end,
    }
    if position != end {
        return Err(Error::Rdata);
    }
    Ok(rr)
}

impl<'a> Message<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() > MAX_MESSAGE {
            return Err(Error::Limit);
        }
        let mut offset = 0;
        let end = data.len();
        let id = u16_at(data, &mut offset, end)?;
        let flags = u16_at(data, &mut offset, end)?;
        let mut counts = [0usize; 4];
        for n in &mut counts {
            *n = usize::from(u16_at(data, &mut offset, end)?)
        }
        // Reject impossible section sizes before count limits or reservations.
        // Even a root question needs 5 bytes; a root owner and RR header need 11.
        let minimum = counts[0] * 5 + counts[1..].iter().sum::<usize>() * 11;
        if minimum > end - offset {
            return Err(Error::Truncated);
        }
        if counts.iter().sum::<usize>() > MAX_RECORDS {
            return Err(Error::Limit);
        }
        let mut budget = Budget::new();
        let mut questions = Vec::new();
        questions
            .try_reserve_exact(counts[0])
            .map_err(|_| Error::Allocation)?;
        for _ in 0..counts[0] {
            let name = name(data, &mut offset, end, &mut budget)?;
            let kind = u16_at(data, &mut offset, end)?;
            let class = u16_at(data, &mut offset, end)?;
            questions.push(Question { name, kind, class })
        }
        let mut sections: [Vec<Record<'a>>; 3] = std::array::from_fn(|_| Vec::new());
        for (section, count) in sections.iter_mut().zip(&counts[1..]) {
            section
                .try_reserve_exact(*count)
                .map_err(|_| Error::Allocation)?;
            for _ in 0..*count {
                budget.charge(1)?;
                section.push(record(data, &mut offset, &mut budget)?)
            }
        }
        Ok(Self {
            id,
            flags,
            questions,
            sections,
            trailing: &data[offset..],
        })
    }
}

struct Writer {
    out: Vec<u8>,
    pointers: HashMap<Vec<u8>, u16>,
    budget: Budget,
}
impl Writer {
    fn append(&mut self, raw: &[u8]) -> Result<(), Error> {
        if self.out.len().checked_add(raw.len()).ok_or(Error::Limit)? > MAX_MESSAGE {
            return Err(Error::Limit);
        }
        self.out
            .try_reserve(raw.len())
            .map_err(|_| Error::Allocation)?;
        self.out.extend_from_slice(raw);
        Ok(())
    }
    fn name(&mut self, value: &str) -> Result<(), Error> {
        if value.is_empty() {
            return self.append(&[0]);
        }
        if value.len() > 253 {
            return Err(Error::Name);
        }
        let labels: Vec<&[u8]> = value.as_bytes().split(|b| *b == b'.').collect();
        if labels.iter().any(|x| x.is_empty() || x.len() > 63) {
            return Err(Error::Name);
        }
        for index in 0..labels.len() {
            let suffix = labels[index..].join(&b'.');
            self.budget.charge(suffix.len() + 1)?;
            let key = suffix.to_ascii_uppercase();
            if let Some(pointer) = self.pointers.get(&key) {
                return self.append(&(0xc000 | pointer).to_be_bytes());
            }
            if self.out.len() < 0x4000 {
                self.pointers.insert(key, self.out.len() as u16);
            }
            self.append(&[labels[index].len() as u8])?;
            self.append(labels[index])?;
        }
        self.append(&[0])
    }
    fn record(&mut self, rr: &Record<'_>) -> Result<(), Error> {
        self.name(&rr.name)?;
        self.append(&rr.kind.to_be_bytes())?;
        self.append(&rr.class.to_be_bytes())?;
        self.append(&rr.ttl.to_be_bytes())?;
        let length_position = self.out.len();
        self.append(&[0, 0])?;
        let start = self.out.len();
        let counts = match rr.kind {
            2 | 5 | 12 => (1, 0),
            15 => (1, 1),
            6 => (2, 5),
            33 => (1, 3),
            _ => (0, 0),
        };
        if rr.names.len() != counts.0 || rr.numbers.len() != counts.1 {
            return Err(Error::Rdata);
        }
        match rr.kind {
            1 | 28 => {
                if rr.raw.len() != if rr.kind == 1 { 4 } else { 16 } {
                    return Err(Error::Rdata);
                }
                self.append(rr.raw)?
            }
            2 | 5 | 12 => self.name(&rr.names[0])?,
            15 | 33 => {
                for value in &rr.numbers {
                    self.append(
                        &u16::try_from(*value)
                            .map_err(|_| Error::Rdata)?
                            .to_be_bytes(),
                    )?
                }
                self.name(&rr.names[0])?
            }
            6 => {
                self.name(&rr.names[0])?;
                self.name(&rr.names[1])?;
                for n in &rr.numbers {
                    self.append(&n.to_be_bytes())?
                }
            }
            13 | 16 => {
                if rr.kind == 13 && rr.text.len() != 2 {
                    return Err(Error::Rdata);
                }
                for chunk in &rr.text {
                    let n = u8::try_from(chunk.len()).map_err(|_| Error::Rdata)?;
                    self.budget.charge(chunk.len() + 1)?;
                    self.append(&[n])?;
                    self.append(chunk.as_bytes())?
                }
            }
            _ => self.append(rr.raw)?,
        }
        let n = u16::try_from(self.out.len() - start).map_err(|_| Error::Limit)?;
        self.out[length_position..length_position + 2].copy_from_slice(&n.to_be_bytes());
        Ok(())
    }
}

pub fn header(id: u16, flags: u16, counts: [usize; 4]) -> Result<[u8; 12], Error> {
    if counts
        .iter()
        .try_fold(0usize, |a, b| a.checked_add(*b))
        .ok_or(Error::Limit)?
        > MAX_RECORDS
    {
        return Err(Error::Limit);
    }
    let mut out = [0; 12];
    out[..2].copy_from_slice(&id.to_be_bytes());
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    for (index, n) in counts.iter().enumerate() {
        out[4 + index * 2..6 + index * 2].copy_from_slice(&(*n as u16).to_be_bytes())
    }
    Ok(out)
}

pub fn encode(
    id: u16,
    flags: u16,
    questions: &[Question],
    sections: [&[Record<'_>]; 3],
    trailing: &[u8],
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
        budget: Budget::new(),
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
    writer.append(trailing)?;
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
}
