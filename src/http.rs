//! HTTP/1.x requests and responses, parsed and packed the way dpkt 1.9.8 does.
//! No stream reassembly or network I/O.
//!
//! dpkt reads a message with `BytesIO.readline()` and `read()`, strips and splits
//! lines with Python's `bytes` and `str` whitespace rules, drops non-ASCII bytes
//! when decoding, and converts lengths with `int()`. Each of those rules is
//! reproduced here so that the same bytes give the same fields and errors.
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

const METHODS: &[&str] = &[
    "GET",
    "PUT",
    "ICY",
    "COPY",
    "HEAD",
    "LOCK",
    "MOVE",
    "POLL",
    "POST",
    "BCOPY",
    "BMOVE",
    "MKCOL",
    "TRACE",
    "LABEL",
    "MERGE",
    "DELETE",
    "SEARCH",
    "UNLOCK",
    "REPORT",
    "UPDATE",
    "NOTIFY",
    "BDELETE",
    "CONNECT",
    "OPTIONS",
    "CHECKIN",
    "PROPFIND",
    "CHECKOUT",
    "CCM_POST",
    "SUBSCRIBE",
    "PROPPATCH",
    "BPROPFIND",
    "BPROPPATCH",
    "UNCHECKOUT",
    "MKACTIVITY",
    "MKWORKSPACE",
    "UNSUBSCRIBE",
    "RPC_CONNECT",
    "VERSION-CONTROL",
    "BASELINE-CONTROL",
];

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// dpkt raises `NeedData`: a short body or an unfinished chunked body.
    NeedData(&'static str),
    /// dpkt raises `UnpackError`.
    Unpack(String),
    /// dpkt fails with a Python error that is not a dpkt error, such as
    /// `ValueError` from `int()` or `AttributeError` from a duplicated
    /// Transfer-Encoding header. Reported as `UnpackError`.
    Invalid(&'static str),
    /// A body or chunk size outside `Py_ssize_t`; dpkt raises `OverflowError`.
    Overflow,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedData(reason) | Self::Invalid(reason) => f.write_str(reason),
            Self::Unpack(reason) => f.write_str(reason),
            Self::Overflow => f.write_str("cannot fit 'int' into an index-sized integer"),
        }
    }
}
impl std::error::Error for Error {}

/// Header names in first-seen order, each with its values in order.
pub type Headers = Vec<(String, Vec<String>)>;

/// ASCII whitespace for `bytes.strip()` and `bytes.split()`.
fn bytes_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}
/// ASCII whitespace for `str.strip()` and `str.split()`, which adds 0x1c to 0x1f.
fn str_space(c: char) -> bool {
    c.is_ascii() && (bytes_space(c as u8) || (0x1c..=0x1f).contains(&(c as u8)))
}
fn strip_bytes(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| !bytes_space(*b)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|b| !bytes_space(*b))
        .map_or(start, |i| i + 1);
    &s[start..end]
}
/// `bytes.decode("ascii", "ignore")`.
fn ascii(s: &[u8]) -> String {
    s.iter()
        .filter(|b| b.is_ascii())
        .map(|b| char::from(*b))
        .collect()
}
/// Python's `repr()` of an ASCII `str`.
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
/// `str.split(None, maxsplit)`.
fn split(s: &str, maxsplit: Option<usize>) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    loop {
        rest = rest.trim_start_matches(str_space);
        if rest.is_empty() {
            return out;
        }
        if maxsplit.is_some_and(|m| out.len() == m) {
            out.push(rest);
            return out;
        }
        let end = rest.find(str_space).unwrap_or(rest.len());
        out.push(&rest[..end]);
        rest = &rest[end..];
    }
}

/// The result of Python's `int()`, reduced to the range that matters here.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Int {
    Negative,
    /// A nonnegative value that fits `Py_ssize_t`.
    Value(usize),
    /// A value outside `Py_ssize_t`, which `BytesIO.read` rejects with
    /// `OverflowError`.
    Overflow,
}

/// A Content-Length (radix 10) or chunk size (radix 16): ASCII digits only,
/// with surrounding whitespace allowed. Signs, `0x` prefixes and underscores,
/// which Python's `int()` and so dpkt accept, are rejected.
pub fn parse_size(text: &str, radix: u32) -> Option<Int> {
    let s = text.trim_matches(|c: char| c.is_ascii() && bytes_space(c as u8));
    if s.is_empty() {
        return None;
    }
    let mut value = 0u128;
    for c in s.chars() {
        let digit = c.to_digit(radix)?;
        value = value
            .saturating_mul(u128::from(radix))
            .saturating_add(u128::from(digit));
    }
    Some(if value > u128::from(i64::MAX.unsigned_abs()) {
        Int::Overflow
    } else {
        Int::Value(usize::try_from(value).unwrap_or(usize::MAX))
    })
}

/// A `BytesIO` over the message.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn readline(&mut self) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        let n = rest
            .iter()
            .position(|b| *b == b'\n')
            .map_or(rest.len(), |i| i + 1);
        self.pos += n;
        &rest[..n]
    }
    /// `read(n)`; a negative size reads everything, like `read(-1)`.
    fn read(&mut self, n: Int) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        let n = match n {
            Int::Negative | Int::Overflow => rest.len(),
            Int::Value(n) => n.min(rest.len()),
        };
        self.pos += n;
        &rest[..n]
    }
    fn rest(&mut self) -> &'a [u8] {
        self.read(Int::Negative)
    }
}

/// dpkt's `parse_headers`.
fn headers(reader: &mut Reader<'_>) -> Result<Headers, Error> {
    let mut out: Headers = Vec::new();
    // Position of each name in `out`, so a repeated name is found without a
    // scan of every earlier header.
    let mut index: HashMap<String, usize> = HashMap::new();
    loop {
        let line = ascii(strip_bytes(reader.readline()));
        if line.is_empty() {
            return Ok(out);
        }
        let (name, value) = match line.split_once(':') {
            Some((name, value)) => (name, value.trim_start_matches(str_space)),
            None => (line.as_str(), ""),
        };
        if split(name, None).len() != 1 {
            return Err(Error::Unpack(format!("invalid header: {}", py_repr(&line))));
        }
        let key = name.to_ascii_lowercase();
        match index.get(&key) {
            Some(&i) => out[i].1.push(value.to_owned()),
            None => {
                index.insert(key.clone(), out.len());
                out.push((key, vec![value.to_owned()]));
            }
        }
    }
}

/// How dpkt's `parse_body` reads the body.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BodyMode {
    Chunked,
    Length(Int),
    ToEnd,
    Empty,
}

/// The body selection of dpkt's `parse_body`.
pub fn body_mode(headers: &Headers) -> Result<BodyMode, Error> {
    let get = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    if let Some(values) = get("transfer-encoding") {
        if values.len() > 1 {
            return Err(Error::Invalid("duplicate Transfer-Encoding headers"));
        }
        if values[0].eq_ignore_ascii_case("chunked") {
            return Ok(BodyMode::Chunked);
        }
    }
    if let Some(values) = get("content-length") {
        if values.len() > 1 {
            return Err(Error::Invalid("duplicate Content-Length headers"));
        }
        let n = parse_size(&values[0], 10).ok_or(Error::Invalid("invalid Content-Length"))?;
        return Ok(BodyMode::Length(n));
    }
    Ok(if get("content-type").is_some() {
        BodyMode::ToEnd
    } else {
        BodyMode::Empty
    })
}

fn read_body<'a>(reader: &mut Reader<'a>, mode: BodyMode) -> Result<Cow<'a, [u8]>, Error> {
    match mode {
        BodyMode::Empty => Ok(Cow::Borrowed(&[])),
        BodyMode::ToEnd => Ok(Cow::Borrowed(reader.rest())),
        BodyMode::Length(Int::Overflow) => Err(Error::Overflow),
        BodyMode::Length(n) => {
            let body = reader.read(n);
            if Int::Value(body.len()) != n {
                return Err(Error::NeedData("short body"));
            }
            Ok(Cow::Borrowed(body))
        }
        BodyMode::Chunked => {
            let mut chunks: Vec<&[u8]> = Vec::new();
            let mut found_end = false;
            loop {
                let line = reader.readline();
                let size = line
                    .split(|b| bytes_space(*b))
                    .find(|t| !t.is_empty())
                    .ok_or_else(|| Error::Unpack("missing chunk size".into()))?;
                // A chunk extension (`;name=value`) after the size is ignored.
                let size = size.split(|b| *b == b';').next().unwrap_or(size);
                let n = std::str::from_utf8(size)
                    .ok()
                    .and_then(|s| parse_size(s, 16))
                    .ok_or_else(|| Error::Unpack("invalid chunk size".into()))?;
                if n == Int::Value(0) {
                    found_end = true;
                }
                if n == Int::Overflow {
                    return Err(Error::Overflow);
                }
                let chunk = reader.read(n);
                if !strip_bytes(reader.readline()).is_empty() {
                    break;
                }
                if n != Int::Value(0) && Int::Value(chunk.len()) == n {
                    chunks.push(chunk);
                } else {
                    break;
                }
            }
            if !found_end {
                return Err(Error::NeedData("premature end of chunked body"));
            }
            Ok(Cow::Owned(chunks.concat()))
        }
    }
}

/// Headers, body and the bytes after the body.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Message<'a> {
    pub headers: Headers,
    pub body: Cow<'a, [u8]>,
    pub data: &'a [u8],
}

/// dpkt's `Message.unpack(buf, is_body_allowed)`.
pub fn message(data: &[u8], body_allowed: bool) -> Result<Message<'_>, Error> {
    let (headers, used) = parse_headers(data)?;
    let (body, data) = body(&data[used..], &headers, body_allowed)?;
    Ok(Message {
        headers,
        body,
        data,
    })
}

/// The second half of `Message.unpack`: the body selected by `headers` from the
/// bytes after the headers, and the bytes after the body.
pub fn body<'a>(
    data: &'a [u8],
    headers: &Headers,
    body_allowed: bool,
) -> Result<(Cow<'a, [u8]>, &'a [u8]), Error> {
    let mut reader = Reader { data, pos: 0 };
    let body = if body_allowed {
        read_body(&mut reader, body_mode(headers)?)?
    } else {
        Cow::Borrowed(&[][..])
    };
    Ok((body, reader.rest()))
}

/// `parse_headers(f)` on the bytes left in `f`: the headers and the bytes used.
pub fn parse_headers(data: &[u8]) -> Result<(Headers, usize), Error> {
    let mut reader = Reader { data, pos: 0 };
    let headers = headers(&mut reader)?;
    Ok((headers, reader.pos))
}

/// `parse_body(f, headers)` on the bytes left in `f`: the body and the bytes used.
pub fn parse_body(data: &[u8], mode: BodyMode) -> Result<(Cow<'_, [u8]>, usize), Error> {
    let mut reader = Reader { data, pos: 0 };
    let body = read_body(&mut reader, mode)?;
    Ok((body, reader.pos))
}

/// A request: method, uri, version and the message after the request line.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Request<'a> {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub message: Message<'a>,
}

/// `str[n:]` on ASCII text.
fn after(s: &str, n: usize) -> String {
    s.get(n..).unwrap_or("").to_owned()
}

/// The request line: method, uri and version, and the bytes it used.
pub fn request_line(data: &[u8]) -> Result<([String; 3], usize), Error> {
    let mut reader = Reader { data, pos: 0 };
    let line = ascii(reader.readline());
    let parts = split(&line, None);
    if parts.len() < 2 {
        return Err(Error::Unpack(format!("invalid request: {line:?}")));
    }
    if !METHODS.contains(&parts[0]) {
        return Err(Error::Unpack(format!(
            "invalid http method: {:?}",
            parts[0]
        )));
    }
    let version = match parts.get(2) {
        None => "0.9".to_owned(),
        Some(v) if v.starts_with("HTTP") => after(v, 5),
        Some(v) => return Err(Error::Unpack(format!("invalid http version: {v:?}"))),
    };
    Ok((
        [parts[0].to_owned(), parts[1].to_owned(), version],
        reader.pos,
    ))
}

impl<'a> Request<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let ([method, uri, version], used) = request_line(data)?;
        Ok(Self {
            method,
            uri,
            version,
            message: message(&data[used..], true)?,
        })
    }
}

/// A response: version, status, reason and the message after the status line.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Response<'a> {
    pub version: String,
    pub status: String,
    pub reason: String,
    pub message: Message<'a>,
}

/// The status line: version, status and reason, and the bytes it used.
pub fn response_line(data: &[u8]) -> Result<([String; 3], usize), Error> {
    let mut reader = Reader { data, pos: 0 };
    let raw = reader.readline();
    let line = ascii(strip_bytes(raw));
    let parts = split(&line, Some(2));
    if parts.len() < 2
        || !parts[0].starts_with("HTTP")
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Unpack(format!("invalid response: {:?}", ascii(raw))));
    }
    Ok((
        [
            after(parts[0], 5),
            parts[1].to_owned(),
            parts.get(2).copied().unwrap_or("").to_owned(),
        ],
        reader.pos,
    ))
}

/// Whether dpkt reads a body for this status: `int(status) >= 200` and not 204 or 304.
pub fn body_allowed(status: &str) -> bool {
    let digits = status.trim_start_matches('0');
    if digits.len() > 3 {
        return true;
    }
    let n: u32 = digits.parse().unwrap_or(0);
    n >= 200 && n != 204 && n != 304
}

impl<'a> Response<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let ([version, status, reason], used) = response_line(data)?;
        let allowed = body_allowed(&status);
        Ok(Self {
            version,
            status,
            reason,
            message: message(&data[used..], allowed)?,
        })
    }
}

/// `str.encode("ascii", "ignore")`.
fn encode_ascii(s: &str) -> impl Iterator<Item = u8> + '_ {
    s.chars().filter(char::is_ascii).map(|c| c as u8)
}

/// Pack a message as dpkt does: the start line and the rendered header lines
/// with non-ASCII characters dropped, an empty line, then the body.
pub fn pack(start: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = encode_ascii(start).chain(encode_ascii(headers)).collect();
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_rules() {
        let v = |s, r| parse_size(s, r);
        assert_eq!(v(" 12\t\x0b\x0c", 10), Some(Int::Value(12)));
        assert_eq!(v("1f", 16), Some(Int::Value(31)));
        assert_eq!(v("1F", 16), Some(Int::Value(31)));
        for bad in [
            "", " ", "+10", "-0", "-3", "1_0", "0x1f", "1f", "1 0", "\u{661}",
        ] {
            assert_eq!(v(bad, 10), None, "{bad:?}");
        }
        for bad in ["0x1f", "+1", "1_f", "-1"] {
            assert_eq!(v(bad, 16), None, "{bad:?}");
        }
        assert_eq!(v("99999999999999999999999", 10), Some(Int::Overflow));
        assert_eq!(
            v("9223372036854775807", 10),
            Some(Int::Value(i64::MAX as usize))
        );
        assert_eq!(v("9223372036854775808", 10), Some(Int::Overflow));
    }

    #[test]
    fn python_split_rules() {
        assert_eq!(split("\x1c a  b\tc d ", Some(2)), ["a", "b", "c d "]);
        assert_eq!(split("  ", None), Vec::<&str>::new());
    }
}
