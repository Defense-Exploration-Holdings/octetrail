//! Explicit bounded HTTP/1.x messages. No stream reassembly or network I/O.
use std::fmt;

pub const MAX_MESSAGE: usize = 1024 * 1024;
pub const MAX_HEAD: usize = 65536;
pub const MAX_LINE: usize = 8192;
pub const MAX_HEADERS: usize = 128;
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Format,
    Unsupported,
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "incomplete HTTP message",
            Self::Format => "invalid HTTP message in supported ASCII subset",
            Self::Unsupported => "unsupported HTTP version or transfer framing",
            Self::Limit => "HTTP message, head, line or header count exceeds limit",
        })
    }
}
impl std::error::Error for Error {}
pub type Headers = Vec<(String, Vec<String>)>;

fn input_size(raw: &[u8]) -> Result<(), Error> {
    if raw.len() > MAX_MESSAGE {
        Err(Error::Limit)
    } else {
        Ok(())
    }
}
fn line<'a>(raw: &'a [u8], pos: &mut usize) -> Result<&'a str, Error> {
    input_size(raw)?;
    let tail = raw.get(*pos..).ok_or(Error::Format)?;
    let length = tail.iter().take(MAX_LINE + 1).position(|b| *b == b'\n');
    let n = match length {
        Some(n) => n,
        None if tail.len() > MAX_LINE => return Err(Error::Limit),
        None => return Err(Error::Truncated),
    };
    if n + 1 > MAX_LINE {
        return Err(Error::Limit);
    }
    if n == 0 || tail[n - 1] != b'\r' {
        return Err(Error::Format);
    }
    *pos += n + 1;
    if *pos > MAX_HEAD {
        return Err(Error::Limit);
    }
    let bytes = &tail[..n - 1];
    if !bytes.iter().all(|b| (32..=126).contains(b) || *b == b'\t') {
        return Err(Error::Format);
    }
    std::str::from_utf8(bytes).map_err(|_| Error::Format)
}
fn version(text: &str) -> Result<(), Error> {
    if matches!(text, "HTTP/1.0" | "HTTP/1.1") {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}
/// Return request method/target/version or response version/status/reason.
pub fn start(raw: &[u8], response: bool) -> Result<([String; 3], usize), Error> {
    let mut pos = 0;
    let first = line(raw, &mut pos)?;
    let fields: Vec<_> = if response {
        let mut parts = first.trim().splitn(2, char::is_whitespace);
        let protocol = parts.next().ok_or(Error::Format)?;
        let rest = parts.next().ok_or(Error::Format)?.trim_start();
        let mut parts = rest.splitn(2, char::is_whitespace);
        vec![
            protocol,
            parts.next().ok_or(Error::Format)?,
            parts.next().unwrap_or("").trim_start(),
        ]
    } else {
        first.split_ascii_whitespace().collect()
    };
    let values = if response {
        if fields.len() < 2
            || fields[1].len() != 3
            || !fields[1].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Format);
        }
        version(fields[0])?;
        [
            fields[0][5..].to_owned(),
            fields[1].to_owned(),
            fields.get(2).unwrap_or(&"").trim_start().to_string(),
        ]
    } else {
        if fields.len() != 3 || !METHODS.contains(&fields[0]) {
            return Err(Error::Format);
        }
        version(fields[2])?;
        [
            fields[0].to_owned(),
            fields[1].to_owned(),
            fields[2][5..].to_owned(),
        ]
    };
    Ok((values, pos))
}
fn token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
/// Validate one field before rendering any delimiters into a message head.
pub fn validate_field(name: &str, value: &str) -> Result<(), Error> {
    if name.len() > MAX_LINE || value.len() > MAX_LINE {
        return Err(Error::Limit);
    }
    if !token(name) || !value.bytes().all(|b| (32..=126).contains(&b)) {
        return Err(Error::Format);
    }
    Ok(())
}

pub fn headers(raw: &[u8], mut pos: usize) -> Result<(Headers, usize), Error> {
    let mut rows: Headers = Vec::new();
    let mut count = 0;
    loop {
        let text = line(raw, &mut pos)?;
        if text.is_empty() {
            return Ok((rows, pos));
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(Error::Limit);
        }
        let (name, value) = text.split_once(':').ok_or(Error::Format)?;
        if !token(name) {
            return Err(Error::Format);
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_owned();
        validate_field(&name, &value)?;
        if let Some((_, values)) = rows.iter_mut().find(|(n, _)| *n == name) {
            values.push(value);
        } else {
            rows.push((name, vec![value]));
        }
    }
}
/// dpkt's declared Content-Length / Content-Type body selection. No chunking.
pub fn body<'a>(
    raw: &'a [u8],
    pos: usize,
    rows: &Headers,
    allowed: bool,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    input_size(raw)?;
    let tail = raw.get(pos..).ok_or(Error::Format)?;
    if !allowed {
        return Ok((&[], tail));
    }
    if rows.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(Error::Unsupported);
    }
    let n = if let Some((_, values)) = rows.iter().find(|(n, _)| n == "content-length") {
        if values.len() != 1
            || values[0].is_empty()
            || !values[0].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Format);
        }
        let n = values[0].parse::<usize>().map_err(|_| Error::Limit)?;
        if n > MAX_MESSAGE {
            return Err(Error::Limit);
        }
        n
    } else if rows.iter().any(|(n, _)| n == "content-type") {
        tail.len()
    } else {
        0
    };
    if n > tail.len() {
        return Err(Error::Truncated);
    }
    Ok(tail.split_at(n))
}
/// Validate a rendered message head, then append an opaque caller body.
/// Length headers remain caller fields; no body/framing rewrite is performed.
pub fn pack(head: &[u8], body: &[u8], response: bool) -> Result<Vec<u8>, Error> {
    if head.len() > MAX_HEAD || head.len().saturating_add(body.len()) > MAX_MESSAGE {
        return Err(Error::Limit);
    }
    if !head
        .iter()
        .all(|b| (32..=126).contains(b) || matches!(b, b'\r' | b'\n'))
    {
        return Err(Error::Format);
    }
    let (_, pos) = start(head, response)?;
    let (rows, end) = headers(head, pos)?;
    if end != head.len() {
        return Err(Error::Format);
    }
    if rows.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(Error::Unsupported);
    }
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head);
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_request_and_body_tail() {
        let raw = b"POST /note HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nnoteTAIL";
        let (s, p) = start(raw, false).unwrap();
        assert_eq!(s, ["POST", "/note", "1.1"]);
        let (h, p) = headers(raw, p).unwrap();
        assert_eq!(
            body(raw, p, &h, true).unwrap(),
            (&b"note"[..], &b"TAIL"[..])
        );
        let expected =
            b"POST /note HTTP/1.1\r\nhost: example.test\r\ncontent-length: 4\r\n\r\nnote";
        assert_eq!(
            pack(&expected[..expected.len() - 4], b"note", false).unwrap(),
            expected
        );
    }
    #[test]
    fn duplicate_order_and_opaque_body() {
        let raw = b"HTTP/1.0 200 OK\r\nX-Note: first\r\nX-Note: second\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xff";
        let (s, p) = start(raw, true).unwrap();
        assert_eq!(s, ["1.0", "200", "OK"]);
        let (h, p) = headers(raw, p).unwrap();
        assert_eq!(
            h[0],
            ("x-note".into(), vec!["first".into(), "second".into()])
        );
        assert_eq!(body(raw, p, &h, true).unwrap().0, b"\x00\xff");
        assert_eq!(body(raw, p, &h, false).unwrap().1, b"\x00\xff");
    }
    #[test]
    fn ordinary_partial_body_and_head() {
        assert_eq!(start(b"GET / HTTP/1.1", false), Err(Error::Truncated));
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nno";
        let (_, p) = start(raw, false).unwrap();
        let (h, p) = headers(raw, p).unwrap();
        assert_eq!(body(raw, p, &h, true), Err(Error::Truncated));
        assert_eq!(
            headers(b"GET / HTTP/1.1\r\nHost: example.test\r\n", 16),
            Err(Error::Truncated)
        );
    }
    #[test]
    fn finite_line_header_and_message_limits() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for _ in 0..MAX_HEADERS {
            raw.extend_from_slice(b"X: note\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        assert!(headers(&raw, 16).is_ok());
        raw.splice(16..16, b"X: note\r\n".iter().copied());
        assert_eq!(headers(&raw, 16), Err(Error::Limit));
        assert_eq!(start(&vec![b'a'; MAX_LINE + 1], false), Err(Error::Limit));
        assert_eq!(
            start(&vec![b'a'; MAX_MESSAGE + 1], false),
            Err(Error::Limit)
        );
        let mut long_head = b"GET / HTTP/1.1\r\n".to_vec();
        for _ in 0..9 {
            long_head.extend_from_slice(b"X: ");
            long_head.extend(vec![b'a'; 8000]);
            long_head.extend_from_slice(b"\r\n");
        }
        long_head.extend_from_slice(b"\r\n");
        assert_eq!(headers(&long_head, 16), Err(Error::Limit));
    }
    #[test]
    fn explicit_framing_and_version_scope() {
        assert_eq!(start(b"GET /\r\n\r\n", false), Err(Error::Format));
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nnote\r\n0\r\n\r\n";
        let (_, p) = start(raw, true).unwrap();
        let (h, p) = headers(raw, p).unwrap();
        assert_eq!(body(raw, p, &h, true), Err(Error::Unsupported));
        assert_eq!(pack(&raw[..p], b"note", true), Err(Error::Unsupported));
    }
    #[test]
    fn field_grammar_validation_is_independent_of_message_rendering() {
        for name in ["Note", "x_note", "note!", "x-note"] {
            assert!(validate_field(name, "ordinary value").is_ok());
        }
        for name in ["", "note name", "note:", "note/name", "noté"] {
            assert_eq!(validate_field(name, "ordinary"), Err(Error::Format));
        }
        for byte in [0, 9, 10, 13, 31, 127] {
            let value = String::from_utf8(vec![byte]).unwrap();
            assert_eq!(validate_field("x-note", &value), Err(Error::Format));
        }
    }
}
