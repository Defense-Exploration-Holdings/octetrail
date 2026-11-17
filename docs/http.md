# HTTP messages

`octetrail.http` parses and packs HTTP/1.x requests and responses the way dpkt
1.9.8 does, with the parsing in Rust. Call `http.Request(bytes)` or
`http.Response(bytes)` on one message's bytes. There is no stream reassembly and
no automatic dispatch from TCP.

```python
from octetrail import http

r = http.Request(b"GET /note HTTP/1.1\r\nHost: example.test\r\n\r\n")
assert (r.method, r.uri, r.version, r.headers["host"]) == ("GET", "/note", "1.1", "example.test")
```

## Fields

- `Request`: `method`, `uri`, `version`, `headers`, `body` and `data`. A new request
  is `GET / HTTP/1.0`.
- `Response`: `version`, `status`, `reason`, `headers`, `body` and `data`. A new
  response is `HTTP/1.0 200 OK`.
- `Message`: the headers and body without a start line, and the base of both.

`headers` is an `OrderedDict` with lower-cased names. A repeated header becomes a
list of its values. `data` holds the bytes after the body. Keyword arguments set
attributes on a new message. When a buffer is given, keyword arguments are
ignored.

## Parsing

dpkt reads a message line by line with `BytesIO`, and the same rules apply here:

- **Request line.** Non-ASCII bytes are dropped and the line is split on
  whitespace. It needs a method from dpkt's list and a URI. With two words the
  version is `0.9`. Otherwise the third word must start with `HTTP`, and the
  version is the text after its fifth character. Further words are ignored.
- **Status line.** The line is split into at most three parts. The first must
  start with `HTTP`, and the status must be all digits. The reason is the rest of
  the line, and it may be empty.
- **Headers.** Each line is stripped and its non-ASCII bytes are dropped. The
  headers end at an empty line or at the end of the input. The name is the text
  before the first colon, lower-cased. It must be one word, and any spaces around
  that word are kept. A line without a colon gives an empty value.
- **Body.** The body is chosen in this order:
  1. `Transfer-Encoding: chunked` (any case) reads chunks until a zero-size
     chunk. Each size is the first word of its line, read as `int(size, 16)`.
  2. Otherwise `Content-Length` reads that many bytes, read as `int()`.
  3. Otherwise `Content-Type` reads to the end.
  4. Otherwise the body is empty.

  Responses with a status below 200, or with 204 or 304, have no body.

Whitespace follows Python's rules, which count 0x1c to 0x1f as whitespace in
text. Integers follow `int()`, which accepts signs, underscores and a `0x` prefix
on chunk sizes.

## Errors

- `NeedData`: the body is shorter than Content-Length, the length is negative,
  or a chunked body ends before its zero-size chunk.
- `UnpackError`: the start line is invalid, a header name is not one word, or a
  chunk size is missing or invalid. A Content-Length that is not an integer, and
  repeated Transfer-Encoding or Content-Length headers, also raise `UnpackError`;
  dpkt fails on these with `ValueError`, `TypeError` or `AttributeError`.

As in dpkt, a request keeps its start-line fields, and a message keeps its
headers, when the body raises. There are no size limits: parsing takes time
linear in the input.

`http.parse_headers(f)` and `http.parse_body(f, headers)` read from a seekable
file object and leave it after what they used, as dpkt's functions do.
`http.decode(bytes)` returns a `Response` for bytes starting with `HTTP/`, a
`Request` otherwise, or the bytes themselves when they do not parse.

## Packing

`bytes()` packs the start line and one `name: value` line per header with
`%s` formatting, so a list value packs as its Python list text. Then come an
empty line and the body. Non-ASCII characters in the start line and headers are
dropped. `data` is not packed, and lengths and chunking are not added or
checked: the headers pack as they are. `str()` is the same text with the body
decoded as UTF-8, ignoring errors, and `len()` is the length of `str()`.

## Measured compatibility

The private parity harness decodes dpkt-built requests and responses and
mutations of them with both libraries. It compares the outcome, every field,
the headers, the body and the packed bytes. Its seeds include chunked bodies,
repeated headers, HTTP/0.9 and a 304 response. The
[fixture driver](../tools/http_differential.py) checks 22 hand-written messages,
16 constructors, the defaults, two mutations and partial state against dpkt
1.9.6 and 1.9.8:

```sh
python3 tools/http_differential.py --oracle-196 ORACLE196/bin/python --oracle-198 ORACLE198/bin/python --python INSTALLED_WHEEL/bin/python
```

Exception messages can differ.
