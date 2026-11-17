# Offline HTTP messages

`octetrail.http.Request` and `Response` parse one complete supplied HTTP/1.0 or
HTTP/1.1 buffer. Parsing is explicit: TCP payloads remain bytes until selected by
the caller. There is no networking, stream reassembly or transfer decoding.

```python
from octetrail import http

request = http.Request(b"GET /note HTTP/1.1\r\nHost: example.test\r\n\r\n")
assert request.headers["host"] == "example.test"
request.uri = "/other"
encoded = bytes(request)
```

Requests expose mutable method, uri, version, headers, body and data. Responses
expose version, string status, reason, headers, body and data. Defaults are
GET / HTTP/1.0 and HTTP/1.0 200 OK. A positional bytes buffer takes precedence
over keywords. Unknown constructor fields and non-bytes input are unsupported.
Parsed header names are lower-case and retain insertion order. Repeated names
become lists. Like dpkt, rendering such a list emits its Python list text rather
than multiple lines. `pack_hdr()` returns header text without the start line or
final blank line.

Header names require ASCII token characters. Before any rendering, names and
individual string values are validated, including values in lists. Serialized
field values and start-line fields permit ASCII 0x20 through 0x7e; control
characters and non-ASCII text raise PackError. The native parser also rejects
unsupported controls in decoded values. Heads require CRLF, colon-separated
headers, a listed reference request method, a three-digit response status and
HTTP/1.0 or HTTP/1.1. Bodies are opaque bytes.

Content-Length selects exactly that many body bytes. Otherwise Content-Type
selects the remainder, following dpkt's convention. Without either, body is empty
and the remainder is data. Statuses below 200, 204 and 304 suppress response-body
parsing. HEAD response context is unavailable. Unread data is inspectable and
excluded from serialization. Mutating a body does not update Content-Length;
length headers remain the caller's responsibility.

`bytes(message)` emits its rendered head and body. Like dpkt, str ignores invalid
UTF-8 body bytes and len counts that text, which can differ from serialized byte
length. Use `len(bytes(message))` for a wire-byte count.

This whole-message API caps all supplied bytes, including unread data, at 1 MiB.
It also caps the head at 64 KiB, each line including CRLF at 8192 bytes and
physical header lines at 128. It does not frame a prefix from an arbitrarily
large backing stream. Stage a bounded message before using this API.

Truncation raises NeedData and unsupported/malformed parsing raises UnpackError.
Parse budgets raise http.ParseLimitError, inheriting both UnpackError and the
existing http.LimitError/ValueError family. Successful start fields remain after
a later parse failure; other stale fields on reused objects are not cleared.
Packing retains separate LimitError guards and uses PackError for invalid fields.
Programmer and allocation errors propagate. These bounds do not promise process
memory or latency limits; error text and every failed-object state are unspecified.

`http.decode(bytes)` returns a selected Request/Response or the identical supplied
bytes for parse failures, including parse-budget refusals. It does not copy an
over-budget buffer or suppress programmer/allocation errors. It is not a stream
iterator.

Transfer-Encoding, chunking/trailers, HTTP/0.9, LF-only or unfinished heads,
folding, arbitrary method/version extensions, decompression and HTTP/2/3 are
unsupported. The public dpkt Message base and file-based parser helpers are absent.

`tools/http_differential.py` compares both hash-pinned dpkt 1.9.6/1.9.8 references
and installed OctetRail. It checks 22 fixtures (18 equal and four explicit scope
differences), 16 constructors, two defaults, two mutations and partial parse state.
The whole-message budget/fallback policy and scalar field validation are tested
separately from those equality cases. These measurements cover the listed API.
