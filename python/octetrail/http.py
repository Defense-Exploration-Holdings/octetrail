"""HTTP/1.x requests and responses, parsed and packed the way dpkt 1.9.8 does.

Parsing runs in Rust and follows dpkt's line reading, whitespace and length
rules. There is no stream reassembly and no application dispatch.
"""

from collections import OrderedDict

from . import _native
from .errors import NeedData, UnpackError


def _parse(function, *args):
    try:
        return function(*args)
    except _native.TruncatedError as error:
        raise NeedData(str(error)) from None
    except _native.HttpFormatError as error:
        raise UnpackError(str(error)) from None


def _headers(rows):
    """Header rows as dpkt's dict: one value, or a list of values when repeated."""
    return OrderedDict((name, values[0] if len(values) == 1 else values) for name, values in rows)


def _buffer(buf):
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise TypeError("HTTP unpack requires bytes")
    return bytes(buf)


def parse_headers(f):
    """Return the dict of headers read from the file object `f`."""
    start = f.tell()
    rows, used = _parse(_native._http_parse_headers, _buffer(f.read()))
    f.seek(start + used)
    return _headers(rows)


def parse_body(f, headers):
    """Return the body read from the file object `f`, given the header dict."""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        mode, length = "chunked", 0
    elif "content-length" in headers:
        mode, length = "length", max(-1, min(int(headers["content-length"]), 1 << 62))
    elif "content-type" in headers:
        mode, length = "end", 0
    else:
        mode, length = "empty", 0
    start = f.tell()
    body, used = _parse(_native._http_parse_body, _buffer(f.read()), mode, length)
    f.seek(start + used)
    return body


class Message:
    """Headers, body and the bytes after the body."""

    __hdr_defaults__ = {}
    headers = None
    body = None

    def __init__(self, *args, **kwargs):
        if args:
            self.unpack(args[0])
        else:
            self.headers = OrderedDict()
            self.body = b""
            self.data = b""
            for key, value in self.__hdr_defaults__.items():
                setattr(self, key, value)
            for key, value in kwargs.items():
                setattr(self, key, value)

    def unpack(self, buf, is_body_allowed=True):
        # Like dpkt, headers are set before the body is read, so they stay set
        # when the body raises.
        buf = _buffer(buf)
        rows, used = _parse(_native._http_parse_headers, buf)
        self.headers = _headers(rows)
        if is_body_allowed:
            self.body, self.data = _parse(_native._http_body, buf[used:], rows, True)
        else:
            self.body, self.data = b"", buf[used:]

    def pack_hdr(self):
        return "".join(["%s: %s\r\n" % t for t in self.headers.items()])

    def _start(self):
        return ""

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return "%s%s\r\n%s" % (self._start(), self.pack_hdr(), self.body.decode("utf8", "ignore"))

    def __bytes__(self):
        return _native._http_pack(self._start(), self.pack_hdr(), self.body or b"")


class Request(Message):
    """An HTTP request: method, uri, version, headers, body and data."""

    __hdr_defaults__ = {"method": "GET", "uri": "/", "version": "1.0"}

    def unpack(self, buf):
        buf = _buffer(buf)
        (self.method, self.uri, self.version), used = _parse(_native._http_request_line, buf)
        Message.unpack(self, buf[used:])

    def _start(self):
        return "%s %s %s/%s\r\n" % (self.method, self.uri, "HTTP", self.version)


class Response(Message):
    """An HTTP response: version, status, reason, headers, body and data."""

    __hdr_defaults__ = {"version": "1.0", "status": "200", "reason": "OK"}

    def unpack(self, buf):
        buf = _buffer(buf)
        (self.version, self.status, self.reason), used = _parse(_native._http_response_line, buf)
        Message.unpack(self, buf[used:], _native._http_body_allowed(self.status))

    def _start(self):
        return "%s/%s %s %s\r\n" % ("HTTP", self.version, self.status, self.reason)


def decode(buf):
    """Return a Response or Request for `buf`, or `buf` itself when it does not parse.

    Bytes starting with "HTTP/" are tried as a response, anything else as a
    request. This function does not iterate streams.
    """
    if not isinstance(buf, bytes):
        raise TypeError("HTTP decode requires bytes")
    try:
        return (Response if buf.startswith(b"HTTP/") else Request)(buf)
    except UnpackError:
        return buf
