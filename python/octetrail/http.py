"""HTTP/1.x requests and responses, parsed and packed the way dpkt 1.9.8 does.

``Request`` and ``Response`` are :class:`octetrail.Packet` subclasses, as in
dpkt. Headers and bodies are read in Rust and follow dpkt's line reading,
whitespace and length rules. There is no stream reassembly and no application
dispatch.
"""

from collections import OrderedDict
from io import BytesIO

from . import _native
from .errors import NeedData, UnpackError
from .packet import Packet


def _parse(function, *args):
    try:
        return function(*args)
    except _native.TruncatedError as error:
        raise NeedData(str(error)) from None
    except _native.HttpFormatError as error:
        raise UnpackError(str(error)) from None
    except _native.HttpOverflowError as error:
        raise LengthOverflowError(str(error)) from None


def _headers(rows):
    """Header rows as dpkt's dict: one value, or a list of values when repeated."""
    return OrderedDict((name, values[0] if len(values) == 1 else values) for name, values in rows)


def _buffer(buf):
    # dpkt reads through BytesIO, which takes any bytes-like object and
    # rejects the rest with its own TypeError.
    return BytesIO(buf).getvalue()


def parse_headers(f):
    """Return the dict of headers read from the file object `f`."""
    start = f.tell()
    rows, used = _parse(_native._http_parse_headers, _buffer(f.read()))
    f.seek(start + used)
    return _headers(rows)


class HeaderValueError(UnpackError, ValueError):
    """A Content-Length that is not a plain decimal number."""


class HeaderTypeError(UnpackError, TypeError):
    """A repeated Content-Length header; dpkt raises TypeError."""


class HeaderAttributeError(UnpackError, AttributeError):
    """A repeated Transfer-Encoding header; dpkt raises AttributeError."""


class LengthOverflowError(UnpackError, OverflowError):
    """A Content-Length or chunk size outside Py_ssize_t; dpkt raises OverflowError."""


def parse_body(f, headers):
    """Return the body read from the file object `f`, given the header dict."""
    try:
        chunked = headers.get("transfer-encoding", "").lower() == "chunked"
    except AttributeError as error:
        raise HeaderAttributeError(*error.args) from None
    if chunked:
        start = f.tell()
        body, used = _parse(_native._http_parse_chunked, _buffer(f.read()))
        f.seek(start + used)
        return body
    if "content-length" in headers:
        value = headers["content-length"]
        if not isinstance(value, str):
            raise HeaderTypeError("duplicate Content-Length headers")
        text = value.strip(" \t\r\n\x0b\x0c")
        # Digits only: int() would also accept signs, underscores and non-ASCII digits.
        if not (text.isascii() and text.isdigit()):
            raise HeaderValueError("invalid Content-Length: %r" % value)
        n = int(text)
        try:
            body = f.read(n)
        except OverflowError as error:
            raise LengthOverflowError(*error.args) from None
        if len(body) != n:
            raise NeedData("short body (missing %d bytes)" % (n - len(body)))
        return body
    if "content-type" in headers:
        return f.read()
    return b""


class Message(Packet):
    """HTTP headers and body, the base of Request and Response.

    As in dpkt, ``headers`` is an ordered dict of lower-cased names, a name
    that repeats holds a list, and ``data`` is whatever follows the body.
    """

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
            for k, v in self.__hdr_defaults__.items():
                setattr(self, k, v)
            for k, v in kwargs.items():
                setattr(self, k, v)

    def unpack(self, buf, is_body_allowed=True):
        f = BytesIO(buf)
        self.headers = parse_headers(f)
        if is_body_allowed:
            self.body = parse_body(f, self.headers)
        else:
            self.body = b""
        self.data = f.read()

    def pack_hdr(self):
        return "".join(["%s: %s\r\n" % t for t in self.headers.items()])

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return "%s\r\n%s" % (self.pack_hdr(), self.body.decode("utf8", "ignore"))

    def __bytes__(self):
        return self.pack_hdr().encode("ascii", "ignore") + b"\r\n" + (self.body or b"")


def _line(buf):
    """The first line, with its line feed, and the rest, as BytesIO.readline reads it."""
    end = buf.find(b"\n") + 1 or len(buf)
    return buf[:end], buf[end:]


class Request(Message):
    """An HTTP request: method, uri, version, headers, body and data.

    As in dpkt, a subclass can set its own ``__methods`` and ``__proto`` under
    the class name ``Request``, as SIP does.
    """

    __hdr_defaults__ = {
        "method": "GET",
        "uri": "/",
        "version": "1.0",
    }
    __methods = dict.fromkeys(
        (
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
        )
    )
    __proto = "HTTP"

    def unpack(self, buf):
        line, rest = _line(_buffer(buf))
        line = line.decode("ascii", "ignore")
        l_ = line.strip().split()
        if len(l_) < 2:
            raise UnpackError("invalid request: %r" % line)
        if l_[0] not in self.__methods:
            raise UnpackError("invalid http method: %r" % l_[0])
        if len(l_) == 2:
            # HTTP/0.9 does not specify a version in the request line.
            self.version = "0.9"
        else:
            if not l_[2].startswith(self.__proto):
                raise UnpackError("invalid http version: %r" % l_[2])
            self.version = l_[2][len(self.__proto) + 1 :]
        self.method = l_[0]
        self.uri = l_[1]
        Message.unpack(self, rest)

    def __str__(self):
        return "%s %s %s/%s\r\n" % (
            self.method,
            self.uri,
            self.__proto,
            self.version,
        ) + Message.__str__(self)

    def __bytes__(self):
        str_out = "%s %s %s/%s\r\n" % (self.method, self.uri, self.__proto, self.version)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


class Response(Message):
    """An HTTP response: version, status, reason, headers, body and data.

    As in dpkt, a subclass can set its own ``__proto`` under the class name
    ``Response``, as SIP does.
    """

    __hdr_defaults__ = {
        "version": "1.0",
        "status": "200",
        "reason": "OK",
    }
    __proto = "HTTP"

    def unpack(self, buf):
        line, rest = _line(_buffer(buf))
        l_ = line.strip().decode("ascii", "ignore").split(None, 2)
        if len(l_) < 2 or not l_[0].startswith(self.__proto) or not l_[1].isdigit():
            raise UnpackError("invalid response: %r" % line)
        self.version = l_[0][len(self.__proto) + 1 :]
        self.status = l_[1]
        self.reason = l_[2] if len(l_) > 2 else ""
        # RFC 2616, section 4.3: responses to HEAD, 1xx, 204 and 304 responses
        # carry no body.
        is_body_allowed = int(self.status) >= 200 and 204 != int(self.status) != 304
        Message.unpack(self, rest, is_body_allowed)

    def __str__(self):
        return "%s/%s %s %s\r\n" % (
            self.__proto,
            self.version,
            self.status,
            self.reason,
        ) + Message.__str__(self)

    def __bytes__(self):
        str_out = "%s/%s %s %s\r\n" % (self.__proto, self.version, self.status, self.reason)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


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
