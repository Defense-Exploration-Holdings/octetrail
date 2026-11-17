"""Explicit bounded HTTP/1.0 and HTTP/1.1 messages with opaque byte bodies.

Content-Length and dpkt's Content-Type-to-end selection are supported. Transfer
encoding, stream reassembly and application dispatch are outside this subset.
Length headers remain caller fields on mutation and serialization.
"""

from . import _native
from .errors import NeedData, PackError, UnpackError

MAX_MESSAGE_BYTES = 1024 * 1024
MAX_HEAD_BYTES = 65536
MAX_LINE_BYTES = 8192
MAX_HEADERS = 128
LimitError = _native.PacketLimitError


class ParseLimitError(UnpackError, LimitError):
    """Bounded parse refusal accepted by both public exception families."""


def _parse(function, *args):
    try:
        return function(*args)
    except _native.PacketLimitError as error:
        raise ParseLimitError(str(error)) from None
    except _native.TruncatedError as error:
        raise NeedData(str(error)) from None
    except _native.HttpFormatError as error:
        raise UnpackError(str(error)) from None


def _field(name, value):
    try:
        _native._http_field(name, value)
    except _native.HttpFormatError as error:
        raise PackError(str(error)) from None


class _Message:
    _response = False
    _defaults = ()

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("HTTP accepts at most one positional bytes buffer")
        if args:
            self.unpack(args[0])
            return
        fields = {name for name, _ in self._defaults} | {"headers", "body", "data"}
        unknown = kwargs.keys() - fields
        if unknown:
            raise TypeError("unsupported HTTP fields: " + ", ".join(sorted(unknown)))
        for name, default in self._defaults:
            setattr(self, name, kwargs.get(name, default))
        self.headers = kwargs.get("headers", {})
        self.body = kwargs.get("body", b"")
        self.data = kwargs.get("data", b"")

    def unpack(self, buf):
        if not isinstance(buf, bytes):
            raise TypeError("HTTP unpack requires bytes")
        values, pos = _parse(_native._http_start, buf, self._response)
        for (name, _), value in zip(self._defaults, values, strict=True):
            setattr(self, name, value)
        rows, pos = _parse(_native._http_headers, buf, pos)
        self.headers = {name: values[0] if len(values) == 1 else values for name, values in rows}
        allowed = not self._response or (
            int(self.status) >= 200 and self.status not in ("204", "304")
        )
        self.body, self.data = _parse(_native._http_body, buf, pos, rows, allowed)

    def pack_hdr(self):
        """Render headers only, as in dpkt. Duplicate lists use Python list text."""
        if not isinstance(self.headers, dict):
            raise TypeError("HTTP headers require an ordered dict")
        if len(self.headers) > MAX_HEADERS:
            raise LimitError("HTTP header count exceeds limit")
        result, total = [], 0
        for name, value in self.headers.items():
            if not isinstance(name, str):
                raise TypeError("HTTP header names require str")
            if isinstance(value, list):
                if len(value) > MAX_HEADERS:
                    raise LimitError("HTTP duplicate header count exceeds limit")
                if not all(isinstance(v, str) for v in value):
                    raise TypeError("HTTP header values require str or list of str")
                if sum(map(len, value)) + len(value) * 4 > MAX_LINE_BYTES:
                    raise LimitError("HTTP header line exceeds limit")
            elif not isinstance(value, str):
                raise TypeError("HTTP header values require str or list of str")
            if len(name) > MAX_LINE_BYTES or len(value) > MAX_LINE_BYTES:
                raise LimitError("HTTP header line exceeds limit")
            for item in value if isinstance(value, list) else [value]:
                _field(name, item)
            rendered = str(value)
            _field(name, rendered)
            if len(name) + len(rendered) + 4 > MAX_LINE_BYTES:
                raise LimitError("HTTP header line exceeds limit")
            line = f"{name}: {rendered}\r\n"
            if len(line) > MAX_LINE_BYTES:
                raise LimitError("HTTP header line exceeds limit")
            total += len(line)
            if total > MAX_HEAD_BYTES:
                raise LimitError("HTTP head exceeds limit")
            result.append(line)
        return "".join(result)

    def _parts(self):
        values = []
        for name, _ in self._defaults:
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError("HTTP start fields require str")
            if len(value) > MAX_LINE_BYTES:
                raise LimitError("HTTP start line exceeds limit")
            _field("value", value)
            values.append(value)
        if not isinstance(self.body, bytes):
            raise TypeError("HTTP body requires bytes")
        if len(self.body) > MAX_MESSAGE_BYTES:
            raise LimitError("HTTP message exceeds limit")
        if self._response:
            start = f"HTTP/{values[0]} {values[1]} {values[2]}\r\n"
        else:
            start = f"{values[0]} {values[1]} HTTP/{values[2]}\r\n"
        head = start + self.pack_hdr() + "\r\n"
        try:
            encoded = head.encode("ascii")
        except UnicodeEncodeError:
            raise PackError("HTTP head requires ASCII") from None
        return encoded, self.body

    def __bytes__(self):
        head, body = self._parts()
        try:
            return _native._http_pack(head, body, self._response)
        except (_native.HttpFormatError, _native.TruncatedError) as error:
            raise PackError(str(error)) from None

    def __str__(self):
        # Reference text/len convention ignores invalid UTF-8 body bytes.
        raw = bytes(self)
        head, body = self._parts()
        return raw[: len(head)].decode("ascii") + body.decode("utf8", "ignore")

    def __len__(self):
        return len(str(self))


class Request(_Message):
    """Mutable method, uri, version, headers, body and unread data fields."""

    _defaults = (("method", "GET"), ("uri", "/"), ("version", "1.0"))


class Response(_Message):
    """Mutable version, status text, reason, headers, body and unread data."""

    _response = True
    _defaults = (("version", "1.0"), ("status", "200"), ("reason", "OK"))


def decode(buf):
    """Select one message or return identical bytes on a scoped parse error.

    Parse budget refusals also retain the original bytes. Programmer and
    allocation errors propagate. This function does not iterate streams.
    """
    if not isinstance(buf, bytes):
        raise TypeError("HTTP decode requires bytes")
    try:
        return (Response if buf.startswith(b"HTTP/") else Request)(buf)
    except UnpackError:
        return buf
