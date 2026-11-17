"""Bounded offline TLS records and passive ServerHello metadata only.

No cryptography, decryption, reassembly or automatic application dispatch.
Record and handshake length fields remain caller-owned after mutation.
"""

import operator

from . import _native
from .errors import NeedData, PackError, UnpackError

SSL3_V, TLS1_V, TLS11_V, TLS12_V = 0x0300, 0x0301, 0x0302, 0x0303
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_RECORD_DATA_BYTES = 65535
MAX_RECORDS = 1024
MAX_EXTENSIONS = 128
LimitError = _native.PacketLimitError


class SSL3Exception(UnpackError):
    """Unsupported record recognition or invalid supported metadata framing."""


class ParseLimitError(UnpackError, LimitError):
    """A framed-message parse budget refusal, separate from packing limits."""


def _parse(function, *args):
    try:
        return function(*args)
    except _native.PacketLimitError as error:
        raise ParseLimitError(str(error)) from None
    except _native.TruncatedError as error:
        raise NeedData(str(error)) from None
    except _native.TlsFormatError as error:
        raise SSL3Exception(str(error)) from None


def _integer(value, bits):
    try:
        result = operator.index(value)
    except TypeError:
        raise PackError("TLS fields require integers") from None
    if not 0 <= result < 1 << bits:
        raise PackError("TLS integer outside field range")
    return result


def _buffer(value, maximum):
    if not isinstance(value, bytes):
        raise TypeError("TLS opaque buffers require bytes")
    if len(value) > maximum:
        raise LimitError("TLS byte limit exceeded")
    return value


def _input(value, maximum=None):
    if not isinstance(value, bytes):
        raise TypeError("TLS parsing requires bytes")
    if maximum is not None and len(value) > maximum:
        raise ParseLimitError("TLS message byte limit exceeded")
    return value


class TLSRecord:
    """Mutable five-byte envelope with exact opaque data and reference flags.

    Direct parsing accepts any unsigned type/version as dpkt does. Only the
    multi-record selector recognizes the supported legacy version range.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("TLSRecord accepts at most one bytes buffer")
        self.compressed = kwargs.pop("compressed", False)
        self.encrypted = kwargs.pop("encrypted", False)
        if args:
            self.unpack(args[0])
        else:
            unknown = kwargs.keys() - {"type", "version", "length", "data"}
            if unknown:
                raise TypeError("unsupported TLSRecord fields")
            self.type = kwargs.get("type", 0)
            self.version = kwargs.get("version", 0)
            self.data = _buffer(kwargs.get("data", b""), MAX_RECORD_DATA_BYTES)
        # dpkt ignores a constructor length override and uses the supplied data.
        self.length = len(self.data)

    def unpack(self, buf):
        _input(buf)
        self.type, self.version, self.data = _parse(_native._tls_record, buf)
        self.length = len(self.data)
        self.compressed = self.encrypted = True

    def pack_hdr(self):
        return _native._tls_record_pack(
            _integer(self.type, 8), _integer(self.version, 16), _integer(self.length, 16), b""
        )

    def __bytes__(self):
        data = _buffer(self.data, MAX_RECORD_DATA_BYTES)
        return self.pack_hdr() + data

    def __len__(self):
        return 5 + len(_buffer(self.data, MAX_RECORD_DATA_BYTES))


class TLSServerHello:
    """Parse a complete ServerHello body; preserve its raw variable tail.

    version/random/data drive serialization, as in dpkt. session_id, cipher code,
    compression and extension attributes are parsed metadata. Changing them
    alone does not rebuild data. CipherSuite objects/inventories are not ported.
    """

    def __init__(self, buf):
        self.unpack(buf)

    def unpack(self, buf):
        _input(buf, MAX_MESSAGE_BYTES)
        (
            self.version,
            self.random,
            self.session_id,
            self.cipher_suite_code,
            self.compression_method,
            extensions,
            self.data,
        ) = _parse(_native._tls_hello, buf)
        if hasattr(self, "extensions"):
            del self.extensions
        if extensions is not None:
            self.extensions = extensions

    @property
    def compression(self):
        return self.compression_method

    def pack_hdr(self):
        random = _buffer(self.random, 32)
        if len(random) != 32:
            raise PackError("ServerHello random requires exactly 32 bytes")
        return _native._tls_hello_pack(_integer(self.version, 16), random, b"")

    def __bytes__(self):
        return self.pack_hdr() + _buffer(self.data, MAX_MESSAGE_BYTES - 34)

    def __len__(self):
        return 34 + len(_buffer(self.data, MAX_MESSAGE_BYTES - 34))


class TLSHandshake:
    """Parse one four-byte handshake envelope and optional ServerHello body.

    Other handshake types retain opaque bytes. Trailing supplied bytes are not
    consumed. No cross-record handshake assembly or nested handshake iteration.
    """

    def __init__(self, buf):
        self.unpack(buf)

    def unpack(self, buf):
        _input(buf)
        self.type, raw = _parse(_native._tls_handshake, buf)
        self.length_bytes = len(raw).to_bytes(3, "big")
        self.data = TLSServerHello(raw) if self.type == 2 else raw

    @property
    def length(self):
        if not isinstance(self.length_bytes, bytes) or len(self.length_bytes) != 3:
            raise PackError("TLS handshake length_bytes requires three bytes")
        return int.from_bytes(self.length_bytes, "big")

    def _body(self):
        if not isinstance(self.data, (bytes, TLSServerHello)):
            raise TypeError("TLS handshake data requires bytes or ServerHello")
        return _buffer(bytes(self.data), MAX_MESSAGE_BYTES - 4)

    def pack_hdr(self):
        return _native._tls_handshake_pack(_integer(self.type, 8), self.length, b"")

    def __bytes__(self):
        return self.pack_hdr() + self._body()

    def __len__(self):
        return 4 + len(self._body())


# Explicitly partial: only the needed ServerHello handshake path is dispatched.
RECORD_TYPES = {22: TLSHandshake}


def tls_multi_factory(buf):
    """Return a bounded prefix of complete records and its consumed byte count.

    Stop at the per-call record/byte budget or an incomplete tail. The supplied
    backing buffer is borrowed by native framing; only completed bodies copy.
    """
    _input(buf)
    spans, consumed = _parse(_native._tls_records, buf)
    return [TLSRecord(buf[start:end]) for start, end in spans], consumed
