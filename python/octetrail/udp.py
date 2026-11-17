"""Offline eight-byte UDP headers, opaque payloads and retained caller fields.

The stored ulen and sum fields are never inferred, checked against the payload,
or recalculated. Complete buffers are limited to 65535 bytes. No dispatch,
pseudoheader checksum automation, or network operations are provided.
"""

import operator

from . import _native
from .errors import NeedData, PackError

UDP_HDR_LEN = 8
UDP_PORT_MAX = 65535
DEFAULT_MAX_DATAGRAM_BYTES = 65535
LimitError = _native.PacketLimitError
_FIELDS = (("sport", 0xDEAD), ("dport", 0), ("ulen", UDP_HDR_LEN), ("sum", 0))


class UDP:
    """Mutable fixed fields with a bytes payload and no implicit length update.

    Construct with keyword fields or one positional bytes buffer. A positional
    buffer ignores field keywords as the references do. Integer range/type errors
    are deferred to header serialization. Unknown constructor fields are outside
    this subset.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("UDP accepts at most one positional buffer")
        if args:
            self.unpack(args[0])
            return
        unknown = kwargs.keys() - {name for name, _ in _FIELDS} - {"data"}
        if unknown:
            raise TypeError("unsupported UDP fields: " + ", ".join(sorted(unknown)))
        for name, default in _FIELDS:
            setattr(self, name, kwargs.get(name, default))
        self.data = kwargs.get("data", b"")

    def unpack(self, buf):
        """Replace fields and keep every supplied byte following the header."""
        if not isinstance(buf, bytes):
            raise TypeError("UDP unpack requires bytes")
        try:
            fields, payload = _native._udp_unpack(buf)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        for (name, _), value in zip(_FIELDS, fields, strict=True):
            setattr(self, name, value)
        self.data = payload
        self.__dict__.pop("_jumbo", None)

    @classmethod
    def _from_jumbo(cls, buf):
        """Decode a datagram over the standalone limit, carried in an IPv6 jumbo payload."""
        self = cls.__new__(cls)
        self.unpack(buf[:UDP_HDR_LEN])
        self.data = buf[UDP_HDR_LEN:]
        self._jumbo = True
        return self

    def _header_args(self):
        result = []
        for name, _ in _FIELDS:
            try:
                value = operator.index(getattr(self, name))
            except TypeError:
                raise PackError(f"{name} requires an integer") from None
            if not 0 <= value <= 65535:
                raise PackError(f"{name} requires an unsigned 16-bit integer")
            result.append(value)
        return tuple(result)

    def pack_hdr(self):
        return _native._udp_header(self._header_args())

    def __bytes__(self):
        fields = self._header_args()
        size = len(self)
        if getattr(self, "_jumbo", False):
            # Decoded from an IPv6 jumbo payload: packs back at any size, as in dpkt.
            return _native._udp_header(fields) + self.data
        if size > DEFAULT_MAX_DATAGRAM_BYTES:
            raise LimitError(f"UDP buffer length {size} exceeds limit {DEFAULT_MAX_DATAGRAM_BYTES}")
        return _native._udp_pack(fields, self.data)

    def __len__(self):
        if not isinstance(self.data, bytes):
            raise TypeError("opaque UDP payload requires bytes")
        return UDP_HDR_LEN + len(self.data)
