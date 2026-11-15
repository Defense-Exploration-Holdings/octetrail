"""Fixed IPv4 headers with opaque bytes, without options or protocol dispatch.

Serialization follows dpkt 1.9.8: a zero checksum updates length and checksum;
a supplied checksum preserves both fields. No transport checksum is computed.
"""

import operator

from . import _native
from .errors import NeedData, PackError, UnpackError

IP_HDR_LEN = 20
IP_DF = 0x4000
IP_MF = 0x2000
IP_RF = 0x8000
IP_OFFMASK = 0x1FFF


class IP:
    """Mutable IPv4 base fields. Parsing requires a complete declared datagram.

    v=4, hl=5 and empty opts are the supported layout. offset uses 1.9.8's
    eight-octet units, which differ from 1.9.6's byte units. Fragment metadata is
    preserved but never reassembled. Legacy off and generic Packet APIs are absent.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("IP accepts at most one positional buffer")
        if args:
            self.unpack(args[0])
            return
        self._v_hl, self.tos, self.len, self.id = 0x45, 0, 20, 0
        self._flags_offset, self.ttl, self.p, self.sum = 0, 64, 0, 0
        self.src = self.dst = bytes(4)
        self.opts = self.data = b""
        allowed = {
            "_v_hl",
            "v",
            "hl",
            "tos",
            "len",
            "id",
            "_flags_offset",
            "rf",
            "df",
            "mf",
            "offset",
            "ttl",
            "p",
            "sum",
            "src",
            "dst",
            "opts",
            "data",
        }
        unknown = kwargs.keys() - allowed
        if unknown:
            raise TypeError("unsupported IP fields: " + ", ".join(sorted(unknown)))
        for key, value in kwargs.items():
            setattr(self, key, value)
        if "len" not in kwargs:
            self.len = len(self)

    def unpack(self, raw):
        if not isinstance(raw, bytes):
            raise TypeError("IP unpack requires bytes")
        try:
            fields, data = _native._ipv4_unpack(raw)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        except _native.Ipv4UnpackError as error:
            raise UnpackError(str(error)) from None
        (
            self._v_hl,
            self.tos,
            self.len,
            self.id,
            self._flags_offset,
            self.ttl,
            self.p,
            self.sum,
            self.src,
            self.dst,
        ) = fields
        self.opts, self.data = b"", data

    @staticmethod
    def _bits(value, width):
        value = operator.index(value)
        if not 0 <= value < (1 << width):
            raise ValueError(f"value does not fit {width} bits")
        return value

    @property
    def v(self):
        return self._v_hl >> 4

    @v.setter
    def v(self, value):
        self._v_hl = (self._bits(value, 4) << 4) | (self._v_hl & 15)

    @property
    def hl(self):
        return self._v_hl & 15

    @hl.setter
    def hl(self, value):
        self._v_hl = (self._v_hl & 0xF0) | self._bits(value, 4)

    @property
    def rf(self):
        return (self._flags_offset >> 15) & 1

    @rf.setter
    def rf(self, value):
        self._flags_offset = (self._flags_offset & ~IP_RF) | (self._bits(value, 1) << 15)

    @property
    def df(self):
        return (self._flags_offset >> 14) & 1

    @df.setter
    def df(self, value):
        self._flags_offset = (self._flags_offset & ~IP_DF) | (self._bits(value, 1) << 14)

    @property
    def mf(self):
        return (self._flags_offset >> 13) & 1

    @mf.setter
    def mf(self, value):
        self._flags_offset = (self._flags_offset & ~IP_MF) | (self._bits(value, 1) << 13)

    @property
    def offset(self):
        return self._flags_offset & IP_OFFMASK

    @offset.setter
    def offset(self, value):
        self._flags_offset = (self._flags_offset & ~IP_OFFMASK) | self._bits(value, 13)

    @property
    def off(self):
        raise NotImplementedError("legacy IP.off is outside this API; use named flags/offset")

    @off.setter
    def off(self, value):
        raise NotImplementedError("legacy IP.off is outside this API; use named flags/offset")

    def _header_args(self):
        if self.opts != b"":
            raise NotImplementedError("IPv4 options are not supported")
        if not isinstance(self.src, bytes) or not isinstance(self.dst, bytes):
            raise PackError("argument for 's' must be a bytes object")
        result = []
        for name, width in (
            ("_v_hl", 8),
            ("tos", 8),
            ("len", 16),
            ("id", 16),
            ("_flags_offset", 16),
            ("ttl", 8),
            ("p", 8),
            ("sum", 16),
        ):
            try:
                value = operator.index(getattr(self, name))
            except TypeError:
                raise PackError("required argument is not an integer") from None
            if not 0 <= value < (1 << width):
                raise PackError(f"{name} does not fit an unsigned {width}-bit field")
            result.append(value)
        return (*result, self.src, self.dst)

    def pack_hdr(self):
        try:
            return _native._ipv4_header(self._header_args())
        except _native.Ipv4UnpackError as error:
            raise UnpackError(str(error)) from None

    def __bytes__(self):
        if not isinstance(self.data, bytes):
            raise TypeError("opaque IPv4 payload requires bytes")
        if len(self.data) > 65535 - IP_HDR_LEN:
            raise PackError("IPv4 datagram exceeds 65535 bytes")
        try:
            raw, length, checksum = _native._ipv4_pack(self._header_args(), self.data)
        except _native.Ipv4UnpackError as error:
            raise UnpackError(str(error)) from None
        self.len, self.sum = length, checksum
        return raw

    def __len__(self):
        return IP_HDR_LEN + len(self.opts) + len(self.data)
