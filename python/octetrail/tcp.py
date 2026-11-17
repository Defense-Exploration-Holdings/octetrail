"""TCP segments with opaque options and payload, parsed and packed as dpkt 1.9.8 does.

Standalone serialization retains the caller checksum. The enclosing IPv4 API
can fill a zero transport checksum while recalculating its own zero checksum.
"""

import operator

from . import _native
from .errors import NeedData, PackError, UnpackError

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80
TH_NS = 0x100
TCP_PORT_MAX = TCP_WIN_MAX = 65535
TCP_HDR_LEN = 20
DEFAULT_MAX_SEGMENT_BYTES = 16 * 1024 * 1024
LimitError = _native.PacketLimitError

TCP_OPT_EOL = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2
TCP_OPT_WSCALE = 3
TCP_OPT_SACKOK = 4
TCP_OPT_SACK = 5
TCP_OPT_ECHO = 6
TCP_OPT_ECHOREPLY = 7
TCP_OPT_TIMESTAMP = 8
TCP_OPT_POCONN = 9
TCP_OPT_POSVC = 10
TCP_OPT_CC = 11
TCP_OPT_CCNEW = 12
TCP_OPT_CCECHO = 13
TCP_OPT_ALTSUM = 14
TCP_OPT_ALTSUMDATA = 15
TCP_OPT_SKEETER = 16
TCP_OPT_BUBBA = 17
TCP_OPT_TRAILSUM = 18
TCP_OPT_MD5 = 19
TCP_OPT_SCPS = 20
TCP_OPT_SNACK = 21
TCP_OPT_REC = 22
TCP_OPT_CORRUPT = 23
TCP_OPT_SNAP = 24
TCP_OPT_TCPCOMP = 26
TCP_OPT_MAX = 27

_FLAG_NAMES = (
    (TH_FIN, "FIN"),
    (TH_SYN, "SYN"),
    (TH_RST, "RST"),
    (TH_PUSH, "PUSH"),
    (TH_ACK, "ACK"),
    (TH_URG, "URG"),
    (TH_ECE, "ECE"),
    (TH_CWR, "CWR"),
    (TH_NS, "NS"),
)

_FIELDS = (
    ("sport", 16, 0xDEAD),
    ("dport", 16, 0),
    ("seq", 32, 0xDEADBEEF),
    ("ack", 32, 0),
    ("_off_flags", 16, (5 << 12) | TH_SYN),
    ("win", 16, TCP_WIN_MAX),
    ("sum", 16, 0),
    ("urp", 16, 0),
)


def tcp_flags_to_str(val):
    """Comma-separated names of the flags set in val."""
    return ",".join(name for bit, name in _FLAG_NAMES if val & bit)


def parse_opts(buf):
    """Split a TCP option buffer into (kind, data) tuples, ending with None if malformed."""
    return _native._tcp_parse_opts(buf)


def _bit_field(name, shift, width):
    mask = ((1 << width) - 1) << shift

    def getter(self):
        return (self._off_flags & mask) >> shift

    def setter(self, value):
        # Same checks as dpkt's bit field setter: only too-large values fail here.
        if value >= 1 << width:
            raise ValueError(f"value {value} is too large for field {name}")
        self._off_flags = (value << shift) | (self._off_flags & (0xFFFF - mask))

    return property(getter, setter)


class TCP:
    """Mutable header fields, opaque options and application bytes.

    Construct with field keywords or one positional bytes buffer. A positional
    buffer ignores field keywords, as dpkt does. Field range and type errors are
    deferred until serialization. off, _rsv and flags (nine bits) are views of
    _off_flags. A supplied checksum, including zero, is preserved unchanged.
    """

    off = _bit_field("off", 12, 4)
    _rsv = _bit_field("_rsv", 9, 3)
    flags = _bit_field("flags", 0, 9)

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("TCP accepts at most one positional buffer")
        if args:
            self.unpack(args[0])
            return
        allowed = {name for name, _, _ in _FIELDS} | {"off", "_rsv", "flags", "opts", "data"}
        unknown = kwargs.keys() - allowed
        if unknown:
            raise TypeError("unsupported TCP fields: " + ", ".join(sorted(unknown)))
        for name, _, default in _FIELDS:
            setattr(self, name, default)
        self.opts = self.data = b""
        for name, value in kwargs.items():
            setattr(self, name, value)

    def unpack(self, buf):
        """Replace fields from buf. Options and data are sliced from the bytes present."""
        if not isinstance(buf, bytes):
            raise TypeError("TCP unpack requires bytes")
        try:
            fields, opts, payload = _native._tcp_unpack(buf)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        except _native.TCPHeaderError as error:
            raise UnpackError(str(error)) from None
        for (name, _, _), value in zip(_FIELDS, fields, strict=True):
            setattr(self, name, value)
        self.opts = opts
        self.data = payload

    def _header_args(self):
        fields = []
        for name, bits, _ in _FIELDS:
            try:
                value = operator.index(getattr(self, name))
            except TypeError:
                raise PackError(f"{name} requires an integer") from None
            if not 0 <= value < 1 << bits:
                raise PackError(f"{name} requires an unsigned {bits}-bit integer")
            fields.append(value)
        return tuple(fields)

    def pack_hdr(self):
        return _native._tcp_header(self._header_args())

    def __bytes__(self):
        fields = self._header_args()
        if not isinstance(self.opts, bytes):
            raise TypeError("TCP opts requires bytes")
        if not isinstance(self.data, bytes):
            raise TypeError("opaque TCP payload requires bytes")
        size = len(self.data) + len(self.opts) + TCP_HDR_LEN
        if size > DEFAULT_MAX_SEGMENT_BYTES:
            raise LimitError(f"TCP segment length {size} exceeds limit {DEFAULT_MAX_SEGMENT_BYTES}")
        return _native._tcp_pack(fields, self.opts, self.data)

    def __len__(self):
        if not isinstance(self.opts, bytes):
            raise TypeError("TCP opts requires bytes")
        if not isinstance(self.data, bytes):
            raise TypeError("opaque TCP payload requires bytes")
        return TCP_HDR_LEN + len(self.opts) + len(self.data)
