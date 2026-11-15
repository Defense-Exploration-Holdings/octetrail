"""Fixed 20-byte TCP headers with opaque bytes and caller-supplied checksums.

Only offset 5, empty options and the eight flags shared by dpkt 1.9.6/1.9.8
are supported. No network operation, IP integration or checksum automation is
provided. The complete offline segment is limited to 16 MiB when parsed/packed.
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
TCP_PORT_MAX = TCP_WIN_MAX = 65535
TCP_HDR_LEN = 20
DEFAULT_MAX_SEGMENT_BYTES = 16 * 1024 * 1024
LimitError = _native.PacketLimitError

_FIELDS = (
    ("sport", 16, 0xDEAD),
    ("dport", 16, 0),
    ("seq", 32, 0xDEADBEEF),
    ("ack", 32, 0),
    ("off", 4, 5),
    ("flags", 8, TH_SYN),
    ("win", 16, TCP_WIN_MAX),
    ("sum", 16, 0),
    ("urp", 16, 0),
)


class TCP:
    """Mutable base-header fields, opts=b'' and data as opaque bytes.

    Construct with field keywords or one positional bytes buffer. A positional
    buffer ignores field keywords, as the references do. Field range/type errors
    are deferred until serialization. Options and nonce/reserved bits are outside
    this API. A supplied checksum, including zero, is preserved unchanged.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("TCP accepts at most one positional buffer")
        if args:
            self.unpack(args[0])
            return
        unknown = kwargs.keys() - {name for name, _, _ in _FIELDS} - {"opts", "data"}
        if unknown:
            raise TypeError("unsupported TCP fields: " + ", ".join(sorted(unknown)))
        for name, _, default in _FIELDS:
            setattr(self, name, kwargs.get(name, default))
        self.opts = kwargs.get("opts", b"")
        self.data = kwargs.get("data", b"")

    def unpack(self, buf):
        """Replace fields after a supported complete base header is validated."""
        if not isinstance(buf, bytes):
            raise TypeError("TCP unpack requires bytes")
        try:
            fields, payload = _native._tcp_unpack(buf)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        except _native.TCPHeaderError as error:
            raise UnpackError(str(error)) from None
        for (name, _, _), value in zip(_FIELDS, fields, strict=True):
            setattr(self, name, value)
        self.opts = b""
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
        if fields[4] != 5:
            raise NotImplementedError("only TCP data offset 5 is supported")
        self._check_options()
        return tuple(fields)

    def _check_options(self):
        if not isinstance(self.opts, bytes):
            raise TypeError("TCP opts requires bytes")
        if self.opts:
            raise NotImplementedError("TCP options are unsupported")

    def pack_hdr(self):
        return _native._tcp_header(self._header_args())

    def __bytes__(self):
        fields = self._header_args()
        if not isinstance(self.data, bytes):
            raise TypeError("opaque TCP payload requires bytes")
        size = len(self.data) + TCP_HDR_LEN
        if size > DEFAULT_MAX_SEGMENT_BYTES:
            raise LimitError(f"TCP segment length {size} exceeds limit {DEFAULT_MAX_SEGMENT_BYTES}")
        return _native._tcp_pack(fields, self.data)

    def __len__(self):
        self._check_options()
        if not isinstance(self.data, bytes):
            raise TypeError("opaque TCP payload requires bytes")
        return TCP_HDR_LEN + len(self.data)
