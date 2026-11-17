"""Bounded offline IPv6 with ordered opaque extensions and TCP/UDP children."""

import operator
from dataclasses import dataclass

from . import _native, tcp, udp
from .errors import NeedData, PackError, UnpackError

IP6_HDR_LEN = 40
MAX_EXTENSIONS = 16
MAX_EXTENSION_BYTES = 2048
LimitError = _native.PacketLimitError


@dataclass(frozen=True)
class ExtensionHeader:
    """Opaque wire framing, not dpkt's extension-specific object API."""

    type: int
    raw: bytes

    @property
    def nxt(self):
        return self.raw[0]

    @property
    def length(self):
        return len(self.raw)

    def __bytes__(self):
        return self.raw

    def __len__(self):
        return len(self.raw)


class IP6:
    """Mutable base fields and data; plen remains caller-owned, as in dpkt.

    Non-atomic fragments and incomplete declared payloads remain bytes. Parsing
    never reassembles fragments or interprets extension option contents.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("IP6 accepts at most one positional buffer")
        if args:
            self.unpack(args[0])
            return
        self._v_fc_flow, self.plen, self.nxt, self.hlim = 0x60000000, 0, 0, 0
        self.src = self.dst = b""
        self.data = b""
        self.all_extension_headers = ()
        self.payload_status = "constructed"
        allowed = {
            "_v_fc_flow",
            "v",
            "fc",
            "flow",
            "plen",
            "nxt",
            "hlim",
            "src",
            "dst",
            "data",
            "all_extension_headers",
        }
        if kwargs.keys() - allowed:
            raise TypeError("unsupported IP6 fields")
        for key, value in kwargs.items():
            setattr(self, key, value)

    @staticmethod
    def _bits(value, width):
        value = operator.index(value)
        if not 0 <= value < 1 << width:
            raise ValueError("value does not fit IPv6 bit field")
        return value

    @property
    def v(self):
        return self._v_fc_flow >> 28

    @v.setter
    def v(self, value):
        self._v_fc_flow = (self._v_fc_flow & 0x0FFFFFFF) | (self._bits(value, 4) << 28)

    @property
    def fc(self):
        return (self._v_fc_flow >> 20) & 255

    @fc.setter
    def fc(self, value):
        self._v_fc_flow = (self._v_fc_flow & 0xF00FFFFF) | (self._bits(value, 8) << 20)

    @property
    def flow(self):
        return self._v_fc_flow & 0xFFFFF

    @flow.setter
    def flow(self, value):
        self._v_fc_flow = (self._v_fc_flow & 0xFFF00000) | self._bits(value, 20)

    @property
    def p(self):
        return self.all_extension_headers[-1].nxt if self.all_extension_headers else self.nxt

    @property
    def fragmented(self):
        return any(
            kind == 44 and len(wire) == 8 and int.from_bytes(wire[2:4], "big") & 0xFFF9 != 0
            for kind, wire in self._extensions()
        )

    def unpack(self, raw):
        if not isinstance(raw, bytes):
            raise TypeError("IP6 unpack requires bytes")
        try:
            fields, extensions, data, protocol, fragmented, status = _native._ipv6_unpack(raw)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        self._v_fc_flow, self.plen, self.nxt, self.hlim, self.src, self.dst = fields
        self.all_extension_headers = tuple(ExtensionHeader(kind, wire) for kind, wire in extensions)
        self.data, self.payload_status = data, status
        # Compare wire fields, not child identity, before preserving a captured
        # zero checksum whose pseudoheader cannot safely be reconstructed.
        self._captured_state = (fields, tuple(extensions), data)
        decoder = {6: tcp.TCP, 17: udp.UDP}.get(protocol)
        if status == "complete" and not fragmented and decoder is not None:
            try:
                decoded = decoder(data)
            except (UnpackError, NotImplementedError):
                pass
            else:
                self.data = decoded
                setattr(self, decoder.__name__.lower(), decoded)

    def _fields(self):
        if not isinstance(self.src, bytes) or not isinstance(self.dst, bytes):
            raise PackError("IPv6 addresses require bytes")
        fields = []
        for key, width in (("_v_fc_flow", 32), ("plen", 16), ("nxt", 8), ("hlim", 8)):
            try:
                value = operator.index(getattr(self, key))
            except TypeError:
                raise PackError("IPv6 fields require integers") from None
            if not 0 <= value < 1 << width:
                raise PackError("IPv6 field out of range")
            fields.append(value)
        return (*fields, self.src, self.dst)

    def _extensions(self):
        if not isinstance(self.all_extension_headers, tuple):
            raise TypeError("IPv6 extensions require an immutable tuple")
        if len(self.all_extension_headers) > MAX_EXTENSIONS:
            raise LimitError("IPv6 extension count exceeded")
        used, result = 0, []
        for header in self.all_extension_headers:
            if not isinstance(header, ExtensionHeader) or not isinstance(header.raw, bytes):
                raise TypeError("IPv6 extensions require ExtensionHeader bytes")
            used += len(header.raw)
            if used > MAX_EXTENSION_BYTES:
                raise LimitError("IPv6 extension byte limit exceeded")
            try:
                kind = operator.index(header.type)
            except TypeError:
                raise PackError("IPv6 extension type requires an integer") from None
            if not 0 <= kind <= 255:
                raise PackError("IPv6 extension type out of range")
            result.append((kind, header.raw))
        return result

    def _payload_size(self):
        if not isinstance(self.data, (bytes, tcp.TCP, udp.UDP)):
            raise TypeError("IPv6 data requires bytes, TCP or UDP")
        return len(self.data)

    def pack_hdr(self):
        return _native._ipv6_header(self._fields())

    def __len__(self):
        return IP6_HDR_LEN + sum(len(raw) for _, raw in self._extensions()) + self._payload_size()

    def __bytes__(self):
        fields, extensions = self._fields(), self._extensions()
        size = sum(len(raw) for _, raw in extensions) + self._payload_size()
        if size > 65535:
            raise LimitError("IPv6 payload exceeds 65535 bytes")
        payload = self.data if isinstance(self.data, bytes) else bytes(self.data)
        try:
            raw, protocol, fragmented, checksum_supported = _native._ipv6_pack(
                fields, extensions, payload
            )
        except _native.Ipv6PackError as error:
            raise PackError(str(error)) from None
        if isinstance(self.data, (tcp.TCP, udp.UDP)):
            if fragmented:
                raise PackError("non-atomic IPv6 fragments require opaque bytes")
            if protocol in (6, 17) and self.data.sum == 0:
                if not checksum_supported:
                    if getattr(self, "_captured_state", None) == (
                        fields,
                        tuple(extensions),
                        payload,
                    ):
                        return raw
                    raise NotImplementedError("active routing-header checksum is unsupported")
                self.data.sum = _native._ipv6_checksum(fields, protocol, payload)
                raw = raw[: IP6_HDR_LEN + sum(len(wire) for _, wire in extensions)] + bytes(
                    self.data
                )
        return raw
