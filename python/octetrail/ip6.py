"""Internet Protocol, version 6, parsed and packed the way dpkt 1.9.8 does.

The extension header chain is read in Rust. The classes follow dpkt's
``dpkt.ip6`` and are built on :class:`octetrail.Packet`.
"""

import socket
import struct
from functools import partial

from . import _native, ip
from .errors import NeedData, NestingError, UnpackError
from .packet import Packet

IP_PROTO_HOPOPTS = 0
IP_PROTO_ROUTING = 43
IP_PROTO_FRAGMENT = 44
IP_PROTO_ESP = 50
IP_PROTO_AH = 51
IP_PROTO_DSTOPTS = 60

# The extension headers dpkt walks, in the order it packs them.
EXT_HDRS = [
    IP_PROTO_HOPOPTS,
    IP_PROTO_ROUTING,
    IP_PROTO_FRAGMENT,
    IP_PROTO_AH,
    IP_PROTO_ESP,
    IP_PROTO_DSTOPTS,
]


def inet_to_str(inet):
    """Return the text form of a 4-byte or 16-byte address."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


class FragmentOffsetError(UnpackError, AttributeError):
    """``nxt`` is 44 but the last extension header has no ``frag_off``.

    dpkt raises a plain AttributeError here. This class is both, so parse
    errors stay UnpackError.
    """


def _frag_off(ext):
    try:
        return ext.frag_off
    except AttributeError as error:
        raise FragmentOffsetError(str(error)) from None


def _native_error(error):
    if isinstance(error, _native.Ipv6ShortError):
        have, need = error.args
        return NeedData("got %d, %d needed at least" % (have, need))
    return NeedData()


class IP6(Packet):
    """IPv6 packet. ``data`` is the decoded payload when its protocol is known."""

    __hdr__ = (
        ("_v_fc_flow", "I", 0x60000000),
        ("plen", "H", 0),
        ("nxt", "B", 0),
        ("hlim", "B", 0),
        ("src", "16s", b""),
        ("dst", "16s", b""),
    )
    __bit_fields__ = {
        "_v_fc_flow": (
            ("v", 4),
            ("fc", 8),
            ("flow", 20),
        )
    }
    __pprint_funcs__ = {"src": inet_to_str, "dst": inet_to_str}
    _protosw = ip.IP._protosw

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.extension_hdrs = {}
        self.all_extension_headers = []
        raw = buf if type(buf) is bytes else bytes(buf)
        _, rows, (start, end), next_ext_hdr, failure = _native._ipv6_unpack(raw)
        src = _source(buf, raw)
        ext = None
        for row in rows:
            ext = _extension(src, row)
            self.extension_hdrs[row[0]] = ext
            self.all_extension_headers.append(ext)
        if failure is not None:
            raise _native_error(failure)
        rest = src[start:end]

        if next_ext_hdr is not None:
            self.p = next_ext_hdr

        # As in dpkt, fragments after the first are not decoded. dpkt reads
        # frag_off from the last header, whatever its type, and fails with
        # AttributeError when it has none.
        if self.nxt == IP_PROTO_FRAGMENT and _frag_off(ext) > 0:
            self.data = rest
            return

        try:
            self.data = self._decode(next_ext_hdr, rest)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except NestingError:
            raise
        except RecursionError as error:
            raise NestingError(*error.args) from None
        except (KeyError, UnpackError):
            self.data = rest

    def _decode(self, p, buf):
        return self._protosw[p](buf)

    def headers_str(self):
        """Return the last next-header value and the packed extension headers."""
        nxt = self.nxt
        if hasattr(self, "all_extension_headers") and self.all_extension_headers:
            nxt = self.all_extension_headers[-1].nxt
            return nxt, b"".join(bytes(ext) for ext in self.all_extension_headers)
        header_str = b""
        if hasattr(self, "extension_hdrs"):
            for hdr in EXT_HDRS:
                if hdr in self.extension_hdrs:
                    nxt = self.extension_hdrs[hdr].nxt
                    header_str += bytes(self.extension_hdrs[hdr])
        return nxt, header_str

    def __bytes__(self):
        self.p, hdr_str = self.headers_str()
        if (
            (self.p == 6 or self.p == 17 or self.p == 58)
            and hasattr(self.data, "sum")
            and not self.data.sum
        ):
            p = bytes(self.data)
            # The RFC 8200 pseudo-header, with a 32-bit length so that jumbo
            # payloads (RFC 2675) get a checksum too. For payloads up to
            # 65535 bytes the sum is the same as dpkt's 16-bit form.
            s = struct.pack(">16s16sI3xB", self.src, self.dst, len(p), self.p)
            self.data.sum = _native._ipv6_checksum(s, p)
        return self.pack_hdr() + hdr_str + bytes(self.data)

    def __len__(self):
        baselen = self.__hdr_len__ + len(self.data)
        if hasattr(self, "all_extension_headers") and self.all_extension_headers:
            return baselen + sum(len(hh) for hh in self.all_extension_headers)
        elif hasattr(self, "extension_hdrs") and self.extension_hdrs:
            return baselen + sum(len(hh) for hh in self.extension_hdrs.values())
        return baselen

    @classmethod
    def set_proto(cls, p, pktclass):
        cls._protosw[p] = pktclass

    @classmethod
    def get_proto(cls, p):
        return cls._protosw[p]


class IP6ExtensionHeader(Packet):
    """Base of the extension header classes."""

    _kind = None

    def unpack(self, buf):
        if self._kind is None:
            return Packet.unpack(self, buf)
        raw = buf if type(buf) is bytes else bytes(buf)
        try:
            row = _native._ipv6_extension(self._kind, raw)
        except _native.Ipv6ShortError:
            # Packet.__init__ turns this into NeedData, as for a short header in dpkt.
            raise struct.error("unpack requires a buffer of %d bytes" % self.__hdr_len__) from None
        except _native.Ipv6OptionsError:
            raise NeedData() from None
        _fill(self, _source(buf, raw), row, lazy=False)


class IP6OptsHeader(IP6ExtensionHeader):
    """Hop-by-hop or destination options. ``options`` skips Pad1 and PadN."""

    __hdr__ = (
        ("nxt", "B", 0),
        ("len", "B", 0),
    )
    _kind = IP_PROTO_HOPOPTS


class IP6HopOptsHeader(IP6OptsHeader):
    _kind = IP_PROTO_HOPOPTS


class IP6DstOptsHeader(IP6OptsHeader):
    _kind = IP_PROTO_DSTOPTS


class IP6RoutingHeader(IP6ExtensionHeader):
    __hdr__ = (
        ("nxt", "B", 0),
        ("len", "B", 0),
        ("type", "B", 0),
        ("segs_left", "B", 0),
        ("_rsvd_sl_bits", "I", 0),
    )
    __bit_fields__ = {
        "_rsvd_sl_bits": (
            ("_rsvd", 8),
            ("sl_bits", 24),
        )
    }
    _kind = IP_PROTO_ROUTING


class IP6FragmentHeader(IP6ExtensionHeader):
    __hdr__ = (
        ("nxt", "B", 0),
        ("_resv", "B", 0),
        ("_frag_off_resv_m", "H", 0),
        ("id", "I", 0),
    )
    __bit_fields__ = {
        "_frag_off_resv_m": (
            ("frag_off", 13),
            ("_resv", 2),
            ("m_flag", 1),
        )
    }
    _kind = IP_PROTO_FRAGMENT


class IP6AHHeader(IP6ExtensionHeader):
    """Authentication header. As in dpkt, ``data`` holds everything after it."""

    __hdr__ = (
        ("nxt", "B", 0),
        ("len", "B", 0),
        ("_resv", "H", 0),
        ("spi", "I", 0),
        ("seq", "I", 0),
    )
    _kind = IP_PROTO_AH

    # In a parsed chain, data and auth_data are copied out of the packet on
    # first use. Each AH header's data is the rest of the packet, so copying
    # them all up front would take time quadratic in the number of headers.
    def __getattr__(self, name):
        lazy = self.__dict__.get("_lazy")
        if lazy is None or name not in ("data", "auth_data"):
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))
        self._materialize()
        return getattr(self, name)

    def _materialize(self):
        # Both fields are set before _lazy is dropped, so another thread
        # reading them in between still finds one or the other.
        lazy = self.__dict__.get("_lazy")
        if lazy is None:
            return
        raw, (ds, de), (a_start, a_end) = lazy
        try:
            object.__getattribute__(self, "data")
        except AttributeError:
            self.data = raw[ds:de]
        if "auth_data" not in self.__dict__:
            self.auth_data = raw[a_start:a_end]
        self.__dict__.pop("_lazy", None)

    def __repr__(self):
        self._materialize()
        return Packet.__repr__(self)

    def pprint(self, indent=1):
        self._materialize()
        return Packet.pprint(self, indent)


class IP6ESPHeader(IP6ExtensionHeader):
    """ESP header. ``data`` holds everything after it and there is no ``nxt``."""

    __hdr__ = (
        ("spi", "I", 0),
        ("seq", "I", 0),
    )
    _kind = IP_PROTO_ESP


EXT_HDRS_CLS = {
    IP_PROTO_HOPOPTS: IP6HopOptsHeader,
    IP_PROTO_ROUTING: IP6RoutingHeader,
    IP_PROTO_FRAGMENT: IP6FragmentHeader,
    IP_PROTO_ESP: IP6ESPHeader,
    IP_PROTO_AH: IP6AHHeader,
    IP_PROTO_DSTOPTS: IP6DstOptsHeader,
}


def _fill(ext, raw, row, lazy):
    """Set the attributes dpkt's unpack sets, in the same order."""
    kind, fields, (ds, de), length, extra = row
    for name, value in zip(ext.__hdr_fields__, fields, strict=True):
        setattr(ext, name, value)
    if kind in (IP_PROTO_HOPOPTS, IP_PROTO_DSTOPTS):
        ext.length = length
        ext.options = [{"type": t, "opt_length": n, "data": raw[s:e]} for t, n, s, e in extra]
        ext.data = raw[ds:de]
    elif kind == IP_PROTO_ROUTING:
        ext.data = raw[ds:de]
        ext.addresses = [raw[s:e] for s, e in extra]
        ext.length = length
    elif kind == IP_PROTO_AH:
        ext.length = length
        if lazy:
            ext._lazy = (raw, (ds, de), extra)
        else:
            ext.data = raw[ds:de]
            ext.auth_data = raw[extra[0] : extra[1]]
    elif kind == IP_PROTO_FRAGMENT:
        ext.length = length
        # dpkt sets a fragment header's data to b"", whatever the buffer type.
        ext.data = bytes(raw[ds:de])
    else:
        ext.length = length
        ext.data = raw[ds:de]


def _source(buf, raw):
    """What to slice so that fields keep the buffer type, as dpkt's slices do.

    ``raw`` is a bytes copy of ``buf``. Slicing a copy rather than ``buf`` keeps
    later changes to a mutable buffer out of the lazily sliced AH fields.
    """
    if type(buf) is bytes:
        return raw
    if isinstance(buf, bytearray):
        return bytearray(raw)
    if isinstance(buf, memoryview):
        return memoryview(raw)
    return raw


def _extension(raw, row):
    cls = EXT_HDRS_CLS[row[0]]
    ext = cls.__new__(cls)
    if row[0] != IP_PROTO_AH:
        ext.data = b""
    _fill(ext, raw, row, lazy=True)
    ext._pack_hdr = partial(struct.pack, cls.__hdr_fmt__)
    return ext
