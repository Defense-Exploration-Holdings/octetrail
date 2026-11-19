"""Generic Routing Encapsulation, parsed and packed the way dpkt 1.9.8 does.

The option fields and source route entries are read in Rust. The classes follow
dpkt's ``dpkt.gre`` and are built on :class:`octetrail.Packet`.
"""

import struct

from . import _native, ethernet
from .errors import NeedData, NestingError, UnpackError
from .packet import Packet

GRE_CP = 0x8000  # Checksum Present
GRE_RP = 0x4000  # Routing Present
GRE_KP = 0x2000  # Key Present
GRE_SP = 0x1000  # Sequence Present
GRE_SS = 0x0800  # Strict Source Route
GRE_AP = 0x0080  # Acknowledgment Present

GRE_opt_fields = (
    (GRE_CP | GRE_RP, "sum", "H"),
    (GRE_CP | GRE_RP, "off", "H"),
    (GRE_KP, "key", "I"),
    (GRE_SP, "seq", "I"),
    (GRE_AP, "ack", "I"),
)


class GRE(Packet):
    """GRE packet. ``data`` is decoded through the Ethernet type table."""

    __hdr__ = (
        ("flags", "H", 0),
        ("p", "H", 0x0800),  # ETH_TYPE_IP
    )
    sre = ()

    @property
    def v(self):
        return self.flags & 0x7

    @v.setter
    def v(self, v):
        self.flags = (self.flags & ~0x7) | (v & 0x7)

    @property
    def recur(self):
        """Recursion control bits. (3 bits)"""
        return (self.flags >> 5) & 0x7

    @recur.setter
    def recur(self, v):
        self.flags = (self.flags & ~0xE0) | ((v & 0x7) << 5)

    class SRE(Packet):
        __hdr__ = [
            ("family", "H", 0),
            ("off", "B", 0),
            ("len", "B", 0),
        ]

        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.data = self.data[: self.len]

    def opt_fields_fmts(self):
        if self.v == 0:
            fields, fmts = [], []
            opt_fields = GRE_opt_fields
        else:
            fields, fmts = ["len", "callid"], ["H", "H"]
            opt_fields = GRE_opt_fields[-2:]
        for flags, field, fmt in opt_fields:
            if self.flags & flags:
                fields.append(field)
                fmts.append(fmt)
        return fields, fmts

    def unpack(self, buf):
        Packet.unpack(self, buf)
        try:
            values, sres, start = _native._gre_layout(buf if type(buf) is bytes else bytes(buf))
        except _native.GreShortOptionsError:
            # dpkt's struct.unpack fails here; Packet turns that into UnpackError.
            raise struct.error("unpack requires a longer buffer") from None
        except _native.GreShortSreError as error:
            raise NeedData("got %d, %d needed at least" % (error.args[0], 4)) from None
        fields, _ = self.opt_fields_fmts()
        self.__dict__.update(zip(fields, values, strict=True))
        if self.flags & GRE_RP:
            self.sre = [self.SRE(buf[a:b]) for a, b in sres]
        self.data = buf[start:]
        try:
            self.data = ethernet.Ethernet._typesw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except NestingError:
            raise
        except RecursionError as error:
            raise NestingError(*error.args) from None
        except (KeyError, UnpackError):
            pass

    def __len__(self):
        opt_fmtlen = struct.calcsize("".join(self.opt_fields_fmts()[1]))
        return self.__hdr_len__ + opt_fmtlen + sum(map(len, self.sre)) + len(self.data)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # A packet built from fields gets a zero checksum computed on pack. A
        # parsed packet packs back to its own bytes.
        self._fill_on_pack = not args

    def __bytes__(self):
        fields, fmts = self.opt_fields_fmts()
        fmt = "!" + "".join(fmts)
        vals = [getattr(self, f, 0) for f in fields]
        rest = b"".join(map(bytes, self.sre)) + bytes(self.data)
        out = self.pack_hdr() + struct.pack(fmt, *vals) + rest
        if self._fill_on_pack and self.v == 0 and self.flags & GRE_CP and vals[0] == 0:
            # A zero checksum is computed over the GRE header and payload
            # (RFC 2784), as IPv4 does for its header checksum.
            self.sum = _native._inet_checksum(out)
            vals[0] = self.sum
            out = self.pack_hdr() + struct.pack(fmt, *vals) + rest
        return out
