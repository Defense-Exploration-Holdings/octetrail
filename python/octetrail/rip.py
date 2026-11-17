"""Routing Information Protocol, as dpkt 1.9.8 reads it.

The 20-byte entries are found in Rust and read by the
:class:`octetrail.Packet` base.
"""

from . import _native
from .errors import NeedData
from .packet import Packet

REQUEST = 1
RESPONSE = 2


class RIP(Packet):
    """Routing Information Protocol message.

    Attributes:
        cmd: Command, request (1) or response (2).
        v: Version.
        rsvd: Reserved.
        rtes: The route entries; ``data`` is the same list.
        auth: The last authentication entry, or None.
    """

    __hdr__ = (
        ("cmd", "B", REQUEST),
        ("v", "B", 2),
        ("rsvd", "H", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = buf if type(buf) is bytes else bytes(buf)
        try:
            rows = _native._rip_entries(raw, self.__hdr_len__)
        except _native.RipShortEntryError as error:
            raise NeedData("got %d, 20 needed at least" % error.args[0]) from None
        l_ = []
        self.auth = None
        for start, is_auth in rows:
            if is_auth:
                self.auth = Auth(buf[start : start + 20])
            else:
                l_.append(RTE(buf[start : start + 20]))
        self.data = self.rtes = l_

    def __len__(self):
        n = self.__hdr_len__
        if self.auth:
            n += len(self.auth)
        n += sum(map(len, self.rtes))
        return n

    def __bytes__(self):
        auth = b""
        if self.auth:
            auth = bytes(self.auth)
        return self.pack_hdr() + auth + b"".join(map(bytes, self.rtes))


class RTE(Packet):
    """Route entry."""

    __hdr__ = (
        ("family", "H", 2),
        ("route_tag", "H", 0),
        ("addr", "I", 0),
        ("subnet", "I", 0),
        ("next_hop", "I", 0),
        ("metric", "I", 1),
    )


class Auth(Packet):
    """Authentication entry. As in dpkt, ``auth`` defaults to 0 and must be
    set before packing."""

    __hdr__ = (
        ("rsvd", "H", 0xFFFF),
        ("type", "H", 2),
        ("auth", "16s", 0),
    )
