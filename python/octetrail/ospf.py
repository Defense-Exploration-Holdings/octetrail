"""Open Shortest Path First, as dpkt 1.9.8 reads it.

OSPF has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet, in_cksum

AUTH_NONE = 0
AUTH_PASSWORD = 1
AUTH_CRYPTO = 2


class OSPF(Packet):
    """Open Shortest Path First header.

    Attributes:
        v: Version.
        type: Packet type.
        len: Packet length.
        router: Router ID.
        area: Area ID.
        sum: Checksum, computed when packing if it is 0.
        atype: Authentication type.
        auth: Authentication data (8 bytes).
    """

    __hdr__ = (
        ("v", "B", 0),
        ("type", "B", 0),
        ("len", "H", 0),
        ("router", "I", 0),
        ("area", "I", 0),
        ("sum", "H", 0),
        ("atype", "H", 0),
        ("auth", "8s", b""),
    )

    def __bytes__(self):
        if not self.sum:
            self.sum = in_cksum(Packet.__bytes__(self))
        return Packet.__bytes__(self)
