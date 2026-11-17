"""Internet Group Management Protocol, as dpkt 1.9.8 reads it.

IGMP has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet, in_cksum


class IGMP(Packet):
    """Internet Group Management Protocol message.

    Attributes:
        type: Message type.
        maxresp: Maximum response time.
        sum: Checksum, computed when packing if it is 0.
        group: Group address (4 bytes).
    """

    __hdr__ = (
        ("type", "B", 0),
        ("maxresp", "B", 0),
        ("sum", "H", 0),
        ("group", "4s", b"\x00" * 4),
    )

    def __bytes__(self):
        if not self.sum:
            self.sum = in_cksum(Packet.__bytes__(self))
        return Packet.__bytes__(self)
