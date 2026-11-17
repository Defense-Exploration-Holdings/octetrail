"""Extreme Discovery Protocol, as dpkt 1.9.8 reads it.

EDP has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet, in_cksum


class EDP(Packet):
    """Extreme Discovery Protocol header.

    Attributes:
        version: Version, 1 by default.
        reserved: Reserved.
        hlen: Length.
        sum: Checksum, computed when packing if it is 0.
        seq: Sequence number.
        mid: Machine ID type.
        mac: Machine MAC address (6 bytes).
    """

    __hdr__ = (
        ("version", "B", 1),
        ("reserved", "B", 0),
        ("hlen", "H", 0),
        ("sum", "H", 0),
        ("seq", "H", 0),
        ("mid", "H", 0),
        ("mac", "6s", b""),
    )

    def __bytes__(self):
        if not self.sum:
            self.sum = in_cksum(Packet.__bytes__(self))
        return Packet.__bytes__(self)
