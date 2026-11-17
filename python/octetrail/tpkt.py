"""ISO transport service on top of TCP (TPKT, RFC 1006), as dpkt 1.9.8 reads it."""

from .packet import Packet


class TPKT(Packet):
    """TPKT header.

    Attributes:
        v: Version.
        rsvd: Reserved.
        len: Packet length.
    """

    __hdr__ = (
        ("v", "B", 3),
        ("rsvd", "B", 0),
        ("len", "H", 0),
    )
