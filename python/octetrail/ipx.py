"""Internetwork Packet Exchange, as dpkt 1.9.8 reads it.

IPX has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet

IPX_HDR_LEN = 30


class IPX(Packet):
    """Internetwork Packet Exchange.

    Attributes:
        sum: Checksum.
        len: Packet length, including the header.
        tc: Transport control (hop count).
        pt: Packet type.
        dst: Destination address (12 bytes).
        src: Source address (12 bytes).
    """

    __hdr__ = (
        ("sum", "H", 0xFFFF),
        ("len", "H", IPX_HDR_LEN),
        ("tc", "B", 0),
        ("pt", "B", 0),
        ("dst", "12s", b""),
        ("src", "12s", b""),
    )
