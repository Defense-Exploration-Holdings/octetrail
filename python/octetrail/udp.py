"""User Datagram Protocol, parsed and packed the way dpkt 1.9.8 does.

The header is fixed, so the :class:`octetrail.Packet` base reads it, as in dpkt.
``ulen`` and ``sum`` are packed as assigned. IPv4 and IPv6 fill a zero ``sum``.
"""

from .packet import Packet

UDP_HDR_LEN = 8
UDP_PORT_MAX = 65535


class UDP(Packet):
    """UDP datagram. ``data`` is the payload as bytes."""

    __hdr__ = (
        ("sport", "H", 0xDEAD),
        ("dport", "H", 0),
        ("ulen", "H", 8),
        ("sum", "H", 0),
    )
