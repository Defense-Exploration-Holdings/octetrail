"""Encapsulating Security Payload, as dpkt 1.9.8 reads it.

ESP has only a fixed header, which the :class:`octetrail.Packet` base reads.
The rest, encrypted, stays bytes.
"""

from .packet import Packet


class ESP(Packet):
    """Encapsulating Security Payload.

    Attributes:
        spi: Security Parameters Index.
        seq: Sequence number.
        data: The encrypted payload and trailer.
    """

    __hdr__ = (
        ("spi", "I", 0),
        ("seq", "I", 0),
    )
