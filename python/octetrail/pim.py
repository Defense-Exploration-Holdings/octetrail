"""Protocol Independent Multicast, parsed and packed the way dpkt 1.9.8 does.

The header is fixed, so the :class:`octetrail.Packet` base reads it, as in dpkt.
"""

from .packet import Packet, in_cksum


class PIM(Packet):
    """PIM message. A ``sum`` of 0 is computed over the whole message when packing."""

    __hdr__ = (
        ("_v_type", "B", 0x20),
        ("_rsvd", "B", 0),
        ("sum", "H", 0),
    )
    __bit_fields__ = {
        "_v_type": (
            ("v", 4),
            ("type", 4),
        )
    }

    def __bytes__(self):
        if not self.sum:
            self.sum = in_cksum(Packet.__bytes__(self))
        return Packet.__bytes__(self)
