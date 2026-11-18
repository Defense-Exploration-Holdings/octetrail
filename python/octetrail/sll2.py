"""Linux libpcap "cooked v2" capture encapsulation, as dpkt 1.9.8 reads it.

SLL2 has only a fixed header, which the :class:`octetrail.Packet` base reads.
The payload is decoded through the Ethernet type table.
"""

from . import arp, ethernet
from .errors import NestingError, UnpackError
from .packet import Packet


class SLL2(Packet):
    """Linux cooked capture v2 header.

    See https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html

    Attributes:
        ethtype: Protocol type, looked up in the Ethernet type table.
        mbz: Reserved, must be zero.
        intindex: 1-based index of the interface the packet was seen on.
        hrd: Link-layer address type.
        type: Packet type. 0: to us, 1: broadcast, 2: multicast, 3: other,
            4: from us.
        hlen: Link-layer address length.
        hdr: First 8 bytes of the link-layer address.
    """

    __hdr__ = (
        ("ethtype", "H", ethernet.ETH_TYPE_IP),
        ("mbz", "H", 0),  # reserved
        ("intindex", "i", 0),  # 1-based index of the interface
        ("hrd", "H", arp.ARP_HRD_ETH),
        ("type", "B", 0),  # 0: to us, 1: bcast, 2: mcast, 3: other, 4: from us
        ("hlen", "B", 6),  # hardware address length
        ("hdr", "8s", b""),  # first 8 bytes of link-layer header
    )
    _typesw = ethernet.Ethernet._typesw

    def unpack(self, buf):
        Packet.unpack(self, buf)
        try:
            self.data = self._typesw[self.ethtype](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except NestingError:
            raise
        except RecursionError as error:
            raise NestingError(*error.args) from None
        except (KeyError, UnpackError):
            pass
