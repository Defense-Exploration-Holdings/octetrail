"""Linux libpcap "cooked" capture encapsulation, as dpkt 1.9.8 reads it.

SLL has only a fixed header, which the :class:`octetrail.Packet` base reads.
The payload is decoded through the Ethernet type table.
"""

from . import arp, ethernet
from .errors import NestingError, UnpackError
from .packet import Packet


class SLL(Packet):
    """Linux cooked capture header.

    Attributes:
        type: Packet type. 0: to us, 1: broadcast, 2: multicast, 3: other,
            4: from us.
        hrd: Link-layer address type.
        hlen: Link-layer address length.
        hdr: First 8 bytes of the link-layer address.
        ethtype: Protocol type, looked up in the Ethernet type table.
    """

    __hdr__ = (
        ("type", "H", 0),  # 0: to us, 1: bcast, 2: mcast, 3: other, 4: from us
        ("hrd", "H", arp.ARP_HRD_ETH),
        ("hlen", "H", 6),  # hardware address length
        ("hdr", "8s", b""),  # first 8 bytes of link-layer header
        ("ethtype", "H", ethernet.ETH_TYPE_IP),
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
