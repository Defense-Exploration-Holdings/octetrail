"""Platform-dependent loopback header, as dpkt 1.9.8 reads it.

The header is one address family word in the byte order of the machine that
reads it, which the :class:`octetrail.Packet` base reads.
See https://wiki.wireshark.org/NullLoopback
"""

from . import ethernet, ip, ip6
from .packet import Packet


class Loopback(Packet):
    """Null/loopback header.

    Attributes:
        family: Address family, normalized to 2, 24, 28 or 30 for IPv4 and
            IPv6 in either byte order.
    """

    __hdr__ = (("family", "I", 0),)
    __byte_order__ = "@"

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.family in (0x02, 0x02000000):
            self.family = 2
            self.data = ip.IP(self.data)

        elif self.family in (0x18, 0x18000000):
            self.family = 24
            self.data = ip6.IP6(self.data)

        elif self.family in (0x1C, 0x1C000000):
            self.family = 28
            self.data = ip6.IP6(self.data)

        elif self.family in (0x1E, 0x1E000000):
            self.family = 30
            self.data = ip6.IP6(self.data)

        else:
            self.data = ethernet.Ethernet(self.data)
