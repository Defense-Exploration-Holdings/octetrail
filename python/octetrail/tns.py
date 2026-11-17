"""Oracle Transparent Network Substrate, as dpkt 1.9.8 reads it."""

from .errors import NeedData
from .packet import Packet


class TNS(Packet):
    """TNS packet. ``msg`` is the next ``length - 8`` bytes and ``data`` the rest."""

    __hdr__ = (
        ("length", "H", 0),
        ("pktsum", "H", 0),
        ("type", "B", 0),
        ("rsvd", "B", 0),
        ("hdrsum", "H", 0),
        ("msg", "0s", b""),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        n = self.length - self.__hdr_len__
        if n > len(self.data):
            raise NeedData("short message (missing %d bytes)" % (n - len(self.data)))
        self.msg = self.data[:n]
        self.data = self.data[n:]
