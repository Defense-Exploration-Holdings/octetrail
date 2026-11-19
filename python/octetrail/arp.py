"""Address Resolution Protocol.

The address fields are ``hln`` and ``pln`` bytes long. Ethernet and IPv4 (6 and
4) use the :class:`octetrail.Packet` base; other lengths are read and packed by
hand. The constants and class names are dpkt's.
"""

import struct

from .errors import NeedData, PackError
from .packet import Packet

# Hardware address format
ARP_HRD_ETH = 0x0001  # ethernet hardware
ARP_HRD_IEEE802 = 0x0006  # IEEE 802 hardware

# Protocol address format
ARP_PRO_IP = 0x0800  # IP protocol

# ARP operation
ARP_OP_REQUEST = 1  # request to resolve ha given pa
ARP_OP_REPLY = 2  # response giving hardware address
ARP_OP_REVREQUEST = 3  # request to resolve pa given ha
ARP_OP_REVREPLY = 4  # response giving protocol address


class ARP(Packet):
    """Address Resolution Protocol.

    See more about the ARP on \
    https://en.wikipedia.org/wiki/Address_Resolution_Protocol

    Attributes:
        __hdr__: Header fields of ARP.
    """

    __hdr__ = (
        ("hrd", "H", ARP_HRD_ETH),
        ("pro", "H", ARP_PRO_IP),
        ("hln", "B", 6),  # hardware address length
        ("pln", "B", 4),  # protocol address length
        ("op", "H", ARP_OP_REQUEST),
        ("sha", "6s", b""),
        ("spa", "4s", b""),
        ("tha", "6s", b""),
        ("tpa", "4s", b""),
    )

    def unpack(self, buf):
        hln, pln = struct.unpack(">4xBB2x", buf[:8]) if len(buf) >= 8 else (6, 4)
        if (hln, pln) == (6, 4):
            Packet.unpack(self, buf)
            return
        need = 8 + 2 * (hln + pln)
        if len(buf) < need:
            raise NeedData("got %d, %d needed at least" % (len(buf), need))
        self.hrd, self.pro, self.hln, self.pln, self.op = struct.unpack(">HHBBH", buf[:8])
        at = 8
        for name, size in (("sha", hln), ("spa", pln), ("tha", hln), ("tpa", pln)):
            setattr(self, name, buf[at : at + size])
            at += size
        self.data = buf[at:]

    def _variable(self):
        return (self.hln, self.pln) != (6, 4)

    def __len__(self):
        if not self._variable():
            return Packet.__len__(self)
        return 8 + 2 * (self.hln + self.pln) + len(self.data)

    def __bytes__(self):
        if not self._variable():
            return Packet.__bytes__(self)
        fixed = struct.pack(">HHBBH", self.hrd, self.pro, self.hln, self.pln, self.op)
        addrs = (self.sha, self.spa, self.tha, self.tpa)
        sizes = (self.hln, self.pln, self.hln, self.pln)
        for value, size in zip(addrs, sizes, strict=True):
            if len(value) != size:
                raise PackError("address of %d bytes, %d expected" % (len(value), size))
        return fixed + b"".join(bytes(a) for a in addrs) + bytes(self.data)
