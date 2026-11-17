"""Point-to-Point Protocol, as dpkt 1.9.8 reads it.

PPP has only a fixed header, which the :class:`octetrail.Packet` base reads.
The protocol table is filled from the ``PPP_*`` names once every OctetRail
module is loaded.
"""

import importlib
import struct

from .errors import NeedData, PackError, UnpackError
from .packet import Packet

# http://www.iana.org/assignments/ppp-numbers
PPP_IP = 0x21  # Internet Protocol
PPP_IP6 = 0x57  # Internet Protocol v6

# Protocol field compression
PFC_BIT = 0x01


class PPP(Packet):
    """Point-to-Point Protocol frame.

    Attributes:
        addr: Address, 0xFF by default.
        cntrl: Control, 3 by default.
        p: Protocol, one byte when its low bit is set, otherwise two.
    """

    __hdr__ = (
        ("addr", "B", 0xFF),
        ("cntrl", "B", 3),
        ("p", "B", PPP_IP),
    )
    _protosw = {}

    @classmethod
    def set_p(cls, p, pktclass):
        cls._protosw[p] = pktclass

    @classmethod
    def get_p(cls, p):
        return cls._protosw[p]

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.p & PFC_BIT == 0:
            try:
                self.p = struct.unpack(">H", buf[2:4])[0]
            except struct.error:
                raise NeedData from None
            self.data = self.data[1:]
        try:
            self.data = self._protosw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, struct.error, UnpackError):
            pass

    def pack_hdr(self):
        try:
            if self.p > 0xFF:
                return struct.pack(">BBH", self.addr, self.cntrl, self.p)
            return Packet.pack_hdr(self)
        except struct.error as e:
            raise PackError(str(e)) from None


def _load_protos():
    # Each PPP_<NAME> maps to class <NAME> of module <name> when one exists.
    for k, v in list(globals().items()):
        if k.startswith("PPP_"):
            name = k[4:]
            try:
                mod = importlib.import_module(__package__ + "." + name.lower())
                PPP.set_p(v, getattr(mod, name))
            except (ImportError, AttributeError):
                continue


def _mod_init():
    """Fill the protocol table once every OctetRail module is loaded."""
    if not PPP._protosw:
        _load_protos()
