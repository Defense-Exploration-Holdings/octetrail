"""Real-Time Transport Protocol, as dpkt 1.9.8 reads it."""

from .packet import Packet

# version 1100 0000 0000 0000 ! 0xC000  14
# p       0010 0000 0000 0000 ! 0x2000  13
# x       0001 0000 0000 0000 ! 0x1000  12
# cc      0000 1111 0000 0000 ! 0x0F00   8
# m       0000 0000 1000 0000 ! 0x0080   7
# pt      0000 0000 0111 1111 ! 0x007F   0

_VERSION_MASK = 0xC000
_P_MASK = 0x2000
_X_MASK = 0x1000
_CC_MASK = 0x0F00
_M_MASK = 0x0080
_PT_MASK = 0x007F
_VERSION_SHIFT = 14
_P_SHIFT = 13
_X_SHIFT = 12
_CC_SHIFT = 8
_M_SHIFT = 7
_PT_SHIFT = 0

VERSION = 2


def _bits(mask, shift):
    def get(self):
        return (self._type & mask) >> shift

    def set(self, value):
        self._type = (value << shift) | (self._type & ~mask)

    return property(get, set)


class RTP(Packet):
    """RTP packet.

    Attributes:
        version, p, x, cc, m, pt: The bit fields of the first two bytes.
        seq: Sequence number.
        ts: Timestamp.
        ssrc: Synchronization source.
        csrc: The ``cc`` contributing sources, as bytes.
    """

    __hdr__ = (
        ("_type", "H", 0x8000),
        ("seq", "H", 0),
        ("ts", "I", 0),
        ("ssrc", "I", 0),
    )
    csrc = b""

    version = _bits(_VERSION_MASK, _VERSION_SHIFT)
    p = _bits(_P_MASK, _P_SHIFT)
    x = _bits(_X_MASK, _X_SHIFT)
    cc = _bits(_CC_MASK, _CC_SHIFT)
    m = _bits(_M_MASK, _M_SHIFT)
    pt = _bits(_PT_MASK, _PT_SHIFT)

    def __len__(self):
        return self.__hdr_len__ + len(self.csrc) + len(self.data)

    def __bytes__(self):
        return self.pack_hdr() + self.csrc + bytes(self.data)

    def unpack(self, buf):
        super().unpack(buf)
        self.csrc = buf[self.__hdr_len__ : self.__hdr_len__ + self.cc * 4]
        self.data = buf[self.__hdr_len__ + self.cc * 4 :]
