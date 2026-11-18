"""AOL Instant Messenger OSCAR framing, as dpkt 1.9.8 reads it.

FLAP and SNAC have only fixed headers, which the :class:`octetrail.Packet`
base reads. The classes and the ``tlv`` helper are dpkt's.
"""

import struct

from .errors import NeedData, UnpackError
from .packet import Packet

# OSCAR: http://iserverd1.khstu.ru/oscar/


class FLAP(Packet):
    """Frame Layer Protocol.

    See more about the FLAP on
    https://en.wikipedia.org/wiki/OSCAR_protocol#FLAP_header

    Attributes:
        __hdr__: Header fields of FLAP.
        data: Message data.
    """

    __hdr__ = (
        ("ast", "B", 0x2A),  # '*'
        ("type", "B", 0),
        ("seq", "H", 0),
        ("len", "H", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.ast != 0x2A:
            raise UnpackError("invalid FLAP header")
        if len(self.data) < self.len:
            raise NeedData("%d left, %d needed" % (len(self.data), self.len))


class SNAC(Packet):
    """Simple Network Atomic Communication.

    See more about the SNAC on
    https://en.wikipedia.org/wiki/OSCAR_protocol#SNAC_data

    Attributes:
        __hdr__: Header fields of SNAC.
    """

    __hdr__ = (("family", "H", 0), ("subtype", "H", 0), ("flags", "H", 0), ("reqid", "I", 0))


def tlv(buf):
    n = 4
    try:
        t, l_ = struct.unpack(">HH", buf[:n])
    except struct.error:
        raise UnpackError("invalid type, length fields")  # noqa: B904
    v = buf[n : n + l_]
    if len(v) < l_:
        raise NeedData("%d left, %d needed" % (len(v), l_))
    buf = buf[n + l_ :]
    return t, l_, v, buf


# TOC 1.0: http://jamwt.com/Py-TOC/PROTOCOL

# TOC 2.0: http://www.firestuff.org/projects/firetalk/doc/toc2.txt
