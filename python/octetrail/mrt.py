"""Multi-threaded Routing Toolkit (MRT) records, as dpkt 1.9.8 reads and writes them.

The record headers use the :class:`octetrail.Packet` base with dpkt's fields.
``TableDump`` reads its path attributes with :mod:`octetrail.bgp`, giving each
attribute only its own bytes, so a long attribute list parses in linear time.
"""

from . import bgp
from .packet import Packet

# Multi-threaded Routing Toolkit
# http://www.ietf.org/internet-drafts/draft-ietf-grow-mrt-03.txt

# MRT Types
NULL = 0
START = 1
DIE = 2
I_AM_DEAD = 3
PEER_DOWN = 4
BGP = 5  # Deprecated by BGP4MP
RIP = 6
IDRP = 7
RIPNG = 8
BGP4PLUS = 9  # Deprecated by BGP4MP
BGP4PLUS_01 = 10  # Deprecated by BGP4MP
OSPF = 11
TABLE_DUMP = 12
BGP4MP = 16
BGP4MP_ET = 17
ISIS = 32
ISIS_ET = 33
OSPF_ET = 64

# BGP4MP Subtypes
BGP4MP_STATE_CHANGE = 0
BGP4MP_MESSAGE = 1
BGP4MP_ENTRY = 2
BGP4MP_SNAPSHOT = 3
BGP4MP_MESSAGE_32BIT_AS = 4

# Address Family Types
AFI_IPv4 = 1
AFI_IPv6 = 2


class MRTHeader(Packet):
    __hdr__ = (("ts", "I", 0), ("type", "H", 0), ("subtype", "H", 0), ("len", "I", 0))


class TableDump(Packet):
    __hdr__ = (
        ("view", "H", 0),
        ("seq", "H", 0),
        ("prefix", "I", 0),
        ("prefix_len", "B", 0),
        ("status", "B", 1),
        ("originated_ts", "I", 0),
        ("peer_ip", "I", 0),
        ("peer_as", "H", 0),
        ("attr_len", "H", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        data = self.data
        plen = self.attr_len
        pos = 0
        l_ = []
        while plen > 0:
            attr = bgp.BGP.Update.Attribute(data[pos : bgp._attribute_end(data, pos)])
            pos += len(attr)
            plen -= len(attr)
            l_.append(attr)
        self.data = data[pos:]
        self.attributes = l_


class BGP4MPMessage(Packet):
    __hdr__ = (
        ("src_as", "H", 0),
        ("dst_as", "H", 0),
        ("intf", "H", 0),
        ("family", "H", AFI_IPv4),
        ("src_ip", "I", 0),
        ("dst_ip", "I", 0),
    )


class BGP4MPMessage_32(Packet):
    __hdr__ = (
        ("src_as", "I", 0),
        ("dst_as", "I", 0),
        ("intf", "H", 0),
        ("family", "H", AFI_IPv4),
        ("src_ip", "I", 0),
        ("dst_ip", "I", 0),
    )
