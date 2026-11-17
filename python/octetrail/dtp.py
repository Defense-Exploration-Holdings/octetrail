"""Dynamic Trunking Protocol, as dpkt 1.9.8 reads it.

The entry list is read in Rust. As in dpkt, ``data`` holds the entries as
``(type, value)`` pairs, and packing writes only the entries, not the version.
"""

import struct

from . import _native
from .packet import Packet

TRUNK_NAME = 0x01
MAC_ADDR = 0x04


class DTP(Packet):
    """Dynamic Trunking Protocol packet.

    Attributes:
        v: Version.
        data: The ``(type, value)`` entries.
    """

    __hdr__ = (("v", "B", 0),)  # rest is TLVs

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = buf if type(buf) is bytes else bytes(buf)
        try:
            rows = _native._dtp_tlvs(raw, self.__hdr_len__)
        except _native.DtpShortTlvError:
            # dpkt's struct.unpack fails here; Packet turns that into
            # UnpackError, or NeedData for an empty buffer.
            raise struct.error("unpack requires a buffer of 4 bytes") from None
        self.data = [(t, buf[s:e]) for t, s, e in rows]

    def __bytes__(self):
        return b"".join([struct.pack(">HH", t, len(v)) + v for t, v in self.data])
