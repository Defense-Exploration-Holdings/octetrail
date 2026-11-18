"""Diameter (RFC 3588), as dpkt 1.9.8 reads it.

The headers use the :class:`octetrail.Packet` base. The AVP walk is read in
Rust. The constants and classes are dpkt's.
"""

import struct

from . import _native
from .packet import Packet

# Diameter Base Protocol - RFC 3588
# http://tools.ietf.org/html/rfc3588

# Request/Answer Command Codes
ABORT_SESSION = 274
ACCOUNTING = 271
CAPABILITIES_EXCHANGE = 257
DEVICE_WATCHDOG = 280
DISCONNECT_PEER = 282
RE_AUTH = 258
SESSION_TERMINATION = 275


class Diameter(Packet):
    """Diameter.

    Diameter is an authentication, authorization, and accounting protocol for computer networks. It evolved from the
    earlier RADIUS protocol. It belongs to the application layer protocols in the internet protocol suite.

    Attributes:
        __hdr__: Header fields of Diameter.
            v: (int) Version. The version of the Diameter Base Protocol.
                As of 2014, the only value supported is 1. (1 byte)
            len: (bytes): Message Length. The Message Length field indicates the length of the Diameter message in
                bytes, including the header fields and the padded AVPs. (3 bytes)
            flags: (int): Command flags. (Request, Proxiable, Error, Potentially re-transmitted message) (1 byte)
            cmd: (bytes): Commands. Determine the action that is to be taken for a particular message. (3 bytes)
            app_id: (int): Application-ID. Application-ID is used to identify for which Diameter application the
                message is applicable. (4 bytes)
            hop_id: (int): Hop-by-Hop Identifier. Used to match the requests with their answers as the same value in
                the request is used in the response. (4 bytes)
            end_id: (int): End-to-End Identifier. used to detect duplicate messages along with the combination of the
                Origin-Host AVP. (4 bytes)
    """

    __hdr__ = (
        ("v", "B", 1),
        ("len", "3s", 0),
        ("flags", "B", 0),
        ("cmd", "3s", 0),
        ("app_id", "I", 0),
        ("hop_id", "I", 0),
        ("end_id", "I", 0),
    )

    @property
    def request_flag(self):
        return (self.flags >> 7) & 0x1

    @request_flag.setter
    def request_flag(self, r):
        self.flags = (self.flags & ~0x80) | ((r & 0x1) << 7)

    @property
    def proxiable_flag(self):
        return (self.flags >> 6) & 0x1

    @proxiable_flag.setter
    def proxiable_flag(self, p):
        self.flags = (self.flags & ~0x40) | ((p & 0x1) << 6)

    @property
    def error_flag(self):
        return (self.flags >> 5) & 0x1

    @error_flag.setter
    def error_flag(self, e):
        self.flags = (self.flags & ~0x20) | ((e & 0x1) << 5)

    @property
    def retransmit_flag(self):
        return (self.flags >> 4) & 0x1

    @retransmit_flag.setter
    def retransmit_flag(self, t):
        self.flags = (self.flags & ~0x10) | ((t & 0x1) << 4)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.cmd = (self.cmd[0] << 16) | (self.cmd[1] << 8) | (self.cmd[2])
        self.len = (self.len[0] << 16) | (self.len[1] << 8) | (self.len[2])
        self.data = self.data[: self.len - self.__hdr_len__]

        # The AVP boundaries are walked in Rust. Each AVP gets only its own
        # bytes, unless a length below its header makes it read to the end.
        l_ = []
        spans, fails_at = _native._diameter_avp_spans(bytes(self.data))
        for start, stop in spans:
            l_.append(AVP(self.data[start:] if stop is None else self.data[start:stop]))
        if fails_at is not None:
            AVP(self.data[fails_at:])
        self.data = self.avps = l_

    def pack_hdr(self):
        self.len = struct.pack(
            "BBB", (self.len >> 16) & 0xFF, (self.len >> 8) & 0xFF, self.len & 0xFF
        )
        self.cmd = struct.pack(
            "BBB", (self.cmd >> 16) & 0xFF, (self.cmd >> 8) & 0xFF, self.cmd & 0xFF
        )
        return Packet.pack_hdr(self)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __bytes__(self):
        return self.pack_hdr() + b"".join(map(bytes, self.data))


class AVP(Packet):
    __hdr__ = (
        ("code", "I", 0),
        ("flags", "B", 0),
        ("len", "3s", 0),
    )

    @property
    def vendor_flag(self):
        return (self.flags >> 7) & 0x1

    @vendor_flag.setter
    def vendor_flag(self, v):
        self.flags = (self.flags & ~0x80) | ((v & 0x1) << 7)

    @property
    def mandatory_flag(self):
        return (self.flags >> 6) & 0x1

    @mandatory_flag.setter
    def mandatory_flag(self, m):
        self.flags = (self.flags & ~0x40) | ((m & 0x1) << 6)

    @property
    def protected_flag(self):
        return (self.flags >> 5) & 0x1

    @protected_flag.setter
    def protected_flag(self, p):
        self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.len = (self.len[0] << 16) | (self.len[1] << 8) | (self.len[2])

        if self.vendor_flag:
            self.vendor = struct.unpack(">I", self.data[:4])[0]
            self.data = self.data[4 : self.len - self.__hdr_len__]
        else:
            self.data = self.data[: self.len - self.__hdr_len__]

    def pack_hdr(self):
        self.len = struct.pack(
            "BBB", (self.len >> 16) & 0xFF, (self.len >> 8) & 0xFF, self.len & 0xFF
        )
        data = Packet.pack_hdr(self)
        if self.vendor_flag:
            data += struct.pack(">I", self.vendor)
        return data

    def __len__(self):
        length = self.__hdr_len__ + len(self.data)
        if self.vendor_flag:
            length += 4
        return length
