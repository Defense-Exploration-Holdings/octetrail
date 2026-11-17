"""Trivial File Transfer Protocol, as dpkt 1.9.8 reads it.

TFTP has a two-byte opcode, which the :class:`octetrail.Packet` base reads, and
fields that depend on it.
"""

import struct

from .errors import UnpackError
from .packet import Packet

OP_RRQ = 1  # read request
OP_WRQ = 2  # write request
OP_DATA = 3  # data packet
OP_ACK = 4  # acknowledgment
OP_ERR = 5  # error code

EUNDEF = 0  # not defined
ENOTFOUND = 1  # file not found
EACCESS = 2  # access violation
ENOSPACE = 3  # disk full or allocation exceeded
EBADOP = 4  # illegal TFTP operation
EBADID = 5  # unknown transfer ID
EEXISTS = 6  # file already exists
ENOUSER = 7  # no such user


class RequestError(UnpackError, IndexError):
    """A read or write request without a NUL after the file name.

    dpkt raises IndexError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class TFTP(Packet):
    """Trivial File Transfer Protocol packet.

    Attributes:
        opcode: Operation code.
        filename: File name, for a read or write request.
        mode: Transfer mode, for a read or write request.
        block: Block number, for data and acknowledgments.
        errcode: Error code, for an error.
        errmsg: Error message, for an error.
    """

    __hdr__ = (("opcode", "H", 1),)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.opcode in (OP_RRQ, OP_WRQ):
            l_ = self.data.split(b"\x00")
            if len(l_) < 2:
                raise RequestError("list index out of range")
            self.filename = l_[0]
            self.mode = l_[1]
            self.data = b""
        elif self.opcode in (OP_DATA, OP_ACK):
            self.block = struct.unpack(">H", self.data[:2])[0]
            self.data = self.data[2:]
        elif self.opcode == OP_ERR:
            self.errcode = struct.unpack(">H", self.data[:2])[0]
            self.errmsg = self.data[2:].split(b"\x00")[0]
            self.data = b""

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        if self.opcode in (OP_RRQ, OP_WRQ):
            s = self.filename + b"\x00" + self.mode + b"\x00"
        elif self.opcode in (OP_DATA, OP_ACK):
            s = struct.pack(">H", self.block)
        elif self.opcode == OP_ERR:
            s = struct.pack(">H", self.errcode) + (b"%s\x00" % self.errmsg)
        else:
            s = b""
        return self.pack_hdr() + s + self.data
