"""Stream Control Transmission Protocol, as dpkt 1.9.8 reads it.

The chunk list is read in Rust. Each parsed chunk copies its data out of the
packet on first use, because a chunk length below four makes chunks overlap
and their data reach to the end of the packet.
"""

import struct
from functools import partial

from . import _native, crc32c
from .errors import NeedData
from .packet import Packet

# Chunk Types
DATA = 0
INIT = 1
INIT_ACK = 2
SACK = 3
HEARTBEAT = 4
HEARTBEAT_ACK = 5
ABORT = 6
SHUTDOWN = 7
SHUTDOWN_ACK = 8
ERROR = 9
COOKIE_ECHO = 10
COOKIE_ACK = 11
ECNE = 12
CWR = 13
SHUTDOWN_COMPLETE = 14


class SCTP(Packet):
    """Stream Control Transmission Protocol packet.

    Attributes:
        sport: Source port.
        dport: Destination port.
        vtag: Verification tag.
        sum: CRC-32C checksum, computed when packing if it is 0.
        chunks: The :class:`Chunk` list, set when parsing.
    """

    __hdr__ = (
        ("sport", "H", 0),
        ("dport", "H", 0),
        ("vtag", "I", 0),
        ("sum", "I", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = buf if type(buf) is bytes else bytes(buf)
        try:
            rows, stopped = _native._sctp_chunks(raw, self.__hdr_len__)
        except _native.SctpShortChunkError as error:
            raise NeedData("got %d, %d needed at least" % (error.args[0], 4)) from None
        self.chunks = [_chunk(buf, row) for row in rows]
        self.data = b"" if stopped else buf[len(buf) :]

    def __len__(self):
        return self.__hdr_len__ + sum(len(x) for x in self.chunks)

    def __bytes__(self):
        l_ = [bytes(x) for x in self.chunks]
        if self.sum == 0:
            s = crc32c.add(0xFFFFFFFF, self.pack_hdr())
            for x in l_:
                s = crc32c.add(s, x)
            self.sum = crc32c.done(s)
        return self.pack_hdr() + b"".join(l_)


class Chunk(Packet):
    """SCTP chunk.

    Attributes:
        type: Chunk type.
        flags: Chunk flags.
        len: Chunk length, header included, padding excluded.
        padding: Padding after a DATA chunk, up to a multiple of four.
    """

    __hdr__ = (
        ("type", "B", INIT),
        ("flags", "B", 0),
        ("len", "H", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)

        self.data = self.data[: self.len - self.__hdr_len__]
        self.padding = b""  # optional padding for DATA chunks

        # SCTP DATA Chunked is padded, 4-bytes aligned
        if self.type == DATA and self.len % 4:
            plen = 4 - self.len % 4  # padded length
            if plen:
                pos = self.__hdr_len__ + len(self.data)  # end of data in buf
                self.padding = buf[pos : pos + plen]

    def __getattr__(self, name):
        lazy = self.__dict__.get("_lazy")
        if lazy is None or name != "data":
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))
        self._materialize()
        return self.data

    def _materialize(self):
        lazy = self.__dict__.pop("_lazy", None)
        if lazy is None:
            return
        try:
            object.__getattribute__(self, "data")
        except AttributeError:
            buf, start, end = lazy
            self.data = buf[start:end]

    def __repr__(self):
        self._materialize()
        return Packet.__repr__(self)

    def pprint(self, indent=1):
        self._materialize()
        return Packet.pprint(self, indent)

    def __len__(self):
        return self.len + len(self.padding)

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.data) + self.padding


def _chunk(buf, row):
    kind, flags, length, ds, de, ps, pe = row
    chunk = Chunk.__new__(Chunk)
    chunk.type, chunk.flags, chunk.len = kind, flags, length
    chunk._lazy = (buf, ds, de)
    chunk.padding = buf[ps:pe] if kind == DATA and length % 4 else b""
    chunk._pack_hdr = partial(struct.pack, Chunk.__hdr_fmt__)
    return chunk
