"""Snoop capture files (RFC 1761), as dpkt 1.9.8 reads and writes them.

The file and record headers use the :class:`octetrail.Packet` base. The
constants, classes and reader and writer methods are dpkt's.
"""

import struct
import time

from .errors import UnpackError
from .packet import Packet

# RFC 1761

SNOOP_MAGIC = 0x736E6F6F70000000

SNOOP_VERSION = 2

SDL_8023 = 0
SDL_8024 = 1
SDL_8025 = 2
SDL_8026 = 3
SDL_ETHER = 4
SDL_HDLC = 5
SDL_CHSYNC = 6
SDL_IBMCC = 7
SDL_FDDI = 8
SDL_OTHER = 9

dltoff = {SDL_ETHER: 14}

# Record bodies are read in pieces of at most this size, so a hostile record
# length cannot make the reader allocate more than the file holds.
_READ_CHUNK = 1 << 20


class HeaderError(UnpackError, ValueError):
    """The file does not start with the snoop magic.

    dpkt raises ValueError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class LinktypeError(UnpackError, KeyError):
    """The file header names a link type with no known data link offset.

    dpkt raises KeyError here. This class is also an UnpackError, so code that
    catches either one handles it.
    """

    def __str__(self):
        return KeyError.__str__(self)


class PktHdr(Packet):
    """A snoop packet record header.

    Attributes:
        orig_len: Length of the packet as received.
        incl_len: Number of packet bytes kept in the record.
        rec_len: Length of the whole record, with this header and the padding.
        cum_drops: Packets dropped since the first record.
        ts_sec: Arrival time, seconds since 1970.
        ts_usec: Microseconds of the arrival time.
    """

    __byte_order__ = "!"
    __hdr__ = (
        ("orig_len", "I", 0),
        ("incl_len", "I", 0),
        ("rec_len", "I", 0),
        ("cum_drops", "I", 0),
        ("ts_sec", "I", 0),
        ("ts_usec", "I", 0),
    )


class FileHdr(Packet):
    """A snoop file header.

    Attributes:
        magic: The snoop magic number.
        v: Format version.
        linktype: Data link type, one of the ``SDL_*`` constants.
    """

    __byte_order__ = "!"
    __hdr__ = (
        ("magic", "Q", SNOOP_MAGIC),
        ("v", "I", SNOOP_VERSION),
        ("linktype", "I", SDL_ETHER),
    )


def _intround(num):
    return int(round(num))


def _read(fileobj, size):
    """Read like fileobj.read(size), in bounded pieces when size is large."""
    if size < _READ_CHUNK:
        return fileobj.read(size)
    pieces = []
    while size > 0:
        piece = fileobj.read(min(size, _READ_CHUNK))
        if not piece:
            break
        pieces.append(piece)
        size -= len(piece)
    return b"".join(pieces)


_PACK_PKTHDR = struct.Struct(PktHdr.__hdr_fmt__).pack


def _record(pkt, ts, multiplier):
    pkt_len = len(pkt)
    pad_len = (4 - pkt_len) & 3
    header = _PACK_PKTHDR(
        pkt_len,
        pkt_len,
        PktHdr.__hdr_len__ + pkt_len + pad_len,
        0,
        int(ts),
        _intround(ts % 1 * multiplier),
    )
    return header + pkt + b"\x00" * pad_len


class FileWriter:
    """Base for capture writers: holds the file and its write method."""

    def __init__(self, fileobj):
        self._f = fileobj
        self.write = self._f.write

    def close(self):
        self._f.close()

    def writepkt(self, pkt, ts=None):
        """Write one packet with a timestamp in seconds, by default now."""
        if ts is None:
            ts = time.time()
        self.writepkt_time(bytes(pkt), ts)

    def writepkt_time(self, pkt, ts):
        """Write one packet (bytes) with its timestamp in seconds."""


class Writer(FileWriter):
    """Write a snoop file with microsecond timestamps."""

    precision_multiplier = 1000000

    def __init__(self, fileobj, linktype=SDL_ETHER):
        super().__init__(fileobj)
        fh = FileHdr(linktype=linktype)
        self._PktHdr = PktHdr()
        self._pack_hdr = self._PktHdr._pack_hdr
        self.write(bytes(fh))

    def writepkt_time(self, pkt, ts):
        """Write one packet (bytes) with its timestamp in seconds."""
        self.write(_record(pkt, ts, self.precision_multiplier))

    def writepkts(self, pkts):
        """Write (ts, pkt) pairs. Each pkt must already be bytes."""
        write = self.write
        multiplier = self.precision_multiplier
        for ts, pkt in pkts:
            write(_record(pkt, ts, multiplier))


class FileReader:
    """Base for capture readers, with dpkt's pypcap-style methods."""

    def __init__(self, fileobj):
        self.name = getattr(fileobj, "name", "<%s>" % fileobj.__class__.__name__)
        self._f = fileobj
        self.filter = ""

    @property
    def fd(self):
        return self._f.fileno()

    def fileno(self):
        return self.fd

    def setfilter(self, value, optimize=1):
        raise NotImplementedError

    def readpkts(self):
        return list(self)

    def dispatch(self, cnt, callback, *args):
        """Call callback(ts, pkt, *args) on cnt packets, or all when cnt <= 0.

        Return the number of packets processed.
        """
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    ts, pkt = next(self)
                except StopIteration:
                    break
                callback(ts, pkt, *args)
                processed += 1
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        """Call callback(ts, pkt, *args) on every packet; return the count."""
        return self.dispatch(0, callback, *args)

    def __iter__(self):
        return self


class Reader(FileReader):
    """Read a snoop file as (timestamp, bytes) pairs, like dpkt's reader."""

    def __init__(self, fileobj):
        super().__init__(fileobj)
        buf = self._f.read(FileHdr.__hdr_len__)
        self._fh = FileHdr(buf)
        self._ph = PktHdr
        if self._fh.magic != SNOOP_MAGIC:
            raise HeaderError("invalid snoop header")
        try:
            self.dloff = dltoff[self._fh.linktype]
        except KeyError:
            raise LinktypeError(self._fh.linktype) from None

    def datalink(self):
        return self._fh.linktype

    def __next__(self):
        buf = self._f.read(self._ph.__hdr_len__)
        if not buf:
            raise StopIteration
        hdr = self._ph(buf)
        buf = _read(self._f, hdr.rec_len - self._ph.__hdr_len__)
        return (hdr.ts_sec + (hdr.ts_usec / 1000000.0), buf[: hdr.incl_len])

    next = __next__
