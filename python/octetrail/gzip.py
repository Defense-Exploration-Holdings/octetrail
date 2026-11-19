"""GNU zip headers (RFC 1952), as dpkt 1.9.8 reads them.

The header and its optional fields use the :class:`octetrail.Packet` base.
The constants, classes and the compress and decompress helpers are dpkt's.
"""

import struct
import zlib

from .errors import NeedData, UnpackError
from .packet import Packet

# RFC 1952
GZIP_MAGIC = b"\x1f\x8b"

# Compression methods
GZIP_MSTORED = 0
GZIP_MCOMPRESS = 1
GZIP_MPACKED = 2
GZIP_MLZHED = 3
GZIP_MDEFLATE = 8

# Flags
GZIP_FTEXT = 0x01
GZIP_FHCRC = 0x02
GZIP_FEXTRA = 0x04
GZIP_FNAME = 0x08
GZIP_FCOMMENT = 0x10
GZIP_FENCRYPT = 0x20
GZIP_FRESERVED = 0xC0

# OS
GZIP_OS_MSDOS = 0
GZIP_OS_AMIGA = 1
GZIP_OS_VMS = 2
GZIP_OS_UNIX = 3
GZIP_OS_VMCMS = 4
GZIP_OS_ATARI = 5
GZIP_OS_OS2 = 6
GZIP_OS_MACOS = 7
GZIP_OS_ZSYSTEM = 8
GZIP_OS_CPM = 9
GZIP_OS_TOPS20 = 10
GZIP_OS_WIN32 = 11
GZIP_OS_QDOS = 12
GZIP_OS_RISCOS = 13
GZIP_OS_UNKNOWN = 255

GZIP_FENCRYPT_LEN = 12


class FilenameDecodeError(UnpackError, UnicodeDecodeError):
    """A file name is not UTF-8.

    dpkt raises UnicodeDecodeError here. This class is also an UnpackError, so
    code that catches either one handles it.
    """


class GzipExtra(Packet):
    __byte_order__ = "<"
    __hdr__ = (("id", "2s", b""), ("len", "H", 0))


class Gzip(Packet):
    __byte_order__ = "<"
    __hdr__ = (
        ("magic", "2s", GZIP_MAGIC),
        ("method", "B", GZIP_MDEFLATE),
        ("flags", "B", 0),
        ("mtime", "I", 0),
        ("xflags", "B", 0),
        ("os", "B", GZIP_OS_UNIX),
    )

    def __init__(self, *args, **kwargs):
        self.extra = None
        self.filename = None
        self.comment = None
        super(Gzip, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        super(Gzip, self).unpack(buf)
        if self.magic != GZIP_MAGIC:
            raise UnpackError("not a gzip member: magic %r" % bytes(self.magic))
        if self.method != GZIP_MDEFLATE:
            raise UnpackError("unsupported gzip method %d" % self.method)
        if self.flags & GZIP_FEXTRA:
            if len(self.data) < 2:
                raise NeedData("Gzip extra")
            n = struct.unpack("<H", self.data[:2])[0]
            if len(self.data) < 2 + n:
                raise NeedData("Gzip extra")
            self.extra = GzipExtra(self.data[2 : 2 + n])
            self.data = self.data[2 + n :]
        if self.flags & GZIP_FNAME:
            n = self.data.find(b"\x00")
            if n == -1:
                raise NeedData("Gzip end of file name not found")
            try:
                self.filename = self.data[:n].decode("utf-8")
            except UnicodeDecodeError as error:
                raise FilenameDecodeError(*error.args) from None
            self.data = self.data[n + 1 :]
        if self.flags & GZIP_FCOMMENT:
            n = self.data.find(b"\x00")
            if n == -1:
                raise NeedData("Gzip end of comment not found")
            self.comment = self.data[:n]
            self.data = self.data[n + 1 :]
        if self.flags & GZIP_FENCRYPT:
            if len(self.data) < GZIP_FENCRYPT_LEN:
                raise NeedData("Gzip encrypt")
            self.data = self.data[GZIP_FENCRYPT_LEN:]  # XXX - skip
        if self.flags & GZIP_FHCRC:
            if len(self.data) < 2:
                raise NeedData("Gzip hcrc")
            self.data = self.data[2:]  # XXX - skip

    def pack_hdr(self):
        l_ = []
        if self.extra:
            self.flags |= GZIP_FEXTRA
            s = bytes(self.extra)
            l_.append(struct.pack("<H", len(s)))
            l_.append(s)
        if self.filename:
            self.flags |= GZIP_FNAME
            l_.append(self.filename.encode("utf-8"))
            l_.append(b"\x00")
        if self.comment:
            self.flags |= GZIP_FCOMMENT
            l_.append(self.comment)
            l_.append(b"\x00")
        l_.insert(0, super(Gzip, self).pack_hdr())
        return b"".join(l_)

    def compress(self):
        """Compress self.data."""
        c = zlib.compressobj(
            zlib.Z_BEST_COMPRESSION,
            zlib.DEFLATED,
            -zlib.MAX_WBITS,
            zlib.DEF_MEM_LEVEL,
            zlib.Z_DEFAULT_STRATEGY,
        )
        self.data = c.compress(self.data) + c.flush()

    def decompress(self):
        """Return decompressed payload."""
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        return d.decompress(self.data)
