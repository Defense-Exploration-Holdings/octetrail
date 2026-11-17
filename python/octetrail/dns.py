"""Domain Name System messages, parsed and packed the way dpkt 1.9.8 does.

As in dpkt, ``DNS`` walks the message with ``unpack_q``, ``unpack_rr`` and
``RR.unpack_rdata`` and packs it with ``pack_q``, ``pack_rr`` and
``RR.pack_rdata``, so a subclass can replace any step. Names are read and
written in Rust.
"""

import codecs
import contextvars
import operator
import struct

from . import _native
from .errors import NeedData, PackError, UnpackError
from .packet import Packet

DNS_Q, DNS_R = 0, 1
DNS_QUERY, DNS_IQUERY, DNS_STATUS, DNS_NOTIFY, DNS_UPDATE = 0, 1, 2, 4, 5
DNS_CD, DNS_AD, DNS_Z, DNS_RA, DNS_RD, DNS_TC, DNS_AA, DNS_QR = (
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x8000,
)
DNS_RCODE_NOERR, DNS_RCODE_FORMERR, DNS_RCODE_SERVFAIL, DNS_RCODE_NXDOMAIN = 0, 1, 2, 3
DNS_RCODE_NOTIMP, DNS_RCODE_REFUSED, DNS_RCODE_YXDOMAIN, DNS_RCODE_YXRRSET = 4, 5, 6, 7
DNS_RCODE_NXRRSET, DNS_RCODE_NOTAUTH, DNS_RCODE_NOTZONE = 8, 9, 10
DNS_A, DNS_NS, DNS_CNAME, DNS_SOA, DNS_NULL, DNS_PTR, DNS_HINFO = 1, 2, 5, 6, 10, 12, 13
DNS_MX, DNS_TXT, DNS_AAAA, DNS_SRV, DNS_OPT = 15, 16, 28, 33, 41
DNS_IN, DNS_CHAOS, DNS_HESIOD, DNS_ANY = 1, 3, 4, 255
MAX_WORK_STEPS = 1 << 24
MAX_WORK_BYTES = 64 * 1024 * 1024
LimitError = _native.PacketLimitError


class ParseLimitError(UnpackError, LimitError):
    """A DNS parse budget refusal, catchable by both existing exception families."""


class TextDecodeError(UnpackError, UnicodeDecodeError):
    """A name or character string is not UTF-8.

    dpkt raises UnicodeDecodeError here. This class is also an UnpackError, so
    code that catches either one handles it.
    """


# While DNS.unpack runs: the buffer it was given, that buffer as bytes and the
# work budget left, so that names are read without copying the message again.
_PARSE = contextvars.ContextVar("octetrail_dns_parse", default=None)


def _decode(raw):
    try:
        return codecs.decode(raw, "utf-8")
    except UnicodeDecodeError as error:
        raise TextDecodeError(*error.args) from None


def pack_name(name, off, label_ptrs):
    """Encode ``name`` for offset ``off``, compressing against ``label_ptrs``.

    The suffixes written below offset 0xc000 are added to ``label_ptrs``.
    """
    name = codecs.encode(name, "utf-8")
    try:
        return _native._dns_pack_name(name, operator.index(off), label_ptrs)
    except _native.DnsLabelError as error:
        struct.pack("B", error.args[0])
        raise
    except _native.DnsPointerError as error:
        struct.pack(">H", error.args[0])
        raise


def unpack_name(buf, off):
    """Decode the possibly compressed name at ``off``; return it and the offset after it."""
    parse = _PARSE.get()
    if parse is not None and parse[0] is buf:
        raw, budget = parse[1], parse[2]
    else:
        raw = buf if type(buf) is bytes else bytes(buf)
        budget = [MAX_WORK_STEPS, MAX_WORK_BYTES]
    try:
        name, off, budget[0], budget[1] = _native._dns_unpack_name(
            raw, operator.index(off), budget[0], budget[1]
        )
    except _native.PacketLimitError as error:
        raise ParseLimitError(str(error)) from None
    except _native.TruncatedError:
        raise NeedData() from None
    except _native.DnsFormatError as error:
        raise UnpackError(str(error)) from None
    return _decode(name), off


class DNS(Packet):
    """Domain Name System message.

    Attributes:
        id: Identification.
        op: The flags and codes, also read through ``qr``, ``opcode``, ``aa``,
            ``tc``, ``rd``, ``ra``, ``zero``, ``ad``, ``cd`` and ``rcode``.
        qd, an, ns, ar: The question, answer, authority and additional
            sections. The header counts are taken from their lengths.
    """

    __hdr__ = (
        ("id", "H", 0),
        ("op", "H", DNS_RD),
        ("qd", "H", []),
        ("an", "H", []),
        ("ns", "H", []),
        ("ar", "H", []),
    )

    @property
    def qr(self):
        """Query (0) or response (1)."""
        return int((self.op & DNS_QR) == DNS_QR)

    @qr.setter
    def qr(self, v):
        if v:
            self.op |= DNS_QR
        else:
            self.op &= ~DNS_QR

    @property
    def opcode(self):
        """Operation code, four bits."""
        return (self.op >> 11) & 0xF

    @opcode.setter
    def opcode(self, v):
        self.op = (self.op & ~0x7800) | ((v & 0xF) << 11)

    @property
    def aa(self):
        """Authoritative answer."""
        return int((self.op & DNS_AA) == DNS_AA)

    @aa.setter
    def aa(self, v):
        if v:
            self.op |= DNS_AA
        else:
            self.op &= ~DNS_AA

    @property
    def tc(self):
        """Truncated."""
        return int((self.op & DNS_TC) == DNS_TC)

    @tc.setter
    def tc(self, v):
        if v:
            self.op |= DNS_TC
        else:
            self.op &= ~DNS_TC

    @property
    def rd(self):
        """Recursion desired."""
        return int((self.op & DNS_RD) == DNS_RD)

    @rd.setter
    def rd(self, v):
        if v:
            self.op |= DNS_RD
        else:
            self.op &= ~DNS_RD

    @property
    def ra(self):
        """Recursion available."""
        return int((self.op & DNS_RA) == DNS_RA)

    @ra.setter
    def ra(self, v):
        if v:
            self.op |= DNS_RA
        else:
            self.op &= ~DNS_RA

    @property
    def zero(self):
        """The reserved bit."""
        return int((self.op & DNS_Z) == DNS_Z)

    @zero.setter
    def zero(self, v):
        if v:
            self.op |= DNS_Z
        else:
            self.op &= ~DNS_Z

    @property
    def ad(self):
        """Authenticated data. dpkt has no accessor for this bit."""
        return int((self.op & DNS_AD) == DNS_AD)

    @ad.setter
    def ad(self, v):
        if v:
            self.op |= DNS_AD
        else:
            self.op &= ~DNS_AD

    @property
    def cd(self):
        """Checking disabled. dpkt has no accessor for this bit."""
        return int((self.op & DNS_CD) == DNS_CD)

    @cd.setter
    def cd(self, v):
        if v:
            self.op |= DNS_CD
        else:
            self.op &= ~DNS_CD

    @property
    def rcode(self):
        """Response code, four bits."""
        return self.op & 0xF

    @rcode.setter
    def rcode(self, v):
        self.op = (self.op & ~0xF) | (v & 0xF)

    class Q(Packet):
        """DNS question. As in dpkt, it is packed and parsed only by DNS."""

        __hdr__ = (
            ("name", "1025s", b""),
            ("type", "H", DNS_A),
            ("cls", "H", DNS_IN),
        )

        def __len__(self):
            raise NotImplementedError

        __str__ = __len__

        def unpack(self, buf):
            raise NotImplementedError

    class RR(Q):
        """DNS resource record."""

        __hdr__ = (
            ("name", "1025s", b""),
            ("type", "H", DNS_A),
            ("cls", "H", DNS_IN),
            ("ttl", "I", 0),
            ("rlen", "H", 4),
            ("rdata", "s", b""),
        )

        def pack_rdata(self, off, label_ptrs):
            """Return the resource data, written at ``off`` in the message.

            A nonempty ``rdata`` is returned as it is. Otherwise the fields of
            the record type are packed.
            """
            if self.rdata:
                return self.rdata
            if self.type == DNS_A:
                return self.ip
            elif self.type == DNS_NS:
                return pack_name(self.nsname, off, label_ptrs)
            elif self.type == DNS_CNAME:
                return pack_name(self.cname, off, label_ptrs)
            elif self.type == DNS_PTR:
                return pack_name(self.ptrname, off, label_ptrs)
            elif self.type == DNS_SOA:
                l_ = []
                l_.append(pack_name(self.mname, off, label_ptrs))
                l_.append(pack_name(self.rname, off + len(l_[0]), label_ptrs))
                l_.append(
                    struct.pack(
                        ">IIIII", self.serial, self.refresh, self.retry, self.expire, self.minimum
                    )
                )
                return b"".join(l_)
            elif self.type == DNS_MX:
                return struct.pack(">H", self.preference) + pack_name(
                    self.mxname, off + 2, label_ptrs
                )
            elif self.type == DNS_TXT or self.type == DNS_HINFO:
                return b"".join(struct.pack("B", len(x)) + x for x in self.text)
            elif self.type == DNS_AAAA:
                return self.ip6
            elif self.type == DNS_SRV:
                return struct.pack(">HHH", self.priority, self.weight, self.port) + pack_name(
                    self.srvname, off + 6, label_ptrs
                )
            elif self.type == DNS_OPT:
                return b""
            else:
                raise PackError("RR type %s is not supported" % self.type)

        def unpack_rdata(self, buf, off):
            """Set the fields of the record type from the message ``buf``.

            ``off`` is where the resource data starts.
            """
            if self.type == DNS_A:
                self.ip = self.rdata
            elif self.type == DNS_NS:
                self.nsname, off = unpack_name(buf, off)
            elif self.type == DNS_CNAME:
                self.cname, off = unpack_name(buf, off)
            elif self.type == DNS_PTR:
                self.ptrname, off = unpack_name(buf, off)
            elif self.type == DNS_SOA:
                self.mname, off = unpack_name(buf, off)
                self.rname, off = unpack_name(buf, off)
                self.serial, self.refresh, self.retry, self.expire, self.minimum = struct.unpack(
                    ">IIIII", buf[off : off + 20]
                )
            elif self.type == DNS_MX:
                self.preference = struct.unpack(">H", self.rdata[:2])
                self.mxname, off = unpack_name(buf, off + 2)
            elif self.type == DNS_TXT or self.type == DNS_HINFO:
                rdata = self.rdata
                raw = rdata if type(rdata) is bytes else bytes(rdata)
                self.text = [_decode(rdata[s:e]) for s, e in _native._dns_text(raw)]
            elif self.type == DNS_AAAA:
                self.ip6 = self.rdata
            elif self.type == DNS_NULL:
                self.null = codecs.encode(self.rdata, "hex")
            elif self.type == DNS_SRV:
                self.priority, self.weight, self.port = struct.unpack(">HHH", self.rdata[:6])
                self.srvname, off = unpack_name(buf, off + 6)
            elif self.type == DNS_OPT:
                pass  # RFC 6891: OPT is a pseudo-RR that carries no DNS data.
            else:
                raise UnpackError("RR type %s is not supported" % self.type)

    def pack_q(self, buf, q):
        """Append a packed question to ``buf`` and return it."""
        return (
            buf + pack_name(q.name, len(buf), self.label_ptrs) + struct.pack(">HH", q.type, q.cls)
        )

    def unpack_q(self, buf, off):
        """Return the question at ``off`` and the offset after it."""
        q = self.Q()
        q.name, off = unpack_name(buf, off)
        q.type, q.cls = struct.unpack(">HH", buf[off : off + 4])
        off += 4
        return q, off

    def pack_rr(self, buf, rr):
        """Append a packed resource record to ``buf`` and return it."""
        name = pack_name(rr.name, len(buf), self.label_ptrs)
        rdata = rr.pack_rdata(len(buf) + len(name) + 10, self.label_ptrs)
        return buf + name + struct.pack(">HHIH", rr.type, rr.cls, rr.ttl, len(rdata)) + rdata

    def unpack_rr(self, buf, off):
        """Return the resource record at ``off`` and the offset after it."""
        rr = self.RR()
        rr.name, off = unpack_name(buf, off)
        rr.type, rr.cls, rr.ttl, rdlen = struct.unpack(">HHIH", buf[off : off + 10])
        off += 10
        rr.rdata = buf[off : off + rdlen]
        rr.rlen = rdlen
        rr.unpack_rdata(buf, off)
        off += rdlen
        return rr, off

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = buf if type(buf) is bytes else bytes(buf)
        token = _PARSE.set((buf, raw, [MAX_WORK_STEPS, MAX_WORK_BYTES]))
        try:
            off = self.__hdr_len__
            cnt = self.qd
            self.qd = []
            for _ in range(cnt):
                q, off = self.unpack_q(buf, off)
                self.qd.append(q)
            for x in ("an", "ns", "ar"):
                cnt = getattr(self, x, 0)
                setattr(self, x, [])
                for _ in range(cnt):
                    rr, off = self.unpack_rr(buf, off)
                    getattr(self, x).append(rr)
        finally:
            _PARSE.reset(token)
        self.data = b""

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        # As in dpkt, the names are compressed against those written before them.
        self.label_ptrs = {}
        buf = struct.pack(
            self.__hdr_fmt__,
            self.id,
            self.op,
            len(self.qd),
            len(self.an),
            len(self.ns),
            len(self.ar),
        )
        for q in self.qd:
            buf = self.pack_q(buf, q)
        for x in ("an", "ns", "ar"):
            for rr in getattr(self, x):
                buf = self.pack_rr(buf, rr)
        del self.label_ptrs
        return buf


Q = DNS.Q
RR = DNS.RR
