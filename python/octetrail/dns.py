"""Offline DNS messages, parsed and packed the way dpkt 1.9.8 does."""

import operator

from . import _native
from .errors import NeedData, PackError, UnpackError

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
LimitError = _native.PacketLimitError


class ParseLimitError(UnpackError, LimitError):
    """A DNS parse budget refusal, catchable by both existing exception families."""


_NAMES = {
    DNS_NS: ("nsname",),
    DNS_CNAME: ("cname",),
    DNS_PTR: ("ptrname",),
    DNS_MX: ("mxname",),
    DNS_SOA: ("mname", "rname"),
    DNS_SRV: ("srvname",),
}
_NUMBERS = {
    DNS_MX: (("preference", 16),),
    DNS_SOA: tuple((n, 32) for n in ("serial", "refresh", "retry", "expire", "minimum")),
    DNS_SRV: tuple((n, 16) for n in ("priority", "weight", "port")),
}
_FORMS = {DNS_NS: "name", DNS_CNAME: "name", DNS_PTR: "name", DNS_SOA: "soa", DNS_MX: "mx"}
_FORMS.update({DNS_SRV: "srv", DNS_TXT: "text", DNS_HINFO: "text"})


def _uint(value, width):
    try:
        value = operator.index(value)
    except TypeError:
        raise PackError("DNS field requires an integer") from None
    if not 0 <= value < 1 << width:
        raise PackError("DNS field out of range")
    return value


def _name(value):
    if not isinstance(value, str):
        raise PackError("DNS names require text")
    return value


def _bytes(value, what):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PackError(what + " requires bytes")
    return bytes(value)


def pack_name(name, off, label_ptrs):
    """Encode `name` for offset `off`, compressing against and adding to `label_ptrs`."""
    if not isinstance(label_ptrs, dict):
        raise TypeError("label_ptrs must be a dict")
    try:
        return _native._dns_pack_name(_name(name), operator.index(off), label_ptrs)
    except _native.DnsPackError as error:
        raise PackError(str(error)) from None


def unpack_name(buf, off):
    """Decode the possibly compressed name at `off`; return it and the offset after it."""
    try:
        return _native._dns_unpack_name(bytes(buf), operator.index(off))
    except _native.PacketLimitError as error:
        raise ParseLimitError(str(error)) from None
    except _native.TruncatedError as error:
        raise NeedData(str(error)) from None
    except _native.DnsFormatError as error:
        raise UnpackError(str(error)) from None


class Q:
    """DNS question."""

    def __init__(self, **kwargs):
        self.name = ""
        self.type = DNS_A
        self.cls = DNS_IN
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __len__(self):
        raise NotImplementedError

    __str__ = __len__

    def unpack(self, buf):
        raise NotImplementedError

    def _wire(self):
        return _name(self.name), _uint(self.type, 16), _uint(self.cls, 16)


class RR(Q):
    """DNS resource record."""

    def __init__(self, **kwargs):
        self.ttl = 0
        self.rlen = 4
        self.rdata = b""
        super().__init__(**kwargs)

    def _wire(self):
        """Resource data as dpkt's pack_rdata chooses it: nonempty rdata wins."""
        name, kind, cls = super()._wire()
        ttl = _uint(self.ttl, 32)
        names, numbers, text = [], [], []
        if self.rdata:
            form, raw = "raw", _bytes(self.rdata, "DNS rdata")
        elif kind == DNS_A:
            form, raw = "raw", _bytes(self.ip, "DNS address")
        elif kind == DNS_AAAA:
            form, raw = "raw", _bytes(self.ip6, "DNS address")
        elif kind == DNS_OPT:
            form, raw = "raw", b""
        elif kind in _FORMS:
            form, raw = _FORMS[kind], b""
            names = [_name(getattr(self, n)) for n in _NAMES.get(kind, ())]
            for field, width in _NUMBERS.get(kind, ()):
                value = getattr(self, field)
                if field == "preference" and isinstance(value, tuple) and len(value) == 1:
                    value = value[0]  # a parsed MX preference is a one-item tuple, as in dpkt
                numbers.append(_uint(value, width))
            if form == "text":
                for chunk in self.text:
                    chunk = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
                    text.append(_bytes(chunk, "DNS text"))
        else:
            raise PackError("RR type %s is not supported" % kind)
        return name, kind, cls, ttl, form, raw, names, numbers, text


def _flag(mask):
    def get(self):
        return int(bool(self.op & mask))

    def set_(self, value):
        self.op = (self.op | mask) if value else (self.op & ~mask)

    return property(get, set_)


class DNS:
    """Domain Name System message, parsed and packed as dpkt 1.9.8 does."""

    Q, RR = Q, RR
    qr, aa, tc, rd, ra, zero, ad, cd = (
        _flag(x) for x in (DNS_QR, DNS_AA, DNS_TC, DNS_RD, DNS_RA, DNS_Z, DNS_AD, DNS_CD)
    )

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("DNS accepts at most one buffer")
        self.data = b""
        if args:
            self.unpack(args[0])
            return
        self.id, self.op = 0, DNS_RD
        self.qd, self.an, self.ns, self.ar = [], [], [], []
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def opcode(self):
        return (self.op >> 11) & 15

    @opcode.setter
    def opcode(self, value):
        self.op = (self.op & ~0x7800) | ((operator.index(value) & 15) << 11)

    @property
    def rcode(self):
        return self.op & 15

    @rcode.setter
    def rcode(self, value):
        self.op = (self.op & ~15) | (operator.index(value) & 15)

    def unpack(self, buf):
        """Decode a message. Bytes after the declared sections are dropped, as in dpkt."""
        if not isinstance(buf, (bytes, bytearray, memoryview)):
            raise TypeError("DNS unpack requires bytes")
        try:
            id_, op, questions, sections = _native._dns_unpack(bytes(buf))
        except _native.PacketLimitError as error:
            raise ParseLimitError(str(error)) from None
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        except _native.DnsFormatError as error:
            raise UnpackError(str(error)) from None
        self.id, self.op = id_, op
        self.qd = [Q(name=name, type=kind, cls=cls) for name, kind, cls in questions]
        self.an, self.ns, self.ar = ([_record(*row) for row in rows] for rows in sections)
        self.data = b""

    def _sections(self):
        sections = [self.qd, self.an, self.ns, self.ar]
        if any(not isinstance(s, list) for s in sections):
            raise TypeError("DNS sections require lists")
        if any(not isinstance(q, Q) for q in self.qd) or any(
            not isinstance(r, RR) for s in sections[1:] for r in s
        ):
            raise TypeError("DNS section member type mismatch")
        return sections

    def pack_hdr(self):
        sections = self._sections()
        try:
            return _native._dns_header(
                _uint(self.id, 16), _uint(self.op, 16), tuple(map(len, sections))
            )
        except _native.DnsPackError as error:
            raise PackError(str(error)) from None

    def __bytes__(self):
        """Pack the header and sections. Like dpkt, `data` is not packed."""
        sections = self._sections()
        questions = [q._wire() for q in self.qd]
        records = [[r._wire() for r in rows] for rows in sections[1:]]
        try:
            return _native._dns_pack(_uint(self.id, 16), _uint(self.op, 16), questions, records)
        except _native.DnsPackError as error:
            raise PackError(str(error)) from None

    def __len__(self):
        return len(bytes(self))


def _record(name, kind, cls, ttl, rlen, rdata, names, numbers, text):
    """A parsed RR with the decoded fields dpkt's unpack_rdata sets for its type."""
    rr = RR(name=name, type=kind, cls=cls, ttl=ttl, rlen=rlen, rdata=rdata)
    for key, value in zip(_NAMES.get(kind, ()), names, strict=True):
        setattr(rr, key, value)
    for (key, _), value in zip(_NUMBERS.get(kind, ()), numbers, strict=True):
        setattr(rr, key, value)
    if kind == DNS_MX:
        rr.preference = (rr.preference,)
    if kind in (DNS_TXT, DNS_HINFO):
        rr.text = text
    if kind == DNS_A:
        rr.ip = rdata
    if kind == DNS_AAAA:
        rr.ip6 = rdata
    if kind == DNS_NULL:
        rr.null = rdata.hex().encode("ascii")
    return rr
