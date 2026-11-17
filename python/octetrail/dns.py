"""Explicit offline DNS messages, bounded names and a measured record subset."""

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
DNS_RCODE_NOTIMP, DNS_RCODE_REFUSED = 4, 5
DNS_A, DNS_NS, DNS_CNAME, DNS_SOA, DNS_NULL, DNS_PTR, DNS_HINFO = 1, 2, 5, 6, 10, 12, 13
DNS_MX, DNS_TXT, DNS_AAAA, DNS_SRV, DNS_OPT = 15, 16, 28, 33, 41
DNS_IN, DNS_CHAOS, DNS_HESIOD, DNS_ANY = 1, 3, 4, 255
MAX_MESSAGE_BYTES, MAX_RECORDS = 65535, 1024
MAX_WORK_STEPS = MAX_RECORDS * (3 * (255 + 128) + 1) + MAX_MESSAGE_BYTES
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
    if len(value) > 253:
        raise PackError("DNS name exceeds wire limit")
    encoded = value.encode("utf-8")
    if len(encoded) > 253 or (value and any(not x or len(x) > 63 for x in encoded.split(b"."))):
        raise PackError("unsupported DNS name layout")
    return value


def _required(record, name):
    try:
        return getattr(record, name)
    except AttributeError:
        raise PackError("missing DNS record field: " + name) from None


class Q:
    def __init__(self, **kwargs):
        if kwargs.keys() - {"name", "type", "cls"}:
            raise TypeError("unsupported DNS question fields")
        self.name = kwargs.get("name", "")
        self.type = kwargs.get("type", DNS_A)
        self.cls = kwargs.get("cls", DNS_IN)

    def __len__(self):
        raise NotImplementedError("question size depends on message compression")

    def unpack(self, raw):
        raise NotImplementedError("decode questions through DNS")

    def _wire(self):
        return _name(self.name), _uint(self.type, 16), _uint(self.cls, 16)


class RR(Q):
    def __init__(self, **kwargs):
        names = {x for fields in _NAMES.values() for x in fields}
        numbers = {x for fields in _NUMBERS.values() for x, _ in fields}
        if kwargs.keys() - (
            {"name", "type", "cls", "ttl", "rlen", "rdata", "ip", "ip6", "text", "null"}
            | names
            | numbers
        ):
            raise TypeError("unsupported DNS record fields")
        super().__init__(**{k: v for k, v in kwargs.items() if k in ("name", "type", "cls")})
        self.ttl = kwargs.get("ttl", 0)
        self.rlen = kwargs.get("rlen", 4)
        self.rdata = kwargs.get("rdata", b"")
        self._parsed_rdata = None
        for key, value in kwargs.items():
            setattr(self, key, value)

    def _wire(self):
        name, kind, cls = super()._wire()
        ttl = _uint(self.ttl, 32)
        if not isinstance(self.rdata, bytes):
            raise PackError("DNS rdata requires bytes")
        names = [_name(_required(self, n)) for n in _NAMES.get(kind, ())]
        numbers = [_uint(_required(self, n), width) for n, width in _NUMBERS.get(kind, ())]
        text = []
        raw = self.rdata
        if kind in _NAMES or kind in (DNS_TXT, DNS_HINFO):
            if raw and raw != self._parsed_rdata:
                raise PackError("use structured fields for name/text RDATA, not raw overrides")
            raw = b""
            if kind in (DNS_TXT, DNS_HINFO):
                chunks = _required(self, "text")
                if not isinstance(chunks, list):
                    raise TypeError("DNS text requires a list")
                if len(chunks) > MAX_WORK_STEPS:
                    raise LimitError("DNS text work limit exceeded")
                text_size = 0
                for chunk in chunks:
                    if isinstance(chunk, bytes):
                        if len(chunk) > 255:
                            raise PackError("DNS text chunk exceeds byte limit")
                        try:
                            chunk = chunk.decode("utf-8")
                        except UnicodeDecodeError:
                            raise PackError("DNS text requires UTF-8") from None
                    if (
                        not isinstance(chunk, str)
                        or len(chunk) > 255
                        or len(chunk.encode("utf-8")) > 255
                    ):
                        raise PackError("DNS text chunk exceeds byte limit")
                    text_size += len(chunk.encode("utf-8")) + 1
                    if text_size > MAX_MESSAGE_BYTES:
                        raise LimitError("DNS text record exceeds message limit")
                    text.append(chunk)
        elif kind in (DNS_A, DNS_AAAA) and not raw:
            raw = getattr(self, "ip" if kind == DNS_A else "ip6", b"")
            if not isinstance(raw, bytes):
                raise PackError("DNS address requires bytes")
        if len(raw) > MAX_MESSAGE_BYTES:
            raise LimitError("DNS RDATA exceeds message limit")
        return name, kind, cls, ttl, raw, names, numbers, text


def _flag(mask):
    def get(self):
        return int(bool(self.op & mask))

    def set_(self, value):
        self.op = (self.op | mask) if value else (self.op & ~mask)

    return property(get, set_)


class DNS:
    Q, RR = Q, RR
    qr, aa, tc, rd, ra, zero, ad, cd = (
        _flag(x) for x in (DNS_QR, DNS_AA, DNS_TC, DNS_RD, DNS_RA, DNS_Z, DNS_AD, DNS_CD)
    )

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("DNS accepts at most one buffer")
        if args:
            self.unpack(args[0])
            return
        if kwargs.keys() - {
            "id",
            "op",
            "qd",
            "an",
            "ns",
            "ar",
            "data",
            "qr",
            "opcode",
            "aa",
            "tc",
            "rd",
            "ra",
            "zero",
            "ad",
            "cd",
            "rcode",
        }:
            raise TypeError("unsupported DNS fields")
        self.id, self.op, self.data = 0, DNS_RD, b""
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

    def unpack(self, raw):
        if not isinstance(raw, bytes):
            raise TypeError("DNS unpack requires bytes")
        try:
            id_, flags, questions, sections, trailing = _native._dns_unpack(raw)
        except _native.PacketLimitError as error:
            raise ParseLimitError(str(error)) from None
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        except _native.DnsFormatError as error:
            raise UnpackError(str(error)) from None
        qd = [Q(name=name, type=kind, cls=cls) for name, kind, cls in questions]
        converted = []
        for section in sections:
            rows = []
            for name, kind, cls, ttl, data, names, numbers, text in section:
                data = bytes(data)
                rr = RR(name=name, type=kind, cls=cls, ttl=ttl, rlen=len(data), rdata=data)
                rr._parsed_rdata = data
                for key, value in zip(_NAMES.get(kind, ()), names, strict=True):
                    setattr(rr, key, value)
                for (key, _), value in zip(_NUMBERS.get(kind, ()), numbers, strict=True):
                    setattr(rr, key, value)
                if kind in (DNS_TXT, DNS_HINFO):
                    rr.text = text
                if kind == DNS_A:
                    rr.ip = data
                if kind == DNS_AAAA:
                    rr.ip6 = data
                if kind == DNS_NULL:
                    rr.null = data.hex().encode("ascii")
                rows.append(rr)
            converted.append(rows)
        self.id, self.op, self.qd = id_, flags, qd
        self.an, self.ns, self.ar = converted
        self.data = trailing

    def _sections(self):
        sections = [self.qd, self.an, self.ns, self.ar]
        if any(not isinstance(s, list) for s in sections):
            raise TypeError("DNS sections require lists")
        if sum(map(len, sections)) > MAX_RECORDS:
            raise LimitError("DNS record count exceeded")
        if any(not isinstance(q, Q) or isinstance(q, RR) for q in self.qd) or any(
            not isinstance(r, RR) for s in sections[1:] for r in s
        ):
            raise TypeError("DNS section member type mismatch")
        return sections

    def pack_hdr(self):
        sections = self._sections()
        return _native._dns_header(
            _uint(self.id, 16), _uint(self.op, 16), tuple(map(len, sections))
        )

    def __bytes__(self):
        self._sections()
        if not isinstance(self.data, bytes):
            raise PackError("DNS trailing data requires bytes")
        if len(self.data) > MAX_MESSAGE_BYTES:
            raise LimitError("DNS data exceeds message limit")
        questions = [q._wire() for q in self.qd]
        sections = []
        byte_budget = len(self.data)
        for rows in (self.an, self.ns, self.ar):
            converted = []
            for record in rows:
                row = record._wire()
                byte_budget += len(row[4]) + sum(len(t.encode("utf-8")) + 1 for t in row[7])
                if byte_budget > MAX_MESSAGE_BYTES:
                    raise LimitError("DNS RDATA total exceeds message limit")
                converted.append(row)
            sections.append(converted)
        try:
            return _native._dns_pack(
                _uint(self.id, 16), _uint(self.op, 16), questions, sections, self.data
            )
        except _native.TruncatedError as error:
            raise PackError(str(error)) from None
        except _native.DnsFormatError as error:
            raise PackError(str(error)) from None

    def __len__(self):
        return len(bytes(self))
