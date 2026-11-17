"""The Packet base class and checksum helpers of dpkt 1.9.8.

A subclass declares ``__hdr__`` as ``(name, struct format, default)`` rows and,
optionally, ``__bit_fields__`` to split a header field into properties.
"""

import copy
import struct
from functools import partial
from itertools import chain

from . import tcp, udp
from .errors import Error, NeedData, PackError, UnpackError

__all__ = [
    "Error",
    "NeedData",
    "PackError",
    "Packet",
    "UnpackError",
    "hexdump",
    "in_cksum",
    "in_cksum_add",
    "in_cksum_done",
]


def _bit_field(ph_name, bits_total, bits_used, bf_name, bf_size):
    shift = bits_total - bits_used - bf_size
    mask = (2**bf_size - 1) << shift
    mask_inv = (2**bits_total - 1) - mask
    max_val = 2**bf_size

    def getter(self):
        return (getattr(self, ph_name) & mask) >> shift

    def setter(self, value):
        if value >= max_val:
            raise ValueError("value %s is too large for field %s" % (value, bf_name))
        setattr(self, ph_name, (value << shift) | (getattr(self, ph_name) & mask_inv))

    return mask, shift, getter, setter


class _MetaPacket(type):
    def __new__(cls, clsname, clsbases, clsdict):
        t = type.__new__(cls, clsname, clsbases, clsdict)
        st = getattr(t, "__hdr__", None)
        if st is not None:
            clsdict["__slots__"] = [x[0] for x in st] + ["data"]
            t = type.__new__(cls, clsname, clsbases, clsdict)
            t.__hdr_fields__ = [x[0] for x in st]
            t.__hdr_fmt__ = getattr(t, "__byte_order__", ">") + "".join(x[1] for x in st)
            t.__hdr_len__ = struct.calcsize(t.__hdr_fmt__)
            t.__hdr_defaults__ = dict(zip(t.__hdr_fields__, [x[2] for x in st], strict=True))
        bit_fields = getattr(t, "__bit_fields__", None)
        if bit_fields:
            t.__bit_fields_defaults__ = {}
            for ph_name, ph_struct, _ in t.__hdr__:
                if ph_name not in bit_fields:
                    continue
                field_defs = bit_fields[ph_name]
                bits_total = sum(bf[1] for bf in field_defs)
                assert bits_total == struct.calcsize(ph_struct) * 8, (
                    "the overall count of bits in [%s] as declared in __bit_fields__ "
                    "does not match its struct size in __hdr__" % ph_name
                )
                bits_used = 0
                for bf_name, bf_size in field_defs:
                    if bf_name.startswith("_"):
                        bits_used += bf_size
                        continue
                    mask, shift, getter, setter = _bit_field(
                        ph_name, bits_total, bits_used, bf_name, bf_size
                    )
                    bits_used += bf_size
                    default = (t.__hdr_defaults__[ph_name] & mask) >> shift
                    t.__bit_fields_defaults__[bf_name] = default

                    def delete(self, bf_name=bf_name, default=default):
                        setattr(self, bf_name, default)

                    setattr(t, bf_name, property(getter, setter, delete))
        t.__public_fields__ = None
        return t


class Packet(metaclass=_MetaPacket):
    """Base packet class, with header fields from ``__hdr__`` and a ``data`` payload.

    A positional buffer is unpacked and keyword arguments are then ignored.
    Without a buffer the header defaults are copied and keyword arguments are
    set as attributes.
    """

    def __init__(self, *args, **kwargs):
        self.data = b""
        if args:
            try:
                self.unpack(args[0])
            except struct.error:
                if len(args[0]) < self.__hdr_len__:
                    raise NeedData(
                        "got %d, %d needed at least" % (len(args[0]), self.__hdr_len__)
                    ) from None
                raise UnpackError("invalid %s: %r" % (self.__class__.__name__, args[0])) from None
        else:
            if hasattr(self, "__hdr_fields__"):
                for k in self.__hdr_fields__:
                    setattr(self, k, copy.copy(self.__hdr_defaults__[k]))
            for k, v in kwargs.items():
                setattr(self, k, v)
        if hasattr(self, "__hdr_fmt__"):
            self._pack_hdr = partial(struct.pack, self.__hdr_fmt__)

    def __len__(self):
        return self.__hdr_len__ + len(self.data)

    def __iter__(self):
        return iter((fld, getattr(self, fld)) for fld in self.__class__.__hdr_fields__)

    def __getitem__(self, kls):
        dd = self.data
        while isinstance(dd, _LAYERS):
            if dd.__class__ == kls:
                return dd
            dd = dd.data
        raise KeyError(kls)

    def __contains__(self, kls):
        # dpkt returns bool() of the layer, which is always true for a layer
        # with a header. bool() would call len(), and the TCP and UDP objects
        # cannot take a length while their data is another layer object.
        try:
            self.__getitem__(kls)
        except KeyError:
            return False
        return True

    def _create_public_fields(self):
        names = []
        for field_name, _, _ in getattr(self, "__hdr__", []):
            if field_name[0] != "_":
                names.append(field_name)
            elif "_" in field_name[1:]:
                if field_name in getattr(self, "__bit_fields__", {}):
                    for prop_name, _ in self.__bit_fields__[field_name]:
                        if isinstance(getattr(self.__class__, prop_name, None), property):
                            names.append(prop_name)
                else:
                    fns = field_name[1:].split("_")
                    for prop_name in chain(
                        fns, ("_".join(x) for x in zip(fns, fns[1:], strict=False))
                    ):
                        if isinstance(getattr(self.__class__, prop_name, None), property):
                            names.append(prop_name)
        assert len(names) == len(set(names))
        self.__class__.__public_fields__ = names

    def __repr__(self):
        if self.__public_fields__ is None:
            self._create_public_fields()
        parts = []
        for field_name in self.__public_fields__:
            field_value = getattr(self, field_name)
            if (
                hasattr(self, "__hdr_defaults__")
                and field_name in self.__hdr_defaults__
                and field_value == self.__hdr_defaults__[field_name]
            ):
                continue
            if (
                hasattr(self, "__bit_fields_defaults__")
                and field_name in self.__bit_fields_defaults__
                and field_value == self.__bit_fields_defaults__[field_name]
            ):
                continue
            parts.append("%s=%r" % (field_name, field_value))
        parts.extend(
            "%s=%r" % (name, value)
            for name, value in self.__dict__.items()
            if name[0] != "_" and name != self.data.__class__.__name__.lower()
        )
        if self.data:
            parts.append("data=%r" % self.data)
        return "%s(%s)" % (self.__class__.__name__, ", ".join(parts))

    def pprint(self, indent=1):
        """Print the fields one per line, descending into packet payloads."""
        if self.__public_fields__ is None:
            self._create_public_fields()
        lines = []

        def add_field(fn, fv):
            try:
                lines.append("%s=%r,  # %s" % (fn, fv, self.__pprint_funcs__[fn](fv)))
            except (AttributeError, KeyError):
                lines.append("%s=%r," % (fn, fv))

        for field_name in self.__public_fields__:
            add_field(field_name, getattr(self, field_name))
        for name, value in self.__dict__.items():
            if name[0] != "_" and name != self.data.__class__.__name__.lower():
                if type(value) is list and value:
                    lines.append("%s=[" % name)
                    for item in value:
                        lines.append("  " + repr(item) + ",")
                    lines.append("],")
                else:
                    add_field(name, value)
        print("%s(" % self.__class__.__name__)
        for line in lines:
            print(" " * indent, "%s" % line)
        if self.data:
            if isinstance(self.data, Packet):
                print(" " * indent, "data=", end="")
                self.data.pprint(indent=indent + 2)
            else:
                print(" " * indent, "data=%r" % self.data)
        print(" " * (indent - 1), end="")
        print(")  # %s" % self.__class__.__name__)

    def __str__(self):
        return str(self.__bytes__())

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.data)

    def pack_hdr(self):
        """Return the packed header bytes."""
        try:
            return self._pack_hdr(*[getattr(self, k) for k in self.__hdr_fields__])
        except (TypeError, struct.error):
            vals = []
            for k in self.__hdr_fields__:
                v = getattr(self, k)
                if isinstance(v, tuple):
                    vals.extend(v)
                else:
                    vals.append(v)
            try:
                return struct.pack(self.__hdr_fmt__, *vals)
            except struct.error as e:
                raise PackError(str(e)) from None

    def pack(self):
        """Return the packed header and data."""
        return bytes(self)

    def unpack(self, buf):
        """Unpack the header fields from buf and set data to the rest."""
        for k, v in zip(
            self.__hdr_fields__,
            struct.unpack(self.__hdr_fmt__, buf[: self.__hdr_len__]),
            strict=False,
        ):
            setattr(self, k, v)
        self.data = buf[self.__hdr_len__ :]


_VIS_FILTER = bytes(c if 32 <= c < 127 and c != 92 else 46 for c in range(256))


def hexdump(buf, length=16):
    """Return a hexdump of buf, length bytes per line."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = " ".join("%02x" % x for x in line)
        text = line.translate(_VIS_FILTER).decode("utf-8")
        res.append("  %04d:  %-*s %s" % (n, length * 3, hexa, text))
        n += length
    return "\n".join(res)


def in_cksum_add(s, buf):
    """Add buf to the running checksum s, as little-endian 16-bit words."""
    n = len(buf)
    cnt = (n // 2) * 2
    res = s + sum(struct.unpack("<{}H".format(n // 2), buf[:cnt]))
    if cnt != n:
        res += buf[-1]
    return res


def _ntole(v):
    return struct.unpack("<H", struct.pack("!H", v))[0]


def in_cksum_done(s):
    """Fold the running checksum s and return it in network order."""
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return _ntole(~s & 0xFFFF)


def in_cksum(buf):
    """Return the Internet checksum of buf."""
    return in_cksum_done(in_cksum_add(0, buf))


# Layers that layer lookup walks through. TCP and UDP are not Packet
# subclasses yet, but dpkt finds them, so they are walked as well.
_LAYERS = (Packet, tcp.TCP, udp.UDP)
