"""Abstract Syntax Notation One, as dpkt 1.9.8's sleazy BER decoder reads it.

The element walk runs in the native core and visits elements in dpkt's order,
including its habit of decoding a constructed element's contents up to the end
of the buffer. The constants, ``utctime`` and the shape of the result are
dpkt's.
"""

import struct
from calendar import timegm

from . import _native
from .errors import NestingError as NestingError
from .errors import UnpackError

# Type class
CLASSMASK = 0xC0
UNIVERSAL = 0x00
APPLICATION = 0x40
CONTEXT = 0x80
PRIVATE = 0xC0

# Constructed (vs. primitive)
CONSTRUCTED = 0x20

# Universal-class tags
TAGMASK = 0x1F
INTEGER = 2
BIT_STRING = 3  # arbitrary bit string
OCTET_STRING = 4  # arbitrary octet string
NULL = 5
OID = 6  # object identifier
SEQUENCE = 16  # ordered collection of types
SET = 17  # unordered collection of types
PRINT_STRING = 19  # printable string
T61_STRING = 20  # T.61 (8-bit) character string
IA5_STRING = 22  # ASCII
UTC_TIME = 23

MAX_ELEMENTS = 1 << 18
MAX_DEPTH = 512
LimitError = _native.PacketLimitError


class ShortIndexError(UnpackError, IndexError):
    """A length, INTEGER or UTCTime runs past the end of the buffer.

    dpkt raises IndexError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class ShortStructError(UnpackError, struct.error):
    """A multi-byte length or INTEGER is cut off by the end of the buffer.

    dpkt raises struct.error here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class TimeValueError(UnpackError, ValueError):
    """A UTCTime value is not made of the digits dpkt expects.

    dpkt raises ValueError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class TimeTypeError(UnpackError, TypeError):
    """A UTCTime value cannot be read as text, as with a memoryview buffer.

    dpkt raises TypeError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class ParseLimitError(UnpackError, LimitError):
    """A decode would produce more than ``MAX_ELEMENTS`` elements.

    dpkt decodes the rest of the buffer for every constructed element, so its
    result can grow exponentially with the input.
    """


def utctime(buf):
    """Convert an ASN.1 UTCTime string to seconds since the Epoch, as dpkt does.

    Args:
        buf: Text in the form "yymmddhhmm", optionally with seconds and an
            offset.

    Returns:
        The time in seconds since the Epoch.
    """
    yy = int(buf[:2])
    mn = int(buf[2:4])
    dd = int(buf[4:6])
    hh = int(buf[6:8])
    mm = int(buf[8:10])
    try:
        ss = int(buf[10:12])
        buf = buf[12:]
    except TypeError:
        ss = 0
        buf = buf[10:]

    if buf[0] == "+":
        hh -= int(buf[1:3])
        mm -= int(buf[3:5])
    elif buf[0] == "-":
        hh += int(buf[1:3])
        mm += int(buf[3:5])
    return timegm((2000 + yy, mn, dd, hh, mm, ss, 0, 0, 0))


def _time(buf):
    try:
        return utctime(buf)
    except IndexError as error:
        raise ShortIndexError(*error.args) from None
    except ValueError as error:
        raise TimeValueError(*error.args) from None
    except TypeError as error:
        raise TimeTypeError(*error.args) from None


def _stop(buf, kind, a, b):
    if kind == 0:
        try:
            buf[a]
        except IndexError as error:
            return ShortIndexError(*error.args)
    elif kind == 1:
        try:
            struct.unpack(">H" if b == 2 else ">I", buf[a : a + b])
        except struct.error as error:
            return ShortStructError(*error.args)
    elif kind == 2:
        return UnpackError("excessive long-form ASN.1 length %d" % a)
    elif kind == 3:
        return UnpackError("excessive integer length > %d bytes" % a)
    elif kind == 4:
        return ParseLimitError("ASN.1 decode would produce more than %d elements" % a)
    elif kind == 5:
        # The package's NestingError. dpkt recurses once per level and raises
        # RecursionError somewhere near the interpreter's recursion limit.
        return NestingError("ASN.1 constructed elements nest deeper than %d levels" % a)
    raise AssertionError("unexpected ASN.1 stop %r" % ((kind, a, b),))


def decode(buf):
    """Decode BER the way dpkt's sleazy decoder does.

    Args:
        buf: The encoded bytes.

    Returns:
        A list of (identifier, value) tuples. A constructed element's value is
        such a list, an INTEGER's is an int, a UTCTime's is seconds since the
        Epoch and any other value is a slice of ``buf``.

    Raises:
        UnpackError: The encoding is cut off, uses a length dpkt does not
            read, or is too large or deeply nested to decode.
    """
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        if not buf:
            return []
        buf[0] & CONSTRUCTED  # noqa: B018 - raises dpkt's TypeError for str.
        raise TypeError("asn1.decode needs a bytes-like object")
    events, stop = _native._asn1_decode(bytes(buf))
    msg = []
    stack = []
    for kind, t, a, b in events:
        if kind == 0:
            stack.append((t, msg))
            msg = []
        elif kind == 1:
            t, parent = stack.pop()
            parent.append((t, msg))
            msg = parent
        elif kind == 2:
            msg.append((t, a))
        elif kind == 3:
            msg.append((t, _time(buf[a:b])))
        else:
            msg.append((t, buf[a:b]))
    if stop is not None:
        raise _stop(buf, *stop)
    return msg
