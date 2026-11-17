"""Simple Traversal of UDP through NAT (RFC 3489), as dpkt 1.9.8 reads it.

Each message has a 20-byte header followed by attribute TLVs, which
:func:`parse_attrs` reads in Rust.
"""

import struct

from . import _native
from .errors import UnpackError
from .packet import Packet

# Message types
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
BINDING_ERROR_RESPONSE = 0x0111
SHARED_SECRET_REQUEST = 0x0002
SHARED_SECRET_RESPONSE = 0x0102
SHARED_SECRET_ERROR_RESPONSE = 0x0112

# Message attributes
MAPPED_ADDRESS = 0x0001
RESPONSE_ADDRESS = 0x0002
CHANGE_REQUEST = 0x0003
SOURCE_ADDRESS = 0x0004
CHANGED_ADDRESS = 0x0005
USERNAME = 0x0006
PASSWORD = 0x0007
MESSAGE_INTEGRITY = 0x0008
ERROR_CODE = 0x0009
UNKNOWN_ATTRIBUTES = 0x000A
REFLECTED_FROM = 0x000B


class ShortAttributeError(UnpackError, struct.error):
    """Fewer than four bytes are left for an attribute header.

    dpkt raises struct.error here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class STUN(Packet):
    """STUN message.

    Attributes:
        type: Message type.
        len: Message length.
        xid: Magic cookie and transaction ID, 16 bytes. As in dpkt, the
            default is 0 and must be replaced before packing.
    """

    __hdr__ = (
        ("type", "H", 0),
        ("len", "H", 0),
        ("xid", "16s", 0),
    )


def _short(buf):
    try:
        struct.unpack(">HH", buf[:4])
    except struct.error as error:
        raise ShortAttributeError(str(error)) from None


def tlv(buf):
    """Return ``(type, length, value, rest)`` for the first attribute."""
    n = 4
    if len(buf) < n:
        _short(buf)
    t, l_ = struct.unpack(">HH", buf[:n])
    v = buf[n : n + l_]
    pad = (n - l_ % n) % n
    buf = buf[n + l_ + pad :]
    return t, l_, v, buf


def parse_attrs(buf):
    """Parse STUN.data buffer into a list of (attribute, data) tuples."""
    raw = buf if type(buf) is bytes else bytes(buf)
    try:
        rows = _native._stun_attrs(raw)
    except _native.StunShortAttrError as error:
        _short(buf[error.args[0] :])
        raise
    return [(t, buf[start:end]) for t, _, start, end in rows]
