"""Explicit offline raw IPv4/IPv6 selection; capture readers remain unchanged."""

from . import ip, ip6
from .errors import NeedData, UnpackError


def decode(data):
    """Decode one bytes packet selected by its IP version nibble."""
    if not isinstance(data, bytes):
        raise TypeError("raw IP decoding requires bytes")
    if not data:
        raise NeedData("raw IP requires a version byte")
    version = data[0] >> 4
    if version == 4:
        return ip.IP(data)
    if version == 6:
        return ip6.IP6(data)
    raise UnpackError("unsupported raw IP version")
