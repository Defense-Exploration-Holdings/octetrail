"""CRC-32C checksum for SCTP, as dpkt 1.9.8 computes it.

The table and the byte loop are native. Other inputs that dpkt accepts, such
as a list of byte values or a running value wider than 32 bits, take the same
loop in Python.
"""

import array

from . import _native

crc32c_table = tuple(_native._crc32c_table())


def add(crc, buf):
    """Add buf to the running CRC crc."""
    if type(buf) is bytes and type(crc) is int and 0 <= crc <= 0xFFFFFFFF:
        return _native._crc32c_add(crc, buf)
    for b in array.array("B", buf):
        crc = (crc >> 8) ^ crc32c_table[(crc ^ b) & 0xFF]
    return crc


def done(crc):
    """Finish a running CRC: invert it and swap its bytes."""
    if type(crc) is int and 0 <= crc <= 0xFFFFFFFF:
        return _native._crc32c_done(crc)
    tmp = ~crc & 0xFFFFFFFF
    return int.from_bytes(tmp.to_bytes(4, "little"), "big")


def cksum(buf):
    """Return computed CRC-32c checksum."""
    return done(add(0xFFFFFFFF, buf))
