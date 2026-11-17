"""Yahoo Messenger, as dpkt 1.9.8 reads it."""

from .packet import Packet


class YHOO(Packet):
    """Yahoo Messenger header, little-endian. As in dpkt, the text fields
    default to strings and must be replaced with bytes before packing."""

    __hdr__ = [
        ("version", "8s", " " * 8),
        ("length", "I", 0),
        ("service", "I", 0),
        ("connid", "I", 0),
        ("magic", "I", 0),
        ("unknown", "I", 0),
        ("type", "I", 0),
        ("nick1", "36s", " " * 36),
        ("nick2", "36s", " " * 36),
    ]
    __byte_order__ = "<"


class YMSG(Packet):
    """YMSG header. As in dpkt, ``version`` defaults to a string and must be
    replaced with bytes before packing."""

    __hdr__ = [
        ("version", "8s", " " * 8),
        ("length", "H", 0),
        ("type", "H", 0),
        ("unknown1", "I", 0),
        ("unknown2", "I", 0),
    ]
