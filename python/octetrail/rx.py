"""The Rx protocol of AFS, as dpkt 1.9.8 reads it."""

from .packet import Packet

DATA = 1
ACK = 2
BUSY = 3
ABORT = 4
ACKALL = 5
CHALLENGE = 6
RESPONSE = 7
DEBUG = 8
CLIENT_INITIATED = 1
REQUEST_ACK = 2
LAST_PACKET = 4
MORE_PACKETS = 8
SLOW_START_OK = 32
JUMBO_PACKET = 32
SEC_NONE = 0
SEC_BCRYPT = 1
SEC_RXKAD = 2
SEC_RXKAD_ENC = 3


class Rx(Packet):
    """Rx packet header."""

    __hdr__ = (
        ("epoch", "I", 0),
        ("cid", "I", 0),
        ("call", "I", 1),
        ("seq", "I", 0),
        ("serial", "I", 1),
        ("type", "B", 0),
        ("flags", "B", CLIENT_INITIATED),
        ("status", "B", 0),
        ("security", "B", 0),
        ("sum", "H", 0),
        ("service", "H", 0),
    )
