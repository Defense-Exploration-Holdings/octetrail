"""Network Time Protocol, as dpkt 1.9.8 reads it.

NTP has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet

NO_WARNING = 0
LAST_MINUTE_61_SECONDS = 1
LAST_MINUTE_59_SECONDS = 2
ALARM_CONDITION = 3

RESERVED = 0
SYMMETRIC_ACTIVE = 1
SYMMETRIC_PASSIVE = 2
CLIENT = 3
SERVER = 4
BROADCAST = 5
CONTROL_MESSAGE = 6
PRIVATE = 7


class NTP(Packet):
    """Network Time Protocol message.

    As in dpkt, the byte-string fields default to 0, so a message built
    without them cannot be packed.

    Attributes:
        li: Leap indicator (2 bits of ``flags``).
        v: Version (3 bits of ``flags``).
        mode: Mode (3 bits of ``flags``).
        stratum: Stratum.
        interval: Poll interval.
        precision: Precision.
        delay: Root delay.
        dispersion: Root dispersion.
        id: Reference ID (4 bytes).
        update_time: Reference timestamp (8 bytes).
        originate_time: Origin timestamp (8 bytes).
        receive_time: Receive timestamp (8 bytes).
        transmit_time: Transmit timestamp (8 bytes).
    """

    __hdr__ = (
        ("flags", "B", 0),
        ("stratum", "B", 0),
        ("interval", "B", 0),
        ("precision", "B", 0),
        ("delay", "I", 0),
        ("dispersion", "I", 0),
        ("id", "4s", 0),
        ("update_time", "8s", 0),
        ("originate_time", "8s", 0),
        ("receive_time", "8s", 0),
        ("transmit_time", "8s", 0),
    )
    __bit_fields__ = {
        "flags": (
            ("li", 2),  # leap indicator, 2 hi bits
            ("v", 3),  # version, 3 bits
            ("mode", 3),  # mode, 3 lo bits
        )
    }
