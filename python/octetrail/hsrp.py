"""Hot Standby Router Protocol, as dpkt 1.9.8 reads it.

HSRP has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet

HELLO = 0
COUP = 1
RESIGN = 2

INITIAL = 0x00
LEARN = 0x01
LISTEN = 0x02
SPEAK = 0x04
STANDBY = 0x08
ACTIVE = 0x10


class HSRP(Packet):
    """Hot Standby Router Protocol message.

    Attributes:
        version: Version.
        opcode: Operation code (hello 0, coup 1, resign 2).
        state: State of the sending router.
        hello: Hello time in seconds.
        hold: Hold time in seconds.
        priority: Priority.
        group: Standby group.
        rsvd: Reserved.
        auth: Clear text authentication data (8 bytes).
        vip: Virtual IP address (4 bytes).
    """

    __hdr__ = (
        ("version", "B", 0),
        ("opcode", "B", 0),
        ("state", "B", 0),
        ("hello", "B", 0),
        ("hold", "B", 0),
        ("priority", "B", 0),
        ("group", "B", 0),
        ("rsvd", "B", 0),
        ("auth", "8s", b"cisco"),
        ("vip", "4s", b""),
    )
