"""ATA over Ethernet configuration command, as dpkt 1.9.8 reads it."""

from .packet import Packet


class AOECFG(Packet):
    """Configuration command: buffer count, firmware version, sector count,
    command and the length of the configuration string in ``data``."""

    __hdr__ = (
        ("bufcnt", "H", 0),
        ("fwver", "H", 0),
        ("scnt", "B", 0),
        ("aoeccmd", "B", 0),
        ("cslen", "H", 0),
    )
