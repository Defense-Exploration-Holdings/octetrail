"""ATA over Ethernet ATA command, as dpkt 1.9.8 reads it."""

from .packet import Packet

ATA_DEVICE_IDENTIFY = 0xEC


class AOEATA(Packet):
    """ATA command: flags, error or feature, sector count, command or status,
    the six LBA bytes and a reserved field."""

    __hdr__ = (
        ("aflags", "B", 0),
        ("errfeat", "B", 0),
        ("scnt", "B", 0),
        ("cmdstat", "B", ATA_DEVICE_IDENTIFY),
        ("lba0", "B", 0),
        ("lba1", "B", 0),
        ("lba2", "B", 0),
        ("lba3", "B", 0),
        ("lba4", "B", 0),
        ("lba5", "B", 0),
        ("res", "H", 0),
    )
