"""Server Message Block, as dpkt 1.9.8 reads it."""

from .packet import Packet

SMB_FLAGS_LOCK_AND_READ_OK = 1
SMB_FLAGS_BUF_AVAIL = 2
SMB_FLAGS_CASE_INSENSITIVE = 8
SMB_FLAGS_CANONICALIZED_PATHS = 16
SMB_FLAGS_OPLOCK = 32
SMB_FLAGS_OPBATCH = 64
SMB_FLAGS_REPLY = 128
SMB_FLAGS2_LONG_NAMES = 1
SMB_FLAGS2_EXTENDED_ATTRIBUTES = 2
SMB_FLAGS2_SECURITY_SIGNATURES = 4
SMB_FLAGS2_COMPRESSED = 8
SMB_FLAGS2_SECURITY_SIGNATURES_REQUIRED = 16
SMB_FLAGS2_IS_LONG_NAME = 64
SMB_FLAGS2_REVERSE_PATH = 1024
SMB_FLAGS2_EXTENDED_SECURITY = 2048
SMB_FLAGS2_DFS = 4096
SMB_FLAGS2_PAGING_IO = 8192
SMB_FLAGS2_NT_STATUS = 16384
SMB_FLAGS2_UNICODE = 32768
SMB_STATUS_SUCCESS = 0


class SMB(Packet):
    """SMB header, little-endian. ``pid`` joins ``_pidhi`` and ``_pidlo``."""

    __byte_order__ = "<"
    __hdr__ = [
        ("proto", "4s", b"\xffSMB"),
        ("cmd", "B", 0),
        ("status", "I", SMB_STATUS_SUCCESS),
        ("flags", "B", 0),
        ("flags2", "H", 0),
        ("_pidhi", "H", 0),
        ("security", "8s", b""),
        ("rsvd", "H", 0),
        ("tid", "H", 0),
        ("_pidlo", "H", 0),
        ("uid", "H", 0),
        ("mid", "H", 0),
    ]

    @property
    def pid(self):
        return self._pidhi << 16 | self._pidlo

    @pid.setter
    def pid(self, v):
        self._pidhi = v >> 16
        self._pidlo = v & 65535
