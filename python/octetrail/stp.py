"""Spanning Tree Protocol, as dpkt 1.9.8 reads it.

STP has only a fixed header, which the :class:`octetrail.Packet` base reads.
"""

from .packet import Packet


class STP(Packet):
    """Spanning Tree Protocol BPDU.

    ``age``, ``max_age``, ``hello`` and ``fd`` are the timer fields in whole
    seconds, the high byte of each 16-bit field.
    """

    __hdr__ = (
        ("proto_id", "H", 0),
        ("v", "B", 0),
        ("type", "B", 0),
        ("flags", "B", 0),
        ("root_id", "8s", b""),
        ("root_path", "I", 0),
        ("bridge_id", "8s", b""),
        ("port_id", "H", 0),
        ("_age", "H", 0),
        ("_max_age", "H", 0),
        ("_hello", "H", 0),
        ("_fd", "H", 0),
    )

    @property
    def age(self):
        return self._age >> 8

    @age.setter
    def age(self, age):
        self._age = age << 8

    @property
    def max_age(self):
        return self._max_age >> 8

    @max_age.setter
    def max_age(self, max_age):
        self._max_age = max_age << 8

    @property
    def hello(self):
        return self._hello >> 8

    @hello.setter
    def hello(self, hello):
        self._hello = hello << 8

    @property
    def fd(self):
        return self._fd >> 8

    @fd.setter
    def fd(self, fd):
        self._fd = fd << 8
