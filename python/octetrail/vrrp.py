"""Virtual Router Redundancy Protocol, parsed and packed the way dpkt 1.9.8 does.

The address list is split in Rust.
"""

from . import _native
from .packet import Packet, in_cksum


class VRRP(Packet):
    """Virtual Router Redundancy Protocol advertisement.

    ``addrs`` holds ``count`` four-byte addresses and ``auth`` the bytes after
    them. ``data`` is empty after parsing.
    """

    __hdr__ = (
        ("_v_type", "B", 0x21),
        ("vrid", "B", 0),
        ("priority", "B", 0),
        ("count", "B", 0),
        ("atype", "B", 0),
        ("advtime", "B", 0),
        ("sum", "H", 0),
    )
    __bit_fields__ = {
        "_v_type": (
            ("v", 4),
            ("type", 4),
        )
    }
    addrs = ()
    auth = b""

    def unpack(self, buf):
        Packet.unpack(self, buf)
        data = self.data
        raw = data if type(data) is bytes else bytes(data)
        addrs, (start, end) = _native._vrrp_layout(self.count, raw)
        self.addrs = [data[a:b] for a, b in addrs]
        self.auth = data[start:end]
        self.data = b""

    def __len__(self):
        return self.__hdr_len__ + (4 * self.count) + len(self.auth)

    def __bytes__(self):
        data = b"".join(self.addrs) + self.auth
        if not self.sum:
            self.sum = in_cksum(self.pack_hdr() + data)
        return self.pack_hdr() + data
