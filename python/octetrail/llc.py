"""IEEE 802.2 Logical Link Control, parsed and packed the way dpkt 1.9.8 does.

The header and its SNAP extension are read in Rust.
"""

import contextlib
import struct

from . import _native, stp
from .errors import UnpackError
from .packet import _LAYERS, Packet


class LLC(Packet):
    """802.2 LLC header, with a SNAP header when DSAP and SSAP are both 0xaa.

    A SNAP payload is decoded by the Ethernet class registered for its type.
    Without SNAP, DSAP 0x06 decodes IP, 0x10 and 0xe0 decode IPX, and 0x42
    decodes STP.
    """

    __hdr__ = (
        ("dsap", "B", 0xAA),
        ("ssap", "B", 0xAA),
        ("ctl", "B", 3),
    )

    @property
    def is_snap(self):
        return self.dsap == self.ssap == 0xAA

    def unpack(self, buf):
        from .ethernet import ETH_TYPE_IP, ETH_TYPE_IPX, Ethernet

        try:
            self.dsap, self.ssap, self.ctl, snap, start = _native._llc(
                buf if isinstance(buf, bytes) else bytes(memoryview(buf))
            )
        except _native.EthernetShortError:
            raise struct.error("unpack requires a buffer of 3 bytes") from None
        except _native.EthernetStructError:
            self.dsap, self.ssap, self.ctl = buf[:3]
            self.data = buf[3:]
            raise struct.error("unpack requires a buffer of 6 bytes") from None
        self.data = buf[start:]
        if snap is not None:
            self.oui, self.type = snap
            try:
                self.data = Ethernet.get_type(self.type)(self.data)
                setattr(self, self.data.__class__.__name__.lower(), self.data)
            except (KeyError, UnpackError):
                pass
        elif self.dsap == 0x06:
            self.data = self.ip = Ethernet.get_type(ETH_TYPE_IP)(self.data)
        elif self.dsap in (0x10, 0xE0):
            self.data = self.ipx = Ethernet.get_type(ETH_TYPE_IPX)(self.data)
        elif self.dsap == 0x42:
            self.data = self.stp = stp.STP(self.data)

    def pack_hdr(self):
        buf = Packet.pack_hdr(self)
        if self.is_snap:
            oui = getattr(self, "oui", 0)
            _type = getattr(self, "type", 0)
            if not _type and isinstance(self.data, _LAYERS):
                from .ethernet import Ethernet

                with contextlib.suppress(KeyError):
                    _type = Ethernet.get_type_rev(self.data.__class__)
            buf += struct.pack(">IH", oui, _type)[1:]
        return buf

    def __len__(self):
        return self.__hdr_len__ + 5 * int(self.is_snap) + len(self.data)
