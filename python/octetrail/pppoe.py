"""PPP over Ethernet, as dpkt 1.9.8 reads it.

PPPoE has only a fixed header, which the :class:`octetrail.Packet` base reads.
A session frame (code 0) carries a :class:`PPP` frame without the address and
control bytes.
"""

import struct

from . import ppp
from .errors import NeedData, NestingError, PackError, UnpackError
from .packet import Packet

# RFC 2516 codes
PPPoE_PADI = 0x09
PPPoE_PADO = 0x07
PPPoE_PADR = 0x19
PPPoE_PADS = 0x65
PPPoE_PADT = 0xA7
PPPoE_SESSION = 0x00


class PPPoE(Packet):
    """PPP over Ethernet header.

    Attributes:
        v: Version (4 bits).
        type: Type (4 bits).
        code: Code, 0 for a session frame.
        session: Session ID.
        len: Payload length.
    """

    __hdr__ = (
        ("_v_type", "B", 0x11),
        ("code", "B", 0),
        ("session", "H", 0),
        ("len", "H", 0),  # payload length
    )
    __bit_fields__ = {
        "_v_type": (
            ("v", 4),
            ("type", 4),
        )
    }

    def unpack(self, buf):
        Packet.unpack(self, buf)
        try:
            if self.code == 0:
                # PPPoE carries PPP without the usual address and control bytes.
                self.data = self.ppp = PPP(self.data)
        except NestingError:
            raise
        except RecursionError as error:
            raise NestingError(*error.args) from None
        except UnpackError:
            pass


class PPP(ppp.PPP):
    """PPP inside PPPoE: only the protocol field, one or two bytes long."""

    __hdr__ = (
        # Usually two bytes, but protocol compression is supported.
        ("p", "B", ppp.PPP_IP),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.p & ppp.PFC_BIT == 0:
            try:
                self.p = struct.unpack(">H", buf[:2])[0]
            except struct.error:
                raise NeedData from None
            self.data = self.data[1:]
        try:
            self.data = self._protosw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except NestingError:
            raise
        except RecursionError as error:
            raise NestingError(*error.args) from None
        except (KeyError, struct.error, UnpackError):
            pass

    def pack_hdr(self):
        try:
            # Protocol compression is not recommended (RFC 2516), but is done.
            if self.p > 0xFF:
                return struct.pack(">H", self.p)
            return Packet.pack_hdr(self)
        except struct.error as e:
            raise PackError(str(e)) from None
