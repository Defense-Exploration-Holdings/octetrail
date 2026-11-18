"""Authentication Header, as dpkt 1.9.8 reads it.

AH has a fixed header and an authentication field whose length the header
gives, which the :class:`octetrail.Packet` base reads.
"""

from . import ip
from .errors import NestingError, UnpackError
from .packet import Packet


class AH(Packet):
    """Authentication Header.

    Attributes:
        nxt: Next header protocol number.
        len: Payload length, in 32-bit words less two.
        rsvd: Reserved.
        spi: Security Parameters Index.
        seq: Sequence number.
        auth: Authentication data.
        data: The next header, decoded through the IP protocol table, or bytes.
    """

    __hdr__ = (
        ("nxt", "B", 0),
        ("len", "B", 0),  # payload length
        ("rsvd", "H", 0),
        ("spi", "I", 0),
        ("seq", "I", 0),
    )
    auth = b""

    def unpack(self, buf):
        Packet.unpack(self, buf)
        auth_len = max(4 * self.len - 4, 0)  # see RFC 4302, section 2.2
        self.auth = self.data[:auth_len]
        buf = self.data[auth_len:]

        try:
            self.data = ip.IP.get_proto(self.nxt)(buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except NestingError:
            raise
        except RecursionError as error:
            raise NestingError(*error.args) from None
        except (KeyError, UnpackError):
            self.data = buf

    def __len__(self):
        return self.__hdr_len__ + len(self.auth) + len(self.data)

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.auth) + bytes(self.data)
