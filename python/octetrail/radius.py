"""Remote Authentication Dial-In User Service, as dpkt 1.9.8 reads it.

The attribute list is read in Rust and sliced from the caller's buffer.
"""

from . import _native
from .errors import UnpackError
from .packet import Packet


class ShortAttributeError(UnpackError, IndexError):
    """One byte is left where an attribute needs a type and a length.

    dpkt raises IndexError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


class RADIUS(Packet):
    """RADIUS message.

    Attributes:
        code: Code.
        id: Identifier.
        len: Length.
        auth: Authenticator, 16 bytes.
        attrs: The attributes, a list of ``(type, value)`` tuples. As in dpkt,
            ``data`` is empty after parsing.
    """

    __hdr__ = (
        ("code", "B", 0),
        ("id", "B", 0),
        ("len", "H", 4),
        ("auth", "16s", b""),
    )
    attrs = b""

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.attrs = parse_attrs(self.data)
        self.data = b""


def parse_attrs(buf):
    """Parse attributes buffer into a list of (type, data) tuples."""
    raw = buf if type(buf) is bytes else bytes(buf)
    try:
        rows = _native._radius_attrs(raw)
    except _native.RadiusShortAttrError as error:
        at = error.args[0]
        try:
            buf[at:][1]
        except IndexError as short:
            raise ShortAttributeError(str(short)) from None
        raise
    return [(t, buf[start:end]) for t, start, end in rows]


# Codes
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCT_REQUEST = 4
RADIUS_ACCT_RESPONSE = 5
RADIUS_ACCT_STATUS = 6
RADIUS_ACCESS_CHALLENGE = 11

# Attributes
RADIUS_USER_NAME = 1
RADIUS_USER_PASSWORD = 2
RADIUS_CHAP_PASSWORD = 3
RADIUS_NAS_IP_ADDR = 4
RADIUS_NAS_PORT = 5
RADIUS_SERVICE_TYPE = 6
RADIUS_FRAMED_PROTOCOL = 7
RADIUS_FRAMED_IP_ADDR = 8
RADIUS_FRAMED_IP_NETMASK = 9
RADIUS_FRAMED_ROUTING = 10
RADIUS_FILTER_ID = 11
RADIUS_FRAMED_MTU = 12
RADIUS_FRAMED_COMPRESSION = 13
RADIUS_LOGIN_IP_HOST = 14
RADIUS_LOGIN_SERVICE = 15
RADIUS_LOGIN_TCP_PORT = 16
# 17 is unassigned
RADIUS_REPLY_MESSAGE = 18
RADIUS_CALLBACK_NUMBER = 19
RADIUS_CALLBACK_ID = 20
# 21 is unassigned
RADIUS_FRAMED_ROUTE = 22
RADIUS_FRAMED_IPX_NETWORK = 23
RADIUS_STATE = 24
RADIUS_CLASS = 25
RADIUS_VENDOR_SPECIFIC = 26
RADIUS_SESSION_TIMEOUT = 27
RADIUS_IDLE_TIMEOUT = 28
RADIUS_TERMINATION_ACTION = 29
RADIUS_CALLED_STATION_ID = 30
RADIUS_CALLING_STATION_ID = 31
RADIUS_NAS_ID = 32
RADIUS_PROXY_STATE = 33
RADIUS_LOGIN_LAT_SERVICE = 34
RADIUS_LOGIN_LAT_NODE = 35
RADIUS_LOGIN_LAT_GROUP = 36
RADIUS_FRAMED_ATALK_LINK = 37
RADIUS_FRAMED_ATALK_NETWORK = 38
RADIUS_FRAMED_ATALK_ZONE = 39
# 40 to 59 are reserved for accounting
RADIUS_CHAP_CHALLENGE = 60
RADIUS_NAS_PORT_TYPE = 61
RADIUS_PORT_LIMIT = 62
RADIUS_LOGIN_LAT_PORT = 63
