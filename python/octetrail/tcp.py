"""Transmission Control Protocol, parsed and packed the way dpkt 1.9.8 does.

The option bounds and option splitting are computed in Rust. The class follows
dpkt's ``dpkt.tcp`` and is built on :class:`octetrail.Packet`. ``sum`` is packed
as assigned. IPv4 and IPv6 fill a zero ``sum``.
"""

from . import _native
from .errors import UnpackError
from .packet import Packet

TH_FIN = 0x01  # end of data
TH_SYN = 0x02  # synchronize sequence numbers
TH_RST = 0x04  # reset connection
TH_PUSH = 0x08  # push
TH_ACK = 0x10  # acknowledgment number set
TH_URG = 0x20  # urgent pointer set
TH_ECE = 0x40  # ECN echo, RFC 3168
TH_CWR = 0x80  # congestion window reduced
TH_NS = 0x100  # nonce sum, RFC 3540

TCP_PORT_MAX = 65535  # maximum port
TCP_WIN_MAX = 65535  # maximum (unscaled) window

_FLAG_NAMES = (
    (TH_FIN, "FIN"),
    (TH_SYN, "SYN"),
    (TH_RST, "RST"),
    (TH_PUSH, "PUSH"),
    (TH_ACK, "ACK"),
    (TH_URG, "URG"),
    (TH_ECE, "ECE"),
    (TH_CWR, "CWR"),
    (TH_NS, "NS"),
)


def tcp_flags_to_str(val):
    """Comma-separated names of the flags set in val."""
    return ",".join(name for bit, name in _FLAG_NAMES if val & bit)


class TCP(Packet):
    """TCP segment. ``opts`` holds the option bytes; call ``parse_opts()`` on them."""

    __hdr__ = (
        ("sport", "H", 0xDEAD),
        ("dport", "H", 0),
        ("seq", "I", 0xDEADBEEF),
        ("ack", "I", 0),
        ("_off_flags", "H", ((5 << 12) | TH_SYN)),
        ("win", "H", TCP_WIN_MAX),
        ("sum", "H", 0),
        ("urp", "H", 0),
    )
    __bit_fields__ = {
        "_off_flags": (
            ("off", 4),
            ("_rsv", 3),
            ("flags", 9),
        )
    }
    __pprint_funcs__ = {
        "flags": tcp_flags_to_str,
        "sum": hex,
    }
    opts = b""

    def __len__(self):
        return self.__hdr_len__ + len(self.opts) + len(self.data)

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.opts) + bytes(self.data)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        try:
            end = _native._tcp_layout(buf if type(buf) is bytes else bytes(buf))
        except _native.TCPHeaderError:
            raise UnpackError("invalid header length") from None
        self.opts = buf[self.__hdr_len__ : end]
        self.data = buf[end:]


# Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2
TCP_OPT_WSCALE = 3
TCP_OPT_SACKOK = 4
TCP_OPT_SACK = 5
TCP_OPT_ECHO = 6
TCP_OPT_ECHOREPLY = 7
TCP_OPT_TIMESTAMP = 8
TCP_OPT_POCONN = 9
TCP_OPT_POSVC = 10
TCP_OPT_CC = 11
TCP_OPT_CCNEW = 12
TCP_OPT_CCECHO = 13
TCP_OPT_ALTSUM = 14
TCP_OPT_ALTSUMDATA = 15
TCP_OPT_SKEETER = 16
TCP_OPT_BUBBA = 17
TCP_OPT_TRAILSUM = 18
TCP_OPT_MD5 = 19
TCP_OPT_SCPS = 20
TCP_OPT_SNACK = 21
TCP_OPT_REC = 22
TCP_OPT_CORRUPT = 23
TCP_OPT_SNAP = 24
TCP_OPT_TCPCOMP = 26
TCP_OPT_MAX = 27


def parse_opts(buf):
    """Split option bytes into (kind, data) tuples, ending with None if malformed."""
    return _native._tcp_parse_opts(buf if type(buf) is bytes else bytes(buf))
