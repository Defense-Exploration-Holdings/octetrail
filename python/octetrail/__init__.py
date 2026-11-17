"""A dpkt rewrite with native offline capture and bounded packet composition."""

from . import capture, ethernet, ip, pcap, pcapng
from . import dns as dns
from . import http as http
from . import icmp as icmp
from . import icmp6 as icmp6
from . import igmp as igmp
from . import ip6 as ip6
from . import ipip as ipip
from . import ipx as ipx
from . import llc as llc
from . import packet as packet
from . import raw as raw
from . import ssl as ssl
from . import stp as stp
from . import tcp as tcp
from . import udp as udp
from . import vrrp as vrrp
from .errors import Error, NeedData, PackError, UnpackError
from .packet import Packet as Packet
from .packet import hexdump as hexdump
from .packet import in_cksum as in_cksum
from .packet import in_cksum_add as in_cksum_add
from .packet import in_cksum_done as in_cksum_done

__version__ = "0.4.1"
__all__ = [
    "Error",
    "NeedData",
    "PackError",
    "UnpackError",
    "capture",
    "ethernet",
    "ip",
    "pcap",
    "pcapng",
]
__all__.append("tcp")
__all__.append("udp")
__all__.extend(("ip6", "raw"))
__all__.append("dns")

__all__.append("http")

__all__.append("ssl")

__all__.extend(("ipip", "ipx", "llc", "stp"))
__all__.extend(("icmp", "icmp6"))
__all__.extend(("igmp", "vrrp"))

__all__.extend(("Packet", "hexdump", "in_cksum", "in_cksum_add", "in_cksum_done", "packet"))

# As in dpkt, the protocol tables are filled once every module is loaded.
ip._mod_init()
