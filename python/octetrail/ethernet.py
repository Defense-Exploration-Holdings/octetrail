"""Ethernet, parsed and packed the way dpkt 1.9.8 does.

Ethernet II, IEEE 802.3 with LLC, LLC/SNAP and Novell raw 802.3 frames are
read, with 802.1Q, MPLS and Cisco ISL decapsulation. The ISL walk, the tag and
label stacks, the 802.3 trailer split and the frame check sequence are computed
in Rust. The classes follow dpkt's ``dpkt.ethernet`` and are built on
:class:`octetrail.Packet`.
"""

import importlib
import struct

from . import _native, llc
from .errors import NeedData, PackError, UnpackError
from .packet import _LAYERS, Packet

ETH_CRC_LEN = 4
ETH_HDR_LEN = 14

ETH_LEN_MIN = 64  # minimum frame length with CRC
ETH_LEN_MAX = 1518  # maximum frame length with CRC

ETH_MTU = ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN
ETH_MIN = ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN

# Ethernet payload types
ETH_TYPE_UNKNOWN = 0x0000
ETH_TYPE_EDP = 0x00BB  # Extreme Networks Discovery Protocol
ETH_TYPE_PUP = 0x0200  # PUP protocol
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_ARP = 0x0806  # address resolution protocol
ETH_TYPE_AOE = 0x88A2  # AoE protocol
ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
ETH_TYPE_8021AD = 0x88A8  # IEEE 802.1ad
ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
ETH_TYPE_PPP = 0x880B  # PPP
ETH_TYPE_MPLS = 0x8847  # MPLS
ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging
ETH_TYPE_PROFINET = 0x8892  # PROFINET protocol

# all QinQ types for fast checking
_ETH_TYPES_QINQ = frozenset([ETH_TYPE_8021Q, ETH_TYPE_8021AD, ETH_TYPE_QINQ1, ETH_TYPE_QINQ2])


class MPLSIndexError(UnpackError, IndexError):
    """No byte follows an MPLS label stack. dpkt raises IndexError here."""


def mac_to_str(address):
    """Format a MAC address as colon-separated hex."""
    return ":".join("%02x" % b for b in address)


def _bytes(buf):
    if isinstance(buf, (bytes, bytearray, memoryview)):
        return bytes(buf)
    raise TypeError("a bytes-like object is required, not '%s'" % type(buf).__name__)


class Ethernet(Packet):
    """Ethernet.

    Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
    with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation.

    Attributes:
        dst: Destination MAC address.
        src: Source MAC address.
        type: Ethernet frame type, or the LLC length of an 802.3 frame.
    """

    __hdr__ = (("dst", "6s", b""), ("src", "6s", b""), ("type", "H", ETH_TYPE_IP))
    _typesw = {}
    _typesw_rev = {}  # reverse mapping

    __pprint_funcs__ = {
        "dst": mac_to_str,
        "src": mac_to_str,
    }

    def __init__(self, *args, **kwargs):
        self._next_type = None
        Packet.__init__(self, *args, **kwargs)
        # if data was given in kwargs, try to unpack it
        if self.data and isinstance(self.data, (str, bytes)):
            self._unpack_data(self.data)

    def _unpack_data(self, buf):
        # unpack vlan tag and mpls label stacks
        if self._next_type in _ETH_TYPES_QINQ or self._next_type in (
            ETH_TYPE_MPLS,
            ETH_TYPE_MPLS_MCAST,
        ):
            try:
                tags, labels, self._next_type, start = _native._ethernet_stack(
                    _bytes(buf), self._next_type
                )
            except _native.EthernetShortError as error:
                have, need = error.args
                raise NeedData("got %d, %d needed at least" % (have, need)) from None
            except _native.EthernetIndexError:
                raise MPLSIndexError("index out of range") from None
            if tags:
                self.vlan_tags = [VLANtag8021Q(buf[at : at + 4]) for at in tags]
                # backward compatibility, use the 1st tag
                self.vlanid, self.priority, self.cfi = self.vlan_tags[0].as_tuple()
            else:
                self.labels = []  # old list containing labels as tuples
                self.mpls_labels = [MPLSlabel(buf[at : at + 4]) for at in labels]
                self.labels.extend(lbl.as_tuple() for lbl in self.mpls_labels)
            buf = buf[start:]
        try:
            eth_type = self._next_type or self.type
            self.data = self._typesw[eth_type](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, UnpackError):
            self.data = buf

    def unpack(self, buf):
        try:
            isl, at, _, kind, body, padding, fcs, trailer = _native._ethernet_frame(_bytes(buf))
        except _native.EthernetShortError as error:
            have, need = error.args
            if need == ETH_HDR_LEN:
                raise struct.error("unpack requires a buffer of 14 bytes") from None
            raise NeedData("got %d, %d needed at least" % (have, need)) from None
        except _native.EthernetStructError:
            raise struct.error("unpack requires a buffer of 14 bytes") from None
        if isl is not None:
            # Cisco ISL: dpkt keeps the innermost tag only
            tag = VLANtagISL(buf[isl : isl + VLANtagISL.__hdr_len__])
            self.vlan_tags = [tag]
            self.vlan = tag.id  # backward compatibility
        Packet.unpack(self, buf[at:])
        if kind == "typed":
            # Ethernet II
            self._next_type = self.type
            self._unpack_data(self.data)
        elif kind == "novell":
            # Novell "raw" 802.3
            self.type = ETH_TYPE_IPX
            self.data = self.ipx = self._typesw[ETH_TYPE_IPX](self.data[2:])
        elif kind == "unknown":
            # Unknown type, assume Ethernet
            self._unpack_data(self.data)
        else:
            # IEEE 802.3 Ethernet - LLC, with Wireshark's tail heuristic
            self.len = self.type
            if padding is not None:
                self.padding = buf[padding[0] : padding[1]]
            if fcs is not None:
                self.fcs = fcs
            if trailer is not None:
                self.trailer = buf[trailer[0] : trailer[1]]
            self.data = self.llc = llc.LLC(buf[body[0] : body[1]])

    def pack_hdr(self):
        tags_buf = b""
        new_type = self.type  # replacement self.type when packing eth header
        is_isl = False  # ISL wraps Ethernet, this determines order of packing

        if getattr(self, "mpls_labels", None):
            # mark all labels with s=0, last one with s=1
            for lbl in self.mpls_labels:
                lbl.s = 0
            lbl.s = 1

            # set encapsulation type
            if new_type not in (ETH_TYPE_MPLS, ETH_TYPE_MPLS_MCAST):
                new_type = ETH_TYPE_MPLS
            tags_buf = b"".join(lbl.pack_hdr() for lbl in self.mpls_labels)

        elif getattr(self, "vlan_tags", None):
            # set last tag type to next layer pointed by self.data
            last_tag_type = self.type  # default
            if isinstance(self.data, _LAYERS):
                last_tag_type = self._typesw_rev.get(self.data.__class__, self.type)

            # set encapsulation types
            t1 = self.vlan_tags[0]
            if len(self.vlan_tags) == 1:
                if isinstance(t1, VLANtag8021Q):
                    if new_type not in _ETH_TYPES_QINQ:  # preserve the type if already set
                        new_type = ETH_TYPE_8021Q
                    t1.type = last_tag_type
                elif isinstance(t1, VLANtagISL):
                    t1.type = 0  # 0 means Ethernet
                    is_isl = True
            elif len(self.vlan_tags) == 2:
                t2 = self.vlan_tags[1]
                if isinstance(t1, VLANtag8021Q) and isinstance(t2, VLANtag8021Q):
                    t1.type = ETH_TYPE_8021Q
                    if new_type not in _ETH_TYPES_QINQ:
                        new_type = ETH_TYPE_8021AD
                t2.type = last_tag_type
            else:
                raise PackError("maximum is 2 VLAN tags per Ethernet frame")
            tags_buf = b"".join(tag.pack_hdr() for tag in self.vlan_tags)

        # initial type is based on next layer, pointed by self.data;
        # try to find an ETH_TYPE matching the data class
        elif isinstance(self.data, _LAYERS):
            new_type = self._typesw_rev.get(self.data.__class__, new_type)

        # if self.data is LLC then this is IEEE 802.3 Ethernet and self.type
        # then actually encodes the length of data
        if isinstance(self.data, llc.LLC):
            new_type = len(self.data)

        hdr_buf = Packet.pack_hdr(self)[:-2] + struct.pack(">H", new_type)
        if not is_isl:
            return hdr_buf + tags_buf
        return tags_buf + hdr_buf

    def __bytes__(self):
        tail = b""
        if isinstance(self.data, llc.LLC):
            fcs = b""
            if hasattr(self, "fcs"):
                if self.fcs:
                    fcs = self.fcs
                else:
                    # if fcs field is present but 0/None, then compute it and add to the tail
                    fcs_buf = self.pack_hdr() + bytes(self.data)
                    # if ISL header is present, exclude it from the calculation
                    if getattr(self, "vlan_tags", None) and isinstance(
                        self.vlan_tags[0], VLANtagISL
                    ):
                        fcs_buf = fcs_buf[VLANtagISL.__hdr_len__ :]
                    fcs_buf += getattr(self, "padding", b"")
                    revcrc = _native._crc32(fcs_buf)
                    fcs = struct.unpack("<I", struct.pack(">I", revcrc))[0]  # bswap32
                fcs = struct.pack(">I", fcs)
            tail = getattr(self, "padding", b"") + fcs + getattr(self, "trailer", b"")
        return bytes(Packet.__bytes__(self) + tail)

    def __len__(self):
        tags = getattr(self, "mpls_labels", []) + getattr(self, "vlan_tags", [])
        _len = Packet.__len__(self) + sum(t.__hdr_len__ for t in tags)
        if isinstance(self.data, llc.LLC):
            _len += len(getattr(self, "padding", b""))
            if hasattr(self, "fcs"):
                _len += 4
            _len += len(getattr(self, "trailer", b""))
        return _len

    @classmethod
    def set_type(cls, t, pktclass):
        cls._typesw[t] = pktclass
        cls._typesw_rev[pktclass] = t

    @classmethod
    def get_type(cls, t):
        return cls._typesw[t]

    @classmethod
    def get_type_rev(cls, k):
        return cls._typesw_rev[k]


class MPLSlabel(Packet):
    """A single entry in MPLS label stack"""

    __hdr__ = (("_val_exp_s_ttl", "I", 0),)
    # field names are according to RFC3032
    __bit_fields__ = {
        "_val_exp_s_ttl": (
            ("val", 20),  # label value, 20 bits
            ("exp", 3),  # experimental use, 3 bits
            ("s", 1),  # bottom of stack flag, 1 bit
            ("ttl", 8),  # time to live, 8 bits
        )
    }

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.data = b""

    def as_tuple(self):  # backward-compatible representation
        return (self.val, self.exp, self.ttl)


class VLANtag8021Q(Packet):
    """IEEE 802.1q VLAN tag"""

    __hdr__ = (("_pri_cfi_id", "H", 0), ("type", "H", ETH_TYPE_IP))
    __bit_fields__ = {
        "_pri_cfi_id": (
            ("pri", 3),  # priority, 3 bits
            ("cfi", 1),  # canonical format indicator, 1 bit
            ("id", 12),  # VLAN id, 12 bits
        )
    }

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.data = b""

    def as_tuple(self):
        return (self.id, self.pri, self.cfi)


class VLANtagISL(Packet):
    """Cisco Inter-Switch Link VLAN tag"""

    __hdr__ = (
        ("da", "5s", b"\x01\x00\x0c\x00\x00"),
        ("_type_pri", "B", 3),
        ("sa", "6s", b""),
        ("len", "H", 0),
        ("snap", "3s", b"\xaa\xaa\x03"),
        ("hsa", "3s", b"\x00\x00\x0c"),
        ("_id_bpdu", "H", 0),
        ("indx", "H", 0),
        ("res", "H", 0),
    )
    __bit_fields__ = {
        "_type_pri": (
            ("type", 4),  # encapsulation type, 4 bits; 0 means Ethernet
            ("pri", 4),  # user defined bits, 2 lo bits are used; means priority
        ),
        "_id_bpdu": (
            ("id", 15),  # vlan id, 15 bits
            ("bpdu", 1),  # bridge protocol data unit indicator
        ),
    }

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.data = b""


def _load_types():
    # Each ETH_TYPE_<NAME> maps to class <NAME> of module <name> when one exists.
    for k, v in list(globals().items()):
        if k.startswith("ETH_TYPE_"):
            name = k[9:]
            try:
                mod = importlib.import_module(__package__ + "." + name.lower())
                Ethernet.set_type(v, getattr(mod, name))
            except (ImportError, AttributeError):
                continue
    Ethernet.set_type(ETH_TYPE_TEB, Ethernet)


_load_types()
