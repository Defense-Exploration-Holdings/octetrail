"""Border Gateway Protocol 4, as dpkt 1.9.8 reads and writes it.

Every message, attribute and route class uses the :class:`octetrail.Packet`
base with dpkt's fields and behavior. dpkt slices the rest of a buffer after
each element of a list; here each element is given only the bytes it can use,
so long lists parse in linear time with the same result.
"""

import socket
import struct

from .errors import UnpackError
from .packet import Packet

# Border Gateway Protocol 4 - RFC 4271
# Communities Attribute - RFC 1997
# Capabilities - RFC 3392
# Route Refresh - RFC 2918
# Route Reflection - RFC 4456
# Confederations - RFC 3065
# Cease Subcodes - RFC 4486
# NOPEER Community - RFC 3765
# Multiprotocol Extensions - RFC 2858
# Advertisement of Multiple Paths in BGP - RFC 7911
# BGP Support for Four-Octet Autonomous System (AS) Number Space - RFC 6793

# Message Types
OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
ROUTE_REFRESH = 5

# Attribute Types
ORIGIN = 1
AS_PATH = 2
NEXT_HOP = 3
MULTI_EXIT_DISC = 4
LOCAL_PREF = 5
ATOMIC_AGGREGATE = 6
AGGREGATOR = 7
COMMUNITIES = 8
ORIGINATOR_ID = 9
CLUSTER_LIST = 10
MP_REACH_NLRI = 14
MP_UNREACH_NLRI = 15

# Origin Types
ORIGIN_IGP = 0
ORIGIN_EGP = 1
INCOMPLETE = 2

# AS Path Types
AS_SET = 1
AS_SEQUENCE = 2
AS_CONFED_SEQUENCE = 3
AS_CONFED_SET = 4

# Reserved Communities Types
NO_EXPORT = 0xFFFFFF01
NO_ADVERTISE = 0xFFFFFF02
NO_EXPORT_SUBCONFED = 0xFFFFFF03
NO_PEER = 0xFFFFFF04

# Common AFI types
AFI_IPV4 = 1
AFI_IPV6 = 2
AFI_L2VPN = 25

# Multiprotocol SAFI types
SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SAFI_UNICAST_MULTICAST = 3
SAFI_EVPN = 70

# OPEN Message Optional Parameters
AUTHENTICATION = 1
CAPABILITY = 2

# Capability Types
CAP_MULTIPROTOCOL = 1
CAP_ROUTE_REFRESH = 2

# NOTIFICATION Error Codes
MESSAGE_HEADER_ERROR = 1
OPEN_MESSAGE_ERROR = 2
UPDATE_MESSAGE_ERROR = 3
HOLD_TIMER_EXPIRED = 4
FSM_ERROR = 5
CEASE = 6

# Message Header Error Subcodes
CONNECTION_NOT_SYNCHRONIZED = 1
BAD_MESSAGE_LENGTH = 2
BAD_MESSAGE_TYPE = 3

# OPEN Message Error Subcodes
UNSUPPORTED_VERSION_NUMBER = 1
BAD_PEER_AS = 2
BAD_BGP_IDENTIFIER = 3
UNSUPPORTED_OPTIONAL_PARAMETER = 4
AUTHENTICATION_FAILURE = 5
UNACCEPTABLE_HOLD_TIME = 6
UNSUPPORTED_CAPABILITY = 7

# UPDATE Message Error Subcodes
MALFORMED_ATTRIBUTE_LIST = 1
UNRECOGNIZED_ATTRIBUTE = 2
MISSING_ATTRIBUTE = 3
ATTRIBUTE_FLAGS_ERROR = 4
ATTRIBUTE_LENGTH_ERROR = 5
INVALID_ORIGIN_ATTRIBUTE = 6
AS_ROUTING_LOOP = 7
INVALID_NEXT_HOP_ATTRIBUTE = 8
OPTIONAL_ATTRIBUTE_ERROR = 9
INVALID_NETWORK_FIELD = 10
MALFORMED_AS_PATH = 11

# Cease Error Subcodes
MAX_NUMBER_OF_PREFIXES_REACHED = 1
ADMINISTRATIVE_SHUTDOWN = 2
PEER_DECONFIGURED = 3
ADMINISTRATIVE_RESET = 4
CONNECTION_REJECTED = 5
OTHER_CONFIGURATION_CHANGE = 6
CONNECTION_COLLISION_RESOLUTION = 7
OUT_OF_RESOURCES = 8


class BGP(Packet):
    """Border Gateway Protocol.

    BGP is an inter-AS routing protocol.
    See more about the BGP on
    https://en.wikipedia.org/wiki/Border_Gateway_Protocol

    Attributes:
        __hdr__: Header fields of BGP.
            marker: (bytes): Marker. Included for compatibility, must be set to all ones. (16 bytes)
            len: (int): Length: Total length of the message in octets, including the header. (2 bytes)
            type: (int): Type: Type of BGP message. (1 byte)
    """

    __hdr__ = (("marker", "16s", "\xff" * 16), ("len", "H", 0), ("type", "B", OPEN))

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.data = self.data[: self.len - self.__hdr_len__]
        if self.type == OPEN:
            self.data = self.open = self.Open(self.data)
        elif self.type == UPDATE:
            self.data = self.update = self.Update(self.data)
        elif self.type == NOTIFICATION:
            self.data = self.notification = self.Notification(self.data)
        elif self.type == KEEPALIVE:
            self.data = self.keepalive = self.Keepalive(self.data)
        elif self.type == ROUTE_REFRESH:
            self.data = self.route_refresh = self.RouteRefresh(self.data)

    class Open(Packet):
        __hdr__ = (
            ("v", "B", 4),
            ("asn", "H", 0),
            ("holdtime", "H", 0),
            ("identifier", "I", 0),
            ("param_len", "B", 0),
        )
        __hdr_defaults__ = {"parameters": []}

        def unpack(self, buf):
            Packet.unpack(self, buf)
            buf, pos = self.data, 0
            l_ = []
            plen = self.param_len
            while plen > 0:
                # A parameter is at most 2 + 255 bytes, so it gets only those.
                param = self.Parameter(buf[pos : pos + 257])
                pos += len(param)
                plen -= len(param)
                l_.append(param)
            self.data = self.parameters = l_

        def __len__(self):
            return self.__hdr_len__ + sum(map(len, self.parameters))

        def __bytes__(self):
            params = b"".join(map(bytes, self.parameters))
            self.param_len = len(params)
            return self.pack_hdr() + params

        class Parameter(Packet):
            __hdr__ = (("type", "B", 0), ("len", "B", 0))

            def unpack(self, buf):
                Packet.unpack(self, buf)
                self.data = self.data[: self.len]

                if self.type == AUTHENTICATION:
                    self.data = self.authentication = self.Authentication(self.data)
                elif self.type == CAPABILITY:
                    self.data = self.capability = self.Capability(self.data)

            class Authentication(Packet):
                __hdr__ = (("code", "B", 0),)

            class Capability(Packet):
                __hdr__ = (("code", "B", 0), ("len", "B", 0))

                def unpack(self, buf):
                    Packet.unpack(self, buf)
                    self.data = self.data[: self.len]

    class Update(Packet):
        __hdr_defaults__ = {"withdrawn": [], "attributes": [], "announced": []}

        def unpack(self, buf):
            # dpkt slices the rest of the buffer after each element. Each
            # element here is given only the bytes it can use, which gives the
            # same result in linear time.
            self.data = buf

            # Withdrawn Routes
            wlen = struct.unpack(">H", buf[:2])[0]
            pos = 2
            l_ = []
            while wlen > 0:
                route = RouteIPV4(buf[pos : pos + _ROUTE_MAX])
                pos += len(route)
                wlen -= len(route)
                l_.append(route)
            self.withdrawn = l_
            self.data = rest = buf[pos:]

            # Path Attributes
            plen = struct.unpack(">H", rest[:2])[0]
            pos += 2
            l_ = []
            while plen > 0:
                attr = self.Attribute(buf[pos : _attribute_end(buf, pos)])
                pos += len(attr)
                plen -= len(attr)
                l_.append(attr)
            self.attributes = l_

            # Announced Routes
            self.announced = _routes(buf, pos, RouteIPV4, extended=True)
            self.data = buf[len(buf) :]

        def __len__(self):
            return (
                2
                + sum(map(len, self.withdrawn))
                + 2
                + sum(map(len, self.attributes))
                + sum(map(len, self.announced))
            )

        def __bytes__(self):
            return (
                struct.pack(">H", sum(map(len, self.withdrawn)))
                + b"".join(map(bytes, self.withdrawn))
                + struct.pack(">H", sum(map(len, self.attributes)))
                + b"".join(map(bytes, self.attributes))
                + b"".join(map(bytes, self.announced))
            )

        class Attribute(Packet):
            __hdr__ = (("flags", "B", 0), ("type", "B", 0))

            @property
            def optional(self):
                return (self.flags >> 7) & 0x1

            @optional.setter
            def optional(self, o):
                self.flags = (self.flags & ~0x80) | ((o & 0x1) << 7)

            @property
            def transitive(self):
                return (self.flags >> 6) & 0x1

            @transitive.setter
            def transitive(self, t):
                self.flags = (self.flags & ~0x40) | ((t & 0x1) << 6)

            @property
            def partial(self):
                return (self.flags >> 5) & 0x1

            @partial.setter
            def partial(self, p):
                self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)

            @property
            def extended_length(self):
                return (self.flags >> 4) & 0x1

            @extended_length.setter
            def extended_length(self, e):
                self.flags = (self.flags & ~0x10) | ((e & 0x1) << 4)

            def unpack(self, buf):
                Packet.unpack(self, buf)

                if self.extended_length:
                    self.len = struct.unpack(">H", self.data[:2])[0]
                    self.data = self.data[2:]
                else:
                    self.len = struct.unpack("B", self.data[:1])[0]
                    self.data = self.data[1:]

                self.data = self.data[: self.len]

                if self.type == ORIGIN:
                    self.data = self.origin = self.Origin(self.data)
                elif self.type == AS_PATH:
                    self.data = self.as_path = self.ASPath(self.data)
                elif self.type == NEXT_HOP:
                    self.data = self.next_hop = self.NextHop(self.data)
                elif self.type == MULTI_EXIT_DISC:
                    self.data = self.multi_exit_disc = self.MultiExitDisc(self.data)
                elif self.type == LOCAL_PREF:
                    self.data = self.local_pref = self.LocalPref(self.data)
                elif self.type == ATOMIC_AGGREGATE:
                    self.data = self.atomic_aggregate = self.AtomicAggregate(self.data)
                elif self.type == AGGREGATOR:
                    self.data = self.aggregator = self.Aggregator(self.data)
                elif self.type == COMMUNITIES:
                    self.data = self.communities = self.Communities(self.data)
                elif self.type == ORIGINATOR_ID:
                    self.data = self.originator_id = self.OriginatorID(self.data)
                elif self.type == CLUSTER_LIST:
                    self.data = self.cluster_list = self.ClusterList(self.data)
                elif self.type == MP_REACH_NLRI:
                    self.data = self.mp_reach_nlri = self.MPReachNLRI(self.data)
                elif self.type == MP_UNREACH_NLRI:
                    self.data = self.mp_unreach_nlri = self.MPUnreachNLRI(self.data)

            def __len__(self):
                attr_len = 2 if self.extended_length else 1
                return self.__hdr_len__ + attr_len + len(self.data)

            def __bytes__(self):
                if self.extended_length:
                    attr_len_str = struct.pack(">H", self.len)
                else:
                    attr_len_str = struct.pack("B", self.len)
                return self.pack_hdr() + attr_len_str + bytes(self.data)

            class Origin(Packet):
                __hdr__ = (("type", "B", ORIGIN_IGP),)

            class ASPath(Packet):
                __hdr_defaults__ = {"segments": []}

                def unpack(self, buf):
                    l_ = []
                    as4 = len(buf) == 6
                    segment = self.ASPathSegment4 if as4 else self.ASPathSegment
                    width = 4 if as4 else 2
                    pos = 0
                    while pos < len(buf):
                        # A segment holds at most 255 AS numbers.
                        seg = segment(buf[pos : pos + 2 + 255 * width])
                        pos += len(seg)
                        l_.append(seg)
                    self.data = self.segments = l_

                def __len__(self):
                    return sum(map(len, self.data))

                def __bytes__(self):
                    return b"".join(map(bytes, self.data))

                class ASPathSegment(Packet):
                    __hdr__ = (("type", "B", 0), ("len", "B", 0))

                    def unpack(self, buf):
                        Packet.unpack(self, buf)
                        l_ = []
                        for _ in range(self.len):
                            AS = struct.unpack(">H", self.data[:2])[0]
                            self.data = self.data[2:]
                            l_.append(AS)
                        self.data = self.path = l_

                    def __len__(self):
                        return self.__hdr_len__ + 2 * len(self.path)

                    def __bytes__(self):
                        as_str = b""
                        for AS in self.path:
                            as_str += struct.pack(">H", AS)
                        return self.pack_hdr() + as_str

                class ASPathSegment4(Packet):
                    __hdr__ = (("type", "B", 0), ("len", "B", 0))

                    def unpack(self, buf):
                        Packet.unpack(self, buf)
                        l_ = []
                        for _ in range(self.len):
                            if len(self.data) >= 4:
                                AS = struct.unpack(">I", self.data[:4])[0]
                                self.data = self.data[4:]
                                l_.append(AS)
                        self.path = l_

                    def __len__(self):
                        return self.__hdr_len__ + 4 * len(self.path)

                    def __bytes__(self):
                        as_str = b""
                        for AS in self.path:
                            as_str += struct.pack(">I", AS)
                        return self.pack_hdr() + as_str

            class NextHop(Packet):
                __hdr__ = (("ip", "I", 0),)

            class MultiExitDisc(Packet):
                __hdr__ = (("value", "I", 0),)

            class LocalPref(Packet):
                __hdr__ = (("value", "I", 0),)

            class AtomicAggregate(Packet):
                def unpack(self, buf):
                    pass

                def __len__(self):
                    return 0

                def __bytes__(self):
                    return b""

            class Aggregator(Packet):
                __hdr__ = (("asn", "H", 0), ("ip", "I", 0))

            class Communities(Packet):
                __hdr_defaults__ = {"list": []}

                def unpack(self, buf):
                    l_ = []
                    pos = 0
                    while pos < len(buf):
                        word = buf[pos : pos + 4]
                        val = struct.unpack(">I", word)[0]
                        if (0x00000000 <= val <= 0x0000FFFF) or (0xFFFF0000 <= val <= 0xFFFFFFFF):
                            comm = self.ReservedCommunity(word)
                        else:
                            comm = self.Community(word)
                        pos += len(comm)
                        l_.append(comm)
                    self.data = self.list = l_

                def __len__(self):
                    return sum(map(len, self.data))

                def __bytes__(self):
                    return b"".join(map(bytes, self.data))

                class Community(Packet):
                    __hdr__ = (("asn", "H", 0), ("value", "H", 0))

                class ReservedCommunity(Packet):
                    __hdr__ = (("value", "I", 0),)

            class OriginatorID(Packet):
                __hdr__ = (("value", "I", 0),)

            class ClusterList(Packet):
                __hdr_defaults__ = {"list": []}

                def unpack(self, buf):
                    l_ = []
                    for pos in range(0, len(buf), 4):
                        id = struct.unpack(">I", buf[pos : pos + 4])[0]
                        l_.append(id)
                    self.data = self.list = l_

                def __len__(self):
                    return 4 * len(self.list)

                def __bytes__(self):
                    cluster_str = b""
                    for val in self.list:
                        cluster_str += struct.pack(">I", val)
                    return cluster_str

            class MPReachNLRI(Packet):
                __hdr__ = (
                    ("afi", "H", AFI_IPV4),
                    ("safi", "B", SAFI_UNICAST),
                )

                def unpack(self, buf):
                    Packet.unpack(self, buf)

                    # Next Hop
                    hop_len = 4
                    if self.afi == AFI_IPV6:
                        hop_len = 16
                    buf = self.data
                    l_ = []
                    nlen = struct.unpack("B", buf[:1])[0]
                    pos = 1
                    # next_hop is kept for backward compatibility
                    self.next_hop = buf[pos : pos + nlen]
                    while nlen > 0:
                        hop = buf[pos : pos + hop_len]
                        l_.append(hop)
                        pos += hop_len
                        nlen -= hop_len
                    self.next_hops = l_

                    # SNPAs
                    l_ = []
                    self.data = buf[pos:]
                    num_snpas = struct.unpack("B", buf[pos : pos + 1])[0]
                    pos += 1
                    for _ in range(num_snpas):
                        # An SNPA is at most 1 + 128 bytes.
                        snpa = self.SNPA(buf[pos : pos + 129])
                        pos += len(snpa)
                        l_.append(snpa)
                    self.snpas = l_

                    if self.afi == AFI_IPV4:
                        Route = RouteIPV4
                    elif self.afi == AFI_IPV6:
                        Route = RouteIPV6
                    elif self.afi == AFI_L2VPN:
                        Route = RouteEVPN
                    else:
                        Route = RouteGeneric

                    # Announced Routes
                    self.data = self.announced = _routes(buf, pos, Route)

                def __len__(self):
                    return (
                        self.__hdr_len__
                        + 1
                        + sum(map(len, self.next_hops))
                        + 1
                        + sum(map(len, self.snpas))
                        + sum(map(len, self.announced))
                    )

                def __bytes__(self):
                    return (
                        self.pack_hdr()
                        + struct.pack("B", sum(map(len, self.next_hops)))
                        + b"".join(map(bytes, self.next_hops))
                        + struct.pack("B", len(self.snpas))
                        + b"".join(map(bytes, self.snpas))
                        + b"".join(map(bytes, self.announced))
                    )

                class SNPA(Packet):
                    __hdr__ = (("len", "B", 0),)

                    def unpack(self, buf):
                        Packet.unpack(self, buf)
                        self.data = self.data[: (self.len + 1) // 2]

            class MPUnreachNLRI(Packet):
                __hdr__ = (
                    ("afi", "H", AFI_IPV4),
                    ("safi", "B", SAFI_UNICAST),
                )

                def unpack(self, buf):
                    Packet.unpack(self, buf)

                    if self.afi == AFI_IPV4:
                        Route = RouteIPV4
                    elif self.afi == AFI_IPV6:
                        Route = RouteIPV6
                    elif self.afi == AFI_L2VPN:
                        Route = RouteEVPN
                    else:
                        Route = RouteGeneric

                    # Withdrawn Routes
                    self.data = self.withdrawn = _routes(self.data, 0, Route)

                def __len__(self):
                    return self.__hdr_len__ + sum(map(len, self.data))

                def __bytes__(self):
                    return self.pack_hdr() + b"".join(map(bytes, self.data))

    class Notification(Packet):
        __hdr__ = (
            ("code", "B", 0),
            ("subcode", "B", 0),
        )

        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.error = self.data

    class Keepalive(Packet):
        def unpack(self, buf):
            pass

        def __len__(self):
            return 0

        def __bytes__(self):
            return b""

    class RouteRefresh(Packet):
        __hdr__ = (("afi", "H", AFI_IPV4), ("rsvd", "B", 0), ("safi", "B", SAFI_UNICAST))


class RouteGeneric(Packet):
    __hdr__ = (("len", "B", 0),)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.data = self.prefix = self.data[: (self.len + 7) // 8]


class RouteIPV4(Packet):
    __hdr__ = (("len", "B", 0),)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        tmp = self.data[: (self.len + 7) // 8]
        tmp += (4 - len(tmp)) * b"\x00"
        self.data = self.prefix = tmp

    def __repr__(self):
        cidr = "%s/%d" % (socket.inet_ntoa(self.prefix), self.len)
        return "%s(%s)" % (self.__class__.__name__, cidr)

    def __len__(self):
        return self.__hdr_len__ + (self.len + 7) // 8

    def __bytes__(self):
        return self.pack_hdr() + self.prefix[: (self.len + 7) // 8]


class ExtendedRouteIPV4(RouteIPV4):
    __hdr__ = (
        ("path_id", "I", 0),
        ("len", "B", 0),
    )

    def __repr__(self):
        cidr = "%s/%d PathId %d" % (socket.inet_ntoa(self.prefix), self.len, self.path_id)
        return "%s(%s)" % (self.__class__.__name__, cidr)


class RouteIPV6(Packet):
    __hdr__ = (("len", "B", 0),)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        tmp = self.data[: (self.len + 7) // 8]
        tmp += (16 - len(tmp)) * b"\x00"
        self.data = self.prefix = tmp

    def __len__(self):
        return self.__hdr_len__ + (self.len + 7) // 8

    def __bytes__(self):
        return self.pack_hdr() + self.prefix[: (self.len + 7) // 8]


class RouteEVPN(Packet):
    __hdr__ = (("type", "B", 0), ("len", "B", 0))

    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.route_data = buf = self.data[: self.len]
        self.data = self.data[self.len :]

        # Get route distinguisher.
        self.rd = buf[:8]
        buf = buf[8:]

        # Get route information.  Not all fields are present on all route types.
        if self.type != 0x3:
            self.esi = buf[:10]
            buf = buf[10:]

        if self.type != 0x4:
            self.eth_id = buf[:4]
            buf = buf[4:]

        if self.type == 0x2:
            self.mac_address_length = _first(buf)
            if self.mac_address_length == 48:
                self.mac_address = buf[1:7]
                buf = buf[7:]
            else:
                self.mac_address = None
                buf = buf[1:]

        if self.type != 0x1:
            self.ip_address_length = _first(buf)
            if self.ip_address_length == 128:
                self.ip_address = buf[1:17]
                buf = buf[17:]
            elif self.ip_address_length == 32:
                self.ip_address = buf[1:5]
                buf = buf[5:]
            else:
                self.ip_address = None
                buf = buf[1:]

        if self.type in [0x1, 0x2]:
            self.mpls_label_stack = buf[:3]
            buf = buf[3:]
            if self.len > len(buf):
                self.mpls_label_stack += buf[:3]

    def __len__(self):
        return self.__hdr_len__ + self.len

    def __bytes__(self):
        return self.pack_hdr() + self.route_data


# The most bytes one route can use: a path ID for the extended IPv4 form, a
# length byte and up to 32 prefix bytes, or an EVPN type, length and value.
_ROUTE_MAX = 4 + 1 + 32
_EVPN_MAX = 2 + 255


def _attribute_end(buf, pos):
    """Where the attribute at buf[pos] ends: its header, length and value."""
    flags = buf[pos] if pos < len(buf) else 0
    if flags & 0x10:
        size = 4
        value = buf[pos + 2 : pos + 4]
    else:
        size = 3
        value = buf[pos + 2 : pos + 3]
    if len(value) < size - 2:
        # The length is cut off; the attribute fails on it either way.
        return len(buf)
    return pos + size + int.from_bytes(value, "big")


class EVPNIndexError(UnpackError, IndexError):
    """An EVPN route ends before its MAC or IP address length byte.

    dpkt raises IndexError here. This class is also an UnpackError, so code
    that catches either one handles it.
    """


def _first(buf):
    try:
        return buf[0]
    except IndexError as error:
        raise EVPNIndexError(*error.args) from None


def _routes(buf, pos, route, extended=False):
    """Read routes from buf[pos:] to the end, as dpkt's ``while self.data`` loops do."""
    window = _EVPN_MAX if route is RouteEVPN else _ROUTE_MAX
    found = []
    end = len(buf)
    while pos < end:
        if extended and (end - pos) % 9 == 0:
            item = ExtendedRouteIPV4(buf[pos : pos + window])
        else:
            item = route(buf[pos : pos + window])
        pos += len(item)
        found.append(item)
    return found
