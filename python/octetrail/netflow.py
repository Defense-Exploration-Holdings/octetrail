"""Cisco NetFlow versions 1, 5, 6 and 7, as dpkt 1.9.8 reads them.

The headers and records use the :class:`octetrail.Packet` base. The record
split is read in Rust. The classes are dpkt's.
"""

import struct

from . import _native
from .packet import Packet


class NetflowBase(Packet):
    """Base class for Cisco Netflow packets.

    NetFlow is a feature that was introduced on Cisco routers around 1996 that provides the ability to collect IP
    network traffic as it enters or exits an interface. By analyzing the data provided by NetFlow, a network
    administrator can determine things such as the source and destination of traffic, class of service, and the causes
    of congestion.

    https://www.ciscopress.com/articles/article.asp?p=2812391&seqNum=3

    Attributes:
        __hdr__: Header fields of NetflowBase.
    """

    __hdr__ = (
        ("version", "H", 1),
        ("count", "H", 0),
        ("sys_uptime", "I", 0),
        ("unix_sec", "I", 0),
        ("unix_nsec", "I", 0),
    )

    def __len__(self):
        return self.__hdr_len__ + (len(self.data[0]) * self.count)

    def __bytes__(self):
        # for now, don't try to enforce any size limits
        self.count = len(self.data)
        return self.pack_hdr() + b"".join(map(bytes, self.data))

    def unpack(self, buf):
        Packet.unpack(self, buf)
        buf = self.data
        l_ = []
        size = 0
        if buf:
            # The fast split needs records whose length is their header size.
            # A record class that changes __len__ or unpack is walked as in dpkt.
            record, base = self.NetflowRecord, NetflowBase.NetflowRecordBase
            if record.__len__ is base.__len__ and record.unpack is base.unpack:
                size = record.__hdr_len__
        if size:
            # The records are split in Rust and each gets only its own bytes.
            count, tail = _native._netflow_records(len(buf), size)
            for i in range(count):
                l_.append(self.NetflowRecord(buf[i * size : (i + 1) * size]))
            if tail is not None:
                self.NetflowRecord(buf[tail:])
        else:
            while buf:
                flow = self.NetflowRecord(buf)
                l_.append(flow)
                buf = buf[len(flow) :]
        self.data = l_

    class NetflowRecordBase(Packet):
        """Base class for netflow v1-v7 netflow records.

        Attributes:
            __hdr__: Header fields of NetflowRecordBase.
        """

        # performance optimizations
        def __len__(self):
            # don't bother with data
            return self.__hdr_len__

        def __bytes__(self):
            # don't bother with data
            return self.pack_hdr()

        def unpack(self, buf):
            # don't bother with data
            for k, v in zip(  # noqa: B905 - dpkt's izip stops at the shorter one.
                self.__hdr_fields__, struct.unpack(self.__hdr_fmt__, buf[: self.__hdr_len__])
            ):
                setattr(self, k, v)
            self.data = b""


class Netflow1(NetflowBase):
    """Netflow Version 1.

    Attributes:
        __hdr__: Header fields of Netflow Version 1.
    """

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v1 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 1 flow record.
        """

        __hdr__ = (
            ("src_addr", "I", 0),
            ("dst_addr", "I", 0),
            ("next_hop", "I", 0),
            ("input_iface", "H", 0),
            ("output_iface", "H", 0),
            ("pkts_sent", "I", 0),
            ("bytes_sent", "I", 0),
            ("start_time", "I", 0),
            ("end_time", "I", 0),
            ("src_port", "H", 0),
            ("dst_port", "H", 0),
            ("pad1", "H", 0),
            ("ip_proto", "B", 0),
            ("tos", "B", 0),
            ("tcp_flags", "B", 0),
            ("pad2", "B", 0),
            ("pad3", "H", 0),
            ("reserved", "I", 0),
        )


# FYI, versions 2-4 don't appear to have ever seen the light of day.


class Netflow5(NetflowBase):
    """Netflow Version 5.

    Popular NetFlow version on many routers from different vendors. Limited to IPv4 flows.

    Attributes:
        __hdr__: Header fields of Netflow Version 5.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ("flow_sequence", "I", 0),
        ("engine_type", "B", 0),
        ("engine_id", "B", 0),
        ("reserved", "H", 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v5 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 5 flow record.
        """

        __hdr__ = (
            ("src_addr", "I", 0),
            ("dst_addr", "I", 0),
            ("next_hop", "I", 0),
            ("input_iface", "H", 0),
            ("output_iface", "H", 0),
            ("pkts_sent", "I", 0),
            ("bytes_sent", "I", 0),
            ("start_time", "I", 0),
            ("end_time", "I", 0),
            ("src_port", "H", 0),
            ("dst_port", "H", 0),
            ("pad1", "B", 0),
            ("tcp_flags", "B", 0),
            ("ip_proto", "B", 0),
            ("tos", "B", 0),
            ("src_as", "H", 0),
            ("dst_as", "H", 0),
            ("src_mask", "B", 0),
            ("dst_mask", "B", 0),
            ("pad2", "H", 0),
        )


class Netflow6(NetflowBase):
    """Netflow Version 6.

    (Obsolete.) No longer supported by Cisco, but may be found in the field.

    Attributes:
        __hdr__: Header fields of Netflow Version 6.
    """

    __hdr__ = Netflow5.__hdr__

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
        """

        __hdr__ = (
            ("src_addr", "I", 0),
            ("dst_addr", "I", 0),
            ("next_hop", "I", 0),
            ("input_iface", "H", 0),
            ("output_iface", "H", 0),
            ("pkts_sent", "I", 0),
            ("bytes_sent", "I", 0),
            ("start_time", "I", 0),
            ("end_time", "I", 0),
            ("src_port", "H", 0),
            ("dst_port", "H", 0),
            ("pad1", "B", 0),
            ("tcp_flags", "B", 0),
            ("ip_proto", "B", 0),
            ("tos", "B", 0),
            ("src_as", "H", 0),
            ("dst_as", "H", 0),
            ("src_mask", "B", 0),
            ("dst_mask", "B", 0),
            ("in_encaps", "B", 0),
            ("out_encaps", "B", 0),
            ("peer_nexthop", "I", 0),
        )


class Netflow7(NetflowBase):
    """Netflow Version 7.

    (Obsolete.) Like version 5, with a source router field.

    Attributes:
        __hdr__: Header fields of Netflow Version 7.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ("flow_sequence", "I", 0),
        ("reserved", "I", 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
        """

        __hdr__ = (
            ("src_addr", "I", 0),
            ("dst_addr", "I", 0),
            ("next_hop", "I", 0),
            ("input_iface", "H", 0),
            ("output_iface", "H", 0),
            ("pkts_sent", "I", 0),
            ("bytes_sent", "I", 0),
            ("start_time", "I", 0),
            ("end_time", "I", 0),
            ("src_port", "H", 0),
            ("dst_port", "H", 0),
            ("flags", "B", 0),
            ("tcp_flags", "B", 0),
            ("ip_proto", "B", 0),
            ("tos", "B", 0),
            ("src_as", "H", 0),
            ("dst_as", "H", 0),
            ("src_mask", "B", 0),
            ("dst_mask", "B", 0),
            ("pad2", "H", 0),
            ("router_sc", "I", 0),
        )
