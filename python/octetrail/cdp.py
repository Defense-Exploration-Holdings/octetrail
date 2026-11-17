"""Cisco Discovery Protocol, as dpkt 1.9.8 reads it.

The entry list is read in Rust. As in dpkt, a parsed packet keeps each entry
as the bytes it packs to, in ``tlvs``, and their concatenation in ``data``.
"""

import struct

from . import _native
from .errors import NeedData, PackError
from .packet import Packet, in_cksum

CDP_DEVID = 1  # string
CDP_ADDRESS = 2
CDP_PORTID = 3  # string
CDP_CAPABILITIES = 4  # 32-bit bitmask
CDP_VERSION = 5  # string
CDP_PLATFORM = 6  # string
CDP_IPPREFIX = 7

CDP_VTP_MGMT_DOMAIN = 9  # string
CDP_NATIVE_VLAN = 10  # 16-bit integer
CDP_DUPLEX = 11  # 8-bit boolean
CDP_TRUST_BITMAP = 18  # 8-bit bitmask0x13
CDP_UNTRUST_COS = 19  # 8-bit port
CDP_SYSTEM_NAME = 20  # string
CDP_SYSTEM_OID = 21  # 10-byte binary string
CDP_MGMT_ADDRESS = 22  # 32-bit number of addrs, Addresses
CDP_LOCATION = 23  # string


class CDP(Packet):
    """Cisco Discovery Protocol packet.

    Attributes:
        version: CDP version, 2 by default.
        ttl: Time to live in seconds, 180 by default.
        sum: Checksum, computed when packing if it is 0.
        tlvs: The entries as packed bytes, set when parsing.
    """

    __hdr__ = (
        ("version", "B", 2),
        ("ttl", "B", 180),
        ("sum", "H", 0),
    )

    class TLV(Packet):
        """Type-length-value entry.

        When constructing an entry, len is not mandatory: if it is 0, data
        must be this exact entry value, and packing sets len.
        """

        __hdr__ = (
            ("type", "H", 0),
            ("len", "H", 0),
        )

        def data_len(self):
            if self.len:
                return self.len - self.__hdr_len__
            return len(self.data)

        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.data = self.data[: self.data_len()]

        def __len__(self):
            return self.__hdr_len__ + len(self.data)

        def __bytes__(self):
            if hasattr(self, "len") and not self.len:
                self.len = len(self)
            return self.pack_hdr() + bytes(self.data)

    class Address(TLV):
        # As in dpkt, only NLPID/IP is handled.
        __hdr__ = (
            ("ptype", "B", 1),  # protocol type (NLPID)
            ("plen", "B", 1),  # protocol length
            ("p", "B", 0xCC),  # IP
            ("alen", "H", 4),  # address length
        )

        def data_len(self):
            return self.alen

    class TLV_Addresses(TLV):  # noqa: N801 - dpkt's name.
        __hdr__ = (
            ("type", "H", CDP_ADDRESS),
            ("len", "H", 0),
            ("Addresses", "L", 1),
        )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        raw = buf if type(buf) is bytes else bytes(buf)
        try:
            rows = _native._cdp_tlvs(raw, self.__hdr_len__)
        except _native.CdpShortTlvError as error:
            have, need = error.args
            raise NeedData("got %d, %d needed at least" % (have, need)) from None
        self.tlvs = [_packed(raw, row) for row in rows]
        self.data = b"".join(self.tlvs)

    def __len__(self):
        return self.__hdr_len__ + len(self.data)

    def __bytes__(self):
        data = bytes(self.data)
        if not self.sum:
            self.sum = in_cksum(self.pack_hdr() + data)
        return self.pack_hdr() + data

    # The entry classes whose header differs from the generic one.
    tlv_types = {CDP_ADDRESS: TLV_Addresses}


def _packed(raw, row):
    # What bytes() of dpkt's entry object gives: a zero length becomes the
    # entry's own length.
    kind, length, addresses, start, end = row
    value = raw[start:end]
    try:
        if addresses is None:
            return struct.pack(">HH", kind, length or 4 + len(value)) + value
        return struct.pack(">HHL", kind, length or 8 + len(value), addresses) + value
    except struct.error as e:
        raise PackError(str(e)) from None
