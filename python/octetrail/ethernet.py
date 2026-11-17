"""Bounded Ethernet II frames with IPv4/IPv6 object composition.

Unknown/undecodable payloads stay bytes. No 802.3, VLAN, MPLS or FCS is supplied.
"""

import operator

from . import _native, ip, ip6
from .errors import NeedData, PackError, UnpackError

ETH_HDR_LEN = 14
ETH_TYPE_IP = 0x0800
ETH_TYPE_IP6 = 0x86DD
DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024
LimitError = _native.PacketLimitError


class Ethernet:
    """Mutable dst/src/type/data fields for the bounded Ethernet II API.

    Use one positional bytes buffer, or keyword dst/src/type/data fields. Buffer
    construction ignores field keywords, as dpkt does. Addresses retain their
    assigned values; packing pads/truncates byte strings to six bytes. IPv4
    payloads are decoded into IP objects with an ip alias; IPv6 uses IP6 and ip6.
    Other types stay bytes.
    Unsupported framing is rejected with NotImplementedError, not reinterpreted.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("Ethernet accepts at most one positional buffer")
        if args:
            self.unpack(args[0])
            return
        unknown = kwargs.keys() - {"dst", "src", "type", "data"}
        if unknown:
            raise TypeError("unsupported Ethernet fields: " + ", ".join(sorted(unknown)))
        self.dst = kwargs.get("dst", b"")
        self.src = kwargs.get("src", b"")
        self.type = kwargs.get("type", ETH_TYPE_IP)
        self.data = kwargs.get("data", b"")
        if isinstance(self.data, bytes):
            if len(self.data) > DEFAULT_MAX_FRAME_BYTES - ETH_HDR_LEN:
                raise LimitError("Ethernet input exceeds frame limit")
            self._decode_data()

    def unpack(self, buf):
        """Replace fields only after a complete supported frame is validated."""
        if not isinstance(buf, bytes):
            raise TypeError("Ethernet unpack requires bytes")
        try:
            fields = _native._ethernet_unpack(buf)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        self.dst, self.src, self.type, self.data = fields
        self._decode_data()

    def _decode_data(self):
        if self.type == ETH_TYPE_IP:
            try:
                decoded = ip.IP(self.data)
            except (UnpackError, NotImplementedError):
                pass
            else:
                self.data = self.ip = decoded
        elif self.type == ETH_TYPE_IP6:
            try:
                decoded = ip6.IP6(self.data)
            except (UnpackError, NotImplementedError, ip6.LimitError):
                pass
            else:
                self.data = self.ip6 = decoded

    def _header_args(self):
        if not isinstance(self.dst, bytes) or not isinstance(self.src, bytes):
            raise PackError("argument for 's' must be a bytes object")
        try:
            ethertype = operator.index(self.type)
        except TypeError:
            raise PackError("required argument is not an integer") from None
        if not 0 <= ethertype <= 0xFFFF:
            raise PackError("'H' format requires 0 <= number <= 65535")
        if isinstance(self.data, ip.IP):
            ethertype = ETH_TYPE_IP
        elif isinstance(self.data, ip6.IP6):
            ethertype = ETH_TYPE_IP6
        return self.dst, self.src, ethertype

    def pack_hdr(self):
        return _native._ethernet_header(*self._header_args())

    def __bytes__(self):
        fields = self._header_args()
        payload = self.data
        if not isinstance(payload, (bytes, bytearray, memoryview, ip.IP, ip6.IP6)):
            raise TypeError("Ethernet data requires IP or bytes-like data")
        size = payload.nbytes if isinstance(payload, memoryview) else len(payload)
        if size > DEFAULT_MAX_FRAME_BYTES - ETH_HDR_LEN:
            raise LimitError(
                f"Ethernet frame length {size + ETH_HDR_LEN} exceeds limit {DEFAULT_MAX_FRAME_BYTES}"
            )
        return _native._ethernet_pack(*fields, bytes(payload))

    def __len__(self):
        if not isinstance(self.data, (bytes, bytearray, memoryview, ip.IP, ip6.IP6)):
            raise TypeError("Ethernet data requires IP or bytes-like data")
        return ETH_HDR_LEN + len(self.data)
