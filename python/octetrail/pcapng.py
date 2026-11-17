"""Bounded offline pcapng Enhanced Packet Block reader.

Single-interface behavior is compared with both dpkt baselines. Section-local
interface timing is applied per packet, which intentionally differs from dpkt's
first-interface-only interpretation on more complex files.
"""

import builtins
import operator
import sys
from contextlib import ExitStack
from time import time

from . import _native, pcap
from .errors import NeedData

LimitError = pcap.LimitError

DLT_NULL = 0
DLT_EN10MB = 1
DLT_LINUX_SLL = 113
PCAPNG_VERSION_MAJOR = 1
PCAPNG_VERSION_MINOR = 0
PCAPNG_BT_SHB = 0x0A0D0D0A
PCAPNG_BT_IDB = 1
PCAPNG_BT_EPB = 6


def _limit(name, value):
    value = operator.index(value)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be between 0 and 4294967295")
    return value


class Reader(pcap.Reader):
    """Borrow a binary pcapng stream and yield (float timestamp, owned bytes).

    Metadata attributes describe the first interface. Each packet uses its own
    interface's time options. Use the Rust API when interface identity is needed.
    The inherited convenience methods share the input cursor.
    """

    def __init__(
        self,
        fileobj,
        *,
        max_packet_bytes=16 * 1024 * 1024,
        max_block_bytes=32 * 1024 * 1024,
        max_interfaces=1024,
        max_blocks_per_read=4096,
        decimal_timestamps=False,
    ):
        if type(decimal_timestamps) is not bool:
            raise TypeError("decimal_timestamps must be bool")
        self.name = getattr(fileobj, "name", f"<{fileobj.__class__.__name__}>")
        limits = [
            _limit("max_packet_bytes", max_packet_bytes),
            _limit("max_block_bytes", max_block_bytes),
            _limit("max_interfaces", max_interfaces),
            _limit("max_blocks_per_read", max_blocks_per_read),
        ]
        try:
            self._raw = _native._PcapngReader(fileobj, *limits)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        self.snaplen, self._linktype = self._raw.metadata()
        # dpkt.pcapng has its own offset inventory; it omits Linux SLL2 (276).
        self.dloff = pcap._OFFSETS.get(self._linktype, 0) if self._linktype != 276 else 0
        self.filter = ""
        self._decimal_timestamps = decimal_timestamps
        self._fileobj = fileobj
        self._owns_file = False
        self._iterator = iter(self)

    def __iter__(self):
        while True:
            try:
                packet = self._raw.read_packet()
            except _native.TruncatedError as error:
                raise NeedData(str(error)) from None
            if packet is None:
                return
            ticks, base, exponent, offset, data = packet
            timestamp = (
                pcap._decimal_timestamp(ticks, base, exponent, offset)
                if self._decimal_timestamps
                else offset + ticks / float(base**exponent)
            )
            yield timestamp, data


def open(path, **limits):
    """Open a local pcapng file and return a reader that owns it."""
    with ExitStack() as cleanup:
        stream = cleanup.enter_context(builtins.open(path, "rb"))
        reader = Reader(stream, **limits)
        reader._owns_file = True
        cleanup.pop_all()
        return reader


class Writer(pcap.Writer):
    """Write one offline section, one interface and Enhanced Packet Blocks.

    Bytes and the default microsecond clock form the dpkt-style subset. Custom
    interface clocks require writepkt_ticks(), an explicit OctetRail addition.
    Full section/interface/packet block objects are not implemented.
    """

    def __init__(
        self,
        fileobj,
        snaplen=1500,
        linktype=1,
        shb=None,
        idb=None,
        *,
        section_comment=None,
        interface_name=None,
        timestamp_resolution=None,
        timestamp_offset=None,
        max_packet_bytes=16 * 1024 * 1024,
        max_block_bytes=32 * 1024 * 1024,
    ):
        if shb is not None or idb is not None:
            raise NotImplementedError("PCAPNG block objects are not supported")
        snaplen = _limit("snaplen", snaplen)
        linktype = _limit("linktype", linktype)
        if linktype > 0xFFFF:
            raise ValueError("PCAPNG linktype must fit 16 bits")
        packet_limit = _limit("max_packet_bytes", max_packet_bytes)
        block_limit = _limit("max_block_bytes", max_block_bytes)
        if timestamp_resolution is not None:
            timestamp_resolution = _limit("timestamp_resolution", timestamp_resolution)
            if timestamp_resolution > 255:
                raise ValueError("timestamp_resolution must fit one encoded byte")
        if timestamp_offset is not None:
            timestamp_offset = operator.index(timestamp_offset)
            if not -(2**63) <= timestamp_offset < 2**63:
                raise ValueError("timestamp_offset must fit signed 64 bits")
        for value in (section_comment, interface_name):
            if value is not None and not isinstance(value, bytes):
                raise TypeError("PCAPNG text options require UTF-8 bytes")
        config = (snaplen, linktype, sys.byteorder == "little", packet_limit, block_limit)
        self._raw = _native._PcapngWriter(
            fileobj,
            config,
            (timestamp_resolution, timestamp_offset),
            (section_comment, interface_name),
        )
        self._fileobj = fileobj
        self._seconds_clock = timestamp_resolution in (None, 6) and timestamp_offset in (None, 0)

    def writepkt(self, pkt, ts=None):
        self._check_open()
        if ts is None:
            ts = time()
        self.writepkt_time(pkt, ts)

    def writepkt_time(self, pkt, ts):
        self._check_open()
        if not isinstance(pkt, bytes):
            raise TypeError("PCAPNG writer requires bytes; block objects are unsupported")
        if not self._seconds_clock:
            raise NotImplementedError(
                "seconds API requires microseconds with zero offset; use writepkt_ticks"
            )
        if not isinstance(ts, (int, float)):
            raise TypeError("seconds timestamp must be int or float")
        if ts < 0:
            raise ValueError("negative seconds timestamps are unsupported")
        self.writepkt_ticks(pkt, round(ts * 1e6))

    def writepkt_ticks(self, pkt, ticks):
        self._check_open()
        if not isinstance(pkt, bytes):
            raise TypeError("PCAPNG writer requires bytes; block objects are unsupported")
        ticks = operator.index(ticks)
        if not 0 <= ticks <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("PCAPNG timestamp ticks must fit unsigned 64 bits")
        self._raw.write_packet(ticks, pkt)
