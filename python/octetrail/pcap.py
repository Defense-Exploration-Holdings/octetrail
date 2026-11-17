"""Strict offline pcap reader with a measured subset of dpkt's reader API.

The distribution and import are named octetrail. This module does not install
or impersonate dpkt. See docs/python-reader.md for differences and exclusions.
"""

import builtins
import operator
import sys
import time
from contextlib import ExitStack
from decimal import Decimal

from . import _native
from .errors import NeedData

DEFAULT_MAX_PACKET_BYTES = 16 * 1024 * 1024
LimitError = _native.PacketLimitError

# Common capture constants measured against both pinned dpkt releases. The full
# upstream export inventory is deliberately not implied by this selection.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_LINUX_SLL = 113
DLT_USER0 = 147
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
TCPDUMP_MAGIC = 0xA1B2C3D4
TCPDUMP_MAGIC_NANO = 0xA1B23C4D

# Fixed link-layer offsets used by dpkt's reader, retained as compatibility data.
# dpkt attribution and BSD terms are in NOTICE and licenses/dpkt.txt.
_OFFSETS = {
    0: 4,
    1: 14,
    6: 22,
    7: 6,
    8: 16,
    9: 4,
    10: 21,
    18: 4,
    117: 48,
    113: 16,
    276: 20,
    12 if "openbsd" in sys.platform else 108: 4,
}


def _decimal_timestamp(ticks, base, exponent, offset=0):
    """Convert a native integer clock exactly, without using Decimal context."""
    coefficient = offset * base**exponent + ticks
    if base == 2:
        coefficient *= 5**exponent
    digits = tuple(int(digit) for digit in str(abs(coefficient)))
    return Decimal((int(coefficient < 0), digits, -exponent))


class Reader:
    """Read a binary stream without taking ownership of the caller's file.

    Iterators share the input cursor. Record read errors terminate native
    iteration. The extra max_packet_bytes keyword enforces an allocation limit.
    The open() helper owns its file and should be used as a context manager.
    """

    def __init__(
        self, fileobj, *, max_packet_bytes=DEFAULT_MAX_PACKET_BYTES, decimal_timestamps=False
    ):
        if type(decimal_timestamps) is not bool:
            raise TypeError("decimal_timestamps must be bool")
        limit = operator.index(max_packet_bytes)
        if not 0 <= limit <= 0xFFFFFFFF:
            raise ValueError("max_packet_bytes must be between 0 and 4294967295")
        self.name = getattr(fileobj, "name", f"<{fileobj.__class__.__name__}>")
        try:
            self._raw = _native._Reader(fileobj, limit)
        except _native.TruncatedError as error:
            raise NeedData(str(error)) from None
        self.snaplen, self._linktype, nano = self._raw.metadata()
        self.dloff = _OFFSETS.get(self._linktype, 0)
        self.filter = ""
        self._divisor = Decimal("1E9") if nano else 1e6
        self._decimal_timestamps = decimal_timestamps
        self._precision_exponent = 9 if nano else 6
        self._fileobj = fileobj
        self._owns_file = False
        self._iterator = iter(self)

    @property
    def fd(self):
        self._check_open()
        return self._fileobj.fileno()

    def fileno(self):
        return self.fd

    def datalink(self):
        return self._linktype

    def setfilter(self, value, optimize=1):
        raise NotImplementedError

    def __iter__(self):
        while True:
            try:
                packet = self._raw.read_packet()
            except _native.TruncatedError as error:
                raise NeedData(str(error)) from None
            if packet is None:
                return
            seconds, fraction, data = packet
            timestamp = (
                _decimal_timestamp(fraction, 10, self._precision_exponent, seconds)
                if self._decimal_timestamps
                else seconds + fraction / self._divisor
            )
            yield timestamp, data

    def __next__(self):
        self._check_open()
        return next(self._iterator)

    next = __next__

    def readpkts(self):
        """Collect all remaining packets; callers control total output memory."""
        return list(self)

    def dispatch(self, cnt, callback, *args):
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    timestamp, packet = next(iter(self))
                except StopIteration:
                    break
                callback(timestamp, packet, *args)
                processed += 1
        else:
            for timestamp, packet in self:
                callback(timestamp, packet, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    @property
    def closed(self):
        return self._raw.closed

    def _check_open(self):
        if self.closed:
            raise ValueError("capture reader is closed")

    def close(self):
        """Release the parser; close the file only if open() created it."""
        if not self.closed:
            self._raw.close()
            self._iterator = iter(())
            if self._owns_file:
                self._fileobj.close()

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def open(path, *, max_packet_bytes=DEFAULT_MAX_PACKET_BYTES, decimal_timestamps=False):
    """Open a local capture and return a reader that owns that file."""
    with ExitStack() as cleanup:
        stream = cleanup.enter_context(builtins.open(path, "rb"))
        reader = Reader(
            stream, max_packet_bytes=max_packet_bytes, decimal_timestamps=decimal_timestamps
        )
        reader._owns_file = True
        cleanup.pop_all()
        return reader


class UniversalReader:
    """Return a concrete native-backed Reader using dpkt 1.9.8 selection rules.

    Try classic PCAP at the current position. Only ValueError triggers an
    absolute seek to zero and a PCAPNG attempt. The caller retains the stream.
    This compatibility factory uses the readers' existing default limits.
    """

    def __new__(cls, fileobj, *, decimal_timestamps=False):
        try:
            return Reader(fileobj, decimal_timestamps=decimal_timestamps)
        except ValueError as classic_error:
            fileobj.seek(0)
            from . import pcapng

            try:
                return pcapng.Reader(fileobj, decimal_timestamps=decimal_timestamps)
            except ValueError as pcapng_error:
                # Preserve upstream's implicit context without adding a cause.
                raise ValueError(  # noqa: B904
                    "unknown pcap format; libpcap error: %s, pcapng error: %s"
                    % (classic_error, pcapng_error)
                )


def _writer_u32(name, value):
    value = operator.index(value)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be between 0 and 4294967295")
    return value


class Writer:
    """Write classic PCAP to a local binary stream using the native core.

    close() closes the supplied file, matching dpkt.Writer. Packet validation
    emits no record bytes; I/O failure can leave a prefix and is terminal.
    Timestamp range and snap length rules are deliberately stricter than dpkt.
    """

    def __init__(
        self,
        fileobj,
        snaplen=1500,
        linktype=1,
        nano=False,
        *,
        max_packet_bytes=DEFAULT_MAX_PACKET_BYTES,
    ):
        snaplen = _writer_u32("snaplen", snaplen)
        linktype = _writer_u32("linktype", linktype)
        limit = _writer_u32("max_packet_bytes", max_packet_bytes)
        nano = bool(nano)
        self._precision_multiplier = 1_000_000_000 if nano else 1_000_000
        self._raw = _native._Writer(
            fileobj, snaplen, linktype, nano, sys.byteorder == "little", limit
        )
        self._fileobj = fileobj

    def _check_open(self):
        if self.closed:
            raise ValueError("capture writer is closed")

    def writepkt(self, pkt, ts=None):
        self._check_open()
        if ts is None:
            ts = time.time()
        self.writepkt_time(bytes(pkt), ts)

    def writepkt_time(self, pkt, ts):
        self._check_open()
        if not isinstance(pkt, bytes):
            raise TypeError("writepkt_time requires bytes")
        if not isinstance(ts, (int, float, Decimal)):
            raise TypeError("timestamp must be int, float or Decimal")
        seconds = int(ts)
        if ts < 0 or not 0 <= seconds <= 0xFFFFFFFF:
            raise ValueError("timestamp outside unsigned 32-bit seconds range")
        fraction = round(ts % 1 * self._precision_multiplier)
        if not 0 <= fraction < self._precision_multiplier:
            raise ValueError("rounded timestamp fraction outside capture resolution")
        self._raw.write_packet(seconds, fraction, pkt)

    def writepkts(self, pkts):
        for timestamp, packet in pkts:
            self.writepkt_time(packet, timestamp)

    def flush(self):
        self._check_open()
        self._raw.flush()

    @property
    def closed(self):
        return self._raw.closed

    def close(self):
        if not self.closed:
            try:
                self._fileobj.close()
            finally:
                self._raw.close()

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
