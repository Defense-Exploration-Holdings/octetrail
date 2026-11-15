"""Installed-wheel offline writer checks with independent wire-field assertions."""

import gc
import io
import struct
import sys
import unittest
import weakref
from decimal import Decimal, Inexact, localcontext
from unittest.mock import patch

from octetrail import pcap

ORDER = "<" if sys.byteorder == "little" else ">"


def header(nano=False, snaplen=1500, linktype=1):
    return struct.pack(
        ORDER + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype
    )


def record(seconds, fraction, data):
    return struct.pack(ORDER + "IIII", seconds, fraction, len(data), len(data)) + data


class WriterTests(unittest.TestCase):
    def test_default_header_and_immediate_global_output(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream)
        self.assertEqual(stream.getvalue(), header())
        self.assertFalse(writer.closed)
        self.assertIsNone(writer.flush())

    def test_microsecond_decimal_rounding_and_exact_bytes(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream, snaplen=64, linktype=147)
        writer.writepkt_time(b"abc", Decimal("1.0000005"))
        writer.writepkt_time(b"", Decimal("1.0000015"))
        self.assertEqual(
            stream.getvalue(),
            header(snaplen=64, linktype=147) + record(1, 0, b"abc") + record(1, 2, b""),
        )

    def test_nanosecond_decimal_precision(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream, nano=True)
        writer.writepkt_time(b"rail", Decimal("1700000000.123456789"))
        self.assertEqual(
            stream.getvalue(), header(nano=True) + record(1_700_000_000, 123_456_789, b"rail")
        )

    def test_writepkt_converts_once_and_clock_can_be_deterministic(self):
        class Packet:
            calls = 0

            def __bytes__(self):
                self.calls += 1
                return b"abc"

        payload = Packet()
        stream = io.BytesIO()
        writer = pcap.Writer(stream)
        with patch.object(pcap.time, "time", return_value=1.25) as clock:
            self.assertIsNone(writer.writepkt(payload))
        self.assertEqual(payload.calls, 1)
        clock.assert_called_once()
        self.assertEqual(stream.getvalue(), header() + record(1, 250_000, b"abc"))
        writer.writepkt(bytearray(b"a"), 2)
        writer.writepkt(memoryview(b"b"), 3)

    def test_direct_methods_require_bytes_and_keep_valid_prefix(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream)
        with self.assertRaises(TypeError):
            writer.writepkt_time(bytearray(b"abc"), 1)
        self.assertEqual(stream.getvalue(), header())
        with self.assertRaises(TypeError):
            writer.writepkts([(1, b"a"), (2, "text")])
        self.assertEqual(stream.getvalue(), header() + record(1, 0, b"a"))
        writer.writepkt_time(b"b", 3)
        self.assertEqual(stream.getvalue(), header() + record(1, 0, b"a") + record(3, 0, b"b"))

    def test_batch_iteration_streams_and_preserves_source_exception(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream)
        failure = RuntimeError("synthetic source stopped")

        def packets():
            self.assertEqual(len(stream.getvalue()), 24)
            yield 1, b"a"
            self.assertEqual(len(stream.getvalue()), 41)
            yield 2, b"b"
            raise failure

        with self.assertRaises(RuntimeError) as raised:
            writer.writepkts(packets())
        self.assertIs(raised.exception, failure)
        self.assertEqual(stream.getvalue(), header() + record(1, 0, b"a") + record(2, 0, b"b"))
        writer.writepkt_time(b"c", 3)

    def test_validation_limits_emit_no_record_and_allow_retry(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream, snaplen=2, max_packet_bytes=3)
        for data in (b"abc", b"abcd"):
            with self.assertRaises(ValueError):
                writer.writepkt_time(data, 1)
            self.assertEqual(stream.getvalue(), header(snaplen=2))
        writer.writepkt_time(b"ab", 1)
        self.assertEqual(stream.getvalue(), header(snaplen=2) + record(1, 0, b"ab"))
        empty = io.BytesIO()
        writer = pcap.Writer(empty, max_packet_bytes=0)
        writer.writepkt_time(b"", 0)
        self.assertEqual(empty.getvalue(), header() + record(0, 0, b""))

    def test_header_validation_precedes_output(self):
        for kwargs in (
            {"snaplen": 0},
            {"snaplen": -1},
            {"linktype": 2**32},
            {"max_packet_bytes": -1},
        ):
            stream = io.BytesIO()
            with self.assertRaises(ValueError):
                pcap.Writer(stream, **kwargs)
            self.assertEqual(stream.getvalue(), b"")
            self.assertFalse(stream.closed)

    def test_timestamp_bounds_and_rounding_carry_are_strict(self):
        for nano, carry in ((False, "1.9999999"), (True, "1.9999999999")):
            stream = io.BytesIO()
            writer = pcap.Writer(stream, nano=nano)
            for timestamp in (-0.25, -1, 2**32, Decimal(carry)):
                with self.assertRaises(ValueError):
                    writer.writepkt_time(b"a", timestamp)
                self.assertEqual(stream.getvalue(), header(nano=nano))
            with self.assertRaises(TypeError):
                writer.writepkt_time(b"a", "1.25")
            writer.writepkt_time(b"a", 0xFFFFFFFF)
            self.assertEqual(stream.getvalue(), header(nano=nano) + record(0xFFFFFFFF, 0, b"a"))

    def test_decimal_context_failure_does_not_poison_writer(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream, nano=True)
        with localcontext() as context:
            context.prec = 6
            context.traps[Inexact] = True
            with self.assertRaises(Inexact):
                writer.writepkt_time(b"a", Decimal("1.123456789"))
        self.assertEqual(stream.getvalue(), header(nano=True))
        writer.writepkt_time(b"a", 2)

    def test_short_writes_complete_without_dropping_bytes(self):
        class Short(io.BytesIO):
            def write(self, data):
                return super().write(data[:3])

        stream = Short()
        writer = pcap.Writer(stream)
        writer.writepkt_time(b"abc", 1.25)
        self.assertEqual(stream.getvalue(), header() + record(1, 250_000, b"abc"))

    def test_zero_progress_is_an_oserror_and_terminal(self):
        class Zero(io.BytesIO):
            def write(self, data):
                return super().write(data) if self.tell() < 24 else 0

        stream = Zero()
        writer = pcap.Writer(stream)
        with self.assertRaises(OSError):
            writer.writepkt_time(b"abc", 1)
        with self.assertRaises(ValueError):
            writer.writepkt_time(b"a", 2)
        self.assertEqual(stream.getvalue(), header())

    def test_invalid_sink_counts_are_terminal(self):
        class Invalid(io.BytesIO):
            def write(self, data):
                if self.tell() < 24:
                    return super().write(data)
                return self.result

        for result, error in (
            (None, BlockingIOError),
            (100, ValueError),
            (-1, OverflowError),
            ("bad", TypeError),
        ):
            stream = Invalid()
            stream.result = result
            writer = pcap.Writer(stream)
            with self.assertRaises(error):
                writer.writepkt_time(b"a", 1)
            with self.assertRaises(ValueError):
                writer.flush()

    def test_original_write_exceptions_preserve_identity(self):
        class Failing(io.BytesIO):
            def write(self, data):
                remaining = self.fail_at - self.tell()
                if remaining == 0:
                    raise self.failure
                return super().write(data[:remaining])

        for at in (0, 10, 24, 28, 41):
            for failure in (OSError("offline output failed"), InterruptedError("interrupted")):
                stream = Failing()
                stream.fail_at, stream.failure = at, failure
                with self.assertRaises(type(failure)) as raised:
                    writer = pcap.Writer(stream)
                    writer.writepkt_time(b"abc", 1)
                self.assertIs(raised.exception, failure)
                self.assertEqual(len(stream.getvalue()), at)
                self.assertFalse(stream.closed)

    def test_flush_exception_is_preserved_and_close_still_releases_stream(self):
        failure = OSError("synthetic flush failed")

        class FailingFlush(io.BytesIO):
            def flush(self):
                raise failure

        stream = FailingFlush()
        writer = pcap.Writer(stream)
        with self.assertRaises(OSError) as raised:
            writer.flush()
        self.assertIs(raised.exception, failure)
        with self.assertRaises(ValueError):
            writer.writepkt_time(b"a", 1)
        writer.close()
        self.assertTrue(stream.closed)

    def test_close_and_context_manager_close_supplied_file(self):
        class Counted(io.BytesIO):
            closes = 0

            def close(self):
                self.closes += 1
                super().close()

        stream = Counted()
        with pcap.Writer(stream) as writer:
            writer.writepkt(b"abc", 1)
        self.assertTrue(stream.closed)
        self.assertTrue(writer.closed)
        writer.close()
        self.assertEqual(stream.closes, 1)
        with self.assertRaises(ValueError):
            writer.writepkt(b"a", 1)

    def test_cycle_collection_and_bounded_output_chunks(self):
        stream = io.BytesIO()
        writer = pcap.Writer(stream)
        stream.writer = writer
        refs = weakref.ref(stream), weakref.ref(writer)
        del stream, writer
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))

        class Chunks(io.BytesIO):
            largest = 0

            def write(self, data):
                self.largest = max(self.largest, len(data))
                return super().write(data)

        stream = Chunks()
        writer = pcap.Writer(stream, snaplen=200_000)
        data = b"r" * 200_000
        writer.writepkt_time(data, 1)
        self.assertLessEqual(stream.largest, 64 * 1024)
        self.assertEqual(stream.getvalue(), header(snaplen=200_000) + record(1, 0, data))


if __name__ == "__main__":
    unittest.main()
