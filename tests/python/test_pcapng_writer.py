"""Offline installed-wheel PCAPNG output tests with independent byte expectations."""

import gc
import io
import struct
import sys
import unittest
import weakref
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from octetrail import pcapng

ROOT = Path(__file__).resolve().parents[2]
ORDER = "<" if sys.byteorder == "little" else ">"


def headers(snaplen=1500, linktype=1):
    return struct.pack(ORDER + "IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28) + struct.pack(
        ORDER + "IIHHII", 1, 20, linktype, 0, snaplen, 20
    )


def epb(ticks, data):
    length = 32 + len(data) + (-len(data) % 4)
    return (
        struct.pack(
            ORDER + "IIIIIII", 6, length, 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)
        )
        + data
        + b"\0" * (-len(data) % 4)
        + struct.pack(ORDER + "I", length)
    )


class PcapngWriterTests(unittest.TestCase):
    def test_default_headers_and_immediate_output(self):
        stream = io.BytesIO()
        writer = pcapng.Writer(stream)
        self.assertEqual(stream.getvalue(), headers())
        self.assertFalse(writer.closed)
        self.assertIsNone(writer.flush())

    def test_seconds_rounding_padding_and_all_methods(self):
        stream = io.BytesIO()
        writer = pcapng.Writer(stream)
        self.assertIsNone(writer.writepkt(b"a", 1.25))
        self.assertIsNone(writer.writepkt_time(b"ab", 1.9999999))
        self.assertIsNone(writer.writepkts([(0.0000005, b"abc"), (0.0000015, b"rail")]))
        self.assertEqual(
            stream.getvalue(),
            headers()
            + epb(1_250_000, b"a")
            + epb(2_000_000, b"ab")
            + epb(0, b"abc")
            + epb(2, b"rail"),
        )

    def test_default_clock_is_deterministic_in_test(self):
        stream = io.BytesIO()
        writer = pcapng.Writer(stream)
        with patch.object(pcapng, "time", return_value=1.25) as clock:
            writer.writepkt(b"clock")
        clock.assert_called_once()
        self.assertEqual(stream.getvalue(), headers() + epb(1_250_000, b"clock"))

    def test_metadata_and_raw_ticks_match_hand_reviewed_fixture(self):
        if sys.byteorder != "little":
            self.skipTest("literal is little endian; native tests cover both orders")
        stream = io.BytesIO()
        writer = pcapng.Writer(
            stream,
            snaplen=64,
            linktype=147,
            section_comment=b"lab",
            interface_name=b"if0",
            timestamp_resolution=0x8A,
            timestamp_offset=-2,
        )
        writer.writepkt_ticks(b"abc", 1024)
        expected = bytes.fromhex((ROOT / "tests/fixtures/pcapng-options-little.hex").read_text())
        self.assertEqual(stream.getvalue(), expected)
        self.assertEqual(list(pcapng.Reader(io.BytesIO(expected))), [(-1.0, b"abc")])

    def test_custom_clock_requires_explicit_ticks_without_emitting_a_record(self):
        for config in (
            {"timestamp_resolution": 9},
            {"timestamp_resolution": 0x8A},
            {"timestamp_offset": 2},
        ):
            stream = io.BytesIO()
            writer = pcapng.Writer(stream, **config)
            prefix = stream.getvalue()
            with self.assertRaises(NotImplementedError):
                writer.writepkt_time(b"a", 1.0)
            self.assertEqual(stream.getvalue(), prefix)
            writer.writepkt_ticks(b"a", 0)
            self.assertEqual(stream.getvalue(), prefix + epb(0, b"a"))

    def test_explicit_default_clock_and_full_tick_range(self):
        stream = io.BytesIO()
        writer = pcapng.Writer(stream, timestamp_resolution=6, timestamp_offset=0)
        prefix = stream.getvalue()
        writer.writepkt_time(b"a", 1.25)
        writer.writepkt_ticks(b"", 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(
            stream.getvalue(), prefix + epb(1_250_000, b"a") + epb(0xFFFFFFFFFFFFFFFF, b"")
        )

    def test_unsupported_blocks_and_bad_metadata_emit_nothing(self):
        for config, exception in [
            ({"shb": object()}, NotImplementedError),
            ({"idb": []}, NotImplementedError),
            ({"section_comment": "text"}, TypeError),
            ({"interface_name": b"\xff"}, ValueError),
            ({"section_comment": b"a" * 65536}, ValueError),
            ({"timestamp_resolution": 256}, ValueError),
            ({"timestamp_offset": 2**63}, ValueError),
            ({"linktype": 65536}, ValueError),
            ({"max_packet_bytes": -1}, ValueError),
        ]:
            stream = io.BytesIO()
            with self.assertRaises(exception):
                pcapng.Writer(stream, **config)
            self.assertEqual(stream.getvalue(), b"")
            self.assertFalse(stream.closed)

    def test_all_initial_block_limits_precede_output(self):
        stream = io.BytesIO()
        with self.assertRaises(pcapng.LimitError):
            pcapng.Writer(stream, timestamp_resolution=6, max_block_bytes=28)
        self.assertEqual(stream.getvalue(), b"")
        with self.assertRaises(pcapng.LimitError):
            pcapng.Writer(stream, max_block_bytes=27)
        self.assertEqual(stream.getvalue(), b"")

    def test_packet_limits_unlimited_snaplen_and_recovery(self):
        for config in ({"snaplen": 2}, {"max_packet_bytes": 2}, {"max_block_bytes": 32}):
            stream = io.BytesIO()
            writer = pcapng.Writer(stream, **config)
            prefix = stream.getvalue()
            with self.assertRaises(ValueError):
                writer.writepkt_ticks(b"abc", 0)
            self.assertEqual(stream.getvalue(), prefix)
            writer.writepkt_ticks(b"", 0)
            self.assertEqual(stream.getvalue(), prefix + epb(0, b""))
        stream = io.BytesIO()
        writer = pcapng.Writer(stream, snaplen=0, max_packet_bytes=3)
        writer.writepkt_ticks(b"abc", 0)
        self.assertEqual(stream.getvalue(), headers(snaplen=0) + epb(0, b"abc"))

    def test_strict_inputs_and_tick_bounds_leave_prefix_usable(self):
        stream = io.BytesIO()
        writer = pcapng.Writer(stream)
        for value in (-1, 2**64):
            with self.assertRaises(ValueError):
                writer.writepkt_ticks(b"a", value)
        with self.assertRaises(TypeError):
            writer.writepkt_ticks(b"a", 1.25)
        for value in (bytearray(b"a"), memoryview(b"a"), object()):
            with self.assertRaises(TypeError):
                writer.writepkt(value, 1.0)
        with self.assertRaises(TypeError):
            writer.writepkt_time(b"a", Decimal("1.25"))
        with self.assertRaises(ValueError):
            writer.writepkt_time(b"a", -0.25)
        self.assertEqual(stream.getvalue(), headers())
        writer.writepkt_ticks(b"a", 1)

    def test_batch_source_exception_preserves_valid_prefix(self):
        stream = io.BytesIO()
        writer = pcapng.Writer(stream)
        failure = RuntimeError("synthetic source stopped")

        def source():
            yield 1, b"a"
            self.assertEqual(stream.getvalue(), headers() + epb(1_000_000, b"a"))
            raise failure

        with self.assertRaises(RuntimeError) as raised:
            writer.writepkts(source())
        self.assertIs(raised.exception, failure)
        writer.writepkt_ticks(b"b", 2)

    def test_short_writes_and_original_output_exception_identity(self):
        class Short(io.BytesIO):
            def write(self, data):
                return super().write(data[:2])

        stream = Short()
        writer = pcapng.Writer(stream)
        writer.writepkt_ticks(b"abc", 1)
        self.assertEqual(stream.getvalue(), headers() + epb(1, b"abc"))

        class Failing(io.BytesIO):
            def write(self, data):
                remaining = self.at - self.tell()
                if remaining == 0:
                    raise self.failure
                return super().write(data[:remaining])

        for at in (0, 10, 35, 47, 52, 77, 79, 82):
            for failure in (OSError("offline output failed"), InterruptedError("interrupted")):
                stream = Failing()
                stream.at, stream.failure = at, failure
                with self.assertRaises(type(failure)) as raised:
                    writer = pcapng.Writer(stream)
                    writer.writepkt_ticks(b"abc", 1)
                self.assertIs(raised.exception, failure)
                self.assertEqual(len(stream.getvalue()), at)

    def test_zero_progress_and_flush_failure_are_terminal(self):
        class Zero(io.BytesIO):
            def write(self, data):
                return super().write(data) if self.tell() < 48 else 0

        stream = Zero()
        writer = pcapng.Writer(stream)
        with self.assertRaises(OSError):
            writer.writepkt_ticks(b"a", 1)
        with self.assertRaises(ValueError):
            writer.writepkt_ticks(b"", 0)
        failure = OSError("synthetic flush failed")

        class BadFlush(io.BytesIO):
            def flush(self):
                raise failure

        stream = BadFlush()
        writer = pcapng.Writer(stream)
        with self.assertRaises(OSError) as raised:
            writer.flush()
        self.assertIs(raised.exception, failure)
        with self.assertRaises(ValueError):
            writer.writepkt_ticks(b"", 0)
        writer.close()
        self.assertTrue(stream.closed)

    def test_file_ownership_cycles_and_bounded_adapter_chunks(self):
        stream = io.BytesIO()
        with pcapng.Writer(stream) as writer:
            writer.writepkt(b"a", 1.0)
        self.assertTrue(stream.closed)
        self.assertTrue(writer.closed)
        writer.close()
        stream = io.BytesIO()
        writer = pcapng.Writer(stream)
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
        writer = pcapng.Writer(stream, snaplen=0)
        writer.writepkt_ticks(b"r" * 65537, 0)
        self.assertLessEqual(stream.largest, 65536)
        self.assertEqual(stream.getvalue(), headers(snaplen=0) + epb(0, b"r" * 65537))


if __name__ == "__main__":
    unittest.main()
