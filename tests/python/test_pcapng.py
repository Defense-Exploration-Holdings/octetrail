"""Installed-wheel pcapng tests using independent benign synthetic capture fields."""

import gc
import io
import os
import runpy
import tempfile
import unittest
import weakref
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import pcapng

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = runpy.run_path(str(ROOT / "tools/pcapng_fixtures.py"))
section, interface, packet = (FIXTURE[name] for name in ("section", "interface", "packet"))
single, block = (FIXTURE[name] for name in ("single", "block"))


class PcapngTests(unittest.TestCase):
    def test_literal_fixtures_and_float_timestamps(self):
        for name, expected in (
            ("pcapng-little.hex", (1.25, b"abc")),
            ("pcapng-big-nano.hex", (-0.75, b"rail")),
        ):
            raw = bytes.fromhex((ROOT / "tests/fixtures" / name).read_text())
            reader = pcapng.Reader(io.BytesIO(raw))
            self.assertEqual((reader.snaplen, reader.datalink(), reader.dloff), (64, 147, 0))
            actual = next(reader)
            self.assertEqual(actual, expected)
            self.assertIs(type(actual[0]), float)
            self.assertIs(type(actual[1]), bytes)
            self.assertEqual(list(reader), [])

    def test_all_independent_expected_records(self):
        for raw, expected, snaplen, linktype in FIXTURE["corpus"]():
            reader = pcapng.Reader(io.BytesIO(raw))
            actual = [[str(ts), type(ts).__name__, data.hex()] for ts, data in reader]
            self.assertEqual(actual, expected)
            self.assertEqual((reader.snaplen, reader.datalink()), (snaplen, linktype))

    def test_shared_cursor_callbacks_and_filter(self):
        raw = single(rows=[(n * 1_000_000, bytes([n]), 1) for n in range(5)])
        reader = pcapng.Reader(io.BytesIO(raw))
        self.assertEqual(next(iter(reader)), (0.0, b"\0"))
        self.assertEqual(reader.next(), (1.0, b"\1"))
        collected = []

        def collect(ts, data, label):
            collected.append((ts, data, label))

        self.assertEqual(reader.dispatch(2, collect, "offline"), 2)
        self.assertIsNone(reader.loop(collect, "offline"))
        self.assertEqual([row[0] for row in collected], [2, 3, 4])
        self.assertEqual(reader.readpkts(), [])
        with self.assertRaises(NotImplementedError):
            reader.setfilter("tcp")

    def test_interface_specific_time_resolution_and_offset(self):
        raw = (
            section()
            + interface()
            + interface(resolution=0x8A, offset=-2)
            + packet(ticks=1_250_000, data=b"one")
            + packet(interface_id=1, ticks=1024, data=b"two")
        )
        self.assertEqual(list(pcapng.Reader(io.BytesIO(raw))), [(1.25, b"one"), (-1.0, b"two")])

    def test_multiple_sections_switch_byte_order_and_reset_interfaces(self):
        raw = single("<", [(1_250_000, b"one", 3)], finite=True) + single(
            ">", [(2_500_000_000, b"two", 3)], resolution=9, offset=3
        )
        self.assertEqual(list(pcapng.Reader(io.BytesIO(raw))), [(1.25, b"one"), (5.5, b"two")])

    def test_borrowed_file_ownership_and_early_stop(self):
        raw = bytes.fromhex((ROOT / "tests/fixtures/pcapng-little.hex").read_text())
        with tempfile.TemporaryFile() as stream:
            stream.write(raw)
            stream.seek(0)
            with pcapng.Reader(stream) as reader:
                self.assertEqual(reader.fd, reader.fileno())
                self.assertEqual(stream.tell(), 48)
                self.assertEqual(next(reader), (1.25, b"abc"))
            self.assertFalse(stream.closed)
            self.assertEqual(stream.tell(), len(raw))
            with self.assertRaises(ValueError):
                next(reader)

    def test_path_helper_owns_file_and_handles_constructor_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pcapng"
            path.write_bytes(single(rows=[(0, b"a", 1)]))
            with pcapng.open(path) as reader:
                descriptor = reader.fd
                self.assertEqual(list(reader), [(0.0, b"a")])
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        stream = io.BytesIO(b"short")
        with patch("builtins.open", return_value=stream), self.assertRaises(octetrail.NeedData):
            pcapng.open("synthetic.pcapng")
        self.assertTrue(stream.closed)

    def test_limits_are_explicit_and_terminal(self):
        raw = bytes.fromhex((ROOT / "tests/fixtures/pcapng-little.hex").read_text())
        for limits in ({"max_packet_bytes": 2}, {"max_block_bytes": 32}):
            reader = pcapng.Reader(io.BytesIO(raw), **limits)
            with self.assertRaises(pcapng.LimitError):
                next(reader)
            self.assertEqual(list(reader), [])
        with self.assertRaises(pcapng.LimitError):
            pcapng.Reader(io.BytesIO(raw), max_interfaces=0)
        raw = section() + interface() + interface() + packet()
        reader = pcapng.Reader(io.BytesIO(raw), max_interfaces=1)
        with self.assertRaises(pcapng.LimitError):
            next(reader)
        raw = section() + interface() + block("<", 0x1234, b"") + packet()
        reader = pcapng.Reader(io.BytesIO(raw), max_blocks_per_read=1)
        with self.assertRaises(pcapng.LimitError):
            next(reader)
        for name in (
            "max_packet_bytes",
            "max_block_bytes",
            "max_interfaces",
            "max_blocks_per_read",
        ):
            with self.assertRaises(ValueError):
                pcapng.Reader(io.BytesIO(raw), **{name: -1})

    def test_short_nonseekable_reads_and_io_exception_identity(self):
        class Short(io.BytesIO):
            def read(self, size):
                return super().read(min(2, size))

        raw = single(rows=[(0, b"abc", 3)])
        self.assertEqual(list(pcapng.Reader(Short(raw))), [(0.0, b"abc")])

        class Failing(io.BytesIO):
            def read(self, size):
                if self.tell() >= self.fail_at:
                    raise self.failure
                return super().read(min(size, self.fail_at - self.tell()))

        for at in (0, 24, len(raw) - 2):
            for failure in (OSError("offline read"), InterruptedError("interrupted")):
                stream = Failing(raw)
                stream.fail_at, stream.failure = at, failure
                with self.assertRaises(type(failure)) as raised:
                    list(pcapng.Reader(stream))
                self.assertIs(raised.exception, failure)

    def test_native_references_participate_in_cycle_collection(self):
        stream = io.BytesIO(single())
        reader = pcapng.Reader(stream)
        stream.reader = reader
        refs = weakref.ref(reader), weakref.ref(stream)
        del stream, reader
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))

    def test_unsupported_packet_blocks_and_incomplete_trailer(self):
        for kind in (2, 3):
            reader = pcapng.Reader(io.BytesIO(section() + interface() + block("<", kind, b"")))
            with self.assertRaises(NotImplementedError):
                next(reader)
            self.assertEqual(list(reader), [])
        reader = pcapng.Reader(io.BytesIO(single(rows=[(0, b"abc", 3)])[:-1]))
        with self.assertRaises(octetrail.NeedData):
            next(reader)
        self.assertEqual(list(reader), [])


if __name__ == "__main__":
    unittest.main()
