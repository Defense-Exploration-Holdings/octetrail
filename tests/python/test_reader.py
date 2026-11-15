"""Installed-wheel tests. Run with the fresh environment's Python and -I."""

import gc
import hashlib
import importlib.metadata
import importlib.util
import io
import os
import struct
import sys
import tempfile
import unittest
import weakref
from decimal import Decimal, Inexact, localcontext
from pathlib import Path

import octetrail
from octetrail import pcap

ROOT = Path(__file__).resolve().parents[1]


def capture(records=(), *, nano=False, order="<", linktype=147):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = struct.pack(order + "IHHIIII", magic, 2, 4, 0, 0, 64, linktype)
    for seconds, fraction, data in records:
        result += struct.pack(order + "IIII", seconds, fraction, len(data), len(data))
        result += data
    return result


class InstalledReaderTests(unittest.TestCase):
    def test_installed_identity_and_no_dpkt(self):
        self.assertNotEqual(sys.prefix, sys.base_prefix)
        self.assertTrue(
            Path(octetrail.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        )
        self.assertTrue(
            Path(pcap._native.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        )
        self.assertEqual(importlib.metadata.version("octetrail"), "0.1.0")
        self.assertIsNone(importlib.util.find_spec("dpkt"))
        distribution = importlib.metadata.distribution("octetrail")
        self.assertFalse(distribution.requires)
        contents = [str(path) for path in distribution.files]
        for filename in ("LICENSE", "NOTICE", "dpkt.txt"):
            self.assertTrue(any(path.endswith(filename) for path in contents))

    def test_literal_microseconds_and_owned_bytes(self):
        raw = bytes.fromhex((ROOT / "fixtures/little-micro.hex").read_text())
        stream = io.BytesIO(raw)
        reader = pcap.Reader(stream)
        self.assertEqual(
            (reader.name, reader.snaplen, reader.datalink(), reader.dloff),
            ("<BytesIO>", 64, 147, 0),
        )
        self.assertEqual(reader.filter, "")
        first = next(reader)
        self.assertEqual(first, (1.25, b"abc"))
        self.assertIs(type(first[0]), float)
        self.assertIs(type(first[1]), bytes)
        self.assertEqual(list(reader), [(2.0, b"")])
        stream.close()
        self.assertEqual(first, (1.25, b"abc"))

    def test_literal_nanoseconds(self):
        raw = bytes.fromhex((ROOT / "fixtures/big-nano.hex").read_text())
        timestamp, data = next(pcap.Reader(io.BytesIO(raw)))
        self.assertIs(type(timestamp), Decimal)
        self.assertEqual(timestamp, Decimal("1700000000.123456789"))
        self.assertEqual(data, b"rail")

    def test_all_byte_orders_resolutions_and_boundary_times(self):
        for order in ("<", ">"):
            for nano in (False, True):
                divisor = Decimal("1E9") if nano else 1e6
                ticks = 1_000_000_000 if nano else 1_000_000
                rows = [(0, 1, b"one"), (0xFFFFFFFF, ticks - 1, b"last")]
                actual = list(pcap.Reader(io.BytesIO(capture(rows, order=order, nano=nano))))
                self.assertEqual(actual, [(sec + frac / divisor, data) for sec, frac, data in rows])

    def test_decimal_context_and_traps(self):
        raw = capture([(1_700_000_000, 123_456_789, b"sample")], nano=True)
        with localcontext() as context:
            context.prec = 6
            actual = next(pcap.Reader(io.BytesIO(raw)))[0]
            self.assertEqual(actual, 1_700_000_000 + 123_456_789 / Decimal("1E9"))
            context.traps[Inexact] = True
            with self.assertRaises(Inexact):
                next(pcap.Reader(io.BytesIO(raw)))

    def test_generator_cursor_interleaving(self):
        raw = capture([(n, 0, bytes([n])) for n in range(5)])
        reader = pcap.Reader(io.BytesIO(raw))
        left, right = iter(reader), iter(reader)
        self.assertIsNot(left, right)
        self.assertEqual(
            [next(left)[0], reader.next()[0], next(right)[0], next(reader)[0]], [0.0, 1.0, 2.0, 3.0]
        )
        self.assertEqual(reader.readpkts(), [(4.0, b"\x04")])
        self.assertEqual(list(left), [])
        self.assertEqual(list(reader), [])

    def test_dispatch_loop_and_callback_failure_cursor(self):
        raw = capture([(n, 0, b"sample") for n in range(5)])
        reader = pcap.Reader(io.BytesIO(raw))
        seen = []

        def callback(ts, data, label):
            seen.append((ts, data, label))

        self.assertEqual(reader.dispatch(2, callback, "label"), 2)
        self.assertIsNone(reader.loop(callback, "label"))
        self.assertEqual([row[0] for row in seen], [0, 1, 2, 3, 4])
        self.assertEqual(reader.dispatch(1, callback, "label"), 0)
        self.assertEqual(reader.dispatch(-1, callback, "label"), 0)
        reader = pcap.Reader(io.BytesIO(raw))
        failure = RuntimeError("callback stopped")

        def stop(*args):
            raise failure

        with self.assertRaises(RuntimeError) as raised:
            reader.dispatch(1, stop)
        self.assertIs(raised.exception, failure)
        self.assertEqual(next(reader)[0], 1.0)

    def test_borrowed_file_cursor_and_ownership(self):
        raw = capture([(1, 0, b"abc"), (2, 0, b"tail")])
        with tempfile.TemporaryFile() as stream:
            stream.write(raw)
            stream.seek(0)
            with pcap.Reader(stream) as reader:
                self.assertEqual(reader.fd, stream.fileno())
                self.assertEqual(reader.fileno(), stream.fileno())
                self.assertEqual(stream.tell(), 24)
                self.assertEqual(next(reader), (1.0, b"abc"))
                self.assertEqual(stream.tell(), 43)
            self.assertFalse(stream.closed)
            self.assertEqual(stream.read(), raw[43:])
            self.assertTrue(reader.closed)
            with self.assertRaises(ValueError):
                next(reader)

    def test_path_helper_closes_owned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            path.write_bytes(capture([(1, 0, b"abc")]))
            with pcap.open(path) as reader:
                descriptor = reader.fd
                self.assertEqual(reader.name, str(path))
                self.assertEqual(next(reader), (1.0, b"abc"))
            self.assertTrue(reader.closed)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            reader.close()
            with self.assertRaises(ValueError):
                reader.__enter__()
            with self.assertRaises(FileNotFoundError):
                pcap.open(path.with_name("absent.pcap"))

    def test_path_helper_closes_file_if_construction_fails(self):
        from unittest.mock import patch

        stream = io.BytesIO(b"short")
        with patch("builtins.open", return_value=stream), self.assertRaises(octetrail.NeedData):
            pcap.open("synthetic.pcap")
        self.assertTrue(stream.closed)

    def test_empty_capture_and_empty_packets(self):
        self.assertEqual(list(pcap.Reader(io.BytesIO(capture()))), [])
        reader = pcap.Reader(io.BytesIO(capture([(0, 0, b"")])), max_packet_bytes=0)
        self.assertEqual(next(reader), (0.0, b""))
        for _ in range(2):
            with self.assertRaises(StopIteration):
                next(reader)

    def test_exception_hierarchy_and_truncated_headers(self):
        self.assertTrue(issubclass(octetrail.NeedData, octetrail.UnpackError))
        self.assertTrue(issubclass(octetrail.UnpackError, octetrail.Error))
        raw = capture([(1, 0, b"abc")])
        for length in range(24):
            with self.assertRaises(octetrail.NeedData):
                pcap.Reader(io.BytesIO(raw[:length]))
        for length in range(25, 40):
            reader = pcap.Reader(io.BytesIO(raw[:length]))
            with self.assertRaises(octetrail.NeedData):
                next(reader)
            self.assertEqual(list(reader), [])

    def test_truncated_payload_is_an_explicit_strict_difference(self):
        raw = capture([(1, 0, b"abc")])[:-1]
        reader = pcap.Reader(io.BytesIO(raw))
        with self.assertRaisesRegex(octetrail.NeedData, "truncated packet payload"):
            next(reader)
        self.assertEqual(list(reader), [])

    def test_unknown_magic_and_version(self):
        raw = bytearray(capture())
        raw[:4] = b"none"
        with self.assertRaisesRegex(ValueError, "invalid tcpdump header"):
            pcap.Reader(io.BytesIO(raw))
        raw = bytearray(capture())
        raw[6:8] = struct.pack("<H", 3)
        with self.assertRaisesRegex(ValueError, "unsupported pcap version 2.3"):
            pcap.Reader(io.BytesIO(raw))

    def test_limits_before_payload_read_and_integer_validation(self):
        class RecordedReads(io.BytesIO):
            def read(self, size):
                self.requests.append(size)
                return super().read(size)

        stream = RecordedReads(capture([(1, 0, b"abc")]))
        stream.requests = []
        reader = pcap.Reader(stream, max_packet_bytes=2)
        with self.assertRaises(pcap.LimitError):
            next(reader)
        self.assertEqual(stream.requests, [24, 1, 15])
        self.assertEqual(stream.tell(), 40)
        self.assertEqual(list(reader), [])
        for value in (-1, 0x100000000):
            with self.assertRaises(ValueError):
                pcap.Reader(io.BytesIO(capture()), max_packet_bytes=value)
        with self.assertRaises(TypeError):
            pcap.Reader(io.BytesIO(capture()), max_packet_bytes=1.5)

    def test_nonseekable_short_reads(self):
        class Partial:
            def __init__(self, data):
                self.stream = io.BytesIO(data)

            def read(self, size):
                return self.stream.read(min(size, 2))

        reader = pcap.Reader(Partial(capture([(1, 0, b"abc")])))
        self.assertEqual(reader.name, "<Partial>")
        self.assertEqual(list(reader), [(1.0, b"abc")])

    def test_python_input_exceptions_are_preserved_by_identity(self):
        class Failing(io.BytesIO):
            def read(self, size):
                if self.tell() >= self.fail_at:
                    raise self.failure
                return super().read(min(size, self.fail_at - self.tell()))

        for at in (0, 10, 24, 30, 41):
            for failure in (OSError("offline read failed"), InterruptedError("interrupted")):
                stream = Failing(capture([(1, 0, b"abc")]))
                stream.fail_at, stream.failure = at, failure
                with self.assertRaises(type(failure)) as raised:
                    reader = pcap.Reader(stream)
                    next(reader)
                self.assertIs(raised.exception, failure)
                self.assertFalse(stream.closed)

    def test_binary_read_contract_rejects_invalid_return_values(self):
        for value in ("text", None, bytearray(b"abc"), b"x" * 25):

            class Invalid:
                def __init__(self, result):
                    self.result = result

                def read(self, size):
                    return self.result

            with self.assertRaises((TypeError, ValueError)):
                pcap.Reader(Invalid(value))

    def test_native_references_participate_in_cycle_collection(self):
        stream = io.BytesIO(capture())
        reader = pcap.Reader(stream)
        stream.reader = reader
        reader_ref, stream_ref = weakref.ref(reader), weakref.ref(stream)
        del stream, reader
        gc.collect()
        self.assertIsNone(reader_ref())
        self.assertIsNone(stream_ref())

    def test_metadata_offsets_filter_and_fileno_errors(self):
        for linktype, offset in ((1, 14), (113, 16), (276, 20), (147, 0)):
            reader = pcap.Reader(io.BytesIO(capture(linktype=linktype)))
            self.assertEqual(reader.dloff, offset)
            self.assertEqual(reader.datalink(), linktype)
            with self.assertRaises(io.UnsupportedOperation):
                reader.fileno()
            with self.assertRaises(NotImplementedError):
                reader.setfilter("tcp")

    def test_bounded_independent_offline_consumer(self):
        # A consumer aggregates records without retaining packet objects or using
        # a capture writer, protocol decoder, live input or downstream services.
        rows = [(n, n, b"row:" + n.to_bytes(2, "big")) for n in range(257)]
        expected = hashlib.sha256(b"".join(row[2] for row in rows)).hexdigest()
        for nano in (False, True):
            digest, count, total = hashlib.sha256(), 0, 0
            with pcap.Reader(io.BytesIO(capture(rows, nano=nano))) as reader:
                for timestamp, data in reader:
                    self.assertIs(type(timestamp), Decimal if nano else float)
                    digest.update(data)
                    count += 1
                    total += len(data)
            self.assertEqual((count, total, digest.hexdigest()), (257, 1542, expected))


if __name__ == "__main__":
    unittest.main()
