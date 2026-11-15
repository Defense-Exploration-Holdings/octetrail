"""Installed-wheel selection boundaries, separate from the differential corpus."""

import io
import unittest
from pathlib import Path

from octetrail import NeedData, pcap, pcapng

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def literal(name):
    return bytes.fromhex((FIXTURES / name).read_text())


class Traced(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.seeks = []

    def seek(self, offset, whence=0):
        self.seeks.append((offset, whence))
        return super().seek(offset, whence)


class UniversalReaderTests(unittest.TestCase):
    def test_classic_returns_concrete_reader_without_rewind(self):
        for name in ("little-micro.hex", "big-nano.hex"):
            with self.subTest(name=name):
                source = Traced(literal(name))
                reader = pcap.UniversalReader(source)
                self.assertIs(type(reader), pcap.Reader)
                self.assertNotIsInstance(reader, pcap.UniversalReader)
                self.assertEqual(source.tell(), 24)
                self.assertEqual(source.seeks, [])
                self.assertTrue(reader.readpkts())
                reader.close()
                self.assertFalse(source.closed)

    def test_pcapng_returns_concrete_reader_after_absolute_rewind(self):
        for name in ("pcapng-little.hex", "pcapng-big-nano.hex"):
            with self.subTest(name=name):
                source = Traced(literal(name))
                reader = pcap.UniversalReader(source)
                self.assertIs(type(reader), pcapng.Reader)
                self.assertEqual(source.seeks, [(0, 0)])
                self.assertTrue(reader.readpkts())
                self.assertFalse(source.closed)

    def test_classic_starts_at_current_position(self):
        source = Traced(b"prefix" + literal("little-micro.hex"))
        io.BytesIO.seek(source, 6)
        reader = pcap.UniversalReader(source)
        self.assertEqual(reader.readpkts(), [(1.25, b"abc"), (2.0, b"")])
        self.assertEqual(source.seeks, [])

    def test_pcapng_fallback_rewinds_to_file_zero_not_initial_position(self):
        first = literal("pcapng-little.hex")
        source = Traced(first + literal("pcapng-big-nano.hex"))
        io.BytesIO.seek(source, len(first))
        reader = pcap.UniversalReader(source)
        self.assertEqual(next(reader), (1.25, b"abc"))
        self.assertEqual(source.seeks, [(0, 0)])

    def test_nonseekable_classic_is_supported(self):
        class ReadOnly:
            read = io.BytesIO(literal("little-micro.hex")).read

        self.assertEqual(list(pcap.UniversalReader(ReadOnly())), [(1.25, b"abc"), (2.0, b"")])

    def test_nonseekable_pcapng_propagates_seek_failure(self):
        class ReadOnly:
            read = io.BytesIO(literal("pcapng-little.hex")).read

        with self.assertRaises(AttributeError):
            pcap.UniversalReader(ReadOnly())

    def test_seek_value_error_is_not_combined_or_retried(self):
        failure = ValueError("synthetic seek failure")

        class FailingSeek(Traced):
            def seek(self, offset, whence=0):
                raise failure

        source = FailingSeek(literal("pcapng-little.hex"))
        with self.assertRaises(ValueError) as raised:
            pcap.UniversalReader(source)
        self.assertIs(raised.exception, failure)
        self.assertFalse(source.closed)

    def test_initial_non_value_error_preserves_identity_without_rewind(self):
        failure = OSError("synthetic read failure")

        class FailingRead(Traced):
            def read(self, count):
                raise failure

        source = FailingRead(b"")
        with self.assertRaises(OSError) as raised:
            pcap.UniversalReader(source)
        self.assertIs(raised.exception, failure)
        self.assertEqual(source.seeks, [])

    def test_short_initial_header_does_not_trigger_fallback(self):
        for length in (0, 3, 23):
            with self.subTest(length=length):
                source = Traced(literal("pcapng-little.hex")[:length])
                with self.assertRaises(NeedData):
                    pcap.UniversalReader(source)
                self.assertEqual(source.tell(), length)
                self.assertEqual(source.seeks, [])
                self.assertFalse(source.closed)

    def test_two_read_value_errors_have_combined_message_and_context(self):
        failures = [ValueError("first read"), ValueError("second read")]

        class FailingRead(Traced):
            def read(self, count):
                raise failures.pop(0)

        source = FailingRead(b"")
        with self.assertRaises(ValueError) as raised:
            pcap.UniversalReader(source)
        self.assertEqual(
            str(raised.exception),
            "unknown pcap format; libpcap error: first read, pcapng error: second read",
        )
        self.assertEqual(str(raised.exception.__context__), "second read")
        self.assertIsNone(raised.exception.__cause__)
        self.assertFalse(raised.exception.__suppress_context__)
        self.assertEqual(source.seeks, [(0, 0)])

    def test_packet_error_is_not_reinterpreted_as_another_format(self):
        source = Traced(literal("pcapng-little.hex")[:-1])
        reader = pcap.UniversalReader(source)
        with self.assertRaises(NeedData):
            next(reader)
        self.assertEqual(source.seeks, [(0, 0)])

    def test_subclass_factory_still_returns_concrete_reader(self):
        class Selected(pcap.UniversalReader):
            pass

        reader = Selected(io.BytesIO(literal("little-micro.hex")))
        self.assertIs(type(reader), pcap.Reader)
        self.assertNotIsInstance(reader, Selected)


if __name__ == "__main__":
    unittest.main()
