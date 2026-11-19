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

    def test_pcapng_returns_concrete_reader_without_rewind(self):
        for name in ("pcapng-little.hex", "pcapng-big-nano.hex"):
            with self.subTest(name=name):
                source = Traced(literal(name))
                reader = pcap.UniversalReader(source)
                self.assertIs(type(reader), pcapng.Reader)
                self.assertEqual(source.seeks, [])
                self.assertTrue(reader.readpkts())
                self.assertFalse(source.closed)

    def test_classic_starts_at_current_position(self):
        source = Traced(b"prefix" + literal("little-micro.hex"))
        io.BytesIO.seek(source, 6)
        reader = pcap.UniversalReader(source)
        self.assertEqual(reader.readpkts(), [(1.25, b"abc"), (2.0, b"")])
        self.assertEqual(source.seeks, [])

    def test_pcapng_starts_at_current_position(self):
        first = literal("pcapng-little.hex")
        source = Traced(first + literal("pcapng-big-nano.hex"))
        io.BytesIO.seek(source, len(first))
        reader = pcap.UniversalReader(source)
        self.assertEqual(next(reader), (-0.75, b"rail"))
        self.assertEqual(source.seeks, [])

    def test_nonseekable_classic_is_supported(self):
        class ReadOnly:
            read = io.BytesIO(literal("little-micro.hex")).read

        self.assertEqual(list(pcap.UniversalReader(ReadOnly())), [(1.25, b"abc"), (2.0, b"")])

    def test_nonseekable_pcapng_is_supported(self):
        class ReadOnly:
            read = io.BytesIO(literal("pcapng-little.hex")).read
            name = "stream"

        reader = pcap.UniversalReader(ReadOnly())
        self.assertIs(type(reader), pcapng.Reader)
        self.assertEqual(reader.name, "stream")
        self.assertEqual(list(reader), [(1.25, b"abc")])

    def test_unknown_magic_is_rejected_after_four_bytes(self):
        source = Traced(bytes(64))
        with self.assertRaisesRegex(ValueError, "^unknown capture format: magic 00000000$"):
            pcap.UniversalReader(source)
        self.assertEqual(source.tell(), 4)
        self.assertEqual(source.seeks, [])

    def test_every_classic_magic_selects_the_classic_reader(self):
        raw = literal("little-micro.hex")
        for magic in ("d4c3b2a1", "4d3cb2a1"):
            with self.subTest(magic=magic):
                selected = pcap.UniversalReader(io.BytesIO(bytes.fromhex(magic) + raw[4:]))
                self.assertIs(type(selected), pcap.Reader)

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

    def test_read_value_error_propagates_without_another_attempt(self):
        failure = ValueError("first read")

        class FailingRead(Traced):
            def read(self, count):
                raise failure

        source = FailingRead(b"")
        with self.assertRaises(ValueError) as raised:
            pcap.UniversalReader(source)
        self.assertIs(raised.exception, failure)
        self.assertEqual(source.seeks, [])

    def test_packet_error_is_not_reinterpreted_as_another_format(self):
        source = Traced(literal("pcapng-little.hex")[:-1])
        reader = pcap.UniversalReader(source)
        with self.assertRaises(NeedData):
            next(reader)
        self.assertEqual(source.seeks, [])

    def test_subclass_factory_still_returns_concrete_reader(self):
        class Selected(pcap.UniversalReader):
            pass

        reader = Selected(io.BytesIO(literal("little-micro.hex")))
        self.assertIs(type(reader), pcap.Reader)
        self.assertNotIsInstance(reader, Selected)


if __name__ == "__main__":
    unittest.main()
