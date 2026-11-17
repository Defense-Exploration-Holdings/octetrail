"""The Packet base class and checksum helpers, which follow dpkt 1.9.8."""

import contextlib
import importlib.util
import io
import struct
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, PackError, Packet, UnpackError, packet

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "packet_fixture", ROOT / "tools/packet_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class Foo(Packet):
    __hdr__ = (("foo", "I", 1), ("bar", "H", 2), ("baz", "4s", b"quux"))


class Bits(Packet):
    __hdr__ = (("_a_b", "B", 1), ("_rsv", "B", 0), ("_c_flag", "B", 1), ("d", "B", 0))
    __bit_fields__ = {"_a_b": (("a", 4), ("b", 4))}

    @property
    def c_flag(self):
        return self.a | self.b


class PacketTests(unittest.TestCase):
    def test_fixture_runs_on_the_installed_package(self):
        report = F.exercise(packet)
        self.assertEqual(
            report["short"], {"error": "NeedData", "message": "got 5, 10 needed at least"}
        )
        self.assertEqual(report["cksum"], {"repr": "[12600, 51150, 65535, 255, 65279, 6]"})

    def test_exports(self):
        self.assertIs(octetrail.Packet, packet.Packet)
        for name in ("hexdump", "in_cksum", "in_cksum_add", "in_cksum_done"):
            self.assertIs(getattr(octetrail, name), getattr(packet, name))
        self.assertIs(packet.NeedData, NeedData)

    def test_header_metadata(self):
        self.assertEqual(Foo.__hdr_fields__, ["foo", "bar", "baz"])
        self.assertEqual((Foo.__hdr_fmt__, Foo.__hdr_len__), (">IH4s", 10))
        self.assertEqual(Foo.__slots__, ["foo", "bar", "baz", "data"])
        self.assertEqual(Bits.__bit_fields_defaults__, {"a": 0, "b": 1})

    def test_construct_unpack_and_pack(self):
        foo = Foo(bar=3)
        self.assertEqual((repr(foo), bytes(foo), len(foo)), ("Foo(bar=3)", b"\0\0\0\1\0\3quux", 10))
        self.assertEqual(dict(foo), {"foo": 1, "bar": 3, "baz": b"quux"})
        parsed = Foo(b"hello, world!", bar=9)
        self.assertEqual(repr(parsed), "Foo(foo=1751477356, bar=28460, baz=b' wor', data=b'ld!')")
        self.assertEqual(str(Foo(data=b"x")), str(bytes(Foo(data=b"x"))))
        self.assertEqual(Foo(data=Foo()).pack(), bytes(Foo()) * 2)

    def test_errors(self):
        with self.assertRaisesRegex(NeedData, "got 5, 10 needed at least"):
            Foo(b"hello")

        class Strict(Packet):
            __hdr__ = (("test", "B", 0),)

            def unpack(self, buf):
                Packet.unpack(self, buf)
                self.attribute = struct.unpack("B", buf[1:])

        with self.assertRaisesRegex(UnpackError, "invalid Strict: "):
            Strict(b"\x00")
        for bad in (Foo(foo=2**32), Foo(bar=-1), Foo(baz="text")):
            with self.assertRaises(PackError):
                bytes(bad)

    def test_tuple_fields(self):
        class Pair(Packet):
            __hdr__ = (("bar", "II", (1, 2)),)

        self.assertEqual(bytes(Pair()), b"\0\0\0\1\0\0\0\2")

    def test_bit_fields_and_repr(self):
        self.assertEqual(repr(Bits()), "Bits(c_flag=1)")
        parsed = Bits(b"\x12\x11\x00\x04")
        self.assertEqual(parsed.__public_fields__, ["a", "b", "c_flag", "d"])
        self.assertEqual(repr(parsed), "Bits(a=1, b=2, c_flag=3, d=4)")
        parsed.a = 15
        self.assertEqual(parsed._a_b, 0xF2)
        with self.assertRaisesRegex(ValueError, "too large for field b"):
            parsed.b = 16
        del parsed.a
        self.assertEqual(parsed._a_b, 0x02)
        if __debug__:
            with self.assertRaises(AssertionError):

                class Wrong(Packet):
                    __hdr__ = (("_a_b", "B", 0),)
                    __bit_fields__ = {"_a_b": (("a", 4), ("b", 3))}

    def test_layers_and_pprint(self):
        inner = Bits(d=5)
        outer = Foo(data=Foo(data=inner))
        self.assertIs(outer[Bits], inner)
        self.assertIn(Bits, outer)
        self.assertNotIn(Packet, outer)
        with self.assertRaises(KeyError):
            inner[Foo]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            Foo(note=[1], data=inner).pprint()
        self.assertEqual(
            out.getvalue(),
            "Foo(\n  foo=1,\n  bar=2,\n  baz=b'quux',\n  note=[\n    1,\n  ],\n"
            "  data=Bits(\n    a=0,\n    b=1,\n    c_flag=1,\n    d=5,\n  )  # Bits\n)  # Foo\n",
        )

    def test_helpers(self):
        data = bytes(range(15))
        self.assertEqual(
            octetrail.hexdump(data),
            "  0000:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e     ...............",
        )
        self.assertEqual(
            octetrail.hexdump(b"\\a~\x7f", 2), "  0000:  5c 61  .a\n  0002:  7e 7f  ~."
        )
        self.assertEqual(octetrail.in_cksum_add(0, data), 12600)
        self.assertEqual(octetrail.in_cksum(data), 51150)
        self.assertEqual(octetrail.in_cksum_done(0x1FFFF), 65279)


if __name__ == "__main__":
    unittest.main()
