"""Installed-wheel tests for fixed TCP headers and opaque bytes only."""

import importlib.metadata
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from octetrail import Error, NeedData, PackError, UnpackError, tcp

LITERAL = Path(__file__).resolve().parents[1] / "fixtures/tcp-base.hex"
PROBE = Path(__file__).resolve().parents[2] / "tools/tcp_probe.py"


def literal():
    return bytes.fromhex(LITERAL.read_text())


class TCPTests(unittest.TestCase):
    def test_defaults_have_independent_explicit_wire_bytes(self):
        packet = tcp.TCP()
        self.assertEqual(
            (packet.sport, packet.dport, packet.seq, packet.ack), (0xDEAD, 0, 0xDEADBEEF, 0)
        )
        self.assertEqual(
            (packet.off, packet.flags, packet.win, packet.sum, packet.urp), (5, 2, 65535, 0, 0)
        )
        self.assertEqual((packet.opts, packet.data), (b"", b""))
        self.assertEqual(bytes(packet), bytes.fromhex("dead0000deadbeef000000005002ffff00000000"))
        self.assertEqual(len(packet), 20)

    def test_literal_exposes_unsigned_fields_and_owned_bytes(self):
        packet = tcp.TCP(literal())
        self.assertEqual((packet.sport, packet.dport), (49152, 443))
        self.assertEqual((packet.seq, packet.ack), (0x89ABCDEF, 0x10203040))
        self.assertEqual(
            (packet.off, packet.flags, packet.win, packet.sum, packet.urp), (5, 24, 32769, 41394, 0)
        )
        self.assertEqual((packet.opts, packet.data), (b"", b"tcp-base"))
        self.assertIs(type(packet.seq), int)
        self.assertIs(type(packet.opts), bytes)
        self.assertIs(type(packet.data), bytes)
        self.assertEqual(bytes(packet), literal())
        self.assertEqual(packet.pack_hdr(), literal()[:20])

    def test_keyword_construction_matches_literal(self):
        packet = tcp.TCP(
            sport=49152,
            dport=443,
            seq=0x89ABCDEF,
            ack=0x10203040,
            off=5,
            flags=tcp.TH_PUSH | tcp.TH_ACK,
            win=32769,
            sum=41394,
            urp=0,
            opts=b"",
            data=b"tcp-base",
        )
        self.assertEqual(bytes(packet), literal())
        self.assertEqual(len(packet), 28)

    def test_unsigned_sixteen_and_thirty_two_bit_fields_preserve_high_bits(self):
        packet = tcp.TCP(
            sport=65535,
            dport=32768,
            seq=0xFFFFFFFF,
            ack=0x80000000,
            flags=tcp.TH_CWR,
            win=32768,
            sum=65535,
            urp=65535,
        )
        expected = bytes.fromhex("ffff8000ffffffff8000000050808000ffffffff")
        self.assertEqual(bytes(packet), expected)
        parsed = tcp.TCP(expected)
        self.assertEqual((parsed.seq, parsed.ack, parsed.flags), (0xFFFFFFFF, 0x80000000, 0x80))

    def test_payload_lengths_do_not_generate_options_or_padding(self):
        for size in (0, 1, 7, 256, 1460):
            with self.subTest(size=size):
                payload = bytes((index * 17) % 256 for index in range(size))
                raw = literal()[:20] + payload
                packet = tcp.TCP(raw)
                self.assertEqual(packet.data, payload)
                self.assertEqual(packet.opts, b"")
                self.assertEqual(len(packet), 20 + size)
                self.assertEqual(bytes(packet), raw)

    def test_mutation_changes_each_header_field_and_payload(self):
        packet = tcp.TCP(literal())
        values = dict(sport=1, dport=2, seq=3, ack=4, off=5, flags=0x30, win=6, sum=7, urp=8)
        for name, value in values.items():
            setattr(packet, name, value)
        packet.data = b"new"
        self.assertEqual(
            bytes(packet), bytes.fromhex("0001000200000003000000045030000600070008") + b"new"
        )
        self.assertEqual(len(packet), 23)
        reparsed = tcp.TCP(bytes(packet))
        for name, value in values.items():
            self.assertEqual(getattr(reparsed, name), value)

    def test_checksum_is_caller_supplied_and_never_computed(self):
        for checksum in (0, 0x8000, 0xFFFF):
            packet = tcp.TCP(sum=checksum, data=b"first")
            first = bytes(packet)
            packet.data = b"replacement"
            self.assertEqual(first[16:18], checksum.to_bytes(2, "big"))
            self.assertEqual(bytes(packet)[16:18], checksum.to_bytes(2, "big"))
            self.assertEqual(packet.sum, checksum)

    def test_serialization_is_stable_and_instances_are_independent(self):
        first, second = tcp.TCP(literal()), tcp.TCP()
        snapshot = bytes(first)
        self.assertEqual(bytes(first), snapshot)
        first.data = b"changed"
        first.flags = tcp.TH_ACK
        self.assertEqual(snapshot, literal())
        self.assertEqual(second.data, b"")
        self.assertEqual(second.flags, tcp.TH_SYN)

    def test_short_headers_raise_need_data_in_the_existing_hierarchy(self):
        for size in range(20):
            with self.subTest(size=size), self.assertRaises(NeedData) as caught:
                tcp.TCP(literal()[:size])
            self.assertIsInstance(caught.exception, UnpackError)
            self.assertIsInstance(caught.exception, Error)

    def test_invalid_data_offset_is_unpack_error_and_preserves_existing_fields(self):
        packet = tcp.TCP(literal())
        with self.assertRaises(UnpackError) as caught:
            packet.unpack(literal()[:12] + b"\x40" + literal()[13:])
        self.assertNotIsInstance(caught.exception, NeedData)
        self.assertEqual(bytes(packet), literal())

    def test_options_and_nonce_reserved_bits_are_explicitly_unsupported(self):
        option_raw = literal()[:12] + b"\x60" + literal()[13:20] + b"\x01" * 4 + literal()[20:]
        for raw in (
            option_raw,
            literal()[:12] + b"\x51" + literal()[13:],
            literal()[:12] + b"\x58" + literal()[13:],
        ):
            with self.subTest(raw=raw), self.assertRaises(NotImplementedError):
                tcp.TCP(raw)
        for fields in ({"off": 6}, {"opts": b"\x01" * 4}):
            with self.subTest(fields=fields), self.assertRaises(NotImplementedError):
                bytes(tcp.TCP(**fields))
        with self.assertRaises(PackError):
            bytes(tcp.TCP(flags=0x100))

    def test_invalid_scalar_fields_fail_when_serialized(self):
        for name, bits in (
            ("sport", 16),
            ("dport", 16),
            ("seq", 32),
            ("ack", 32),
            ("win", 16),
            ("sum", 16),
            ("urp", 16),
        ):
            for value in (-1, 1 << bits, 1.5):
                with self.subTest(name=name, value=value):
                    packet = tcp.TCP(**{name: value})
                    with self.assertRaises(PackError) as caught:
                        bytes(packet)
                    self.assertIsInstance(caught.exception, Error)

    def test_nonbytes_inputs_and_payloads_are_declared_type_errors(self):
        for value in (bytearray(literal()), memoryview(literal())):
            with self.subTest(kind=type(value).__name__), self.assertRaises(TypeError):
                tcp.TCP(value)
            with self.subTest(kind=type(value).__name__), self.assertRaises(TypeError):
                bytes(tcp.TCP(data=value))

    def test_positional_buffer_ignores_field_keywords_and_extra_arguments_fail(self):
        self.assertEqual(bytes(tcp.TCP(literal(), seq=0, data=b"ignored")), literal())
        with self.assertRaises(TypeError):
            tcp.TCP(literal(), literal())
        with self.assertRaises(TypeError):
            tcp.TCP(unknown=1)

    def test_complete_segment_limit_accepts_boundary_and_rejects_one_extra_byte(self):
        payload = b"x" * (tcp.DEFAULT_MAX_SEGMENT_BYTES - 20)
        raw = literal()[:20] + payload
        self.assertEqual(len(tcp.TCP(raw)), tcp.DEFAULT_MAX_SEGMENT_BYTES)
        self.assertEqual(bytes(tcp.TCP(data=payload))[20:], payload)
        with self.assertRaises(tcp.LimitError):
            tcp.TCP(raw + b"x")
        with self.assertRaises(tcp.LimitError):
            bytes(tcp.TCP(data=payload + b"x"))

    def test_shared_flag_and_size_constants_are_exact(self):
        self.assertEqual(
            [
                tcp.TH_FIN,
                tcp.TH_SYN,
                tcp.TH_RST,
                tcp.TH_PUSH,
                tcp.TH_ACK,
                tcp.TH_URG,
                tcp.TH_ECE,
                tcp.TH_CWR,
            ],
            [1, 2, 4, 8, 16, 32, 64, 128],
        )
        self.assertEqual((tcp.TCP_PORT_MAX, tcp.TCP_WIN_MAX, tcp.TCP_HDR_LEN), (65535, 65535, 20))

    def test_optimized_probe_rejects_wrong_requested_version(self):
        command = [
            sys.executable,
            "-B",
            "-I",
            "-O",
            str(PROBE),
            "--module",
            "octetrail",
            "--version",
        ]
        good = subprocess.run(
            [*command, importlib.metadata.version("octetrail")],
            input="[]",
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
            timeout=30,
            check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIs(json.loads(good.stdout)["origin_verified"], True)
        bad = subprocess.run(
            [*command, "0.invalid.tcp-probe-control"],
            input="[]",
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
            timeout=30,
            check=False,
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")
        self.assertIn("version mismatch", bad.stderr)

    def test_optimized_probe_rejects_nonisolated_execution(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-O",
                str(PROBE),
                "--module",
                "octetrail",
                "--version",
                importlib.metadata.version("octetrail"),
            ],
            input="[]",
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("isolated", result.stderr)

    def test_optimized_probe_rejects_wrong_provider_origin(self):
        script = textwrap.dedent("""
            import importlib
            import importlib.metadata
            import runpy
            import sys
            from pathlib import Path
            probe_path = sys.argv[1]
            probe = runpy.run_path(probe_path)
            provider = importlib.import_module('octetrail')
            provider.__file__ = str(Path(sys.prefix).parent / 'wrong-tcp-origin' / '__init__.py')
            sys.argv = [probe_path, '--module', 'octetrail', '--version',
                        importlib.metadata.version('octetrail')]
            probe['main']()
        """)
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-O", "-c", script, str(PROBE)],
            input="[]",
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("origin", result.stderr)


if __name__ == "__main__":
    unittest.main()
