"""Explicit DNS API with independently constructed ordinary offline messages."""

import importlib.util
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, PackError, dns, ip, ip6, udp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dns_fixture", ROOT / "tools/dns_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class DnsTests(unittest.TestCase):
    def test_independent_fixture_fields_bytes_construction_mutation(self):
        report = F.exercise(octetrail, "octetrail")
        self.assertEqual(report["cases"], {c["id"]: F.expected(c, "octetrail") for c in F.cases()})
        self.assertEqual(len(report["constructors"]), 12)

    def test_explicit_dns_does_not_change_transport_dispatch(self):
        wire = bytes.fromhex(next(c["wire"] for c in F.cases() if c["id"] == "query"))
        for cls, fields in ((ip.IP, {"p": 17}), (ip6.IP6, {"nxt": 17, "plen": len(wire) + 8})):
            packet = cls(
                data=udp.UDP(sport=32000, dport=53, ulen=8 + len(wire), data=wire), **fields
            )
            decoded = cls(bytes(packet))
            self.assertIsInstance(decoded.data, udp.UDP)
            self.assertEqual(decoded.data.data, wire)
            self.assertEqual(dns.DNS(decoded.data.data).qd[0].name, F.QNAME)

    def test_positive_name_record_message_boundaries(self):
        name = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        message = dns.DNS(qd=[dns.DNS.Q(name=name)])
        self.assertEqual(dns.DNS(bytes(message)).qd[0].name, name)
        with self.assertRaises(PackError):
            bytes(dns.DNS(qd=[dns.DNS.Q(name=name + "x")]))
        message = dns.DNS(qd=[dns.DNS.Q(name="") for _ in range(1024)])
        self.assertEqual(len(dns.DNS(bytes(message)).qd), 1024)
        message.qd.append(dns.DNS.Q(name=""))
        with self.assertRaises(dns.LimitError) as result:
            bytes(message)
        self.assertNotIsInstance(result.exception, octetrail.UnpackError)
        raw = b"x" * (65535 - 23)
        message = dns.DNS(an=[dns.DNS.RR(name="", type=65280, rdata=raw)])
        self.assertEqual(len(bytes(message)), 65535)
        self.assertEqual(dns.DNS(bytes(message)).an[0].rdata, raw)
        with self.assertRaises(dns.LimitError):
            dns.DNS(bytes(message) + b"x")

    def test_generic_truncation_and_declared_count_limits(self):
        for n in range(12):
            with self.assertRaises(NeedData):
                dns.DNS(bytes(n))
        query = bytes.fromhex(next(c["wire"] for c in F.cases() if c["id"] == "query"))
        with self.assertRaises(NeedData):
            dns.DNS(query[:-1])
        with self.assertRaises(NeedData):
            dns.DNS(struct.pack("!6H", 0, 0, 1025, 0, 0, 0))
        complete = struct.pack("!6H", 0, 0, 1025, 0, 0, 0) + b"\0\0\1\0\1" * 1025
        with self.assertRaises(dns.ParseLimitError) as result:
            dns.DNS(complete)
        self.assertIsInstance(result.exception, octetrail.UnpackError)
        self.assertIsInstance(result.exception, ValueError)
        self.assertIsInstance(result.exception, dns.LimitError)
        with self.assertRaises(TypeError):
            dns.DNS(bytearray(query))

    def test_known_name_rdata_rebases_when_question_layout_changes(self):
        case = next(c for c in F.cases() if c["id"] == "rr-5")
        message = dns.DNS(bytes.fromhex(case["wire"]))
        message.qd[0].name = "another.example"
        wire = F.header([1, 1, 0, 0]) + b"\x07another\x07example\0" + struct.pack("!HH", 5, 1)
        wire += b"\x04note\xc0\x14" + struct.pack("!HHIH", 5, 1, 60, 8) + b"\x05alias\xc0\x14"
        self.assertEqual(bytes(message), wire)
        self.assertEqual(dns.DNS(wire).an[0].cname, "alias.example")
        message.an[0].rdata = b"new raw override"
        with self.assertRaises(PackError):
            bytes(message)

    def test_addresses_keep_raw_precedence_and_opaque_bytes_stay_exact(self):
        case = next(c for c in F.cases() if c["id"] == "rr-1")
        message = dns.DNS(bytes.fromhex(case["wire"]))
        message.an[0].ip = bytes.fromhex("c000020a")
        self.assertEqual(bytes(message).hex(), case["wire"])
        message.an[0].rdata = b""
        self.assertEqual(dns.DNS(bytes(message)).an[0].ip, bytes.fromhex("c000020a"))
        for kind in (65280, 65281, 10, 41):
            case = next(c for c in F.cases() if c["id"] == "rr-" + str(kind))
            p = dns.DNS(bytes.fromhex(case["wire"]))
            self.assertEqual(bytes(p).hex(), case["wire"])
        with self.assertRaises(PackError):
            bytes(dns.DNS(an=[dns.DNS.RR(type=dns.DNS_A, rdata=b"x")]))

    def test_utf8_text_mutations_and_unsupported_binary_text(self):
        message = dns.DNS(
            qd=[dns.DNS.Q(name="café.example")],
            an=[dns.DNS.RR(name="", type=dns.DNS_TXT, text=["café"])],
        )
        parsed = dns.DNS(bytes(message))
        self.assertEqual(parsed.qd[0].name, "café.example")
        self.assertEqual(parsed.an[0].text, ["café"])
        parsed.an[0].text.append("note")
        self.assertEqual(dns.DNS(bytes(parsed)).an[0].text, ["café", "note"])
        with self.assertRaises(PackError):
            bytes(dns.DNS(an=[dns.DNS.RR(type=dns.DNS_TXT, text=[b"\xff"])]))
        with self.assertRaises(PackError):
            bytes(dns.DNS(an=[dns.DNS.RR(type=dns.DNS_HINFO, text=["one"])]))
        with self.assertRaises(PackError):
            bytes(dns.DNS(an=[dns.DNS.RR(type=dns.DNS_TXT, text=["x" * 256])]))
        with self.assertRaises(dns.LimitError):
            bytes(dns.DNS(an=[dns.DNS.RR(type=dns.DNS_TXT, text=["x" * 255] * 257)]))

    def test_header_counts_flags_and_independent_defaults(self):
        a, b = dns.DNS(), dns.DNS()
        a.qd.append(dns.DNS.Q(name=""))
        self.assertEqual(b.qd, [])
        a.opcode = 31
        a.rcode = 31
        a.ad = 1
        a.cd = 1
        self.assertEqual((a.opcode, a.rcode, a.ad, a.cd), (15, 15, 1, 1))
        self.assertEqual(a.pack_hdr(), struct.pack("!6H", 0, a.op, 1, 0, 0, 0))
        self.assertEqual(len(a), len(bytes(a)))
        for q in (dns.DNS.Q(name=""), dns.DNS.RR(name="")):
            with self.assertRaises(NotImplementedError):
                len(q)
        with self.assertRaises(PackError):
            bytes(dns.DNS(id=65536))
        with self.assertRaises(PackError):
            bytes(dns.DNS(an=[dns.DNS.RR(type=dns.DNS_MX)]))
        with self.assertRaises(TypeError):
            bytes(dns.DNS(qd=[object()]))

    def test_resource_and_programmer_errors_propagate(self):
        for error in (MemoryError("memory"), ValueError("caller")):
            with (
                patch.object(dns._native, "_dns_unpack", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                dns.DNS(bytes(12))
            self.assertIs(result.exception, error)

    def test_optimized_probe_rejects_wrong_installed_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/dns_differential.py",
                "--probe",
                "--module",
                "octetrail",
                "--version",
                "9.9.9",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong provider version", result.stderr)


if __name__ == "__main__":
    unittest.main()
